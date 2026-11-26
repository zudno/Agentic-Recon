package toolbox

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

const nvdFixture = `{
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-2021-44228",
      "descriptions": [
        {"lang": "en", "value": "Apache Log4j2 remote code execution via JNDI lookup."}
      ]
    }
  }]
}`

const jsFixture = `var API = {
  login: "/api/login",
  users: "/api/v2/users",
  dup:   "/api/login",
  docs:  "/v2/api-docs",
  bad:   "not-a-route"
};`

type fixtureEgress struct {
	calls []string
	route map[string]*policy.HTTPResponse
}

func (f *fixtureEgress) do(_ context.Context, r *policy.HTTPRequest) (*policy.HTTPResponse, error) {
	f.calls = append(f.calls, r.URL)
	if resp, ok := f.route[r.URL]; ok {
		return resp, nil
	}
	return nil, constErr("no fixture for " + r.URL)
}

type constErr string

func (e constErr) Error() string { return string(e) }

func testScopeYAML(intrusive, nvd bool) string {
	srcs := "[crt.sh]"
	if nvd {
		srcs = "[crt.sh, nvd]"
	}
	risk := "[PASSIVE, LOW_IMPACT]"
	if intrusive {
		risk = "[PASSIVE, LOW_IMPACT, INTRUSIVE]"
	}
	return `
authorization:
  reference: "ROE-TEST-001"
  window: {start: "2000-01-01T00:00:00Z", end: "2999-01-01T00:00:00Z"}
scope:
  domains: [example.com]
  exclude: [partner.example.com]
  sources: ` + srcs + `
policy:
  risk_levels: ` + risk + `
  rate: {requests_per_second: 1000, per_host_per_second: 1000, jitter_ms: 1}
budgets:
  agent_max_steps_per_hypothesis: 8
  campaign_max_tokens: 1000000
`
}

type rig struct {
	scope *policy.Scope
	eng   *policy.Engine
	st    *store.Store
	tb    *Toolbox
	cid   int64
	eg    *fixtureEgress
}

func setup(t *testing.T, intrusive, nvd bool) *rig {
	t.Helper()
	scope, err := policy.Parse([]byte(testScopeYAML(intrusive, nvd)))
	if err != nil {
		t.Fatalf("parse scope: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	camp, err := st.CreateCampaign(context.Background(), "test", "ROE-TEST-001", "sha256:test")
	if err != nil {
		t.Fatalf("campaign: %v", err)
	}
	eg := &fixtureEgress{route: map[string]*policy.HTTPResponse{}}
	eng, err := policy.NewEngine(policy.EngineConfig{
		Scope:     scope,
		Sink:      st.Sink(camp.ID),
		Egress:    eg.do,
		Approvals: st, // the store IS the approval gate
		Now:       func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn:  func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return &rig{scope: scope, eng: eng, st: st, tb: New(scope, eng, st, camp.ID), cid: camp.ID, eg: eg}
}

func TestHTTPRequestTool(t *testing.T) {
	r := setup(t, false, false)
	r.eg.route["https://api.example.com/health"] = &policy.HTTPResponse{
		Status: 200, Body: []byte("ok"),
		Headers: map[string][]string{"Content-Type": {"application/json"}}}

	res := r.tb.HTTPRequest(context.Background(), "operator:test", "health check", "GET",
		"https://api.example.com/health", nil)
	if !res.OK || res.Data["status"] != 200 || len(res.EvidenceIDs) != 1 || res.EvidenceIDs[0] == 0 {
		t.Fatalf("res = %+v", res)
	}
	log, _ := r.st.ListRequestLog(context.Background(), r.cid, 5)
	if len(log) != 1 || log[0].Tool != "http_request" || log[0].Actor != "operator:test" {
		t.Fatalf("request_log = %+v", log)
	}

	// Out of scope: denied, nothing executed, denial logged.
	denied := r.tb.HTTPRequest(context.Background(), "operator:test", "x", "GET", "https://other.com/", nil)
	if denied.OK || denied.Denied == nil {
		t.Fatalf("res = %+v", denied)
	}
	log, _ = r.st.ListRequestLog(context.Background(), r.cid, 5)
	if len(log) != 2 || log[0].Allowed {
		t.Fatalf("the denial must be logged: %+v", log[0])
	}
}

func TestFetchJSRoutes(t *testing.T) {
	r := setup(t, false, false)
	r.eg.route["https://api.example.com/static/app.js"] = &policy.HTTPResponse{
		Status: 200, Body: []byte(jsFixture)}

	res := r.tb.FetchJSRoutes(context.Background(), "operator:test", "route sweep",
		"https://api.example.com/static/app.js")
	if !res.OK {
		t.Fatalf("res = %+v", res)
	}
	got, _ := res.Data["routes"].([]string)
	joined := strings.Join(got, ",")
	for _, want := range []string{"/api/login", "/api/v2/users", "/v2/api-docs"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing route %s in %v", want, got)
		}
	}
	if strings.Contains(joined, "not-a-route") || strings.Count(joined, "/api/login") != 1 {
		t.Fatalf("routes not deduped/filtered: %v", got)
	}
}

func TestCheckCVEDetails(t *testing.T) {
	// nvd allow-listed: a reference query about public knowledge.
	r := setup(t, false, true)
	r.eg.route["https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"] =
		&policy.HTTPResponse{Status: 200, Body: []byte(nvdFixture)}

	res := r.tb.CheckCVEDetails(context.Background(), "operator:test", "version check", "cve-2021-44228")
	if !res.OK || !strings.Contains(res.Data["description"].(string), "Log4j2") {
		t.Fatalf("res = %+v", res)
	}
	// The subject is a public reference, never a target — but the source
	// must still be allow-listed (next case).

	// nvd NOT allow-listed: denied by the sources allow-list.
	r2 := setup(t, false, false)
	r2.eg.route["https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"] =
		&policy.HTTPResponse{Status: 200, Body: []byte(nvdFixture)}
	denied := r2.tb.CheckCVEDetails(context.Background(), "operator:test", "x", "CVE-2021-44228")
	if denied.OK || denied.Denied == nil || !strings.Contains(denied.Denied.Reason, "allow-list") {
		t.Fatalf("res = %+v", denied)
	}

	// Malformed id: rejected before any network action.
	if bad := r.tb.CheckCVEDetails(context.Background(), "o", "r", "CVE-BAD"); bad.OK {
		t.Fatalf("malformed CVE accepted: %+v", bad)
	}
}

func TestDirProbeApprovalGate(t *testing.T) {
	r := setup(t, true, false) // INTRUSIVE enabled in this campaign
	ctx := context.Background()
	r.eg.route["https://api.example.com/admin"] = &policy.HTTPResponse{Status: 200, Body: []byte("<h1>admin</h1>")}
	r.eg.route["https://api.example.com/.env"] = &policy.HTTPResponse{Status: 200, Body: []byte("SECRET=x")}
	r.eg.route["https://api.example.com/api"] = &policy.HTTPResponse{Status: 404, Body: nil}

	// 1. Without a token the engine denies every request — the campaign
	// pauses for approval instead of acting.
	noToken := r.tb.DirProbe(ctx, "agent:test", "find exposed paths",
		"https://api.example.com", nil, "")
	if noToken.OK || noToken.Denied == nil ||
		!strings.Contains(noToken.Denied.Reason, "approval token") {
		t.Fatalf("res = %+v", noToken)
	}
	if len(r.eg.calls) != 0 {
		t.Fatal("no request may leave before approval")
	}

	// 2. File the request; a PENDING token alone still changes nothing.
	appr, err := r.tb.RequestApproval(ctx, "agent:test", "dir-probe", "api.example.com",
		"content discovery on the API host")
	if err != nil || appr.State != store.ApprovalPending {
		t.Fatalf("approval = %+v err=%v", appr, err)
	}
	pending := r.tb.DirProbe(ctx, "agent:test", "find exposed paths",
		"https://api.example.com", nil, appr.Token)
	if pending.OK || pending.Denied == nil || !strings.Contains(pending.Denied.Reason, "not APPROVED") {
		t.Fatalf("a PENDING token must be refused: %+v", pending)
	}

	// 3. The operator approves — the y/n is recorded.
	decided, err := r.st.ResolveApproval(ctx, appr.Token, true, "operator:alexis@lab")
	if err != nil || decided.State != store.ApprovalApproved || decided.DecidedBy != "operator:alexis@lab" {
		t.Fatalf("resolved = %+v err=%v", decided, err)
	}

	// 4. The probe runs and the approval is consumed exactly once.
	words := []string{"admin", ".env", "api"}
	res := r.tb.DirProbe(ctx, "agent:test", "find exposed paths",
		"https://api.example.com", words, appr.Token)
	if !res.OK {
		t.Fatalf("res = %+v", res)
	}
	if len(res.EvidenceIDs) != 3 {
		t.Fatalf("evidence ids = %v", res.EvidenceIDs)
	}
	found, _ := res.Data["found"].([]map[string]any)
	if len(found) != 2 { // admin + .env; api is 404
		t.Fatalf("found = %v", found)
	}
	ep, err := r.st.GetAssetByValue(ctx, r.cid, store.KindEndpoint, "api.example.com/admin")
	if err != nil || ep.Attrs["status"] != float64(200) {
		t.Fatalf("endpoint asset = %+v err=%v", ep, err)
	}
	if a, _ := r.st.GetApprovalByToken(ctx, appr.Token); a.State != store.ApprovalConsumed {
		t.Fatalf("approval state = %s, want CONSUMED", a.State)
	}

	// 5. Reuse of the consumed token: refused.
	again := r.tb.DirProbe(ctx, "agent:test", "find exposed paths",
		"https://api.example.com", words, appr.Token)
	if again.OK || again.Denied == nil {
		t.Fatalf("a consumed token must be refused: %+v", again)
	}

	// 6. The whole action is audited: every probe line carries the token —
	// the executed requests, and the two refused attempts (PENDING and
	// CONSUMED tokens) as well. Evidence-everything cuts both ways.
	log, _ := r.st.ListRequestLog(ctx, r.cid, 50)
	allowed, refused := 0, 0
	for _, row := range log {
		if row.Tool == "dir-probe" && row.ApprovedBy == appr.Token {
			if row.Allowed {
				allowed++
			} else {
				refused++
			}
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed probe lines = %d, want 3", allowed)
	}
	if refused != 2 {
		t.Fatalf("refused-with-token probe lines = %d, want 2 (pending + consumed)", refused)
	}
}

func TestReadAndRecordTools(t *testing.T) {
	r := setup(t, false, false)
	ctx := context.Background()
	ws, err := r.st.UpsertAsset(ctx, r.cid, store.KindWebService, "api.example.com", "http-probe", false,
		map[string]any{"title": "Swagger UI", "server": "nginx"})
	if err != nil {
		t.Fatal(err)
	}

	unexplored, err := r.tb.GetUnexploredAssets(ctx, store.KindWebService, 10)
	if err != nil || len(unexplored) != 1 || unexplored[0].ID != ws.ID {
		t.Fatalf("unexplored = %+v err=%v", unexplored, err)
	}
	byTech, err := r.tb.SearchByTech(ctx, "swagger")
	if err != nil || len(byTech) != 1 {
		t.Fatalf("search_by_tech = %+v err=%v", byTech, err)
	}
	det, err := r.tb.GetAssetDetails(ctx, ws.ID)
	if err != nil || det.Value != "api.example.com" {
		t.Fatalf("details = %+v err=%v", det, err)
	}

	h, err := r.tb.SaveHypothesis(ctx, ws.ID, "human:alexis",
		"Swagger UI exposed at root — enumerate /v2/api-docs", 0.8)
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.tb.PromoteToFinding(ctx, ws.ID, h.ID, "high", []int64{1})
	if err != nil || f.Severity != "high" {
		t.Fatalf("finding = %+v err=%v", f, err)
	}
}
