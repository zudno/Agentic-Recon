package pipeline

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// errTestNotInstalled makes wrapper tests hermetic: even when the tools are
// installed on the dev machine, tests never invoke real binaries.
type testErr string

func (e testErr) Error() string { return string(e) }

var errTestNotInstalled = testErr("not found on PATH — hermetic tests never invoke wrappers")

const ctFixture = `[
  {"common_name":"api.example.com","name_value":"api.example.com"},
  {"common_name":"*.example.com","name_value":"www.example.com\napi.example.com"},
  {"common_name":"partner.example.com","name_value":"partner.example.com"},
  {"common_name":"evil.net","name_value":"evil.net"}
]`

const probeHTML = `<html><head><title>Example API</title></head><body>ok</body></html>`

// routingEgress routes URLs to fixtures: crt.sh queries, live-looking
// probes, and a sinkhole for everything else. No test ever leaves memory.
type routingEgress struct {
	calls []string
	route map[string]*policy.HTTPResponse
	fail  map[string]error
}

func (r *routingEgress) do(_ context.Context, req *policy.HTTPRequest) (*policy.HTTPResponse, error) {
	r.calls = append(r.calls, req.URL)
	if err, ok := r.fail[req.URL]; ok {
		return nil, err
	}
	if resp, ok := r.route[req.URL]; ok {
		return resp, nil
	}
	return nil, errUnrouted
}

type constErr string

func (e constErr) Error() string { return string(e) }

var errUnrouted = constErr("no fixture for this URL — tests never dial out")

func testScopeYAML(t *testing.T) string {
	t.Helper()
	return `
authorization:
  reference: "ROE-TEST-001"
  window: {start: "2000-01-01T00:00:00Z", end: "2999-01-01T00:00:00Z"}
scope:
  domains: [example.com]
  exclude: [partner.example.com]
  sources: [crt.sh]
policy:
  risk_levels: [PASSIVE, LOW_IMPACT]
  rate: {requests_per_second: 1000, per_host_per_second: 1000, jitter_ms: 1}
budgets:
  agent_max_steps_per_hypothesis: 8
  campaign_max_tokens: 1000000
`
}

func setup(t *testing.T, eg policy.Egress) (*policy.Scope, *policy.Engine, *store.Store, int64) {
	t.Helper()
	// Wrappers must be hermetic in tests: even when the binaries are
	// installed on the developer's machine, tests never invoke them
	// (safe-test skill — zero third parties). Force "not installed".
	origLook := execLookPath
	execLookPath = func(string) (string, error) { return "", errTestNotInstalled }
	t.Cleanup(func() { execLookPath = origLook })

	scope, err := policy.Parse([]byte(testScopeYAML(t)))
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
		t.Fatalf("create campaign: %v", err)
	}
	eng, err := policy.NewEngine(policy.EngineConfig{
		Scope:    scope,
		Sink:     st.Sink(camp.ID), // evidence lands in the real request_log
		Egress:   eg,
		Now:      func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return scope, eng, st, camp.ID
}

func TestCTSubdomainsClassifiesAndLinks(t *testing.T) {
	eg := &routingEgress{route: map[string]*policy.HTTPResponse{
		"https://crt.sh/?q=%25.example.com&output=json": {Status: 200, Body: []byte(ctFixture)},
	}}
	scope, eng, st, cid := setup(t, eg.do)

	if err := CTSubdomains(context.Background(), scope, eng, st, cid); err != nil {
		t.Fatalf("CTSubdomains: %v", err)
	}

	// In-scope discoveries are visible and DISCOVERED. The apex counts:
	// the wildcard cert entry (*.example.com) normalizes to example.com,
	// and apex probing is legitimate recon.
	subs, err := st.ListAssets(context.Background(), store.ListFilter{
		CampaignID: cid, Kind: store.KindSubdomain})
	if err != nil || len(subs) != 3 {
		t.Fatalf("in-scope subdomains = %+v err=%v", subs, err)
	}
	values := map[string]bool{subs[0].Value: true, subs[1].Value: true, subs[2].Value: true}
	for _, want := range []string{"api.example.com", "www.example.com", "example.com"} {
		if !values[want] {
			t.Fatalf("missing %q in %v", want, values)
		}
	}

	// The excluded partner and the foreign evil.net persist as OUT_OF_SCOPE
	// for the exclusions report — invisible by default, present with the flag.
	hidden, err := st.ListAssets(context.Background(), store.ListFilter{
		CampaignID: cid, Kind: store.KindSubdomain, IncludeOutOfScope: true})
	if err != nil || len(hidden) != 5 {
		t.Fatalf("all subdomains = %+v err=%v", hidden, err)
	}

	// The root domain exists and every subdomain links to it (belongs_to).
	dom, err := st.GetAssetByValue(context.Background(), cid, store.KindDomain, "example.com")
	if err != nil {
		t.Fatalf("root domain missing: %v", err)
	}
	for _, s := range subs {
		links, err := st.LinksOf(context.Background(), s.ID)
		if err != nil || len(links) != 1 || links[0].ToID != dom.ID || links[0].LinkType != "belongs_to" {
			t.Fatalf("links of %s = %+v err=%v", s.Value, links, err)
		}
	}

	// The source query is in the campaign's evidence trail.
	log, err := st.ListRequestLog(context.Background(), cid, 10)
	if err != nil || len(log) != 1 || log[0].Risk != policy.RiskPassive ||
		!strings.Contains(log[0].Target, "crt.sh query about example.com") {
		t.Fatalf("request_log = %+v err=%v", log, err)
	}
}

func TestCTSubdomainsRejectsMalformedSourceResponse(t *testing.T) {
	eg := &routingEgress{route: map[string]*policy.HTTPResponse{
		"https://crt.sh/?q=%25.example.com&output=json": {Status: 200, Body: []byte("<html>blocked</html>")},
	}}
	scope, eng, st, cid := setup(t, eg.do)
	err := CTSubdomains(context.Background(), scope, eng, st, cid)
	if err == nil || !strings.Contains(err.Error(), "parse crt.sh response") {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPProbeRecordsAndIsIdempotent(t *testing.T) {
	eg := &routingEgress{route: map[string]*policy.HTTPResponse{
		"https://api.example.com/": {Status: 200, Body: []byte(probeHTML),
			Headers: map[string][]string{"Server": {"nginx"}, "Content-Type": {"text/html"}}},
	}}
	_, eng, st, cid := setup(t, eg.do)
	ctx := context.Background()
	sub, err := st.UpsertAsset(ctx, cid, store.KindSubdomain, "api.example.com", "ct-subdomains", false, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := HTTPProbe(ctx, eng, st, cid); err != nil {
		t.Fatalf("HTTPProbe: %v", err)
	}
	ws, err := st.GetAssetByValue(ctx, cid, store.KindWebService, "api.example.com")
	if err != nil {
		t.Fatalf("web service missing: %v", err)
	}
	if ws.Attrs["status"] != float64(200) || ws.Attrs["title"] != "Example API" ||
		ws.Attrs["server"] != "nginx" || ws.Attrs["scheme"] != "https" {
		t.Fatalf("web service attrs = %v", ws.Attrs)
	}
	links, err := st.LinksOf(ctx, sub.ID)
	if err != nil || len(links) != 1 || links[0].LinkType != "served_by" || links[0].ToID != ws.ID {
		t.Fatalf("links = %+v err=%v", links, err)
	}
	obs, err := st.ObservationsOf(ctx, ws.ID)
	if err != nil || len(obs) != 1 || obs[0].Source != "http-probe" {
		t.Fatalf("observations = %+v err=%v", obs, err)
	}
	callsAfterFirst := len(eg.calls)

	// Resume: a second run must not re-probe.
	if err := HTTPProbe(ctx, eng, st, cid); err != nil {
		t.Fatal(err)
	}
	if len(eg.calls) != callsAfterFirst {
		t.Fatalf("re-run re-probed: %d calls vs %d", len(eg.calls), callsAfterFirst)
	}
}

func TestHTTPProbeRecordsDeadHostsOnce(t *testing.T) {
	eg := &routingEgress{} // no fixtures: both https and http fail
	_, eng, st, cid := setup(t, eg.do)
	ctx := context.Background()
	if _, err := st.UpsertAsset(ctx, cid, store.KindSubdomain, "dead.example.com", "ct-subdomains", false, nil); err != nil {
		t.Fatal(err)
	}
	if err := HTTPProbe(ctx, eng, st, cid); err != nil {
		t.Fatal(err)
	}
	sub, err := st.GetAssetByValue(ctx, cid, store.KindSubdomain, "dead.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Attrs["probed"] != true || sub.Attrs["probe_error"] == nil {
		t.Fatalf("dead host must be marked probed with its error: %v", sub.Attrs)
	}
	// Second run: no retry storm.
	calls := len(eg.calls)
	if err := HTTPProbe(ctx, eng, st, cid); err != nil {
		t.Fatal(err)
	}
	if len(eg.calls) != calls {
		t.Fatal("dead host must not be retried on resume")
	}
	// And no web_service was minted for it.
	if _, err := st.GetAssetByValue(ctx, cid, store.KindWebService, "dead.example.com"); err == nil {
		t.Fatal("dead host must not produce a web service asset")
	}
}

// TestRunPassiveEndToEnd is the R3 criterion in miniature: a campaign
// against an owned domain produces triaged assets and its whole evidence
// trail stays inside the signed scope.
func TestRunPassiveEndToEnd(t *testing.T) {
	eg := &routingEgress{route: map[string]*policy.HTTPResponse{
		"https://crt.sh/?q=%25.example.com&output=json": {Status: 200, Body: []byte(ctFixture)},
		"https://api.example.com/": {Status: 200, Body: []byte(probeHTML),
			Headers: map[string][]string{"Server": {"nginx"}}},
	}}
	scope, eng, st, cid := setup(t, eg.do)
	ctx := context.Background()

	if err := RunPassive(ctx, scope, eng, st, cid); err != nil {
		t.Fatalf("RunPassive: %v", err)
	}

	// The evidence trail only ever touched in-scope targets: every allowed
	// entry's host is IN — the R3 criterion, verified by the log itself.
	log, err := st.ListRequestLog(ctx, cid, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) == 0 {
		t.Fatal("no evidence recorded")
	}
	for _, row := range log {
		if row.Allowed && strings.HasPrefix(row.Target, "GET ") {
			// Target like "GET https://api.example.com/" — parse the host
			// for both schemes and verify it never left the signed scope.
			u, err := url.Parse(strings.TrimPrefix(row.Target, "GET "))
			if err != nil {
				t.Fatalf("unparseable target in log: %+v", row)
			}
			if scope.HostVerdict(u.Hostname()) != policy.ScopeIn {
				t.Fatalf("allowed request left the scope: %+v", row)
			}
		}
	}

	// The operator triages: subdomain → web service validated.
	api, err := st.GetAssetByValue(ctx, cid, store.KindWebService, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateAssetState(ctx, api.ID, store.StateTriaged); err != nil {
		t.Fatalf("triage: %v", err)
	}
}
