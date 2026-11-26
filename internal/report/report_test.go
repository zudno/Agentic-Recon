package report

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// rig builds a complete campaign in a temp store: assets (including
// out-of-scope), hypotheses, findings with evidence, and a request_log.
func rig(t *testing.T) (*store.Store, int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	camp, err := st.CreateCampaign(ctx, "alpha", "ROE-2026-001", "sha256:deadbeef")
	if err != nil {
		t.Fatal(err)
	}

	// Assets: one validated, one discarded, one out-of-scope.
	ws, _ := st.UpsertAsset(ctx, camp.ID, store.KindWebService, "api.example.com", "http-probe", false,
		map[string]any{"title": "Swagger UI", "server": "nginx"})
	_, _ = st.UpsertAsset(ctx, camp.ID, store.KindSubdomain, "partner-site.com", "ct-subdomains", true, nil)
	_, _ = st.UpsertAsset(ctx, camp.ID, store.KindSubdomain, "www.example.com", "ct-subdomains", false, nil)
	_, _ = st.UpsertAsset(ctx, camp.ID, store.KindSubdomain, "dead.example.com", "ct-subdomains", false, nil)

	// State transitions: validated + discarded.
	if _, err := st.UpdateAssetState(ctx, ws.ID, store.StateTriaged); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateAssetState(ctx, ws.ID, store.StateInvestigating); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateAssetState(ctx, ws.ID, store.StateValidated); err != nil {
		t.Fatal(err)
	}

	// Evidence trail: one allowed + one denied request_log line.
	sink := st.Sink(camp.ID)
	if err := sink.Log(ctx, policy.Entry{
		TS:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Actor: "agent:specialist", Tool: "http_request",
		Target: "GET https://api.example.com/v2/api-docs", Risk: policy.RiskLowImpact,
		Scope: policy.ScopeIn, Allowed: true, Result: "200",
	}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Log(ctx, policy.Entry{
		TS:    time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
		Actor: "module:ct-subdomains", Tool: "ct-subdomains",
		Target: "crt.sh query about example.com", Risk: policy.RiskPassive,
		Scope: policy.ScopeIn, Allowed: true, Result: "200",
	}); err != nil {
		t.Fatal(err)
	}

	// Hypothesis → finding with the first log line as evidence.
	h, err := st.AddHypothesis(ctx, camp.ID, ws.ID, "agent:triage",
		"Exposed Swagger UI at the root path", 0.9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddFinding(ctx, camp.ID, ws.ID, h.ID, "high", []int64{1}); err != nil {
		t.Fatal(err)
	}

	return st, camp.ID
}

func TestBuildReproducesCampaignFromLog(t *testing.T) {
	st, cid := rig(t)
	ctx := context.Background()

	rep, err := Build(ctx, st, cid)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rep.Campaign.Name != "alpha" || rep.Campaign.AuthorizationReference != "ROE-2026-001" {
		t.Fatalf("campaign = %+v", rep.Campaign)
	}

	// Inventory: all 4 assets + 1 out-of-scope.
	if rep.Inventory.Total != 4 {
		t.Fatalf("total = %d", rep.Inventory.Total)
	}
	if len(rep.OutOfScope) != 1 || rep.OutOfScope[0].Value != "partner-site.com" {
		t.Fatalf("out_of_scope = %+v", rep.OutOfScope)
	}
	if rep.Inventory.ByState["VALIDATED"] != 1 || rep.Inventory.ByState["DISCOVERED"] != 2 {
		t.Fatalf("by_state = %v", rep.Inventory.ByState)
	}

	// Findings: 1, high severity, with hypothesis + evidence.
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %d", len(rep.Findings))
	}
	f := rep.Findings[0]
	if f.Finding.Severity != "high" || f.Asset.Value != "api.example.com" {
		t.Fatalf("finding = %+v", f.Finding)
	}
	if f.Hypothesis.Reasoning != "Exposed Swagger UI at the root path" ||
		f.Hypothesis.CreatedBy != "agent:triage" {
		t.Fatalf("hypothesis = %+v", f.Hypothesis)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].ID != 1 ||
		f.Evidence[0].Tool != "http_request" || f.Evidence[0].Result != "200" {
		t.Fatalf("evidence = %+v", f.Evidence)
	}

	// The complete action trail.
	if len(rep.RequestLog) != 2 {
		t.Fatalf("request_log = %d", len(rep.RequestLog))
	}
}

func TestMarkdownContainsAllSections(t *testing.T) {
	st, cid := rig(t)
	rep, err := Build(context.Background(), st, cid)
	if err != nil {
		t.Fatal(err)
	}
	md := rep.Markdown()

	sections := []string{
		"# Agentic-Recon — Engagement Report",
		"## Campaign",
		"- **Authorization:** ROE-2026-001",
		"## Scope Summary",
		"### Excluded / Out-of-Scope Assets",
		"partner-site.com",
		"## Inventory",
		"## Findings — Prioritized Paths Toward Initial Access",
		"HIGH severity",
		"api.example.com",
		"Exposed Swagger UI at the root path",
		"agent:triage",
		"[log #1]",
		"## Complete Action Log",
		"ct-subdomains",
		"http_request",
	}
	for _, want := range sections {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n%.300s…", want, md)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	st, cid := rig(t)
	rep, err := Build(context.Background(), st, cid)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if back.Campaign.Name != "alpha" || back.Inventory.Total != 4 ||
		len(back.Findings) != 1 || len(back.Findings[0].Evidence) != 1 {
		t.Fatalf("round-trip lost data: %+v", back.Campaign)
	}
}

func TestBuildFailsOnMissingCampaign(t *testing.T) {
	st, _ := rig(t)
	if _, err := Build(context.Background(), st, 999); err == nil {
		t.Fatal("a missing campaign must error")
	}
}
