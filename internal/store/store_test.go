package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agenticrecon/internal/policy"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustCampaign(t *testing.T, s *Store) int64 {
	t.Helper()
	c, err := s.CreateCampaign(context.Background(), "test-campaign", "ROE-TEST-001", "sha256:abc")
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	return c.ID
}

func TestOpenMigratesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recon.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var version int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("schema version = %d, want %d", version, len(migrations))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopening is idempotent — the same version, no duplicated migrations.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if err := s2.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("schema version after reopen = %d", version)
	}
}

func TestCampaignLifecycle(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	if _, err := s.CreateCampaign(ctx, "", "ROE-1", "h"); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if _, err := s.CreateCampaign(ctx, "n", "", "h"); err == nil {
		t.Fatal("empty authorization reference must be rejected")
	}
	c, err := s.CreateCampaign(ctx, "alpha", "ROE-2026-001", "sha256:deadbeef")
	if err != nil || c.State != CampaignRunning {
		t.Fatalf("campaign = %+v err = %v", c, err)
	}
	if err := s.SetCampaignState(ctx, c.ID, CampaignPaused); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCampaign(ctx, c.ID)
	if err != nil || got.State != CampaignPaused {
		t.Fatalf("campaign = %+v err = %v", got, err)
	}
	if err := s.SetCampaignState(ctx, c.ID, "SLEEPING"); err == nil {
		t.Fatal("unknown campaign state must be rejected")
	}
	list, err := s.ListCampaigns(ctx)
	if err != nil || len(list) != 1 || list[0].ID != c.ID {
		t.Fatalf("campaigns = %+v err = %v", list, err)
	}
}

func TestUpsertAssetDiscoveredAndMerge(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)

	a, err := s.UpsertAsset(ctx, cid, KindSubdomain, "API.Example.COM ", "ct-subdomains", false,
		map[string]any{"status": 200, "title": "Example API"})
	if err != nil || a.ID == 0 {
		t.Fatalf("upsert: %+v %v", a, err)
	}
	if a.State != StateDiscovered || a.Value != "api.example.com" {
		t.Fatalf("asset = %+v", a)
	}
	if a.Attrs["status"] != float64(200) { // JSON round-trip yields float64
		t.Fatalf("attrs = %v", a.Attrs)
	}

	// Re-discovery merges attrs and keeps the same identity.
	b, err := s.UpsertAsset(ctx, cid, KindSubdomain, "api.example.com", "http-probe", false,
		map[string]any{"server": "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != a.ID {
		t.Fatalf("re-upsert minted a new asset: %d != %d", b.ID, a.ID)
	}
	if b.Attrs["title"] != "Example API" || b.Attrs["server"] != "nginx" {
		t.Fatalf("attrs did not merge: %v", b.Attrs)
	}
	if b.LastTouched.Before(b.FirstSeen) {
		t.Fatal("last_touched must never regress before first_seen")
	}
}

func TestUpsertRejectsInvalid(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)
	if _, err := s.UpsertAsset(ctx, cid, "", "x", "s", false, nil); err == nil {
		t.Fatal("empty kind must be rejected")
	}
	if _, err := s.UpsertAsset(ctx, cid, KindSubdomain, "  ", "s", false, nil); err == nil {
		t.Fatal("empty value must be rejected")
	}
}

func TestOutOfScopeStickyAndInvisible(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)

	// A third-party asset discovered by the pipeline is persisted as
	// OUT_OF_SCOPE for the exclusions report…
	oos, err := s.UpsertAsset(ctx, cid, KindSubdomain, "partner-site.com", "ct-subdomains", true, nil)
	if err != nil || oos.State != StateOutOfScope {
		t.Fatalf("asset = %+v err = %v", oos, err)
	}
	ok, err := s.UpsertAsset(ctx, cid, KindSubdomain, "api.example.com", "ct-subdomains", false, nil)
	if err != nil {
		t.Fatal(err)
	}

	// …but no default listing ever returns it — tools cannot see it.
	visible, err := s.ListAssets(ctx, ListFilter{CampaignID: cid})
	if err != nil || len(visible) != 1 || visible[0].ID != ok.ID {
		t.Fatalf("default listing must hide out-of-scope: %+v err=%v", visible, err)
	}
	// Asking for OUT_OF_SCOPE without the flag yields nothing (silent rule).
	asked, err := s.ListAssets(ctx, ListFilter{CampaignID: cid, States: []AssetState{StateOutOfScope}})
	if err != nil || len(asked) != 0 {
		t.Fatalf("out-of-scope filter must yield nothing: %+v err=%v", asked, err)
	}
	// Only the exclusions report (IncludeOutOfScope) may see them.
	report, err := s.ListAssets(ctx, ListFilter{CampaignID: cid, IncludeOutOfScope: true})
	if err != nil || len(report) != 2 {
		t.Fatalf("exclusions listing = %+v err=%v", report, err)
	}

	// The mark is sticky: a later in-scope-looking discovery never unmarks it.
	again, err := s.UpsertAsset(ctx, cid, KindSubdomain, "partner-site.com", "http-probe", false, nil)
	if err != nil || again.State != StateOutOfScope {
		t.Fatalf("re-upsert must keep OUT_OF_SCOPE: %+v err=%v", again, err)
	}
	if _, err := s.UpdateAssetState(ctx, oos.ID, StateTriaged); err == nil {
		t.Fatal("OUT_OF_SCOPE is terminal — no tool may revive it")
	}
}

func TestAssetStateMachine(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)

	newAsset := func(t *testing.T) Asset {
		a, err := s.UpsertAsset(ctx, cid, KindWebService, "svc"+time.Now().Format("150405.000000000"),
			"test", false, nil)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// The happy path from the README §7 diagram.
	a := newAsset(t)
	for _, to := range []AssetState{StateTriaged, StateInvestigating, StateValidated} {
		updated, err := s.UpdateAssetState(ctx, a.ID, to)
		if err != nil || updated.State != to {
			t.Fatalf("%s → %s failed: %v", a.State, to, err)
		}
	}
	// VALIDATED is terminal.
	if _, err := s.UpdateAssetState(ctx, a.ID, StateTriaged); err == nil {
		t.Fatal("VALIDATED must be terminal")
	}

	// Illegal jumps are rejected.
	b := newAsset(t)
	if _, err := s.UpdateAssetState(ctx, b.ID, StateInvestigating); err == nil {
		t.Fatal("DISCOVERED → INVESTIGATING must be illegal (triage first)")
	}
	// A mid-investigation reservation can be released.
	if _, err := s.UpdateAssetState(ctx, b.ID, StateTriaged); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateAssetState(ctx, b.ID, StateInvestigating); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateAssetState(ctx, b.ID, StateTriaged); err != nil {
		t.Fatalf("releasing an INVESTIGATING reservation must be legal: %v", err)
	}
}

func TestLinks(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)
	sub, _ := s.UpsertAsset(ctx, cid, KindSubdomain, "api.example.com", "s", false, nil)
	ip, _ := s.UpsertAsset(ctx, cid, KindIP, "203.0.113.10", "s", false, nil)

	if err := s.LinkAssets(ctx, sub.ID, ip.ID, "resolves_to"); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAssets(ctx, sub.ID, ip.ID, "resolves_to"); err != nil {
		t.Fatalf("links must be idempotent: %v", err)
	}
	out, err := s.LinksOf(ctx, sub.ID)
	if err != nil || len(out) != 1 || out[0].LinkType != "resolves_to" || out[0].ToID != ip.ID {
		t.Fatalf("LinksOf = %+v err=%v", out, err)
	}
	in, err := s.LinksTo(ctx, ip.ID)
	if err != nil || len(in) != 1 || in[0].FromID != sub.ID {
		t.Fatalf("LinksTo = %+v err=%v", in, err)
	}
	if err := s.LinkAssets(ctx, sub.ID, sub.ID, "self"); err == nil {
		t.Fatal("self-links must be rejected")
	}
}

func TestObservationsHypothesesFindings(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)
	asset, _ := s.UpsertAsset(ctx, cid, KindWebService, "api.example.com", "ct-subdomains", false, nil)

	obs, err := s.AddObservation(ctx, cid, asset.ID, "http-probe",
		map[string]any{"status": 200.0, "title": "Swagger UI"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.ObservationsOf(ctx, asset.ID)
	if err != nil || len(list) != 1 || list[0].ID != obs.ID || list[0].Attrs["title"] != "Swagger UI" {
		t.Fatalf("observations = %+v err=%v", list, err)
	}

	h, err := s.AddHypothesis(ctx, cid, asset.ID, "human:alexis",
		"Exposed Swagger UI at the root path — enumerate /v2/api-docs", 0.8)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.AddFinding(ctx, cid, asset.ID, h.ID, "high", nil); err == nil {
		t.Fatal("a finding without evidence must be rejected")
	}
	f, err := s.AddFinding(ctx, cid, asset.ID, h.ID, "high", []int64{7, 9})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := s.ListFindings(ctx, cid)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %+v err=%v", findings, err)
	}
	if findings[0].ID != f.ID || len(findings[0].EvidenceRefs) != 2 ||
		findings[0].EvidenceRefs[0] != 7 || findings[0].EvidenceRefs[1] != 9 {
		t.Fatalf("finding = %+v", findings[0])
	}

	// Findings never drift from their hypothesis's asset.
	other, _ := s.UpsertAsset(ctx, cid, KindWebService, "other.example.com", "s", false, nil)
	if _, err := s.AddFinding(ctx, cid, other.ID, h.ID, "low", []int64{1}); err == nil {
		t.Fatal("asset/hypothesis mismatch must be rejected")
	}
}

func TestDBSinkAndRequestLog(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)
	sink := s.Sink(cid)

	e1 := policy.Entry{
		TS:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Actor: "module:http-probe", Tool: "http-probe",
		Target: "GET https://api.example.com/", Risk: policy.RiskLowImpact,
		Scope: policy.ScopeIn, Allowed: true, Result: "200",
	}
	e2 := policy.Entry{
		TS:    time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
		Actor: "module:http-probe", Tool: "http-probe",
		Target: "GET https://other.com/", Risk: policy.RiskLowImpact,
		Scope: policy.ScopeOut, Allowed: false, Reason: "blocked",
		Result: "denied:target other.com is outside the signed scope",
	}
	if err := sink.Log(ctx, e1); err != nil {
		t.Fatal(err)
	}
	if err := sink.Log(ctx, e2); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ListRequestLog(ctx, cid, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows = %+v err=%v", rows, err)
	}
	// Newest first.
	if rows[0].Allowed || rows[0].Scope != policy.ScopeOut ||
		!strings.HasPrefix(rows[0].Result, "denied:") {
		t.Fatalf("row = %+v", rows[0])
	}
	if !rows[1].Allowed || rows[1].Actor != "module:http-probe" || rows[1].ID == 0 {
		t.Fatalf("row = %+v", rows[1])
	}
}

// TestResumeAcrossReopen is the R2 criterion: the campaign pauses and
// resumes with every asset, state, and evidence line intact.
func TestResumeAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recon.db")
	ctx := context.Background()

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s1.CreateCampaign(ctx, "engagement-alpha", "ROE-2026-001", "sha256:deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	keep, _ := s1.UpsertAsset(ctx, c.ID, KindSubdomain, "api.example.com", "ct-subdomains", false,
		map[string]any{"title": "Example API"})
	if _, err := s1.UpdateAssetState(ctx, keep.ID, StateTriaged); err != nil {
		t.Fatal(err)
	}
	if err := s1.Sink(c.ID).Log(ctx, policy.Entry{
		TS: time.Now().UTC(), Actor: "module:x", Tool: "x",
		Target: "GET https://api.example.com/", Risk: policy.RiskPassive,
		Scope: policy.ScopeIn, Allowed: true, Result: "200",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s1.SetCampaignState(ctx, c.ID, CampaignPaused); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// "Resume": reopen the same file and keep working without loss.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetCampaign(ctx, c.ID)
	if err != nil || got.State != CampaignPaused || got.AuthorizationReference != "ROE-2026-001" {
		t.Fatalf("campaign after reopen = %+v err=%v", got, err)
	}
	asset, err := s2.GetAsset(ctx, keep.ID)
	if err != nil || asset.State != StateTriaged || asset.Attrs["title"] != "Example API" {
		t.Fatalf("asset after reopen = %+v err=%v", asset, err)
	}
	if _, err := s2.UpdateAssetState(ctx, keep.ID, StateInvestigating); err != nil {
		t.Fatalf("state machine must continue after resume: %v", err)
	}
	log, err := s2.ListRequestLog(ctx, c.ID, 10)
	if err != nil || len(log) != 1 || log[0].Target != "GET https://api.example.com/" {
		t.Fatalf("request_log after reopen = %+v err=%v", log, err)
	}
	if err := s2.SetCampaignState(ctx, c.ID, CampaignRunning); err != nil {
		t.Fatalf("resume: %v", err)
	}
}

func TestGetAssetMissing(t *testing.T) {
	s := openStore(t)
	if _, err := s.GetAsset(context.Background(), 999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v, want sql.ErrNoRows", err)
	}
}
