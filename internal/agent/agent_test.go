package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
	"agenticrecon/internal/toolbox"
)

// scriptedClient plays back fixed assistant turns and records what the
// agents asked — zero third parties, zero cost, deterministic loops.
type scriptedClient struct {
	turns    []Assistant
	usages   []Usage
	systems  []string
	turnMsgs [][]Msg
	next     int
}

func (s *scriptedClient) Complete(_ context.Context, system string, msgs []Msg, _ []ToolDef) (Assistant, Usage, error) {
	i := s.next
	s.next++
	s.systems = append(s.systems, system)
	s.turnMsgs = append(s.turnMsgs, msgs)
	u := Usage{InputTokens: 10, OutputTokens: 5}
	if i < len(s.usages) {
		u = s.usages[i]
	}
	if i < len(s.turns) {
		return s.turns[i], u, nil
	}
	return Assistant{Text: `{"verdict":"discarded","severity":"info","reasoning":"script exhausted"}`}, u, nil
}

func (s *scriptedClient) calls() int { return s.next }

func toolTurn(calls ...ToolCall) Assistant {
	return Assistant{ToolCalls: calls, StoppedOnTools: true}
}

type constErr string

func (e constErr) Error() string { return string(e) }

func agentScope(t *testing.T) *policy.Scope {
	t.Helper()
	s, err := policy.Parse([]byte(`
authorization:
  reference: "ROE-TEST-001"
  window: {start: "2000-01-01T00:00:00Z", end: "2999-01-01T00:00:00Z"}
scope:
  domains: [example.com]
  sources: [crt.sh, nvd]
policy:
  risk_levels: [PASSIVE, LOW_IMPACT]
  rate: {requests_per_second: 1000, per_host_per_second: 1000, jitter_ms: 1}
budgets:
  agent_max_steps_per_hypothesis: 3
  campaign_max_tokens: 1000000
`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func agentRig(t *testing.T, eg policy.Egress) (*policy.Scope, *store.Store, *toolbox.Toolbox, int64) {
	t.Helper()
	scope := agentScope(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	camp, err := st.CreateCampaign(context.Background(), "test", "ROE-TEST-001", "sha256:t")
	if err != nil {
		t.Fatal(err)
	}
	if eg == nil {
		eg = func(context.Context, *policy.HTTPRequest) (*policy.HTTPResponse, error) {
			return nil, constErr("no egress in this test")
		}
	}
	eng, err := policy.NewEngine(policy.EngineConfig{
		Scope:    scope,
		Sink:     st.Sink(camp.ID),
		Egress:   eg,
		Now:      func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return scope, st, toolbox.New(scope, eng, st, camp.ID), camp.ID
}

func TestTriageAgentPromotesAndDiscards(t *testing.T) {
	scope, st, tb, cid := agentRig(t, nil)
	ctx := context.Background()
	interesting, _ := st.UpsertAsset(ctx, cid, store.KindWebService, "api.example.com", "http-probe", false,
		map[string]any{"title": "Swagger UI", "server": "nginx"})
	boring, _ := st.UpsertAsset(ctx, cid, store.KindWebService, "www.example.com", "http-probe", false,
		map[string]any{"title": "Marketing site"})

	scripted := &scriptedClient{turns: []Assistant{
		{Text: `{"score": 0.9, "reasoning": "Exposed Swagger UI at the root", "investigate": true}`},
		{Text: `{"score": 0.1, "reasoning": "Plain marketing front", "investigate": false}`},
		{Text: `not json at all`},
	}}
	tri := NewTriageAgent("agent:triage", tb, scripted, scope)
	report, err := tri.Run(ctx, store.KindWebService, 10)
	if err != nil {
		t.Fatal(err)
	}
	if report.Reviewed != 2 || report.Promoted != 1 || report.Discarded != 1 {
		t.Fatalf("report = %+v", report)
	}
	api, _ := st.GetAsset(ctx, interesting.ID)
	if api.State != store.StateTriaged {
		t.Fatalf("interesting asset = %s", api.State)
	}
	www, _ := st.GetAsset(ctx, boring.ID)
	if www.State != store.StateDiscarded {
		t.Fatalf("boring asset = %s", www.State)
	}
	list, err := st.ListAssets(ctx, store.ListFilter{CampaignID: cid, Kind: store.KindWebService})
	if err != nil || len(list) != 2 {
		t.Fatalf("assets = %+v err=%v", list, err)
	}
	// The third scripted reply (garbage) is never reached: only 2 assets.
	if scripted.calls() != 2 {
		t.Fatalf("llm calls = %d", scripted.calls())
	}
}

func TestTriageBudgetAbortsRun(t *testing.T) {
	scope, st, tb, cid := agentRig(t, nil)
	ctx := context.Background()
	if _, err := st.UpsertAsset(ctx, cid, store.KindWebService, "a.example.com", "s", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAsset(ctx, cid, store.KindWebService, "b.example.com", "s", false, nil); err != nil {
		t.Fatal(err)
	}
	// The first turn alone blows the ceiling.
	scripted := &scriptedClient{
		usages: []Usage{{InputTokens: 900_000, OutputTokens: 900_000}},
		turns:  []Assistant{{Text: `{"score":0.5,"reasoning":"r","investigate":true}`}},
	}
	tri := NewTriageAgent("agent:triage", tb, scripted, scope)
	report, err := tri.Run(ctx, store.KindWebService, 10)
	if err == nil || !report.Aborted {
		t.Fatalf("err = %v report = %+v", err, report)
	}
	if scripted.calls() != 1 {
		t.Fatalf("the budget must abort after the first turn: calls = %d", scripted.calls())
	}
}

func TestSpecialistValidatesWithEvidence(t *testing.T) {
	eg := func(_ context.Context, r *policy.HTTPRequest) (*policy.HTTPResponse, error) {
		if r.URL == "https://api.example.com/v2/api-docs" {
			return &policy.HTTPResponse{Status: 200,
				Body: []byte(`{"swagger":"2.0","paths":{"/users":{}}}`)}, nil
		}
		return nil, constErr("no fixture")
	}
	scope, st, tb, cid := agentRig(t, eg)
	ctx := context.Background()
	ws, _ := st.UpsertAsset(ctx, cid, store.KindWebService, "api.example.com", "http-probe", false,
		map[string]any{"title": "Swagger UI"})
	if _, err := st.UpdateAssetState(ctx, ws.ID, store.StateTriaged); err != nil {
		t.Fatal(err)
	}

	scripted := &scriptedClient{turns: []Assistant{
		toolTurn(ToolCall{ID: "c1", Name: "http_request",
			Arguments: `{"method":"GET","url":"https://api.example.com/v2/api-docs","reason":"confirm the exposed API docs"}`}),
		{Text: `{"verdict":"validated","severity":"high","reasoning":"Swagger API docs exposed without authentication; /users endpoint enumerable."}`},
	}}
	spec := NewSpecialistAgent("agent:specialist", tb, scripted, scope)
	out, err := spec.Run(ctx, Investigation{AssetID: ws.ID, Reasoning: "Swagger UI exposed at root"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "validated" || out.FindingID == 0 || len(out.Evidence) != 1 {
		t.Fatalf("outcome = %+v", out)
	}
	if out.StepsUsed != 2 {
		t.Fatalf("steps = %d", out.StepsUsed)
	}
	asset, _ := st.GetAsset(ctx, ws.ID)
	if asset.State != store.StateValidated {
		t.Fatalf("asset = %s", asset.State)
	}
	findings, _ := st.ListFindings(ctx, cid)
	if len(findings) != 1 || findings[0].Severity != "high" ||
		len(findings[0].EvidenceRefs) != 1 || findings[0].EvidenceRefs[0] != out.Evidence[0] {
		t.Fatalf("findings = %+v", findings)
	}
	// The evidence reference points at a real request_log line.
	log, _ := st.ListRequestLog(ctx, cid, 10)
	if len(log) != 1 || log[0].Tool != "http_request" || log[0].Actor != "agent:specialist" {
		t.Fatalf("request_log = %+v", log)
	}
}

func TestSpecialistValidatedWithoutEvidenceIsDiscarded(t *testing.T) {
	scope, st, tb, cid := agentRig(t, nil)
	ctx := context.Background()
	ws, _ := st.UpsertAsset(ctx, cid, store.KindWebService, "x.example.com", "s", false, nil)
	if _, err := st.UpdateAssetState(ctx, ws.ID, store.StateTriaged); err != nil {
		t.Fatal(err)
	}
	scripted := &scriptedClient{turns: []Assistant{
		{Text: `{"verdict":"validated","severity":"high","reasoning":"looks bad"}`},
	}}
	spec := NewSpecialistAgent("agent:specialist", tb, scripted, scope)
	out, err := spec.Run(ctx, Investigation{AssetID: ws.ID, Reasoning: "check it"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "discarded" {
		t.Fatalf("evidence-free validation must downgrade: %+v", out)
	}
	asset, _ := st.GetAsset(ctx, ws.ID)
	if asset.State != store.StateDiscarded {
		t.Fatalf("asset = %s", asset.State)
	}
	findings, _ := st.ListFindings(ctx, cid)
	if len(findings) != 0 {
		t.Fatal("no finding may exist without evidence")
	}
}

func TestSpecialistStepsExhaustedReleasesAsset(t *testing.T) {
	scope, st, tb, cid := agentRig(t, nil)
	ctx := context.Background()
	ws, _ := st.UpsertAsset(ctx, cid, store.KindWebService, "loop.example.com", "s", false, nil)
	if _, err := st.UpdateAssetState(ctx, ws.ID, store.StateTriaged); err != nil {
		t.Fatal(err)
	}
	// The model never concludes: every turn asks for the same tool. The
	// agent package has no egress fixture, so the tool returns an error —
	// the loop must still stop at the step ceiling and release the asset.
	alwaysTools := toolTurn(ToolCall{ID: "c", Name: "http_request",
		Arguments: `{"method":"GET","url":"https://loop.example.com/","reason":"again"}`})
	scripted := &scriptedClient{turns: []Assistant{alwaysTools, alwaysTools, alwaysTools, alwaysTools}}
	spec := NewSpecialistAgent("agent:specialist", tb, scripted, scope)
	out, err := spec.Run(ctx, Investigation{AssetID: ws.ID, Reasoning: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "aborted" || out.StepsUsed != 3 { // scope sets max 3
		t.Fatalf("outcome = %+v", out)
	}
	asset, _ := st.GetAsset(ctx, ws.ID)
	if asset.State != store.StateTriaged {
		t.Fatalf("an exhausted run must release the reservation, got %s", asset.State)
	}
}

func TestTriageDecisionParsing(t *testing.T) {
	good := `Here you go: {"score": 0.8, "reasoning": "admin panel", "investigate": true} — done.`
	if d, ok := parseTriageDecision(good); !ok || d.Investigate != true || d.Score != 0.8 {
		t.Fatalf("d = %+v ok=%v", d, ok)
	}
	if _, ok := parseTriageDecision("no json here"); ok {
		t.Fatal("garbage must not parse")
	}
	if _, ok := parseTriageDecision(`{"score": 5, "reasoning": "x", "investigate": true}`); ok {
		t.Fatal("out-of-range score must not parse")
	}
}
