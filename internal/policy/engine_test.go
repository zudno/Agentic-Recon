package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeEgress struct {
	mu    chan struct{}
	calls []*HTTPRequest
	resp  *HTTPResponse
	err   error
}

func (f *fakeEgress) do(_ context.Context, r *HTTPRequest) (*HTTPResponse, error) {
	f.calls = append(f.calls, r)
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func newTestEngine(t *testing.T, doc string, eg Egress) (*Engine, *MemSink) {
	t.Helper()
	scope := mustParse(t, doc)
	if eg == nil {
		eg = (&fakeEgress{resp: &HTTPResponse{Status: 200, Body: []byte("ok")}}).do
	}
	sink := &MemSink{}
	eng, err := NewEngine(EngineConfig{
		Scope:    scope,
		Sink:     sink,
		Egress:   eg,
		Now:      func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng, sink
}

func targetReq(url string, risk RiskLevel) *Request {
	return &Request{
		Actor:  "module:test",
		Tool:   "test-tool",
		Reason: "unit test",
		Risk:   risk,
		Target: &HTTPRequest{Method: "GET", URL: url},
	}
}

func TestDoAllowedExecutesAndLogs(t *testing.T) {
	eg := &fakeEgress{resp: &HTTPResponse{Status: 200, Body: []byte("ok")}}
	eng, sink := newTestEngine(t, defaultScopeYAML, eg.do)

	resp, v, err := eng.Do(context.Background(),
		targetReq("https://api.example.com/health", RiskLowImpact))
	if err != nil || !v.Allowed || v.Scope != ScopeIn {
		t.Fatalf("do: resp=%v verdict=%+v err=%v", resp, v, err)
	}
	if resp == nil || resp.Status != 200 {
		t.Fatalf("resp = %+v", resp)
	}
	if len(eg.calls) != 1 || eg.calls[0].URL != "https://api.example.com/health" {
		t.Fatalf("egress calls = %+v", eg.calls)
	}
	if sink.Len() != 1 {
		t.Fatalf("entries = %d, want 1", sink.Len())
	}
	e := sink.Entries[0]
	if !e.Allowed || e.Result != "200" || e.Scope != ScopeIn ||
		e.Actor != "module:test" || e.Target != "GET https://api.example.com/health" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestDoDeniedOutOfScope(t *testing.T) {
	eg := &fakeEgress{}
	eng, sink := newTestEngine(t, defaultScopeYAML, eg.do)

	_, v, err := eng.Do(context.Background(), targetReq("https://other.com/", RiskLowImpact))
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if !strings.Contains(denied.Reason, "outside the signed scope") {
		t.Fatalf("reason = %q", denied.Reason)
	}
	if v.Allowed || len(eg.calls) != 0 {
		t.Fatalf("denied request must never reach the egress: %+v", v)
	}
	e := sink.Entries[0]
	if e.Allowed || e.Scope != ScopeOut || !strings.HasPrefix(e.Result, "denied:") {
		t.Fatalf("entry = %+v", e)
	}
}

func TestDoDeniedExcludedIP(t *testing.T) {
	eg := &fakeEgress{}
	eng, sink := newTestEngine(t, defaultScopeYAML, eg.do)

	_, v, err := eng.Do(context.Background(), targetReq("https://203.0.113.7/", RiskLowImpact))
	if err == nil || v.Allowed || len(eg.calls) != 0 {
		t.Fatalf("excluded target must be denied: %+v", v)
	}
	if sink.Entries[0].Scope != ScopeExcluded {
		t.Fatalf("scope verdict = %s", sink.Entries[0].Scope)
	}
}

func TestDoDeniedRiskNotEnabled(t *testing.T) {
	eg := &fakeEgress{}
	eng, _ := newTestEngine(t, defaultScopeYAML, eg.do)

	_, v, err := eng.Do(context.Background(),
		targetReq("https://api.example.com/", RiskIntrusive))
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "not enabled") {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestDoIntrusiveFailsClosedWithoutGate(t *testing.T) {
	eg := &fakeEgress{}
	doc := strings.Replace(defaultScopeYAML,
		"risk_levels: [PASSIVE, LOW_IMPACT]",
		"risk_levels: [PASSIVE, LOW_IMPACT, INTRUSIVE]", 1)
	eng, _ := newTestEngine(t, doc, eg.do) // no Approvals configured

	req := targetReq("https://api.example.com/", RiskIntrusive)
	req.ApprovalID = "forged-approval" // a claimed approval must not pass
	_, v, err := eng.Do(context.Background(), req)
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "approval gate") {
		t.Fatalf("verdict = %+v", v)
	}
	if len(eg.calls) != 0 {
		t.Fatal("intrusive action must not reach the egress without a gate")
	}
}

// fakeApprovals is a controllable policy.Approvals for engine tests.
type fakeApprovals struct {
	token string
	tool  string
	host  string
	valid bool
}

func (f *fakeApprovals) ValidateApproval(_ context.Context, token, tool, host string) error {
	if token == f.token && tool == f.tool && host == f.host && f.valid {
		return nil
	}
	return errors.New("no matching APPROVED approval")
}

func (f *fakeApprovals) ConsumeApproval(context.Context, string, string, string) error {
	return nil
}

func TestDoIntrusiveApprovalFlow(t *testing.T) {
	eg := &fakeEgress{resp: &HTTPResponse{Status: 200}}
	doc := strings.Replace(defaultScopeYAML,
		"risk_levels: [PASSIVE, LOW_IMPACT]",
		"risk_levels: [PASSIVE, LOW_IMPACT, INTRUSIVE]", 1)
	scope := mustParse(t, doc)
	sink := &MemSink{}
	eng, err := NewEngine(EngineConfig{
		Scope: scope, Sink: sink, Egress: eg.do,
		Approvals: &fakeApprovals{token: "appr-good", tool: "dir-probe", host: "api.example.com", valid: true},
		Now:       func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn:  func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Missing token → denied.
	_, v, err := eng.Do(context.Background(), targetReq("https://api.example.com/", RiskIntrusive))
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "approval token") {
		t.Fatalf("verdict = %+v", v)
	}

	// A valid (tool, host) approval lets the INTRUSIVE request through —
	// and the log line carries the token for the audit trail.
	req := targetReq("https://api.example.com/", RiskIntrusive)
	req.Tool = "dir-probe"
	req.ApprovalID = "appr-good"
	resp, v, err := eng.Do(context.Background(), req)
	if err != nil || !v.Allowed || resp.Status != 200 {
		t.Fatalf("verdict = %+v err = %v", v, err)
	}
	if sink.Entries[sink.Len()-1].ApprovedBy != "appr-good" {
		t.Fatalf("entry = %+v", sink.Entries[sink.Len()-1])
	}

	// Mismatched host → the gate rejects.
	req2 := targetReq("https://www.example.com/", RiskIntrusive)
	req2.Tool = "dir-probe"
	req2.ApprovalID = "appr-good"
	_, v, err = eng.Do(context.Background(), req2)
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "approval rejected") {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestDoSourceQueryAllowed(t *testing.T) {
	eg := &fakeEgress{resp: &HTTPResponse{Status: 200}}
	eng, sink := newTestEngine(t, defaultScopeYAML, eg.do)

	resp, v, err := eng.Do(context.Background(), &Request{
		Actor:  "module:ct-subdomains",
		Tool:   "ct-subdomains",
		Reason: "enumerate subdomains",
		Risk:   RiskPassive,
		Source: &SourceRequest{
			Source:  "crt.sh",
			Subject: "example.com",
			URL:     "https://crt.sh/?q=example.com",
		},
	})
	if err != nil || !v.Allowed || resp.Status != 200 {
		t.Fatalf("do: %+v %v", v, err)
	}
	if len(eg.calls) != 1 || eg.calls[0].URL != "https://crt.sh/?q=example.com" {
		t.Fatalf("egress calls = %+v", eg.calls)
	}
	if sink.Entries[0].Target != "crt.sh query about example.com" {
		t.Fatalf("entry target = %q", sink.Entries[0].Target)
	}
}

func TestDoSourceQueryNotAllowedSource(t *testing.T) {
	eg := &fakeEgress{}
	eng, _ := newTestEngine(t, defaultScopeYAML, eg.do)

	req := &Request{
		Actor: "module:ct-subdomains", Tool: "ct-subdomains", Risk: RiskPassive,
		Source: &SourceRequest{Source: "virustotal", Subject: "example.com", URL: "https://x/"},
	}
	_, v, err := eng.Do(context.Background(), req)
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "allow-list") {
		t.Fatalf("verdict = %+v", v)
	}
	if len(eg.calls) != 0 {
		t.Fatal("a forbidden source must never reach the egress")
	}
}

func TestDoSourceQueryAboutOutOfScopeDomain(t *testing.T) {
	eg := &fakeEgress{}
	eng, _ := newTestEngine(t, defaultScopeYAML, eg.do)

	req := &Request{
		Actor: "module:ct-subdomains", Tool: "ct-subdomains", Risk: RiskPassive,
		Source: &SourceRequest{Source: "crt.sh", Subject: "other.com", URL: "https://crt.sh/?q=other.com"},
	}
	_, v, err := eng.Do(context.Background(), req)
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "signed scope") {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestDoRequiresActorAndTool(t *testing.T) {
	eg := &fakeEgress{}
	eng, _ := newTestEngine(t, defaultScopeYAML, eg.do)

	req := targetReq("https://api.example.com/", RiskLowImpact)
	req.Actor = ""
	_, v, err := eng.Do(context.Background(), req)
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "audit attribution") {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestDoOutsideWindowDenied(t *testing.T) {
	eg := &fakeEgress{}
	eng, _ := newTestEngine(t, defaultScopeYAML, eg.do)
	eng.now = func() time.Time { return time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC) }

	_, v, err := eng.Do(context.Background(), targetReq("https://api.example.com/", RiskLowImpact))
	if err == nil || v.Allowed || !strings.Contains(v.Reason, "window") {
		t.Fatalf("verdict = %+v", v)
	}
	if len(eg.calls) != 0 {
		t.Fatal("requests outside the window must never reach the egress")
	}
}

func TestDoPacesUnderRate(t *testing.T) {
	eg := &fakeEgress{resp: &HTTPResponse{Status: 200}}
	doc := strings.Replace(defaultScopeYAML,
		"requests_per_second: 100", "requests_per_second: 1", 1)
	doc = strings.Replace(doc, "per_host_per_second: 100", "per_host_per_second: 1", 1)
	eng, sink := newTestEngine(t, doc, eg.do)

	if _, _, err := eng.Do(context.Background(), targetReq("https://api.example.com/a", RiskLowImpact)); err != nil {
		t.Fatalf("first request must pass: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	_, _, err := eng.Do(ctx, targetReq("https://api.example.com/b", RiskLowImpact))
	if err == nil || !strings.Contains(err.Error(), "pacing") {
		t.Fatalf("second request must be paced out, got: %v", err)
	}
	if len(eg.calls) != 1 {
		t.Fatalf("egress calls = %d, want 1", len(eg.calls))
	}
	last := sink.Entries[sink.Len()-1]
	if !strings.HasPrefix(last.Result, "paced-out:") {
		t.Fatalf("paced-out attempt not logged: %+v", last)
	}
}

func TestCheckDoesNotLogOrExecute(t *testing.T) {
	eg := &fakeEgress{}
	eng, sink := newTestEngine(t, defaultScopeYAML, eg.do)

	v := eng.Check(targetReq("https://other.com/", RiskLowImpact))
	if v.Allowed {
		t.Fatal("must be denied")
	}
	if len(eg.calls) != 0 || sink.Len() != 0 {
		t.Fatal("Check must not execute or log — only Do does")
	}
}

func TestDoRejectsURLWithoutHost(t *testing.T) {
	eg := &fakeEgress{}
	eng, _ := newTestEngine(t, defaultScopeYAML, eg.do)

	_, v, err := eng.Do(context.Background(), targetReq("not a url", RiskLowImpact))
	if err == nil || v.Allowed {
		t.Fatalf("verdict = %+v", v)
	}
}
