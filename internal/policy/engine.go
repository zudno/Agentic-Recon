package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxEgressBodyBytes caps what the egress reads back from the wire.
const maxEgressBodyBytes = 1 << 20

// HTTPRequest is the wire-shaped contract the engine hands to its egress.
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// HTTPResponse is what comes back through the egress.
type HTTPResponse struct {
	Status  int
	Headers map[string][]string
	Body    []byte
}

// Egress executes one validated HTTP request. Production uses DefaultEgress;
// tests inject fakes to assert the choke point.
type Egress func(ctx context.Context, r *HTTPRequest) (*HTTPResponse, error)

// DefaultEgress is the ONLY net/http client in the codebase (README §6.1 —
// enforced by TestNativeEgressOnlyInPolicy). Redirects are recorded, not
// followed; bodies are capped at 1 MiB; the user agent is honest by design.
func DefaultEgress() Egress {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return func(ctx context.Context, r *HTTPRequest) (*HTTPResponse, error) {
		method := r.Method
		if method == "" {
			method = http.MethodGet
		}
		var body io.Reader
		if len(r.Body) > 0 {
			body = bytes.NewReader(r.Body)
		}
		hreq, err := http.NewRequestWithContext(ctx, method, r.URL, body)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		for k, v := range r.Headers {
			hreq.Header.Set(k, v)
		}
		hreq.Header.Set("User-Agent", "Agentic-Recon/0.1")
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxEgressBodyBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		if len(b) > maxEgressBodyBytes {
			b = b[:maxEgressBodyBytes]
		}
		hdrs := make(map[string][]string, len(resp.Header))
		for k, vv := range resp.Header {
			hdrs[k] = vv
		}
		return &HTTPResponse{Status: resp.StatusCode, Headers: hdrs, Body: b}, nil
	}
}

// Request is one network action seeking egress: exactly one of Target
// (toward in-scope infrastructure) or Source (a query to an allowed third
// party about an in-scope asset).
type Request struct {
	Actor    string
	Tool     string
	Reason   string
	Campaign string
	Risk     RiskLevel

	Target *HTTPRequest
	Source *SourceRequest

	// ApprovalID is required for INTRUSIVE actions; the approval gate that
	// mints these lands in R4.
	ApprovalID string
}

// SourceRequest queries an allowed third-party source (README §5: sources
// are an allow-list). Subject is the query's subject: the in-scope asset
// for host-bound sources (crt.sh, dns-resolver), or a public reference id —
// a CVE — for reference sources (nvd), which carry nothing about the
// target.
type SourceRequest struct {
	Source  string
	Subject string
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// sourceSubjects classifies how the engine validates each known source's
// subject. Unknown sources default to "host" — the strictest rule: their
// subjects must be in scope.
var sourceSubjects = map[string]string{
	"crt.sh":       "host",
	"dns-resolver": "host",
	"nvd":          "reference",
}

// Approvals validates operator approvals for INTRUSIVE actions
// (README §6.2). Approvals bind (token, tool, host) and are consumed by
// the executing tool — one approval, one logical action. The
// store-backed implementation ships in R4; a nil gate fails closed.
type Approvals interface {
	// ValidateApproval reports whether the token approves this tool+host
	// without consuming it (checked on every request of a logical action).
	ValidateApproval(ctx context.Context, token, tool, host string) error
	// ConsumeApproval atomically marks the token used.
	ConsumeApproval(ctx context.Context, token, tool, host string) error
}

// Verdict is the engine's decision for one request.
type Verdict struct {
	Allowed bool
	Reason  string
	Scope   ScopeVerdict
	Risk    RiskLevel
}

// ErrDenied reports a policy refusal; Reason carries the cause.
type ErrDenied struct{ Reason string }

func (e *ErrDenied) Error() string { return "policy: " + e.Reason }

// Engine is the deterministic choke point: check, pace, execute, and log —
// in that order, every time (README §6).
type Engine struct {
	scope     *Scope
	limiter   *Limiter
	sink      Sink
	egress    Egress
	approvals Approvals
	now       func() time.Time
}

// EngineConfig wires an engine. Scope and Sink are mandatory —
// evidence-everything is not optional. Approvals is nil = the INTRUSIVE
// gate fails closed.
type EngineConfig struct {
	Scope     *Scope
	Sink      Sink
	Egress    Egress
	Approvals Approvals
	Now       func() time.Time
	JitterFn  func() time.Duration
}

// NewEngine validates the configuration and compiles the rate limiter.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Scope == nil {
		return nil, errors.New("policy: scope is required")
	}
	if cfg.Sink == nil {
		return nil, errors.New("policy: sink is required — evidence-everything is not optional")
	}
	if cfg.Egress == nil {
		cfg.Egress = DefaultEgress()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{
		scope:     cfg.Scope,
		limiter:   NewLimiter(cfg.Scope.Policy.Rate, cfg.Now, cfg.JitterFn),
		sink:      cfg.Sink,
		egress:    cfg.Egress,
		approvals: cfg.Approvals,
		now:       cfg.Now,
	}, nil
}

// PreFlightTargets validates a full target list before invoking a wrapper
// binary (README §6.1): the engine checks that every host in the list is
// inside the signed scope. This is the first of the three enforcement
// layers for wrapped tools — the binary's own rate flags and the
// persistence-layer scope check complete the gauntlet.
func (e *Engine) PreFlightTargets(ctx context.Context, hosts []string) error {
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if e.scope.HostVerdict(h) != ScopeIn {
			return fmt.Errorf("policy: pre-flight — %s is not inside the signed scope", h)
		}
	}
	return nil
}

// Check returns the verdict for a request without executing or logging it.
// It never consumes approvals — consumption belongs to the executing tool.
func (e *Engine) Check(req *Request) Verdict {
	return e.check(context.Background(), req)
}

func (e *Engine) check(ctx context.Context, req *Request) Verdict {
	deny := func(reason string, sv ScopeVerdict) Verdict {
		return Verdict{Allowed: false, Reason: reason, Scope: sv, Risk: req.Risk}
	}
	if !e.scope.InWindow(e.now()) {
		return deny("outside the authorized engagement window", ScopeOut)
	}
	if strings.TrimSpace(req.Actor) == "" || strings.TrimSpace(req.Tool) == "" {
		return deny("actor and tool are required for audit attribution", ScopeOut)
	}
	if req.Target != nil && req.Source != nil {
		return deny("a request carries exactly one of target or source", ScopeOut)
	}
	if req.Risk == "" || !knownRiskLevels[req.Risk] {
		return deny("request must declare a known risk level (PASSIVE | LOW_IMPACT | INTRUSIVE)", ScopeOut)
	}
	if !e.scope.RiskEnabled(req.Risk) {
		return deny(fmt.Sprintf("risk level %s is not enabled in policy.risk_levels", req.Risk), ScopeOut)
	}
	if req.Risk == RiskIntrusive {
		// The approval gate (README §6.2): without a configured gate, or
		// without a token the gate validates for this tool+host, the
		// action is refused. Fail closed.
		if e.approvals == nil {
			return deny("INTRUSIVE actions require the approval gate — none configured", ScopeOut)
		}
		if req.ApprovalID == "" {
			return deny("INTRUSIVE actions require an operator approval token (recon approve)", ScopeOut)
		}
		if err := e.approvals.ValidateApproval(ctx, req.ApprovalID, req.Tool, e.hostKey(req)); err != nil {
			return deny("approval rejected: "+err.Error(), ScopeOut)
		}
	}
	switch {
	case req.Target != nil:
		host, err := hostOf(req.Target.URL)
		if err != nil {
			return deny("invalid target URL: "+err.Error(), ScopeOut)
		}
		sv := e.scope.HostVerdict(host)
		if sv != ScopeIn {
			return deny(fmt.Sprintf("target %s is %s the signed scope", host, scopePhrase(sv)), sv)
		}
		return Verdict{Allowed: true, Scope: ScopeIn, Risk: req.Risk}
	case req.Source != nil:
		if !e.scope.SourceAllowed(req.Source.Source) {
			return deny(fmt.Sprintf("source %q is not in the sources allow-list", req.Source.Source), ScopeOut)
		}
		if sourceSubjects[strings.ToLower(req.Source.Source)] != "reference" {
			sv := e.scope.HostVerdict(req.Source.Subject)
			if sv != ScopeIn {
				return deny(fmt.Sprintf("source query about %s — the asset is %s the signed scope",
					req.Source.Subject, scopePhrase(sv)), sv)
			}
		}
		return Verdict{Allowed: true, Scope: ScopeIn, Risk: req.Risk}
	default:
		return deny("request carries neither a target nor a source query", ScopeOut)
	}
}

// Do runs one request through the full gauntlet: check → pace → egress →
// log. Denied and paced-out attempts are logged too — evidence-everything.
// Do validates (but never consumes) approvals; consumption belongs to the
// executing tool, once per logical action.
func (e *Engine) Do(ctx context.Context, req *Request) (*HTTPResponse, Verdict, error) {
	v := e.check(ctx, req)
	label := e.targetLabel(req)
	if !v.Allowed {
		if err := e.log(ctx, req, v, label, "denied:"+v.Reason); err != nil {
			return nil, v, fmt.Errorf("policy: evidence log failed: %w", err)
		}
		return nil, v, &ErrDenied{Reason: v.Reason}
	}
	if err := e.limiter.Wait(ctx, e.hostKey(req)); err != nil {
		if lerr := e.log(ctx, req, v, label, "paced-out:"+err.Error()); lerr != nil {
			return nil, v, fmt.Errorf("policy: evidence log failed: %w", lerr)
		}
		return nil, v, fmt.Errorf("policy: pacing: %w", err)
	}
	resp, err := e.egress(ctx, e.wireRequest(req))
	if err != nil {
		if lerr := e.log(ctx, req, v, label, "error:"+err.Error()); lerr != nil {
			return nil, v, fmt.Errorf("policy: evidence log failed: %w", lerr)
		}
		return nil, v, fmt.Errorf("policy: egress: %w", err)
	}
	if lerr := e.log(ctx, req, v, label, strconv.Itoa(resp.Status)); lerr != nil {
		return resp, v, fmt.Errorf("policy: evidence log failed: %w", lerr)
	}
	return resp, v, nil
}

func (e *Engine) log(ctx context.Context, req *Request, v Verdict, target, result string) error {
	return e.sink.Log(ctx, Entry{
		TS:         e.now().UTC(),
		Campaign:   req.Campaign,
		Actor:      req.Actor,
		Tool:       req.Tool,
		Target:     target,
		Risk:       req.Risk,
		Scope:      v.Scope,
		Allowed:    v.Allowed,
		Reason:     req.Reason,
		Result:     result,
		ApprovedBy: req.ApprovalID,
	})
}

func (e *Engine) targetLabel(req *Request) string {
	if req.Target != nil {
		return req.Target.Method + " " + req.Target.URL
	}
	if req.Source != nil {
		return req.Source.Source + " query about " + req.Source.Subject
	}
	return ""
}

func (e *Engine) hostKey(req *Request) string {
	if req.Target != nil {
		if host, err := hostOf(req.Target.URL); err == nil {
			return host
		}
	}
	if req.Source != nil {
		return "source:" + strings.ToLower(req.Source.Source)
	}
	return ""
}

func (e *Engine) wireRequest(req *Request) *HTTPRequest {
	if req.Target != nil {
		return req.Target
	}
	s := req.Source
	return &HTTPRequest{Method: s.Method, URL: s.URL, Headers: s.Headers, Body: s.Body}
}

func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no host in URL %q", rawURL)
	}
	return strings.ToLower(host), nil
}

func scopePhrase(sv ScopeVerdict) string {
	if sv == ScopeExcluded {
		return "excluded by"
	}
	return "outside"
}

// randInt63n is a package-level variable so tests can make jitter
// deterministic if they need to.
var randInt63n = rand.Int63n
