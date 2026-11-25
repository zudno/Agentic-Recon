package policy

import (
	"strings"
	"testing"
	"time"
)

const defaultScopeYAML = `
authorization:
  reference: "ROE-TEST-001"
  window: {start: "2000-01-01T00:00:00Z", end: "2999-01-01T00:00:00Z"}
scope:
  domains: [example.com]
  ips: [203.0.113.0/24]
  exclude: [partner.example.com, 203.0.113.7]
  sources: [crt.sh]
policy:
  risk_levels: [PASSIVE, LOW_IMPACT]
  rate: {requests_per_second: 100, per_host_per_second: 100, jitter_ms: 1}
budgets:
  agent_max_steps_per_hypothesis: 8
  campaign_max_tokens: 1000000
`

func mustParse(t *testing.T, doc string) *Scope {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

func TestParseValid(t *testing.T) {
	s := mustParse(t, defaultScopeYAML)
	if s.Authorization.Reference != "ROE-TEST-001" {
		t.Fatalf("reference = %q", s.Authorization.Reference)
	}
	if !s.InWindow(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("2026 must be inside the window")
	}
	if !s.RiskEnabled(RiskLowImpact) {
		t.Fatal("LOW_IMPACT must be enabled")
	}
	if !s.SourceAllowed("crt.sh") || !s.SourceAllowed("CRT.SH") {
		t.Fatal("source allow-list must be case-insensitive")
	}
}

func TestParseRequiresAuthorization(t *testing.T) {
	doc := strings.Replace(defaultScopeYAML, "ROE-TEST-001", "", 1)
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "authorization.reference") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRequiresWindow(t *testing.T) {
	doc := strings.Replace(defaultScopeYAML,
		`window: {start: "2000-01-01T00:00:00Z", end: "2999-01-01T00:00:00Z"}`, "", 1)
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "authorization.window") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRequiresTargets(t *testing.T) {
	doc := strings.Replace(defaultScopeYAML, "domains: [example.com]", "domains: []", 1)
	doc = strings.Replace(doc, "ips: [203.0.113.0/24]", "ips: []", 1)
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "at least one authorized target") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRejectsBadIP(t *testing.T) {
	doc := strings.Replace(defaultScopeYAML, "203.0.113.0/24", "not-an-ip", 1)
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "not a valid IP") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRejectsUnknownRisk(t *testing.T) {
	doc := strings.Replace(defaultScopeYAML, "[PASSIVE, LOW_IMPACT]", "[PASSIVE, LOUD]", 1)
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "unknown level") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDefaultsToPassiveOnly(t *testing.T) {
	doc := strings.Replace(defaultScopeYAML, "risk_levels: [PASSIVE, LOW_IMPACT]", "risk_levels: []", 1)
	s := mustParse(t, doc)
	if !s.RiskEnabled(RiskPassive) || s.RiskEnabled(RiskLowImpact) || s.RiskEnabled(RiskIntrusive) {
		t.Fatal("default must be PASSIVE-only")
	}
}

func TestParseRejectsLLMWithoutKeyEnv(t *testing.T) {
	doc := defaultScopeYAML + `
llm:
  provider: "anthropic"
  model: "claude-sonnet-4-20250514"
`
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "llm.api_key_env") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRejectsBadLLMProvider(t *testing.T) {
	doc := defaultScopeYAML + `
llm:
  provider: "skynet"
  model: "m"
  api_key_env: "X"
`
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "llm.provider") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseExcludesMixDomainsAndIPs(t *testing.T) {
	// Regression: exclude lists may mix domains and IPs in one entry list.
	s := mustParse(t, defaultScopeYAML)
	if s.HostVerdict("partner.example.com") != ScopeExcluded {
		t.Fatal("domain exclusion missing")
	}
	if s.HostVerdict("203.0.113.7") != ScopeExcluded {
		t.Fatal("IP exclusion missing")
	}
}

func TestHostVerdict(t *testing.T) {
	s := mustParse(t, defaultScopeYAML)
	cases := []struct {
		host string
		want ScopeVerdict
	}{
		{"example.com", ScopeIn},
		{"api.example.com", ScopeIn},
		{"deep.api.example.com", ScopeIn},
		{"evil-example.com", ScopeOut}, // suffix must include the dot
		{"notexample.com", ScopeOut},   // no partial-label matches
		{"partner.example.com", ScopeExcluded},
		{"other.com", ScopeOut},
		{"203.0.113.5", ScopeIn},
		{"203.0.113.7", ScopeExcluded},
		{"198.51.100.1", ScopeOut},
		{"", ScopeOut},
	}
	for _, tc := range cases {
		if got := s.HostVerdict(tc.host); got != tc.want {
			t.Fatalf("HostVerdict(%q) = %s, want %s", tc.host, got, tc.want)
		}
	}
}

func TestInWindowBoundaries(t *testing.T) {
	s := mustParse(t, defaultScopeYAML)
	start := s.Authorization.Window.Start
	end := s.Authorization.Window.End
	if !s.InWindow(start) || !s.InWindow(end) {
		t.Fatal("window boundaries are inclusive")
	}
	if s.InWindow(end.Add(time.Second)) || s.InWindow(start.Add(-time.Second)) {
		t.Fatal("outside the boundaries must be denied")
	}
}
