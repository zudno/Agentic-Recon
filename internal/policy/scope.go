// Package policy is the deterministic control plane of Agentic-Recon: every
// network action —human, module, or agent— must pass through the Engine,
// which enforces the signed scope.yaml contract (README §5, §6). There is
// deliberately no AI in this package: agents propose, the engine disposes.
package policy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RiskLevel classifies a tool's interaction with the target (README §6.2).
type RiskLevel string

const (
	RiskPassive   RiskLevel = "PASSIVE"
	RiskLowImpact RiskLevel = "LOW_IMPACT"
	RiskIntrusive RiskLevel = "INTRUSIVE"
)

var knownRiskLevels = map[RiskLevel]bool{
	RiskPassive:   true,
	RiskLowImpact: true,
	RiskIntrusive: true,
}

// ScopeVerdict classifies a target relative to the signed scope.
type ScopeVerdict string

const (
	ScopeIn       ScopeVerdict = "IN"
	ScopeExcluded ScopeVerdict = "EXCLUDED"
	ScopeOut      ScopeVerdict = "OUT"
)

// TimeWindow is the authorized engagement window; the campaign refuses to
// run outside it.
type TimeWindow struct {
	Start time.Time `yaml:"start"`
	End   time.Time `yaml:"end"`
}

// Authorization ties the campaign to a signed RoE.
type Authorization struct {
	Reference string     `yaml:"reference"`
	Window    TimeWindow `yaml:"window"`
}

// Targets is the scope block of scope.yaml. Exclude always wins over
// Domains/IPs; Sources is an allow-list (absent = forbidden).
type Targets struct {
	Domains []string `yaml:"domains"`
	IPs     []string `yaml:"ips"`
	Exclude []string `yaml:"exclude"`
	Sources []string `yaml:"sources"`
}

// RateConfig bounds request pacing (README §6.3).
type RateConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	PerHostPerSecond  float64 `yaml:"per_host_per_second"`
	JitterMS          int     `yaml:"jitter_ms"`
}

// PolicyConfig is the policy block of scope.yaml.
type PolicyConfig struct {
	RiskLevels   []RiskLevel `yaml:"risk_levels"`
	Rate         RateConfig  `yaml:"rate"`
	NoiseProfile string      `yaml:"noise_profile"`
}

// Budgets bound agent loops (README §10).
type Budgets struct {
	AgentMaxStepsPerHypothesis int   `yaml:"agent_max_steps_per_hypothesis"`
	CampaignMaxTokens          int64 `yaml:"campaign_max_tokens"`
}

// LLM is the optional agent backend. The API key lives ONLY in the env var
// named by APIKeyEnv — never in scope.yaml.
type LLM struct {
	Provider  string `yaml:"provider"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
	BaseURL   string `yaml:"base_url"`
}

// Scope is the parsed, validated scope.yaml contract (README §5).
type Scope struct {
	Authorization Authorization `yaml:"authorization"`
	Targets       Targets       `yaml:"scope"`
	Policy        PolicyConfig  `yaml:"policy"`
	Budgets       Budgets       `yaml:"budgets"`
	LLM           *LLM          `yaml:"llm"`

	// compiled matchers, built by validate
	domains   []string
	cidrs     []*net.IPNet
	litIPs    map[string]bool
	exDomains []string
	exCidrs   []*net.IPNet
	exLitIPs  map[string]bool
	sources   map[string]bool
	risks     map[RiskLevel]bool
}

// Load reads and validates a scope.yaml file.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	s, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Parse validates a scope.yaml document and compiles its matchers.
func Parse(data []byte) (*Scope, error) {
	var s Scope
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse scope.yaml: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Scope) validate() error {
	if strings.TrimSpace(s.Authorization.Reference) == "" {
		return errors.New("authorization.reference is mandatory — a campaign refuses to run without a signed RoE")
	}
	if s.Authorization.Window.Start.IsZero() || s.Authorization.Window.End.IsZero() {
		return errors.New("authorization.window requires start and end")
	}
	if !s.Authorization.Window.Start.Before(s.Authorization.Window.End) {
		return errors.New("authorization.window: start must precede end")
	}
	if len(s.Targets.Domains) == 0 && len(s.Targets.IPs) == 0 {
		return errors.New("scope.domains or scope.ips must list at least one authorized target")
	}

	var err error
	if s.domains, err = normalizeDomains(s.Targets.Domains, "scope.domains"); err != nil {
		return err
	}
	if s.cidrs, s.litIPs, err = parseIPs(s.Targets.IPs, "scope.ips"); err != nil {
		return err
	}
	// Exclusions may mix domains and IPs/CIDRs — classify each entry.
	if s.exDomains, s.exCidrs, s.exLitIPs, err = parseMixedHosts(s.Targets.Exclude, "scope.exclude"); err != nil {
		return err
	}

	s.sources = make(map[string]bool)
	for _, src := range s.Targets.Sources {
		src = strings.ToLower(strings.TrimSpace(src))
		if src == "" {
			continue
		}
		s.sources[src] = true
	}

	if len(s.Policy.RiskLevels) == 0 {
		// Most conservative default: passive-only until the RoE says more.
		s.Policy.RiskLevels = []RiskLevel{RiskPassive}
	}
	s.risks = make(map[RiskLevel]bool, len(s.Policy.RiskLevels))
	for _, r := range s.Policy.RiskLevels {
		if !knownRiskLevels[r] {
			return fmt.Errorf("policy.risk_levels: unknown level %q (PASSIVE | LOW_IMPACT | INTRUSIVE)", r)
		}
		s.risks[r] = true
	}

	rc := &s.Policy.Rate
	if rc.RequestsPerSecond < 0 || rc.PerHostPerSecond < 0 || rc.JitterMS < 0 {
		return errors.New("policy.rate values must be >= 0")
	}
	if rc.RequestsPerSecond == 0 {
		rc.RequestsPerSecond = 5
	}
	if rc.PerHostPerSecond == 0 {
		rc.PerHostPerSecond = 1
	}
	if rc.JitterMS == 0 {
		rc.JitterMS = 750
	}
	if s.Budgets.AgentMaxStepsPerHypothesis == 0 {
		s.Budgets.AgentMaxStepsPerHypothesis = 8
	}
	if s.Budgets.CampaignMaxTokens == 0 {
		s.Budgets.CampaignMaxTokens = 2_000_000
	}

	if s.LLM != nil {
		switch s.LLM.Provider {
		case "anthropic", "openai-compatible":
		default:
			return fmt.Errorf("llm.provider: %q (anthropic | openai-compatible)", s.LLM.Provider)
		}
		if s.LLM.Model == "" {
			return errors.New("llm.model is required when llm is configured")
		}
		if s.LLM.APIKeyEnv == "" {
			return errors.New("llm.api_key_env is required — API keys never live in scope.yaml")
		}
	}
	return nil
}

// InWindow reports whether t falls inside the authorized window.
func (s *Scope) InWindow(t time.Time) bool {
	w := s.Authorization.Window
	return !t.Before(w.Start) && !t.After(w.End)
}

// RiskEnabled reports whether the campaign allows the given risk level.
func (s *Scope) RiskEnabled(r RiskLevel) bool { return s.risks[r] }

// SourceAllowed reports whether a third-party source is in the allow-list.
func (s *Scope) SourceAllowed(source string) bool {
	return s.sources[strings.ToLower(strings.TrimSpace(source))]
}

// HostVerdict classifies a host (hostname or IP literal, no port). R1
// simplification: hostnames are judged by name; resolution-aware verdicts
// (an in-scope name resolving to an excluded IP) arrive with the store.
func (s *Scope) HostVerdict(host string) ScopeVerdict {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ScopeOut
	}
	if ip := net.ParseIP(host); ip != nil {
		if s.exLitIPs[ip.String()] {
			return ScopeExcluded
		}
		for _, n := range s.exCidrs {
			if n.Contains(ip) {
				return ScopeExcluded
			}
		}
		if s.litIPs[ip.String()] {
			return ScopeIn
		}
		for _, n := range s.cidrs {
			if n.Contains(ip) {
				return ScopeIn
			}
		}
		return ScopeOut
	}
	if domainMatches(s.exDomains, host) {
		return ScopeExcluded
	}
	if domainMatches(s.domains, host) {
		return ScopeIn
	}
	return ScopeOut
}

// domainMatches: host equals base or is a subdomain of it.
func domainMatches(bases []string, host string) bool {
	for _, b := range bases {
		if host == b || strings.HasSuffix(host, "."+b) {
			return true
		}
	}
	return false
}

func normalizeDomains(entries []string, field string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		d, err := normalizeDomain(e, field)
		if err != nil {
			return nil, err
		}
		if d != "" {
			out = append(out, d)
		}
	}
	return out, nil
}

func normalizeDomain(e, field string) (string, error) {
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), "*.")
	if d == "" {
		return "", nil
	}
	if strings.ContainsAny(d, "/ :") || !strings.Contains(d, ".") {
		return "", fmt.Errorf("%s: %q is not a valid domain", field, e)
	}
	return d, nil
}

// parseMixedHosts classifies entries that may be domains or IPs/CIDRs —
// used for exclusions, which accept both.
func parseMixedHosts(entries []string, field string) ([]string, []*net.IPNet, map[string]bool, error) {
	var domains []string
	var cidrs []*net.IPNet
	lits := make(map[string]bool)
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%s: %q is not a valid CIDR", field, e)
			}
			cidrs = append(cidrs, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			lits[ip.String()] = true
			continue
		}
		d, err := normalizeDomain(e, field)
		if err != nil {
			return nil, nil, nil, err
		}
		domains = append(domains, d)
	}
	return domains, cidrs, lits, nil
}

func parseIPs(entries []string, field string) ([]*net.IPNet, map[string]bool, error) {
	var cidrs []*net.IPNet
	lits := make(map[string]bool)
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %q is not a valid CIDR", field, e)
			}
			cidrs = append(cidrs, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, nil, fmt.Errorf("%s: %q is not a valid IP or CIDR", field, e)
		}
		lits[ip.String()] = true
	}
	return cidrs, lits, nil
}
