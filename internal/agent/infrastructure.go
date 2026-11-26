// Package agent — infrastructure.go: the Infrastructure Specialist Agent
// (README §10). Unlike the web specialist (one task, one asset), this
// agent takes a WHOLE CAMPAIGN view: it reads every host, every banner,
// every observation, correlates versions against known vulnerabilities,
// and synthesizes prioritized attack paths — the "if I were an attacker,
// I'd start here because..." analysis.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
	"agenticrecon/internal/toolbox"
)

// InfraReport is the Infrastructure Specialist's synthesis.
type InfraReport struct {
	Summary     string            `json:"summary"`
	NetworkMap  []HostSummary     `json:"network_map"`
	AttackPaths []AttackPath      `json:"attack_paths"`
	Priorities  []PriorityFinding `json:"priorities"`
	TokensUsed  int64             `json:"tokens_used"`
}

// HostSummary is one host's classification and risk level.
type HostSummary struct {
	Host      string   `json:"host"`
	Role      string   `json:"role"`
	SSHBanner string   `json:"ssh_banner,omitempty"`
	SSHRisk   string   `json:"ssh_risk,omitempty"`
	Services  []string `json:"services,omitempty"`
	RiskLevel string   `json:"risk_level"`
}

// AttackPath is a multi-step path toward initial access.
type AttackPath struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	RiskLevel   string   `json:"risk_level"`
	EntryHost   string   `json:"entry_host"`
}

// PriorityFinding is the top actionable intelligence.
type PriorityFinding struct {
	Host      string `json:"host"`
	Finding   string `json:"finding"`
	Severity  string `json:"severity"`
	Reasoning string `json:"reasoning"`
	Evidence  string `json:"evidence"`
}

// InfrastructureAgent runs the whole-campaign analysis.
type InfrastructureAgent struct {
	Actor            string
	tb               *toolbox.Toolbox
	client           Client
	budget           *Budget
	campaignFindings []store.Finding
}

// NewInfrastructureAgent wires the agent.
func NewInfrastructureAgent(actor string, tb *toolbox.Toolbox, client Client, scope *policy.Scope) *InfrastructureAgent {
	return &InfrastructureAgent{Actor: actor, tb: tb, client: client, budget: NewBudget(scope)}
}

const infraSystem = `You are an Infrastructure Security Analyst conducting the final synthesis of an AUTHORIZED network security assessment. You are given the complete inventory of a network scan. Your job is to produce a JSON report (as text, no tool calls) with this exact structure:

{"summary":"2-3 sentences about overall security posture","network_map":[{"host":"10.50.77.x","role":"windows-server|linux-server|router|etc","ssh_banner":"SSH-2.0-...","ssh_risk":"high|medium|low|info","services":["ssh","http"],"risk_level":"critical|high|medium|low|info"}],"attack_paths":[{"description":"multi-step path","steps":["step1","step2"],"risk_level":"high","entry_host":"10.50.77.x"}],"priorities":[{"host":"10.50.77.x","finding":"what you found","severity":"high|medium|low","reasoning":"why it matters","evidence":"banner or probe data"}]}

Respond with ONLY the JSON object, starting with { and ending with }. No markdown, no explanation.

IMPORTANT: Be CONCISE. Include at most 10 entries in network_map (only the most interesting hosts), at most 3 attack_paths, and at most 5 priorities. Quality over quantity — the operator needs actionable intelligence, not an exhaustive list.`

// Run executes the full-campaign analysis in ONE LLM call.
func (a *InfrastructureAgent) Run(ctx context.Context) (*InfraReport, error) {
	// Gather all data from the store.
	inventory, _, err := a.buildInventory(ctx)
	if err != nil {
		return nil, err
	}

	// One LLM call — no tools, JSON as text.
	prompt := fmt.Sprintf("Analyze this network inventory and produce your JSON report:\n\n%s", inventory)

	assistant, usage, err := a.client.Complete(ctx, infraSystem, []Msg{{Role: "user", Text: prompt}}, nil)
	if err != nil {
		return nil, fmt.Errorf("infrastructure agent: %w", err)
	}
	if err := a.budget.Spend(usage); err != nil {
		return nil, err
	}

	// Parse the submit_infrastructure_report tool call.
	for _, call := range assistant.ToolCalls {
		if call.Name != "submit_infrastructure_report" {
			continue
		}
		var report InfraReport
		if err := json.Unmarshal([]byte(call.Arguments), &report); err != nil {
			return nil, fmt.Errorf("infrastructure agent: parse report: %w", err)
		}
		report.TokensUsed = a.budget.TokensUsed()
		return &report, nil
	}

	// Fallback: the model may have responded with a JSON report as text
	// instead of calling the tool. Try to parse it.
	if assistant.Text != "" {
		var report InfraReport
		if raw, ok := extractJSON(assistant.Text); ok {
			if err := json.Unmarshal(raw, &report); err == nil && report.Summary != "" {
				report.TokensUsed = a.budget.TokensUsed()
				return &report, nil
			}
		}
	}

	// If the LLM fails or returns empty, fall back to deterministic analysis.
	return a.deterministicReport(ctx), nil
}

// deterministicReport produces a useful analysis without any LLM — pure
// data analysis on the store. The LLM adds commentary; this is the floor.
func (a *InfrastructureAgent) deterministicReport(ctx context.Context) *InfraReport {
	ips, _ := a.tb.Store.ListAssets(ctx, store.ListFilter{
		CampaignID: a.tb.Campaign, Kind: store.KindIP, Limit: 1000,
	})

	report := &InfraReport{
		Summary: fmt.Sprintf("%d live hosts analyzed. ", len(ips)),
	}

	var oldSSH, windowsSMB, multiPort []HostSummary
	for _, ip := range ips {
		hs := HostSummary{Host: ip.Value}
		if role, ok := ip.Attrs["role"]; ok {
			hs.Role = fmt.Sprintf("%v", role)
		}
		if ports, ok := ip.Attrs["open_ports"]; ok {
			hs.Services = portList(ports)
		}

		// Check SSH banner for old versions.
		obs, _ := a.tb.Store.ObservationsOf(ctx, ip.ID)
		for _, o := range obs {
			if banner, ok := o.Attrs["banner"]; ok {
				b := fmt.Sprintf("%v", banner)
				if strings.Contains(b, "OpenSSH_6.") || strings.Contains(b, "dropbear_2016") {
					hs.SSHBanner = b
					hs.SSHRisk = "high"
					hs.RiskLevel = "high"
					oldSSH = append(oldSSH, hs)
				} else if strings.Contains(b, "OpenSSH_7.") {
					hs.SSHBanner = b
					hs.SSHRisk = "medium"
					hs.RiskLevel = "medium"
				}
			}
		}

		// Multi-port hosts are high-value targets.
		ports, _ := ip.Attrs["open_ports"].([]any)
		if len(ports) >= 4 {
			hs.RiskLevel = "high"
			multiPort = append(multiPort, hs)
		}

		// Windows with SMB.
		if hs.Role == "windows-server" || hs.Role == "windows-workstation" {
			windowsSMB = append(windowsSMB, hs)
		}

		if hs.RiskLevel == "" {
			hs.RiskLevel = "info"
		}
		report.NetworkMap = append(report.NetworkMap, hs)
	}

	// Build attack paths deterministically.
	if len(oldSSH) > 0 {
		path := AttackPath{
			Description: "Legacy SSH daemons on " + hostList(oldSSH) + " may allow unauthorized access or downgrade attacks",
			RiskLevel:   "high",
			EntryHost:   oldSSH[0].Host,
		}
		if len(windowsSMB) > 0 {
			path.Steps = []string{
				"Target legacy SSH on " + oldSSH[0].Host,
				"Pivot via SMB to Windows hosts: " + hostList(windowsSMB[:min(3, len(windowsSMB))]),
				"Access Windows Server with RDP",
			}
		} else {
			path.Steps = []string{"Target legacy SSH on " + oldSSH[0].Host}
		}
		report.AttackPaths = append(report.AttackPaths, path)
	}
	if len(windowsSMB) > 0 {
		report.AttackPaths = append(report.AttackPaths, AttackPath{
			Description: fmt.Sprintf("SMB exposed on %d Windows hosts — lateral movement via pass-the-hash or relay",
				len(windowsSMB)),
			RiskLevel: "medium",
			EntryHost: windowsSMB[0].Host,
			Steps:     []string{"Capture or relay credentials", "Authenticate via SMB", "Move laterally to RDP hosts"},
		})
	}
	if len(multiPort) > 0 {
		report.AttackPaths = append(report.AttackPaths, AttackPath{
			Description: fmt.Sprintf("Multi-service hosts (%s) offer multiple entry vectors",
				hostList(multiPort[:min(3, len(multiPort))])),
			RiskLevel: "medium",
			EntryHost: multiPort[0].Host,
		})
	}

	// Priorities.
	for _, hs := range oldSSH {
		report.Priorities = append(report.Priorities, PriorityFinding{
			Host:      hs.Host,
			Finding:   "Legacy SSH version: " + hs.SSHBanner,
			Severity:  "high",
			Reasoning: "SSH daemon is years out of date — check for known CVEs",
			Evidence:  hs.SSHBanner,
		})
	}
	for _, hs := range multiPort {
		if hs.RiskLevel == "high" && !containsHost(report.Priorities, hs.Host) {
			report.Priorities = append(report.Priorities, PriorityFinding{
				Host:      hs.Host,
				Finding:   "Multi-service exposure: " + strings.Join(hs.Services, ", "),
				Severity:  "medium",
				Reasoning: "Multiple services increase the attack surface",
				Evidence:  fmt.Sprintf("Ports: %v", hs.Services),
			})
		}
	}

	report.Summary += fmt.Sprintf("%d hosts with legacy SSH, %d Windows hosts with SMB, %d multi-service hosts. Attack paths constructed from port patterns and SSH version analysis.", len(oldSSH), len(windowsSMB), len(multiPort))
	return report
}

func portList(ports any) []string {
	var out []string
	if arr, ok := ports.([]any); ok {
		for _, p := range arr {
			out = append(out, fmt.Sprintf("%v", p))
		}
	}
	return out
}

func hostList(hosts []HostSummary) string {
	var names []string
	for _, h := range hosts {
		names = append(names, h.Host)
	}
	return strings.Join(names, ", ")
}

func containsHost(findings []PriorityFinding, host string) bool {
	for _, f := range findings {
		if f.Host == host {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// the store into a structured text for the LLM to analyze.
func (a *InfrastructureAgent) buildInventory(ctx context.Context) (string, string, error) {
	// Findings are looked up once, not per-host.
	a.campaignFindings, _ = a.tb.Store.ListFindings(ctx, a.tb.Campaign)
	ips, err := a.tb.Store.ListAssets(ctx, store.ListFilter{
		CampaignID: a.tb.Campaign, Kind: store.KindIP, Limit: 1000,
	})
	if err != nil {
		return "", "", err
	}

	var b strings.Builder
	b.WriteString("NETWORK INVENTORY (compact)\n")
	b.WriteString("==========================\n\n")

	for _, ip := range ips {
		// One compact line per host.
		line := ip.Value
		if role, ok := ip.Attrs["role"]; ok {
			line += fmt.Sprintf(" | role:%v", role)
		}
		if ports, ok := ip.Attrs["open_ports"]; ok {
			line += fmt.Sprintf(" | ports:%v", ports)
		}

		// Read observations for SSH banners only (most important signal).
		obs, _ := a.tb.Store.ObservationsOf(ctx, ip.ID)
		for _, o := range obs {
			if banner, ok := o.Attrs["banner"]; ok && fmt.Sprintf("%v", banner) != "" {
				port := o.Attrs["port"]
				bannerStr := fmt.Sprintf("%v", banner)
				// Truncate long banners (binary dropbear data can be noisy).
				if len(bannerStr) > 80 {
					bannerStr = bannerStr[:80]
				}
				line += fmt.Sprintf(" | [%v]%s", port, bannerStr)
			}
		}

		// Check for any findings already recorded.
		for _, f := range a.campaignFindings {
			if f.AssetID == ip.ID {
				line += fmt.Sprintf(" | FINDING:[%s]", f.Severity)
			}
		}
		b.WriteString(line + "\n")
	}

	return b.String(), "", nil
}
