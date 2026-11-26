package report

import (
	"fmt"
	"strings"
)

// Markdown renders the engagement report as a human-readable document
// (README §12): the operator's primary output.
func (r *Report) Markdown() string {
	var b strings.Builder

	b.WriteString("# Agentic-Recon — Engagement Report\n\n")

	// Campaign summary.
	b.WriteString("## Campaign\n\n")
	fmt.Fprintf(&b, "- **Name:** %s\n", r.Campaign.Name)
	fmt.Fprintf(&b, "- **Authorization:** %s\n", r.Campaign.AuthorizationReference)
	fmt.Fprintf(&b, "- **Scope hash:** %s\n", r.Campaign.ScopeHash)
	fmt.Fprintf(&b, "- **State:** %s\n", r.Campaign.State)
	fmt.Fprintf(&b, "- **Created:** %s\n", r.Campaign.CreatedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "- **Report generated:** %s\n\n", r.GeneratedAt.Format("2006-01-02T15:04:05Z"))

	// Scope summary with exclusions.
	visible := r.Inventory.Total - len(r.OutOfScope)
	fmt.Fprintf(&b, "## Scope Summary\n\n")
	fmt.Fprintf(&b, "%d asset(s) tested; %d excluded as out-of-scope.\n", visible, len(r.OutOfScope))
	if len(r.OutOfScope) > 0 {
		b.WriteString("\n### Excluded / Out-of-Scope Assets\n\n")
		b.WriteString("| ID | Kind | Value | Source |\n")
		b.WriteString("|---:|------|-------|--------|\n")
		for _, a := range r.OutOfScope {
			fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", a.ID, a.Kind, a.Value, a.Source)
		}
	}
	b.WriteString("\n")

	// Inventory.
	fmt.Fprintf(&b, "## Inventory\n\n")
	fmt.Fprintf(&b, "**Total:** %d asset(s)\n\n", r.Inventory.Total)
	fmt.Fprintf(&b, "| State | Count |\n|-------|------:|\n")
	for _, state := range orderedStates() {
		if n, ok := r.Inventory.ByState[state]; ok {
			fmt.Fprintf(&b, "| %s | %d |\n", state, n)
		}
	}
	fmt.Fprintf(&b, "\n| Kind | Count |\n|------|------:|\n")
	for _, kind := range orderedKinds() {
		if n, ok := r.Inventory.ByKind[kind]; ok {
			fmt.Fprintf(&b, "| %s | %d |\n", kind, n)
		}
	}
	b.WriteString("\n### Assets\n\n")
	b.WriteString("| ID | Kind | Value | State | Source |\n")
	b.WriteString("|---:|------|-------|-------|--------|\n")
	for _, a := range r.Inventory.Assets {
		if a.State == "OUT_OF_SCOPE" {
			continue // already in the exclusions table
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", a.ID, a.Kind, a.Value, a.State, a.Source)
	}
	b.WriteString("\n")

	// Findings — the prioritized paths.
	fmt.Fprintf(&b, "## Findings — Prioritized Paths Toward Initial Access\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_No findings recorded._\n\n")
	}
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "### Finding #%d — %s severity\n\n", i+1, strings.ToUpper(f.Finding.Severity))
		fmt.Fprintf(&b, "**Asset:** %s (%s, id %d)\n\n", f.Asset.Value, f.Asset.Kind, f.Asset.ID)
		if f.Hypothesis.ID > 0 {
			fmt.Fprintf(&b, "**Hypothesis:** [%s] %s (score %.1f)\n\n",
				f.Hypothesis.CreatedBy, f.Hypothesis.Reasoning, f.Hypothesis.Score)
		}
		fmt.Fprintf(&b, "**Reasoning:** %s\n\n", f.Finding.Severity)
		if len(f.Evidence) > 0 {
			b.WriteString("**Evidence:**\n\n")
			for _, ev := range f.Evidence {
				allowed := "ALLOWED"
				if !ev.Allowed {
					allowed = "DENIED"
				}
				fmt.Fprintf(&b, "- [log #%d] %s `%s` → %s %s — %s\n",
					ev.ID, ev.Actor, ev.Tool, ev.Target, allowed, ev.Result)
			}
			b.WriteString("\n")
		}
	}

	// Complete action trail.
	fmt.Fprintf(&b, "## Complete Action Log\n\n")
	fmt.Fprintf(&b, "Every network action of the campaign — allowed and denied —\n")
	fmt.Fprintf(&b, "reconstructed from `request_log` (%d entries):\n\n", len(r.RequestLog))
	b.WriteString("| ID | Time | Actor | Tool | Target | Risk | Allowed | Result |\n")
	b.WriteString("|---:|------|-------|------|--------|------|---------|--------|\n")
	for _, row := range r.RequestLog {
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %t | %s |\n",
			row.ID, row.TS.Format("15:04:05"), row.Actor, row.Tool,
			truncate(row.Target, 60), row.Risk, row.Allowed, truncate(row.Result, 40))
	}

	return b.String()
}

func orderedStates() []string {
	return []string{"DISCOVERED", "TRIAGED", "INVESTIGATING", "VALIDATED", "DISCARDED", "OUT_OF_SCOPE"}
}

func orderedKinds() []string {
	return []string{"domain", "subdomain", "ip", "web_service", "endpoint", "tech"}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
