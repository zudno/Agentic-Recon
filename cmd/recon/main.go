// Command recon is the operator CLI of Agentic-Recon: campaign lifecycle
// (init/run/triage/approve/report) over a signed scope.yaml. Every network
// action goes through the policy engine (README §6).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"agenticrecon/internal/policy"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-h", "--help", "help":
		usage()
	case "version":
		fmt.Println("agentic-recon", version)
	case "init":
		cmdInit(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "triage":
		// R2/R3: manual triage over the store, no LLM required.
		notImplemented("triage", "R2")
	case "approve":
		// R4: resolve pending INTRUSIVE approval requests.
		notImplemented("approve", "R4")
	case "report":
		// R6: export the engagement report (md/json) from the store.
		notImplemented("report", "R6")
	default:
		fmt.Fprintf(os.Stderr, "recon: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

// cmdInit scaffolds a scope.yaml contract, refusing to overwrite.
func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	scopePath := fs.String("scope", "scope.yaml", "path of the scope contract to scaffold")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if _, err := os.Stat(*scopePath); err == nil {
		fatalf("refusing to overwrite existing %s", *scopePath)
	}
	if err := os.WriteFile(*scopePath, []byte(scopeSkeleton), 0o600); err != nil {
		fatalf("%v", err)
	}
	fmt.Fprintf(os.Stderr, "recon: scaffolded %s\n", *scopePath)
	fmt.Fprintln(os.Stderr, "  fill authorization.reference, window, and targets —")
	fmt.Fprintln(os.Stderr, "  the campaign refuses to run until the contract validates (README §5)")
}

// cmdRun loads and validates the signed contract, then gates on the
// authorization window. The passive pipeline itself lands in R3 (README
// §14); R1 delivers the gate the pipeline will run behind.
func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	scopePath := fs.String("scope", "scope.yaml", "path of the signed scope contract")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	scope, err := policy.Load(*scopePath)
	if err != nil {
		fatalf("%v", err)
	}

	w := scope.Authorization.Window
	now := time.Now().UTC()
	in := scope.InWindow(now)
	fmt.Fprintf(os.Stderr, "recon: contract OK — authorization %s\n", scope.Authorization.Reference)
	fmt.Fprintf(os.Stderr, "  window: %s → %s (%s)\n",
		w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339), windowState(in))
	fmt.Fprintf(os.Stderr, "  scope: %d root domain(s), %d ip entr(y|ies), %d exclusion(s), %d source(s)\n",
		len(scope.Targets.Domains), len(scope.Targets.IPs),
		len(scope.Targets.Exclude), len(scope.Targets.Sources))
	fmt.Fprintf(os.Stderr, "  policy: risk=%s rate=%.0f/s (host %.0f/s) jitter=%dms\n",
		strings.Join(riskLabels(scope.Policy.RiskLevels), ","),
		scope.Policy.Rate.RequestsPerSecond, scope.Policy.Rate.PerHostPerSecond,
		scope.Policy.Rate.JitterMS)
	if scope.LLM != nil {
		fmt.Fprintf(os.Stderr, "  llm: %s/%s (key via %s)\n",
			scope.LLM.Provider, scope.LLM.Model, scope.LLM.APIKeyEnv)
	} else {
		fmt.Fprintln(os.Stderr, "  llm: none — manual triage")
	}
	if !in {
		fatalf("campaign window is not active — refusing to run")
	}
	fmt.Fprintln(os.Stderr, "recon: campaign accepted — pipeline lands in R3 (README §14)")
}

func riskLabels(levels []policy.RiskLevel) []string {
	out := make([]string, len(levels))
	for i, l := range levels {
		out[i] = string(l)
	}
	return out
}

func windowState(in bool) string {
	if in {
		return "ACTIVE"
	}
	return "INACTIVE"
}

func notImplemented(cmd, phase string) {
	fmt.Fprintf(os.Stderr, "recon: %q lands in %s (README §14 roadmap)\n", cmd, phase)
	os.Exit(1)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "recon: "+format+"\n", a...)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `agentic-recon `+version+` — operator CLI

Usage: recon <command>

Commands:
  init      scaffold scope.yaml (authorization.reference mandatory)   [R1]
  run       validate the contract; gate on the authorization window   [R1]
  triage    manual triage over the store                              [R2/R3]
  approve   resolve pending INTRUSIVE approval requests               [R4]
  report    export the engagement report (md/json)                    [R6]
  version   print the version

Every network action goes through the policy engine (README §6).
`)
}

// scopeSkeleton is the minimal contract scaffold written by "recon init".
// It parses but deliberately fails validation until the operator fills the
// mandatory fields — fail closed from the very first file.
const scopeSkeleton = `# scope.yaml — the campaign contract (gitignored: it names client assets).
# Full annotated template: scope.example.yaml / README §5.

authorization:
  reference: ""              # MANDATORY: id of the signed RoE
  window:
    start: 2026-01-01T00:00:00Z
    end: 2026-01-31T23:59:59Z

scope:
  domains: []                # e.g. [example.com]
  ips: []                    # e.g. [203.0.113.0/24]
  exclude: []                # hard exclusions — always win
  sources: [crt.sh]          # third-party allow-list (absent = forbidden)

policy:
  risk_levels: [PASSIVE]     # PASSIVE | LOW_IMPACT | INTRUSIVE
  rate:
    requests_per_second: 5
    per_host_per_second: 1
    jitter_ms: 750
  noise_profile: "agreed-with-client"

budgets:
  agent_max_steps_per_hypothesis: 8
  campaign_max_tokens: 2000000
`
