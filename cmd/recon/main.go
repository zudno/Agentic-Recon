// Command recon is the operator CLI of Agentic-Recon: campaign lifecycle
// (init/run/triage/approve/report) over a signed scope.yaml. Every network
// action goes through the policy engine (README §6).
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"agenticrecon/internal/pipeline"
	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
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
	case "campaigns":
		cmdCampaigns(os.Args[2:])
	case "triage":
		cmdTriage(os.Args[2:])
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

// ─── init ───────────────────────────────────────────────────────────────────

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

// ─── run ────────────────────────────────────────────────────────────────────

// cmdRun loads the signed contract, opens (or resumes) the campaign, and
// executes the passive pipeline behind the policy engine. Interrupting
// (Ctrl-C) pauses the campaign; rerun with --campaign to resume.
func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	scopePath := fs.String("scope", "scope.yaml", "signed scope contract")
	dbPath := fs.String("db", "recon.db", "campaign database")
	resume := fs.Int64("campaign", 0, "resume this campaign id (must match the scope hash)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	scope, err := policy.Load(*scopePath)
	if err != nil {
		fatalf("%v", err)
	}
	w := scope.Authorization.Window
	now := time.Now().UTC()
	if !scope.InWindow(now) {
		fatalf("campaign window %s → %s is not active — refusing to run",
			w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
	}
	fmt.Fprintf(os.Stderr, "recon: contract OK — authorization %s (window active)\n",
		scope.Authorization.Reference)

	hash, err := scopeFileHash(*scopePath)
	if err != nil {
		fatalf("%v", err)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer st.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var campaign store.Campaign
	if *resume > 0 {
		campaign, err = st.GetCampaign(ctx, *resume)
		if errors.Is(err, sql.ErrNoRows) {
			fatalf("campaign %d not found in %s", *resume, *dbPath)
		}
		if err != nil {
			fatalf("%v", err)
		}
		if campaign.ScopeHash != hash {
			fatalf("scope hash mismatch: campaign %d ran under a different contract — refusing to resume", *resume)
		}
		fmt.Fprintf(os.Stderr, "recon: resuming campaign %d (%s)\n", campaign.ID, campaign.Name)
	} else {
		name := strings.TrimSuffix(filepath.Base(*scopePath), filepath.Ext(*scopePath))
		campaign, err = st.CreateCampaign(ctx, name, scope.Authorization.Reference, hash)
		if err != nil {
			fatalf("%v", err)
		}
		fmt.Fprintf(os.Stderr, "recon: campaign %d created — %s\n", campaign.ID, campaign.Name)
	}

	eng, err := policy.NewEngine(policy.EngineConfig{
		Scope: scope,
		Sink:  st.Sink(campaign.ID), // evidence lands in the campaign's request_log
	})
	if err != nil {
		fatalf("%v", err)
	}

	fmt.Fprintln(os.Stderr, "recon: running passive pipeline (ct-subdomains → http-probe)…")
	runErr := pipeline.RunPassive(ctx, scope, eng, st, campaign.ID)

	if ctx.Err() != nil {
		_ = st.SetCampaignState(context.Background(), campaign.ID, store.CampaignPaused)
		fmt.Fprintf(os.Stderr, "\nrecon: interrupted — campaign %d PAUSED\n", campaign.ID)
		fmt.Fprintf(os.Stderr, "  resume with: recon run --scope %s --db %s --campaign %d\n",
			*scopePath, *dbPath, campaign.ID)
		os.Exit(130)
	}
	if runErr != nil {
		_ = st.SetCampaignState(context.Background(), campaign.ID, store.CampaignPaused)
		fmt.Fprintf(os.Stderr, "recon: pipeline failed — campaign %d PAUSED: %v\n", campaign.ID, runErr)
		fmt.Fprintf(os.Stderr, "  resume with: recon run --scope %s --db %s --campaign %d\n",
			*scopePath, *dbPath, campaign.ID)
		os.Exit(1)
	}

	printRunSummary(ctx, st, campaign.ID)
	fmt.Fprintf(os.Stderr, "recon: triage with \"recon triage list --db %s --campaign %d\"\n",
		*dbPath, campaign.ID)
}

func printRunSummary(ctx context.Context, st *store.Store, campaignID int64) {
	subs, err := st.ListAssets(ctx, store.ListFilter{CampaignID: campaignID, Kind: store.KindSubdomain, Limit: 1000})
	if err == nil {
		excluded, _ := st.ListAssets(ctx, store.ListFilter{
			CampaignID: campaignID, Kind: store.KindSubdomain, IncludeOutOfScope: true, Limit: 1000})
		fmt.Fprintf(os.Stderr, "recon: %d subdomain(s) discovered (%d excluded/out-of-scope)\n",
			len(subs), len(excluded)-len(subs))
	}
	ws, err := st.ListAssets(ctx, store.ListFilter{CampaignID: campaignID, Kind: store.KindWebService, Limit: 1000})
	if err == nil {
		fmt.Fprintf(os.Stderr, "recon: %d web service(s) fingerprinted\n", len(ws))
	}
}

// scopeFileHash pins the exact contract bytes the campaign runs under.
func scopeFileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read scope for hashing: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ─── campaigns ──────────────────────────────────────────────────────────────

func cmdCampaigns(args []string) {
	fs := flag.NewFlagSet("campaigns", flag.ContinueOnError)
	dbPath := fs.String("db", "recon.db", "campaign database")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer st.Close()
	list, err := st.ListCampaigns(context.Background())
	if err != nil {
		fatalf("%v", err)
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "recon: no campaigns — run one first")
		return
	}
	fmt.Printf("%-4s %-8s %-24s %-18s %s\n", "id", "state", "name", "authorization", "created")
	for _, c := range list {
		fmt.Printf("%-4d %-8s %-24s %-18s %s\n",
			c.ID, c.State, c.Name, c.AuthorizationReference, c.CreatedAt.Format(time.RFC3339))
	}
}

// ─── triage ────────────────────────────────────────────────────────────────

var stateWords = map[string]store.AssetState{
	"discovered":    store.StateDiscovered,
	"triaged":       store.StateTriaged,
	"investigating": store.StateInvestigating,
	"validated":     store.StateValidated,
	"discarded":     store.StateDiscarded,
}

func cmdTriage(args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		cmdTriageList(args[1:])
	case "show":
		cmdTriageShow(args[1:])
	case "mark":
		cmdTriageMark(args[1:])
	default:
		fatalf("unknown triage command %q (list | show | mark)", args[0])
	}
}

func openStoreFlag(fs *flag.FlagSet) *string {
	return fs.String("db", "recon.db", "campaign database")
}

func resolveCampaign(fs *flag.FlagSet, st *store.Store, explicit *int64) int64 {
	if *explicit > 0 {
		return *explicit
	}
	list, err := st.ListCampaigns(context.Background())
	if err != nil {
		fatalf("%v", err)
	}
	if len(list) == 0 {
		fatalf("no campaigns in the database — run one first")
	}
	return list[len(list)-1].ID
}

func cmdTriageList(args []string) {
	fs := flag.NewFlagSet("triage list", flag.ContinueOnError)
	dbPath := openStoreFlag(fs)
	campaign := fs.Int64("campaign", 0, "campaign id (default: latest)")
	showAll := fs.Bool("all", false, "include out-of-scope assets (exclusions report)")
	kind := fs.String("kind", "", "filter: domain|subdomain|ip|web_service|endpoint|tech")
	state := fs.String("state", "", "filter by state(s): discovered,triaged,investigating,validated,discarded")
	limit := fs.Int("limit", 100, "maximum rows")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer st.Close()
	cid := resolveCampaign(fs, st, campaign)

	f := store.ListFilter{CampaignID: cid, IncludeOutOfScope: *showAll, Limit: *limit}
	if k := strings.TrimSpace(*kind); k != "" {
		f.Kind = store.AssetKind(k)
	}
	for _, w := range strings.Split(*state, ",") {
		if s, ok := stateWords[strings.TrimSpace(w)]; ok {
			f.States = append(f.States, s)
		}
	}
	assets, err := st.ListAssets(context.Background(), f)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Fprintf(os.Stderr, "recon: campaign %d — %d asset(s)%s\n", cid, len(assets),
		map[bool]string{true: " (including out-of-scope)", false: ""}[*showAll])
	fmt.Printf("%-4s %-12s %-42s %-13s %-14s %s\n", "id", "kind", "value", "state", "source", "highlights")
	for _, a := range assets {
		fmt.Printf("%-4d %-12s %-42s %-13s %-14s %s\n",
			a.ID, a.Kind, a.Value, a.State, a.Source, summarizeAttrs(a.Attrs))
	}
}

func summarizeAttrs(attrs map[string]any) string {
	var parts []string
	for _, key := range []string{"title", "status", "server", "redirect", "probe_error"} {
		if v, ok := attrs[key]; ok && v != nil && v != "" {
			s := fmt.Sprintf("%v", v)
			if len(s) > 40 {
				s = s[:40]
			}
			parts = append(parts, key+"="+s)
		}
	}
	return strings.Join(parts, " ")
}

func cmdTriageShow(args []string) {
	fs := flag.NewFlagSet("triage show", flag.ContinueOnError)
	dbPath := openStoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fatalf("usage: recon triage show <asset-id> [--db path]")
	}
	id, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		fatalf("asset id must be numeric: %v", err)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer st.Close()
	ctx := context.Background()
	a, err := st.GetAsset(ctx, id)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("asset %d — %s %s\n  state: %s   source: %s\n  first: %s   last: %s\n",
		a.ID, a.Kind, a.Value, a.State, a.Source,
		a.FirstSeen.Format(time.RFC3339), a.LastTouched.Format(time.RFC3339))
	if len(a.Attrs) > 0 {
		fmt.Println("  attrs:")
		for k, v := range a.Attrs {
			fmt.Printf("    %s: %v\n", k, v)
		}
	}
	if obs, _ := st.ObservationsOf(ctx, a.ID); len(obs) > 0 {
		fmt.Printf("  observations (%d):\n", len(obs))
		for _, o := range obs {
			fmt.Printf("    [%s] %s %v\n", o.ObservedAt.Format(time.RFC3339), o.Source, o.Attrs)
		}
	}
	if links, _ := st.LinksOf(ctx, a.ID); len(links) > 0 {
		fmt.Printf("  links (outgoing):\n")
		for _, l := range links {
			fmt.Printf("    → %d (%s)\n", l.ToID, l.LinkType)
		}
	}
	if links, _ := st.LinksTo(ctx, a.ID); len(links) > 0 {
		fmt.Printf("  links (incoming):\n")
		for _, l := range links {
			fmt.Printf("    ← %d (%s)\n", l.FromID, l.LinkType)
		}
	}
}

func cmdTriageMark(args []string) {
	fs := flag.NewFlagSet("triage mark", flag.ContinueOnError)
	dbPath := openStoreFlag(fs)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fatalf("usage: recon triage mark <asset-id> <discovered|triaged|investigating|validated|discarded>")
	}
	id, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		fatalf("asset id must be numeric: %v", err)
	}
	to, ok := stateWords[rest[1]]
	if !ok {
		fatalf("unknown state %q", rest[1])
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer st.Close()
	updated, err := st.UpdateAssetState(context.Background(), id, to)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Fprintf(os.Stderr, "recon: asset %d (%s) is now %s\n", id, updated.Value, updated.State)
}

// ─── misc ──────────────────────────────────────────────────────────────────

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
  init                 scaffold scope.yaml (authorization.reference mandatory) [R1]
  run                  execute the passive pipeline behind the policy engine  [R3]
  campaigns            list campaigns in the database                        [R3]
  triage list|show|mark manual triage over the store — no LLM required       [R3]
  approve              resolve pending INTRUSIVE approval requests           [R4]
  report               export the engagement report (md/json)                 [R6]
  version              print the version

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
