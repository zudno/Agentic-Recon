package pipeline

import (
	"context"
	"fmt"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// Subfinder enriches the campaign's subdomain inventory from 20+ passive
// sources (PASSIVE risk — subfinder queries third parties, never the
// target's infrastructure). Targets are pre-validated through the policy
// engine; the output is scope-checked again at persistence.
//
// Requires the subfinder binary on PATH. Gracefully no-ops if absent.
func Subfinder(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) error {
	if _, err := lookup("subfinder"); err != nil {
		return err // not installed — the runner skips gracefully
	}

	roots := scope.RootDomains()
	if len(roots) == 0 {
		return nil
	}

	// Pre-flight: the engine validates every root before the binary runs.
	if err := eng.PreFlightTargets(ctx, roots); err != nil {
		return fmt.Errorf("subfinder: %w", err)
	}

	// Invoke with the binary's own rate limiting.
	args := []string{
		"-d", strings.Join(roots, ","),
		"-json",             // one JSON object per line
		"-silent",           // no banner
		"-rate-limit", "10", // be a good citizen to third-party sources
	}
	out, err := invoke(ctx, "subfinder", args...)
	if err != nil {
		return fmt.Errorf("subfinder: %w", err)
	}

	// ETL: parse → scope-check → upsert.
	for _, obj := range parseJSONLines(out) {
		host, _ := obj["host"].(string)
		if host == "" {
			continue
		}
		if _, err := upsertDiscovered(ctx, scope, st, campaignID, host, "subfinder"); err != nil {
			return err
		}
	}
	return nil
}

// DNSx resolves every discovered subdomain and stores the resolved IP,
// creating the graph edge resolves_to (LOW_IMPACT — queries target DNS).
// CNAME chains are also recorded as links.
//
// Requires the dnsx binary on PATH. Gracefully no-ops if absent.
func DNSx(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) error {
	if _, err := lookup("dnsx"); err != nil {
		return err // not installed — the runner skips gracefully
	}

	// Collect all in-scope subdomain assets that need resolution.
	subs, err := st.ListAssets(ctx, store.ListFilter{
		CampaignID: campaignID, Kind: store.KindSubdomain, Limit: 1000,
	})
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		return nil
	}

	var targets []string
	for _, s := range subs {
		targets = append(targets, s.Value)
	}

	// Pre-flight: every target must be in scope.
	if err := eng.PreFlightTargets(ctx, targets); err != nil {
		return fmt.Errorf("dnsx: %w", err)
	}

	// Invoke: resolve to JSON, capture A/AAAA/CNAME records.
	args := []string{
		"-l", strings.Join(targets, ","),
		"-json",
		"-silent",
		"-resp",                 // include response data
		"-a", "-aaaa", "-cname", // record types we care about
	}
	out, err := invoke(ctx, "dnsx", args...)
	if err != nil {
		return fmt.Errorf("dnsx: %w", err)
	}

	for _, obj := range parseJSONLines(out) {
		host, _ := obj["host"].(string)
		if host == "" {
			continue
		}

		// The resolved address becomes an IP asset.
		if addr, ok := obj["a"].(string); ok && addr != "" {
			ip, err := st.UpsertAsset(ctx, campaignID, store.KindIP, addr, "dnsx",
				scope.HostVerdict(addr) != policy.ScopeIn, nil)
			if err != nil {
				return err
			}
			// Link subdomain → IP (resolves_to).
			sub, err := st.GetAssetByValue(ctx, campaignID, store.KindSubdomain, host)
			if err == nil {
				if err := st.LinkAssets(ctx, sub.ID, ip.ID, "resolves_to"); err != nil {
					return err
				}
			}
		}

		// CNAME: the subdomain resolves to another hostname.
		if cname, ok := obj["cname"].(string); ok && cname != "" {
			target, err := upsertDiscovered(ctx, scope, st, campaignID, cname, "dnsx-cname")
			if err != nil {
				return err
			}
			sub, err := st.GetAssetByValue(ctx, campaignID, store.KindSubdomain, host)
			if err == nil {
				if err := st.LinkAssets(ctx, sub.ID, target.ID, "cname_to"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// lookup wraps exec.LookPath with a descriptive error for the operator.
func lookup(binary string) (string, error) {
	path, err := execLookPath(binary)
	if err != nil {
		for _, w := range registry {
			if w.Binary == binary {
				return "", fmt.Errorf("%s not found on PATH — install with: %s", binary, w.Install)
			}
		}
		return "", fmt.Errorf("%s not found on PATH", binary)
	}
	return path, nil
}
