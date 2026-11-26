// Package pipeline is the deterministic recon layer (README §8): native
// modules execute discovery and low-impact validation, writing only
// through the policy engine (every action lands in request_log) and the
// store (every finding is a first-class asset). It never opens sockets of
// its own — TestNativeEgressOnlyInPolicy enforces that.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// CTSubdomains enumerates subdomains via Certificate Transparency (crt.sh):
// a PASSIVE source query through the policy engine. Every discovered name
// becomes an asset — in-scope names DISCOVERED, excluded or foreign names
// OUT_OF_SCOPE for the exclusions report — linked to its root domain.
func CTSubdomains(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) error {
	for _, root := range scope.RootDomains() {
		dom, err := st.UpsertAsset(ctx, campaignID, store.KindDomain, root, "scope", false, nil)
		if err != nil {
			return err
		}
		resp, _, err := eng.Do(ctx, &policy.Request{
			Actor:  "module:ct-subdomains",
			Tool:   "ct-subdomains",
			Reason: "enumerate subdomains via Certificate Transparency",
			Risk:   policy.RiskPassive,
			Source: &policy.SourceRequest{
				Source:  "crt.sh",
				Subject: root,
				URL:     "https://crt.sh/?q=" + url.QueryEscape("%."+root) + "&output=json",
			},
		})
		if err != nil {
			return fmt.Errorf("ct-subdomains: %w", err)
		}
		names, err := parseCTNames(resp.Body)
		if err != nil {
			return fmt.Errorf("ct-subdomains: %w", err)
		}
		for _, name := range names {
			out := scope.HostVerdict(name) != policy.ScopeIn
			sub, err := st.UpsertAsset(ctx, campaignID, store.KindSubdomain, name, "ct-subdomains", out, nil)
			if err != nil {
				return err
			}
			if err := st.LinkAssets(ctx, sub.ID, dom.ID, "belongs_to"); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseCTNames extracts unique, normalized names from a crt.sh JSON
// response. name_value entries are newline-separated; wildcard labels are
// stripped.
func parseCTNames(body []byte) ([]string, error) {
	var rows []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parse crt.sh response: %w", err)
	}
	seen := make(map[string]bool)
	var out []string
	add := func(n string) {
		n = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n)), "*.")
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, r := range rows {
		add(r.CommonName)
		for _, n := range strings.Split(r.NameValue, "\n") {
			add(n)
		}
	}
	return out, nil
}
