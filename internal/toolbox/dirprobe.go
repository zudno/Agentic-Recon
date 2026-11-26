package toolbox

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// defaultProbeWords is the small, honest content-discovery list: paths a
// legitimate user would not casually walk. Custom lists can be passed in.
var defaultProbeWords = []string{
	"admin", "api", "backup", "config", "dashboard", "debug",
	"graphql", "swagger", ".env", ".git",
}

// DirProbe is the R4 INTRUSIVE action: content discovery against one
// in-scope host. Every request flows through the engine with the
// approval token validated per-request (tool + host); the tool consumes
// the approval exactly once — one approval, one logical action. Found
// paths become endpoint assets linked to the host's web service.
//
// Without a token (or with a PENDING one) the engine denies everything:
// call RequestApproval first, have the operator resolve it via
// `recon approve <token> --yes`, then retry with the token.
func (tb *Toolbox) DirProbe(ctx context.Context, caller, reason, baseURL string, words []string, approvalToken string) ToolResult {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return ToolResult{OK: false, Summary: fmt.Sprintf("invalid base URL %q", baseURL)}
	}
	host := strings.ToLower(u.Hostname())
	if len(words) == 0 {
		words = defaultProbeWords
	}
	base := strings.TrimSuffix(baseURL, "/")

	var (
		found    []map[string]any
		evidence []int64
		missing  int
	)
	for _, w := range words {
		target := base + "/" + w
		req := &policy.Request{
			Actor: caller, Tool: "dir-probe", Reason: reason,
			Risk:       policy.RiskIntrusive,
			ApprovalID: approvalToken,
			Target:     &policy.HTTPRequest{Method: "GET", URL: target},
		}
		resp, _, derr := tb.Engine.Do(ctx, req)
		if derr != nil {
			// A denial mid-run (scope, gate, pacing) aborts the action.
			return failResult("dir-probe denied at "+target, derr, map[string]any{"host": host})
		}
		if ev := tb.evidence(ctx); ev > 0 {
			evidence = append(evidence, ev)
		}
		if resp.Status == 404 || resp.Status >= 500 {
			missing++
			continue
		}
		found = append(found, map[string]any{"path": "/" + w, "status": resp.Status})
		if err := tb.recordEndpoint(ctx, host, w, resp.Status); err != nil {
			return ToolResult{OK: false, Summary: "dir-probe failed recording an endpoint: " + err.Error()}
		}
	}

	// One approval, one logical action: consume it after the sweep.
	if approvalToken != "" {
		if cerr := tb.Store.ConsumeApproval(ctx, approvalToken, "dir-probe", host); cerr != nil {
			return ToolResult{
				OK:          true,
				Summary:     fmt.Sprintf("%d endpoint(s) found — but the approval could not be consumed: %v", len(found), cerr),
				Data:        map[string]any{"found": found, "approval_warning": cerr.Error()},
				EvidenceIDs: compact(evidence...),
			}
		}
	}
	data := map[string]any{
		"found":   found,
		"probed":  len(words),
		"missing": missing,
		"host":    host,
	}
	return okResult(fmt.Sprintf("dir-probe %s: %d endpoint(s) found of %d path(s)", host, len(found), len(words)),
		data, evidence...)
}

// recordEndpoint stores a discovered path as an endpoint asset linked to
// the host's web service (created minimally if the pipeline hasn't yet).
func (tb *Toolbox) recordEndpoint(ctx context.Context, host, word string, status int) error {
	ws, err := tb.Store.UpsertAsset(ctx, tb.Campaign, store.KindWebService, host, "dir-probe", false, nil)
	if err != nil {
		return err
	}
	ep, err := tb.Store.UpsertAsset(ctx, tb.Campaign, store.KindEndpoint, host+"/"+word, "dir-probe", false,
		map[string]any{"status": status})
	if err != nil {
		return err
	}
	return tb.Store.LinkAssets(ctx, ws.ID, ep.ID, "serves")
}
