// Package toolbox is the closed catalog of typed tools (README §9): read
// tools over the store, low-impact inspection through the policy engine,
// reference lookups, and recording tools for hypotheses and findings. The
// CLI and the R5 agents both consume it — nobody gets a raw shell, and
// every network action lands in the campaign's request_log.
package toolbox

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// Toolbox is the catalog bound to one campaign.
type Toolbox struct {
	Scope    *policy.Scope
	Engine   *policy.Engine
	Store    *store.Store
	Campaign int64
}

// New wires a toolbox over an engine and a store.
func New(scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) *Toolbox {
	return &Toolbox{Scope: scope, Engine: eng, Store: st, Campaign: campaignID}
}

// ToolResult is what every network tool returns: structured, attributable,
// and evidence-linked (request_log ids usable in findings).
type ToolResult struct {
	OK          bool
	Summary     string
	Data        map[string]any
	EvidenceIDs []int64
	Denied      *policy.ErrDenied
}

func okResult(summary string, data map[string]any, evidence ...int64) ToolResult {
	return ToolResult{OK: true, Summary: summary, Data: data, EvidenceIDs: compact(evidence...)}
}

func failResult(summary string, err error, data map[string]any) ToolResult {
	var denied *policy.ErrDenied
	if errorsAs(err, &denied) {
		return ToolResult{OK: false, Summary: summary, Data: data, Denied: denied}
	}
	return ToolResult{OK: false, Summary: summary + ": " + err.Error(), Data: data}
}

func compact(ids ...int64) []int64 {
	var out []int64
	for _, id := range ids {
		if id > 0 {
			out = append(out, id)
		}
	}
	return out
}

func errorsAs(err error, target **policy.ErrDenied) bool {
	for err != nil {
		if d, ok := err.(*policy.ErrDenied); ok {
			*target = d
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// evidence captures the newest request_log id of the campaign — the
// sequential-tool contract (CLI and R5 agent loops run one tool at a time)
// makes this the exact reference for the action that just ran.
func (tb *Toolbox) evidence(ctx context.Context) int64 {
	id, err := tb.Store.LastRequestLogID(ctx, tb.Campaign)
	if err != nil {
		return 0
	}
	return id
}

// ─── read tools (store only, no network) ────────────────────────────────────

// GetUnexploredAssets lists assets still awaiting triage (state DISCOVERED).
func (tb *Toolbox) GetUnexploredAssets(ctx context.Context, kind store.AssetKind, limit int) ([]store.Asset, error) {
	return tb.Store.ListAssets(ctx, store.ListFilter{
		CampaignID: tb.Campaign, Kind: kind, States: []store.AssetState{store.StateDiscovered}, Limit: limit,
	})
}

// GetAssetDetails fetches one asset by id.
func (tb *Toolbox) GetAssetDetails(ctx context.Context, id int64) (store.Asset, error) {
	return tb.Store.GetAsset(ctx, id)
}

// SearchByTech finds assets whose attributes mention a technology
// (server headers, content types, titles) — e.g. "swagger", "nginx".
func (tb *Toolbox) SearchByTech(ctx context.Context, tech string) ([]store.Asset, error) {
	all, err := tb.Store.ListAssets(ctx, store.ListFilter{CampaignID: tb.Campaign, Limit: 1000})
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(tech))
	var out []store.Asset
	for _, a := range all {
		for _, v := range a.Attrs {
			if strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), needle) {
				out = append(out, a)
				break
			}
		}
	}
	return out, nil
}

// ─── recording tools ────────────────────────────────────────────────────────

// SaveHypothesis records a scored conjecture about an asset.
func (tb *Toolbox) SaveHypothesis(ctx context.Context, assetID int64, createdBy, reasoning string, score float64) (store.Hypothesis, error) {
	return tb.Store.AddHypothesis(ctx, tb.Campaign, assetID, createdBy, reasoning, score)
}

// PromoteToFinding turns a hypothesis into a finding backed by evidence
// (request_log ids returned in ToolResult.EvidenceIDs).
func (tb *Toolbox) PromoteToFinding(ctx context.Context, assetID, hypothesisID int64, severity string, evidence []int64) (store.Finding, error) {
	return tb.Store.AddFinding(ctx, tb.Campaign, assetID, hypothesisID, severity, evidence)
}

// ─── low-impact inspection (through the engine) ────────────────────────────

// HTTPRequest performs one request toward in-scope infrastructure —
// LOW_IMPACT, paced, and evidence-logged by the engine.
func (tb *Toolbox) HTTPRequest(ctx context.Context, caller, reason, method, urlStr string, headers map[string]string) ToolResult {
	req := &policy.Request{
		Actor: caller, Tool: "http_request", Reason: reason,
		Risk:   policy.RiskLowImpact,
		Target: &policy.HTTPRequest{Method: method, URL: urlStr, Headers: headers},
	}
	resp, _, err := tb.Engine.Do(ctx, req)
	if err != nil {
		return failResult("http_request denied or failed", err, nil)
	}
	body := string(resp.Body)
	if len(body) > 4096 {
		body = body[:4096]
	}
	data := map[string]any{
		"status": resp.Status,
		"body":   body,
	}
	if ct, ok := headerValue(resp.Headers, "Content-Type"); ok {
		data["content_type"] = ct
	}
	if loc, ok := headerValue(resp.Headers, "Location"); ok {
		data["location"] = loc
	}
	return okResult(fmt.Sprintf("%s %s → %d", method, urlStr, resp.Status), data, tb.evidence(ctx))
}

var routeRe = regexp.MustCompile("[\"'`](/[A-Za-z0-9_\\-./:%{}]{2,80})[\"'`]")

// FetchJSRoutes fetches a JavaScript asset (LOW_IMPACT) and extracts
// route-like strings from it — the classic exposed-endpoint sweep.
func (tb *Toolbox) FetchJSRoutes(ctx context.Context, caller, reason, jsURL string) ToolResult {
	res := tb.HTTPRequest(ctx, caller, reason, "GET", jsURL, nil)
	if !res.OK {
		res.Summary = "fetch_js_and_extract_routes: " + res.Summary
		return res
	}
	body, _ := res.Data["body"].(string)
	seen := map[string]bool{}
	var routes []string
	for _, m := range routeRe.FindAllStringSubmatch(body, -1) {
		r := m[1]
		if seen[r] {
			continue
		}
		seen[r] = true
		routes = append(routes, r)
		if len(routes) == 50 {
			break
		}
	}
	sort.Strings(routes)
	res.Data["routes"] = routes
	res.Summary = fmt.Sprintf("fetch_js %s → %d route(s)", jsURL, len(routes))
	return res
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

// CheckCVEDetails looks a CVE up in NVD — a PASSIVE reference query: the
// subject is public knowledge and carries nothing about the target. The
// source must still be allow-listed in scope.yaml (`nvd`).
func (tb *Toolbox) CheckCVEDetails(ctx context.Context, caller, reason, cveID string) ToolResult {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !cveRe.MatchString(cveID) {
		return ToolResult{OK: false, Summary: fmt.Sprintf("invalid CVE id %q — expected CVE-YYYY-NNNN", cveID)}
	}
	req := &policy.Request{
		Actor: caller, Tool: "check_cve_details", Reason: reason,
		Risk: policy.RiskPassive,
		Source: &policy.SourceRequest{
			Source:  "nvd",
			Subject: cveID,
			URL:     "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID,
		},
	}
	resp, _, err := tb.Engine.Do(ctx, req)
	if err != nil {
		return failResult("check_cve_details denied or failed", err, nil)
	}
	data := map[string]any{"cve": cveID, "description": parseCVEDescription(resp.Body)}
	return okResult(fmt.Sprintf("%s: %s", cveID, data["description"]), data, tb.evidence(ctx))
}

func parseCVEDescription(body []byte) string {
	var out struct {
		Vulnerabilities []struct {
			CVE struct {
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return ""
	}
	for _, v := range out.Vulnerabilities {
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				return d.Value
			}
		}
	}
	return ""
}

// ─── the approval gate (INTRUSIVE) ──────────────────────────────────────────

// RequestApproval files an INTRUSIVE (tool, host) action for operator
// review. The returned approval is PENDING until `recon approve` resolves
// it; the operator's decision and the consumption are both audited.
func (tb *Toolbox) RequestApproval(ctx context.Context, caller, tool, host, reason string) (store.Approval, error) {
	return tb.Store.RequestApproval(ctx, tb.Campaign, tool, host, reason, caller)
}

func headerValue(h map[string][]string, name string) (string, bool) {
	for k, vv := range h {
		if strings.EqualFold(k, name) && len(vv) > 0 {
			return vv[0], true
		}
	}
	return "", false
}
