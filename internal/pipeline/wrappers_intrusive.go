package pipeline

import (
	"context"
	"fmt"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// HTTPx enhances the campaign's web service assets with tech detection,
// CDN detection, and richer fingerprinting (LOW_IMPACT — same requests as
// the native probe, just more parsing). Runs after the native http-probe;
// merges attrs rather than replacing them. Gracefully no-ops if absent.
func HTTPx(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) error {
	if _, err := lookup("httpx"); err != nil {
		return err
	}

	// Only probe assets that already have web_service data (from the native probe).
	services, err := st.ListAssets(ctx, store.ListFilter{
		CampaignID: campaignID, Kind: store.KindWebService, Limit: 1000,
	})
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return nil
	}

	var targets []string
	for _, s := range services {
		targets = append(targets, s.Value)
	}
	if err := eng.PreFlightTargets(ctx, targets); err != nil {
		return fmt.Errorf("httpx: %w", err)
	}

	args := []string{
		"-l", strings.Join(targets, ","),
		"-json",
		"-silent",
		"-tech-detect", // Wappalyzer-style tech fingerprinting
		"-status-code",
		"-title",
		"-web-server",       // server header
		"-follow-redirects", // record the redirect chain
		"-rate-limit", "25", // per-request pacing inside the binary
		"-threads", "10",
	}
	out, err := invoke(ctx, "httpx", args...)
	if err != nil {
		return fmt.Errorf("httpx: %w", err)
	}

	for _, obj := range parseJSONLines(out) {
		url, _ := obj["url"].(string)
		if url == "" {
			continue
		}
		// Extract the host from the URL (httpx returns full URLs).
		host := extractHostFromURL(url)
		if host == "" {
			continue
		}

		// Merge the richer attrs into the existing web_service asset.
		attrs := make(map[string]any)
		if tech, ok := obj["tech"].([]any); ok && len(tech) > 0 {
			attrs["tech"] = strings.Join(toStrings(tech), ",")
		}
		if title, ok := obj["title"].(string); ok && title != "" {
			attrs["title_httpx"] = title
		}
		if cdn, ok := obj["cdn"].(string); ok && cdn != "" {
			attrs["cdn"] = cdn
		}
		if status, ok := obj["status_code"].(float64); ok {
			attrs["status_httpx"] = int(status)
		}
		if len(attrs) > 0 {
			if _, err := st.UpsertAsset(ctx, campaignID, store.KindWebService, host, "httpx", false, attrs); err != nil {
				return err
			}
		}
	}
	return nil
}

// Naabu port-scans one host (INTRUSIVE — the operator must approve the
// (tool, host) pair first via the approval gate). The binary's own rate
// limits plus the pre-flight target check and the persistence-layer scope
// check complete the triple enforcement. Found ports become assets.
func Naabu(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64, host, approvalToken string) error {
	if _, err := lookup("naabu"); err != nil {
		return err
	}

	// Pre-flight: the host must be in scope.
	if err := eng.PreFlightTargets(ctx, []string{host}); err != nil {
		return fmt.Errorf("naabu: %w", err)
	}

	// The approval gate: the token must be APPROVED for (naabu, host).
	// The binary runs outside the engine's per-request control, so the
	// approval is the operator's explicit y/n for this logical action.
	if approvalToken == "" {
		return fmt.Errorf("naabu: INTRUSIVE — request approval first (recon approve)")
	}
	if err := st.ValidateApproval(ctx, approvalToken, "naabu", host); err != nil {
		return fmt.Errorf("naabu: %w", err)
	}

	args := []string{
		"-host", host,
		"-json",
		"-silent",
		"-top-ports", "1000", // the standard port range
		"-rate-limit", "50", // the binary's own pacing
		"-timeout", "3", // per-probe timeout
	}
	out, err := invoke(ctx, "naabu", args...)
	if err != nil {
		return fmt.Errorf("naabu: %w", err)
	}

	var foundPorts []map[string]any
	for _, obj := range parseJSONLines(out) {
		scanHost, _ := obj["host"].(string)
		port, _ := obj["port"].(float64)
		if scanHost == "" || port == 0 {
			continue
		}
		proto, _ := obj["proto"].(string)
		if proto == "" {
			proto = "tcp"
		}
		foundPorts = append(foundPorts, map[string]any{
			"host": scanHost, "port": int(port), "proto": proto,
		})
		// Each open port becomes an asset linked to the host's IP.
		portValue := fmt.Sprintf("%s:%d/%s", scanHost, int(port), proto)
		if _, err := st.UpsertAsset(ctx, campaignID, store.KindIP, portValue, "naabu",
			scope.HostVerdict(scanHost) != policy.ScopeIn,
			map[string]any{"port": int(port), "proto": proto}); err != nil {
			return err
		}
	}

	// Consume the approval — one token, one scan.
	if err := st.ConsumeApproval(ctx, approvalToken, "naabu", host); err != nil {
		return fmt.Errorf("naabu: scan completed but the approval could not be consumed: %w", err)
	}
	return nil
}

// Katana crawls a target URL discovering endpoints, forms, and parameters
// (INTRUSIVE — the operator must approve). Discovered URLs become endpoint
// assets; forms and parameters are recorded in attrs.
func Katana(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64, baseURL, approvalToken string) error {
	if _, err := lookup("katana"); err != nil {
		return err
	}

	// Extract the host and pre-flight.
	host := extractHostFromURL(baseURL)
	if host == "" {
		return fmt.Errorf("katana: invalid base URL %q", baseURL)
	}
	if err := eng.PreFlightTargets(ctx, []string{host}); err != nil {
		return fmt.Errorf("katana: %w", err)
	}

	// Approval gate.
	if approvalToken == "" {
		return fmt.Errorf("katana: INTRUSIVE — request approval first (recon approve)")
	}
	if err := st.ValidateApproval(ctx, approvalToken, "katana", host); err != nil {
		return fmt.Errorf("katana: %w", err)
	}

	args := []string{
		"-u", baseURL,
		"-json",
		"-silent",
		"-depth", "3", // how deep to follow links
		"-rate-limit", "25", // the binary's own pacing
		"-js-crawl",        // also parse JS files for routes
		"-form-extraction", // extract form fields
		"-timeout", "5",
	}
	out, err := invoke(ctx, "katana", args...)
	if err != nil {
		return fmt.Errorf("katana: %w", err)
	}

	var endpoints []string
	for _, obj := range parseJSONLines(out) {
		reqURL, _ := obj["request"].(string)
		if reqURL == "" {
			continue
		}
		// Scope-check the discovered URL at persistence (third layer).
		reqHost := extractHostFromURL(reqURL)
		if reqHost == "" || scope.HostVerdict(reqHost) != policy.ScopeIn {
			continue // out-of-scope URLs are silently dropped
		}
		endpoints = append(endpoints, reqURL)

		method, _ := obj["method"].(string)
		attrs := map[string]any{"url": reqURL}
		if method != "" {
			attrs["method"] = method
		}
		if tag, ok := obj["tag"].(string); ok && tag != "" {
			attrs["tag"] = tag // form, script, link...
		}
		if source, ok := obj["source"].(string); ok && source != "" {
			attrs["discovered_from"] = source
		}
		// Store as an endpoint asset linked to the web service.
		ep, err := st.UpsertAsset(ctx, campaignID, store.KindEndpoint, reqURL, "katana", false, attrs)
		if err != nil {
			return err
		}
		// Link the endpoint to the host's web_service asset when it exists.
		if ws, err := st.GetAssetByValue(ctx, campaignID, store.KindWebService, reqHost); err == nil {
			if err := st.LinkAssets(ctx, ws.ID, ep.ID, "serves"); err != nil {
				return err
			}
		}
	}

	// Consume the approval.
	if err := st.ConsumeApproval(ctx, approvalToken, "katana", host); err != nil {
		return fmt.Errorf("katana: crawl completed but the approval could not be consumed: %w", err)
	}
	return nil
}

// extractHostFromURL pulls the hostname out of a URL string.
func extractHostFromURL(rawURL string) string {
	// Simple extraction: strip scheme, then take up to : or /.
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, ":/"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// toStrings converts a []any of strings to []string.
func toStrings(items []any) []string {
	var out []string
	for _, v := range items {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
