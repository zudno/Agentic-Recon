package pipeline

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

// HTTPProbe fingerprints discovered in-scope subdomains over HTTP(S): a
// LOW_IMPACT action through the policy engine (README §8). For each probe
// it records a web_service asset (status, title, server, redirect), links
// the subdomain to it, and stores an observation. Probed subdomains are
// skipped, so interrupted campaigns resume without repeating work.
func HTTPProbe(ctx context.Context, eng *policy.Engine, st *store.Store, campaignID int64) error {
	subs, err := st.ListAssets(ctx, store.ListFilter{
		CampaignID: campaignID,
		Kind:       store.KindSubdomain,
		Limit:      1000,
	})
	if err != nil {
		return err
	}
	for _, sub := range subs {
		if sub.Attrs["probed"] == true {
			continue
		}
		resp, scheme, err := probeOnce(ctx, eng, sub.Value)
		if err != nil {
			// Record the failure and move on — a dead host is a finding
			// too, and resume must not retry it forever.
			if _, uerr := st.UpsertAsset(ctx, campaignID, store.KindSubdomain, sub.Value,
				"http-probe", false, map[string]any{"probed": true, "probe_error": err.Error()}); uerr != nil {
				return uerr
			}
			continue
		}
		attrs := probeAttrs(resp, scheme)
		ws, err := st.UpsertAsset(ctx, campaignID, store.KindWebService, sub.Value,
			"http-probe", false, attrs)
		if err != nil {
			return err
		}
		if err := st.LinkAssets(ctx, sub.ID, ws.ID, "served_by"); err != nil {
			return err
		}
		if _, err := st.AddObservation(ctx, campaignID, ws.ID, "http-probe", attrs); err != nil {
			return err
		}
		if _, err := st.UpsertAsset(ctx, campaignID, store.KindSubdomain, sub.Value,
			"http-probe", false, map[string]any{"probed": true}); err != nil {
			return err
		}
	}
	return nil
}

// probeOnce tries HTTPS and falls back to plain HTTP — both through the
// policy engine, so every attempt is paced and logged.
func probeOnce(ctx context.Context, eng *policy.Engine, host string) (*policy.HTTPResponse, string, error) {
	resp, _, err := eng.Do(ctx, &policy.Request{
		Actor:  "module:http-probe",
		Tool:   "http-probe",
		Reason: "web service fingerprinting",
		Risk:   policy.RiskLowImpact,
		Target: &policy.HTTPRequest{Method: "GET", URL: "https://" + host + "/"},
	})
	if err == nil {
		return resp, "https", nil
	}
	resp, _, err2 := eng.Do(ctx, &policy.Request{
		Actor:  "module:http-probe",
		Tool:   "http-probe",
		Reason: "web service fingerprinting (http fallback)",
		Risk:   policy.RiskLowImpact,
		Target: &policy.HTTPRequest{Method: "GET", URL: "http://" + host + "/"},
	})
	if err2 == nil {
		return resp, "http", nil
	}
	return nil, "", fmt.Errorf("https: %v; http: %v", err, err2)
}

func probeAttrs(resp *policy.HTTPResponse, scheme string) map[string]any {
	attrs := map[string]any{
		"status": resp.Status,
		"scheme": scheme,
	}
	if len(resp.Body) > 4096 {
		attrs["title"] = extractTitle(resp.Body[:4096])
	} else {
		attrs["title"] = extractTitle(resp.Body)
	}
	if v, ok := headerValue(resp.Headers, "Server"); ok {
		attrs["server"] = v
	}
	if v, ok := headerValue(resp.Headers, "Content-Type"); ok {
		attrs["content_type"] = v
	}
	if resp.Status >= 300 && resp.Status < 400 {
		if v, ok := headerValue(resp.Headers, "Location"); ok {
			attrs["redirect"] = v
		}
	}
	return attrs
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

func headerValue(h map[string][]string, name string) (string, bool) {
	for k, vv := range h {
		if strings.EqualFold(k, name) && len(vv) > 0 {
			return vv[0], true
		}
	}
	return "", false
}
