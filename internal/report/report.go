// Package report generates the engagement report from the campaign store
// (README §12): the scope summary with exclusions, the validated inventory,
// the prioritized paths toward initial access (findings + hypotheses +
// evidence), and the complete action trail. Everything is reconstructed
// from request_log — the accountability backbone: the report IS the log.
package report

import (
	"context"
	"fmt"
	"sort"
	"time"

	"agenticrecon/internal/store"
)

// Report is the canonical engagement report data.
type Report struct {
	Campaign    store.Campaign `json:"campaign"`
	GeneratedAt time.Time      `json:"generated_at"`
	OutOfScope  []store.Asset  `json:"out_of_scope"` // the exclusions report
	Inventory   Inventory      `json:"inventory"`
	Findings    []FindingView  `json:"findings"`
	RequestLog  []store.LogRow `json:"request_log"`
}

// Inventory summarizes the campaign's assets.
type Inventory struct {
	Total   int            `json:"total"`
	ByState map[string]int `json:"by_state"`
	ByKind  map[string]int `json:"by_kind"`
	Assets  []store.Asset  `json:"assets"`
}

// FindingView is one prioritized path: the finding, its origin hypothesis,
// and the evidence rows that back it.
type FindingView struct {
	Finding    store.Finding    `json:"finding"`
	Asset      store.Asset      `json:"asset"`
	Hypothesis store.Hypothesis `json:"hypothesis"`
	Evidence   []store.LogRow   `json:"evidence"`
}

// Build assembles the full report from the store. Every finding is traced
// back to its hypothesis and its exact request_log rows — the R6 criterion:
// the report reproduces the campaign from the log.
func Build(ctx context.Context, st *store.Store, campaignID int64) (*Report, error) {
	camp, err := st.GetCampaign(ctx, campaignID)
	if err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}

	// 1. Inventory (all assets, including out-of-scope).
	allAssets, err := st.ListAssets(ctx, store.ListFilter{
		CampaignID: campaignID, IncludeOutOfScope: true, Limit: 1000,
	})
	if err != nil {
		return nil, fmt.Errorf("report: inventory: %w", err)
	}
	var outOfScope []store.Asset
	for _, a := range allAssets {
		if a.State == store.StateOutOfScope {
			outOfScope = append(outOfScope, a)
		}
	}

	inv := Inventory{
		Total:   len(allAssets),
		ByState: make(map[string]int),
		ByKind:  make(map[string]int),
		Assets:  allAssets,
	}
	for _, a := range allAssets {
		inv.ByState[string(a.State)]++
		inv.ByKind[string(a.Kind)]++
	}

	// 2. Findings — each with its hypothesis, asset, and evidence rows.
	rawFindings, err := st.ListFindings(ctx, campaignID)
	if err != nil {
		return nil, fmt.Errorf("report: findings: %w", err)
	}
	findings := make([]FindingView, 0, len(rawFindings))
	for _, f := range rawFindings {
		fv := FindingView{Finding: f}
		if h, err := st.GetHypothesis(ctx, f.HypothesisID); err == nil {
			fv.Hypothesis = h
		}
		if a, err := st.GetAsset(ctx, f.AssetID); err == nil {
			fv.Asset = a
		}
		for _, ref := range f.EvidenceRefs {
			if row, err := st.GetRequestLogByID(ctx, ref); err == nil {
				fv.Evidence = append(fv.Evidence, row)
			}
		}
		findings = append(findings, fv)
	}
	// Severity-ordered: high first — the prioritized paths.
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Finding.Severity) < severityRank(findings[j].Finding.Severity)
	})

	// 3. The complete action trail.
	log, err := st.ListRequestLog(ctx, campaignID, 1000)
	if err != nil {
		return nil, fmt.Errorf("report: request_log: %w", err)
	}

	return &Report{
		Campaign:    camp,
		GeneratedAt: time.Now().UTC(),
		OutOfScope:  outOfScope,
		Inventory:   inv,
		Findings:    findings,
		RequestLog:  log,
	}, nil
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}
