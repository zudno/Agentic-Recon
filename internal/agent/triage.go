package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
	"agenticrecon/internal/toolbox"
)

// Budget enforces the campaign's hard ceilings (README §10): tokens per
// campaign and steps per hypothesis. Overspending aborts the run — agents
// accelerate, they never get to run away.
type Budget struct {
	MaxTokens  int64
	MaxSteps   int
	tokensUsed int64
}

// NewBudget builds the budget from the scope's ceilings.
func NewBudget(scope *policy.Scope) *Budget {
	return &Budget{
		MaxTokens: scope.Budgets.CampaignMaxTokens,
		MaxSteps:  scope.Budgets.AgentMaxStepsPerHypothesis,
	}
}

// Spend records a turn's usage; it errors once the campaign ceiling is
// crossed — the caller must stop issuing LLM calls.
func (b *Budget) Spend(u Usage) error {
	b.tokensUsed += int64(u.InputTokens) + int64(u.OutputTokens)
	if b.MaxTokens > 0 && b.tokensUsed > b.MaxTokens {
		return fmt.Errorf("agent: campaign token budget exhausted (%d > %d)", b.tokensUsed, b.MaxTokens)
	}
	return nil
}

// TokensUsed reports consumption so far.
func (b *Budget) TokensUsed() int64 { return b.tokensUsed }

// TriageReport summarizes one triage run.
type TriageReport struct {
	Reviewed  int
	Promoted  int  // → TRIAGED, awaiting a specialist
	Discarded int  // dead ends closed early
	Skipped   int  // unparseable model replies — the store stays untouched
	Aborted   bool // budget exhausted mid-run
}

// TriageAgent is the orchestrator (README §10): it scores unexplored
// assets, files a hypothesis for each, and moves the interesting ones to
// TRIAGED. One bounded LLM call per asset; every state change flows through
// the store — the model proposes, the deterministic layer disposes.
type TriageAgent struct {
	Actor  string
	tb     *toolbox.Toolbox
	client Client
	budget *Budget
}

// NewTriageAgent wires the orchestrator.
func NewTriageAgent(actor string, tb *toolbox.Toolbox, client Client, scope *policy.Scope) *TriageAgent {
	return &TriageAgent{Actor: actor, tb: tb, client: client, budget: NewBudget(scope)}
}

const triageSystem = `You are the triage orchestrator of an AUTHORIZED security assessment with a signed scope. For each asset you are shown, reply with ONLY a JSON object, no other text:
{"score": <0.0-1.0>, "reasoning": "<one or two sentences>", "investigate": <true|false>}

Interest signals: exposed admin panels or dashboards, dev/qa/staging hosts, Swagger/OpenAPI documentation, login pages on internal-looking hosts, old or unusual server versions, .git/.env exposure, non-standard ports. Plain marketing sites and CDN fronts score low. Be conservative: high scores need a concrete signal from the asset's attributes.`

// Run triages up to limit unexplored assets of the given kind ("" = all).
func (a *TriageAgent) Run(ctx context.Context, kind store.AssetKind, limit int) (TriageReport, error) {
	assets, err := a.tb.GetUnexploredAssets(ctx, kind, limit)
	if err != nil {
		return TriageReport{}, err
	}
	var report TriageReport
	for _, asset := range assets {
		details, err := json.Marshal(map[string]any{
			"id": asset.ID, "kind": asset.Kind, "value": asset.Value,
			"source": asset.Source, "attrs": asset.Attrs,
		})
		if err != nil {
			return report, err
		}
		assistant, usage, err := a.client.Complete(ctx, triageSystem,
			[]Msg{{Role: "user", Text: string(details)}}, nil)
		if err != nil {
			report.Aborted = true
			return report, err
		}
		if err := a.budget.Spend(usage); err != nil {
			report.Aborted = true
			return report, err
		}
		report.Reviewed++
		d, ok := parseTriageDecision(assistant.Text)
		if !ok {
			// An unparseable reply changes nothing — fail closed, move on.
			report.Skipped++
			continue
		}
		if _, err := a.tb.SaveHypothesis(ctx, asset.ID, a.Actor, d.Reasoning, d.Score); err != nil {
			return report, err
		}
		if d.Investigate {
			if _, err := a.tb.Store.UpdateAssetState(ctx, asset.ID, store.StateTriaged); err != nil {
				return report, err
			}
			report.Promoted++
		} else {
			if _, err := a.tb.Store.UpdateAssetState(ctx, asset.ID, store.StateDiscarded); err != nil {
				return report, err
			}
			report.Discarded++
		}
	}
	return report, nil
}

type triageDecision struct {
	Score       float64 `json:"score"`
	Reasoning   string  `json:"reasoning"`
	Investigate bool    `json:"investigate"`
}

// parseTriageDecision extracts the JSON object from a model reply.
func parseTriageDecision(text string) (triageDecision, bool) {
	var d triageDecision
	raw, ok := extractJSON(text)
	if !ok {
		return d, false
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, false
	}
	if d.Score < 0 || d.Score > 1 || strings.TrimSpace(d.Reasoning) == "" {
		return d, false
	}
	return d, true
}
