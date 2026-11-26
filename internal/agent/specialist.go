package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
	"agenticrecon/internal/toolbox"
)

// Outcome is how one specialist investigation ends.
type Outcome struct {
	Verdict      string // "validated" | "discarded" | "aborted"
	Severity     string
	Reasoning    string
	FindingID    int64
	HypothesisID int64
	StepsUsed    int
	Evidence     []int64
}

// Investigation is one bounded task: an asset and why it matters.
type Investigation struct {
	AssetID   int64
	Reasoning string
}

// SpecialistAgent runs the bounded ReAct loop (README §10): ONE task,
// ONLY the typed toolbox as tools, a hard step ceiling, and evidence-gated
// conclusions — "validated" without evidence gathered this run is
// downgraded to discarded. No free shell, ever.
type SpecialistAgent struct {
	Actor  string
	tb     *toolbox.Toolbox
	client Client
	budget *Budget
}

// NewSpecialistAgent wires the specialist.
func NewSpecialistAgent(actor string, tb *toolbox.Toolbox, client Client, scope *policy.Scope) *SpecialistAgent {
	return &SpecialistAgent{Actor: actor, tb: tb, client: client, budget: NewBudget(scope)}
}

const specialistSystem = `You are a specialist investigator in an AUTHORIZED security assessment with a signed scope. You investigate ONE bounded task about ONE in-scope asset, using ONLY the provided tools. You have a limited number of steps.

HOW TO FINISH: When your investigation is complete, you MUST call the submit_conclusion tool with your verdict. Do NOT write your conclusion as text — always use the submit_conclusion tool.

Rules:
- "validated" REQUIRES concrete evidence from tool results of THIS run (statuses, endpoints found, exposed documentation). No evidence → "discarded".
- Be conservative: you are prioritizing attack-surface paths for a human operator, not claiming exploits.
- Never invent URLs outside the asset's host; the policy engine will deny them anyway.
- Start by reading the asset's details and observations with get_asset_details and get_observations, then probe with http_request, and finish with submit_conclusion.`

// Run executes the loop for one investigation. On abort (budget, steps,
// context) the asset is released back to TRIAGED for another run.
func (a *SpecialistAgent) Run(ctx context.Context, inv Investigation) (Outcome, error) {
	asset, err := a.tb.GetAssetDetails(ctx, inv.AssetID)
	if err != nil {
		return Outcome{}, err
	}
	if strings.TrimSpace(inv.Reasoning) == "" {
		return Outcome{}, fmt.Errorf("agent: an investigation needs a reasoning")
	}

	// The hypothesis exists before any tool runs — promotion needs it.
	h, err := a.tb.SaveHypothesis(ctx, asset.ID, a.Actor, inv.Reasoning, 0.5)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{HypothesisID: h.ID}

	// Reserve the asset; DISCOVERED assets pass through TRIAGED first —
	// the state machine is the law, not the agent.
	if asset.State == store.StateDiscovered {
		if _, err := a.tb.Store.UpdateAssetState(ctx, asset.ID, store.StateTriaged); err != nil {
			return out, err
		}
	}
	if _, err := a.tb.Store.UpdateAssetState(ctx, asset.ID, store.StateInvestigating); err != nil {
		return out, err
	}
	finish := func(verdict string) (Outcome, error) {
		switch verdict {
		case "validated":
			if _, serr := a.tb.Store.UpdateAssetState(ctx, asset.ID, store.StateValidated); serr != nil {
				return out, serr
			}
		case "discarded":
			if _, serr := a.tb.Store.UpdateAssetState(ctx, asset.ID, store.StateDiscarded); serr != nil {
				return out, serr
			}
		default: // aborted — release the reservation
			if _, serr := a.tb.Store.UpdateAssetState(ctx, asset.ID, store.StateTriaged); serr != nil {
				return out, serr
			}
		}
		return out, nil
	}

	task := fmt.Sprintf("Investigate asset %d (%s %s).\nHypothesis: %s\nCollect concrete evidence with the tools, then conclude with the JSON verdict.",
		asset.ID, asset.Kind, asset.Value, inv.Reasoning)
	msgs := []Msg{{Role: "user", Text: task}}
	tools := specialistTools()

	for step := 1; step <= a.budget.MaxSteps; step++ {
		out.StepsUsed = step
		assistant, usage, err := a.client.Complete(ctx, specialistSystem, msgs, tools)
		if err != nil {
			out.Verdict = "aborted"
			return finish("aborted")
		}
		if err := a.budget.Spend(usage); err != nil {
			out.Verdict = "aborted"
			return finish("aborted")
		}
		// Check for the submit_conclusion tool — the model's structured exit.
		for _, call := range assistant.ToolCalls {
			if call.Name == "submit_conclusion" {
				var c conclusion
				if err := json.Unmarshal([]byte(call.Arguments), &c); err == nil && c.Verdict != "" {
					out.Verdict = c.Verdict
					out.Severity = c.Severity
					out.Reasoning = c.Reasoning
					switch {
					case c.Verdict == "validated" && len(out.Evidence) == 0:
						out.Verdict = "discarded"
						return finish("discarded")
					case c.Verdict == "validated":
						f, ferr := a.tb.PromoteToFinding(ctx, asset.ID, out.HypothesisID, c.Severity, out.Evidence)
						if ferr != nil {
							out.Verdict = "aborted"
							return finish("aborted")
						}
						out.FindingID = f.ID
						return finish("validated")
					default:
						return finish("discarded")
					}
				}
			}
		}

		// Text-only response (no tool calls) — try parsing as a conclusion.
		if len(assistant.ToolCalls) == 0 {
			c, ok := parseConclusion(assistant.Text)
			out.Verdict = c.Verdict
			out.Severity = c.Severity
			out.Reasoning = c.Reasoning
			switch {
			case !ok:
				out.Verdict = "aborted"
				return finish("aborted")
			case c.Verdict == "validated" && len(out.Evidence) == 0:
				out.Verdict = "discarded"
				return finish("discarded")
			case c.Verdict == "validated":
				f, ferr := a.tb.PromoteToFinding(ctx, asset.ID, out.HypothesisID, c.Severity, out.Evidence)
				if ferr != nil {
					out.Verdict = "aborted"
					return finish("aborted")
				}
				out.FindingID = f.ID
				return finish("validated")
			default:
				return finish("discarded")
			}
		}
		// Execute the requested tools and feed the results back.
		msgs = append(msgs, Msg{Role: "assistant", Text: assistant.Text, ToolCalls: assistant.ToolCalls})
		var results []ToolResult
		for _, call := range assistant.ToolCalls {
			if call.Name == "submit_conclusion" {
				// Already handled above — shouldn't reach here.
				results = append(results, ToolResult{CallID: call.ID, Content: "(already processed)", IsError: false})
				continue
			}
			content, evidence, derr := a.dispatch(ctx, call)
			out.Evidence = append(out.Evidence, evidence...)
			if derr != nil && content == "" {
				content = fmt.Sprintf("tool error: %v", derr)
			}
			if content == "" {
				content = "(no output)"
			}
			results = append(results, ToolResult{CallID: call.ID, Content: content, IsError: derr != nil})
		}
		msgs = append(msgs, Msg{Role: "user", ToolResults: results})
	}
	// Steps exhausted without a conclusion: release the reservation.
	out.Verdict = "aborted"
	return finish("aborted")
}

// dispatch executes one model-requested tool through the typed toolbox —
// the ONLY path agents have to the world (README §9).
func (a *SpecialistAgent) dispatch(ctx context.Context, call ToolCall) (string, []int64, error) {
	switch call.Name {
	case "http_request":
		var args struct{ Method, URL, Reason string }
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return "", nil, err
		}
		return a.marshal(a.tb.HTTPRequest(ctx, a.Actor, args.Reason, args.Method, args.URL, nil))
	case "fetch_js_and_extract_routes":
		var args struct{ URL, Reason string }
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return "", nil, err
		}
		return a.marshal(a.tb.FetchJSRoutes(ctx, a.Actor, args.Reason, args.URL))
	case "check_cve_details":
		var args struct{ CVE, Reason string }
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return "", nil, err
		}
		return a.marshal(a.tb.CheckCVEDetails(ctx, a.Actor, args.Reason, args.CVE))
	case "get_asset_details":
		var args map[string]any
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return "", nil, err
		}
		id, err := parseAssetID(args["id"])
		if err != nil {
			return "", nil, err
		}
		asset, err := a.tb.GetAssetDetails(ctx, id)
		if err != nil {
			return "", nil, err
		}
		b, _ := json.Marshal(asset)
		return string(b), nil, nil
	case "get_observations":
		// Returns the raw observations (banners, port data) captured by
		// the network scan. The ID may arrive as int or string depending
		// on the model — handle both.
		var args map[string]any
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return "", nil, err
		}
		id, err := parseAssetID(args["id"])
		if err != nil {
			return "", nil, err
		}
		obs, err := a.tb.Store.ObservationsOf(ctx, id)
		if err != nil {
			return "", nil, err
		}
		b, _ := json.Marshal(obs)
		return string(b), nil, nil
	case "search_by_tech":
		var args struct{ Tech string }
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return "", nil, err
		}
		assets, err := a.tb.SearchByTech(ctx, args.Tech)
		if err != nil {
			return "", nil, err
		}
		b, _ := json.Marshal(assets)
		return string(b), nil, nil
	default:
		return "unknown tool " + call.Name, nil, nil
	}
}

func (a *SpecialistAgent) marshal(res toolbox.ToolResult) (string, []int64, error) {
	b, err := json.Marshal(map[string]any{
		"ok":          res.OK,
		"summary":     res.Summary,
		"data":        res.Data,
		"evidence_id": res.EvidenceIDs,
	})
	if err != nil {
		return "", nil, err
	}
	return string(b), res.EvidenceIDs, nil
}

// specialistTools is the closed catalog exposed to the model: read tools
// plus low-impact inspection. INTRUSIVE actions stay operator-driven (R4).
func specialistTools() []ToolDef {
	obj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	return []ToolDef{
		{
			Name:        "submit_conclusion",
			Description: "REQUIRED to finish: submit your final verdict. You MUST call this tool instead of writing a text conclusion.",
			Schema: obj(map[string]any{
				"verdict":   map[string]any{"type": "string", "enum": []any{"validated", "discarded"}, "description": "your verdict"},
				"severity":  map[string]any{"type": "string", "enum": []any{"high", "medium", "low", "info"}, "description": "severity if validated"},
				"reasoning": str("one concrete sentence backed by evidence"),
			}, "verdict", "severity", "reasoning"),
		},
		{
			Name:        "get_asset_details",
			Description: "Full details of one asset in the campaign store.",
			Schema:      obj(map[string]any{"id": str("asset id")}, "id"),
		},
		{
			Name:        "get_observations",
			Description: "Raw observations for one asset — service banners (SSH versions, HTTP servers), port details, and protocol info captured by the network scan. Use this to see what services are running before probing.",
			Schema:      obj(map[string]any{"id": str("asset id")}, "id"),
		},
		{
			Name:        "search_by_tech",
			Description: "Assets whose attributes mention a technology (e.g. swagger, nginx, tomcat).",
			Schema:      obj(map[string]any{"tech": str("technology keyword")}, "tech"),
		},
		{
			Name:        "http_request",
			Description: "One HTTP request toward in-scope infrastructure (low impact, policy-checked, evidence-logged).",
			Schema: obj(map[string]any{
				"method": str("HTTP method, e.g. GET"),
				"url":    str("absolute URL of the in-scope target"),
				"reason": str("why this request advances the investigation"),
			}, "method", "url", "reason"),
		},
		{
			Name:        "fetch_js_and_extract_routes",
			Description: "Fetch a JavaScript asset and extract route-like strings from it.",
			Schema: obj(map[string]any{
				"url":    str("absolute URL of the .js asset"),
				"reason": str("why this fetch advances the investigation"),
			}, "url", "reason"),
		},
		{
			Name:        "check_cve_details",
			Description: "Look up a CVE id in NVD (public reference data).",
			Schema: obj(map[string]any{
				"cve":    str("CVE id, e.g. CVE-2021-44228"),
				"reason": str("why this lookup advances the investigation"),
			}, "cve", "reason"),
		},
	}
}

type conclusion struct {
	Verdict   string `json:"verdict"`
	Severity  string `json:"severity"`
	Reasoning string `json:"reasoning"`
}

func parseConclusion(text string) (conclusion, bool) {
	var c conclusion
	raw, ok := extractJSON(text)
	if !ok {
		return c, false
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, false
	}
	if c.Verdict != "validated" && c.Verdict != "discarded" {
		return c, false
	}
	if c.Verdict == "validated" && !validSeverity(c.Severity) {
		return c, false
	}
	return c, true
}

func validSeverity(s string) bool {
	switch s {
	case "high", "medium", "low", "info":
		return true
	}
	return false
}

// extractJSON pulls the outermost JSON object out of a model reply.
func extractJSON(text string) ([]byte, bool) {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, false
	}
	return []byte(text[start : end+1]), true
}

// parseAssetID accepts an asset id as int64, float64 (JSON number), or
// string — LLMs pass tool arguments in inconsistent types.
func parseAssetID(v any) (int64, error) {
	switch id := v.(type) {
	case float64:
		return int64(id), nil
	case string:
		return strconv.ParseInt(id, 10, 64)
	case json.Number:
		return id.Int64()
	default:
		return 0, fmt.Errorf("cannot parse asset id from %T (%v)", v, v)
	}
}
