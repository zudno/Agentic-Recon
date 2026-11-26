// Package agent implements the LLM layer (README §10): the triage
// orchestrator and the specialist ReAct loops, both with hard budgets and
// both consuming ONLY the typed toolbox — no free shell, ever. The model
// proposes; the deterministic policy engine and store dispose.
//
// This file (llm.go) is the single documented exception to the
// native-egress-only-in-policy rule (see the guard test): it talks to the
// configured LLM provider exclusively — never to recon targets — and its
// traffic is not recon egress.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"agenticrecon/internal/policy"
)

// ToolDef describes one typed toolbox function to the model.
type ToolDef struct {
	Name        string
	Description string
	Schema      map[string]any
}

// ToolCall is a model-requested tool invocation.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string // raw JSON
}

// ToolResult carries one tool outcome back to the model.
type ToolResult struct {
	CallID  string
	Content string
	IsError bool
}

// Msg is one normalized conversation turn: a plain user text, an assistant
// reply (text + tool calls), or a user turn carrying tool results.
type Msg struct {
	Role        string // "user" | "assistant"
	Text        string
	ToolCalls   []ToolCall   // assistant turns
	ToolResults []ToolResult // user turns
}

// Assistant is the model's reply for one turn.
type Assistant struct {
	Text           string
	ToolCalls      []ToolCall
	StoppedOnTools bool
}

// Usage reports token consumption for budget enforcement.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// Client performs one conversation turn against the configured provider.
type Client interface {
	Complete(ctx context.Context, system string, msgs []Msg, tools []ToolDef) (Assistant, Usage, error)
}

// NewClient builds the provider client from the scope's llm block. The API
// key is read from the env var named there — keys never live in scope.yaml.
func NewClient(scope *policy.Scope) (Client, error) {
	if scope.LLM == nil {
		return nil, errors.New("agent: no llm block in scope.yaml — manual triage still works (README §10)")
	}
	key := os.Getenv(scope.LLM.APIKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("agent: env var %s (llm.api_key_env) is not set", scope.LLM.APIKeyEnv)
	}
	switch scope.LLM.Provider {
	case "anthropic":
		base := "https://api.anthropic.com"
		if scope.LLM.BaseURL != "" {
			base = strings.TrimSuffix(scope.LLM.BaseURL, "/")
		}
		return &anthropicClient{base: base, model: scope.LLM.Model, key: key}, nil
	case "openai-compatible":
		if scope.LLM.BaseURL == "" {
			return nil, errors.New("agent: openai-compatible providers require llm.base_url")
		}
		return &openaiClient{base: strings.TrimSuffix(scope.LLM.BaseURL, "/"), model: scope.LLM.Model, key: key}, nil
	default:
		return nil, fmt.Errorf("agent: unknown provider %q", scope.LLM.Provider)
	}
}

var llmHTTP = &http.Client{Timeout: 120 * time.Second}

func postJSON(ctx context.Context, url string, headers map[string]string, payload any, into any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("agent: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := llmHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("agent: llm request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		excerpt := string(data)
		if len(excerpt) > 512 {
			excerpt = excerpt[:512]
		}
		return fmt.Errorf("agent: llm %s → %d: %s", url, resp.StatusCode, excerpt)
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("agent: parse llm response: %w", err)
	}
	return nil
}

// ─── Anthropic Messages API ─────────────────────────────────────────────────

type anthropicClient struct {
	base  string
	model string
	key   string
}

func (c *anthropicClient) Complete(ctx context.Context, system string, msgs []Msg, tools []ToolDef) (Assistant, Usage, error) {
	var wireTools []map[string]any
	for _, t := range tools {
		wireTools = append(wireTools, map[string]any{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": t.Schema,
		})
	}
	payload := map[string]any{
		"model":      c.model,
		"max_tokens": 2048,
		"messages":   anthropicMessages(msgs),
	}
	if system != "" {
		payload["system"] = system
	}
	if len(wireTools) > 0 {
		payload["tools"] = wireTools
	}
	var out anthropicResponse
	err := postJSON(ctx, c.base+"/v1/messages",
		map[string]string{"x-api-key": c.key, "anthropic-version": "2023-06-01"},
		payload, &out)
	if err != nil {
		return Assistant{}, Usage{}, err
	}
	a := Assistant{StoppedOnTools: out.StopReason == "tool_use"}
	for _, b := range out.Content {
		switch b.Type {
		case "text":
			a.Text += b.Text
		case "tool_use":
			a.ToolCalls = append(a.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Arguments: string(b.Input)})
		}
	}
	return a, Usage{InputTokens: out.Usage.InputTokens, OutputTokens: out.Usage.OutputTokens}, nil
}

func anthropicMessages(msgs []Msg) []map[string]any {
	var out []map[string]any
	for _, m := range msgs {
		var content []map[string]any
		if m.Text != "" {
			content = append(content, map[string]any{"type": "text", "text": m.Text})
		}
		for _, tc := range m.ToolCalls {
			content = append(content, map[string]any{
				"type": "tool_use", "id": tc.ID, "name": tc.Name,
				"input": json.RawMessage(tc.Arguments),
			})
		}
		for _, tr := range m.ToolResults {
			entry := map[string]any{"type": "tool_result", "tool_use_id": tr.CallID, "content": tr.Content}
			if tr.IsError {
				entry["is_error"] = true
			}
			content = append(content, entry)
		}
		out = append(out, map[string]any{"role": m.Role, "content": content})
	}
	return out
}

type anthropicResponse struct {
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ─── OpenAI-compatible chat completions ────────────────────────────────────

type openaiClient struct {
	base  string
	model string
	key   string
}

func (c *openaiClient) Complete(ctx context.Context, system string, msgs []Msg, tools []ToolDef) (Assistant, Usage, error) {
	wireMsgs := []map[string]any{}
	if system != "" {
		wireMsgs = append(wireMsgs, map[string]any{"role": "system", "content": system})
	}
	for _, m := range msgs {
		switch {
		case m.Role == "assistant":
			entry := map[string]any{"role": "assistant", "content": nil}
			if m.Text != "" {
				entry["content"] = m.Text
			}
			if len(m.ToolCalls) > 0 {
				var calls []map[string]any
				for _, tc := range m.ToolCalls {
					calls = append(calls, map[string]any{
						"id": tc.ID, "type": "function",
						"function": map[string]any{"name": tc.Name, "arguments": tc.Arguments},
					})
				}
				entry["tool_calls"] = calls
			}
			wireMsgs = append(wireMsgs, entry)
		case len(m.ToolResults) > 0:
			for _, tr := range m.ToolResults {
				wireMsgs = append(wireMsgs, map[string]any{
					"role": "tool", "tool_call_id": tr.CallID, "content": tr.Content,
				})
			}
			if m.Text != "" {
				wireMsgs = append(wireMsgs, map[string]any{"role": "user", "content": m.Text})
			}
		default:
			wireMsgs = append(wireMsgs, map[string]any{"role": m.Role, "content": m.Text})
		}
	}
	payload := map[string]any{"model": c.model, "messages": wireMsgs}
	if len(tools) > 0 {
		var wireTools []map[string]any
		for _, t := range tools {
			wireTools = append(wireTools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": t.Name, "description": t.Description, "parameters": t.Schema,
				},
			})
		}
		payload["tools"] = wireTools
	}
	var out openaiResponse
	err := postJSON(ctx, c.base+"/chat/completions",
		map[string]string{"Authorization": "Bearer " + c.key}, payload, &out)
	if err != nil {
		return Assistant{}, Usage{}, err
	}
	if len(out.Choices) == 0 {
		return Assistant{}, Usage{}, errors.New("agent: llm returned no choices")
	}
	choice := out.Choices[0]
	a := Assistant{
		Text:           choice.Message.Content,
		StoppedOnTools: choice.FinishReason == "tool_calls",
	}
	for _, tc := range choice.Message.ToolCalls {
		a.ToolCalls = append(a.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments})
	}
	return a, Usage{InputTokens: out.Usage.PromptTokens, OutputTokens: out.Usage.CompletionTokens}, nil
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}
