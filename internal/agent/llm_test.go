package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"agenticrecon/internal/policy"
)

func llmScope(provider, baseURL string) *policy.Scope {
	s, err := policy.Parse([]byte(`
authorization:
  reference: "ROE-TEST-001"
  window: {start: "2000-01-01T00:00:00Z", end: "2999-01-01T00:00:00Z"}
scope:
  domains: [example.com]
  sources: [crt.sh]
policy:
  risk_levels: [PASSIVE]
  rate: {requests_per_second: 100, per_host_per_second: 100, jitter_ms: 1}
budgets:
  agent_max_steps_per_hypothesis: 8
  campaign_max_tokens: 1000000
llm:
  provider: "` + provider + `"
  model: "test-model"
  api_key_env: "AR_TEST_KEY"
  base_url: "` + baseURL + `"
`))
	if err != nil {
		panic(err)
	}
	return s
}

func TestAnthropicAdapterRoundTrip(t *testing.T) {
	t.Setenv("AR_TEST_KEY", "sk-test")
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "sk-test" || r.Header.Get("anthropic-version") == "" {
			t.Error("anthropic headers missing")
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{
			"content": [
				{"type":"text","text":"thinking..."},
				{"type":"tool_use","id":"toolu_1","name":"http_request","input":{"method":"GET","url":"https://api.example.com/"}}
			],
			"stop_reason":"tool_use",
			"usage":{"input_tokens":100,"output_tokens":20}
		}`))
	}))
	defer srv.Close()

	client, err := NewClient(llmScope("anthropic", srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	// A tool-result turn must marshal back as tool_result blocks.
	assistant, usage, err := client.Complete(context.Background(), "sys",
		[]Msg{{Role: "user", Text: "hi"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "toolu_1", Name: "http_request", Arguments: `{"method":"GET"}`}}},
			{Role: "user", ToolResults: []ToolResult{{CallID: "toolu_1", Content: `{"status":200}`}}}},
		[]ToolDef{{Name: "http_request", Description: "d", Schema: map[string]any{"type": "object"}}})
	if err != nil {
		t.Fatal(err)
	}
	if assistant.Text != "thinking..." || !assistant.StoppedOnTools ||
		len(assistant.ToolCalls) != 1 || assistant.ToolCalls[0].ID != "toolu_1" {
		t.Fatalf("assistant = %+v", assistant)
	}
	if usage.InputTokens != 100 || usage.OutputTokens != 20 {
		t.Fatalf("usage = %+v", usage)
	}
	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("wire messages = %d", len(msgs))
	}
}

func TestOpenAIAdapterRoundTrip(t *testing.T) {
	t.Setenv("AR_TEST_KEY", "sk-oai")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-oai" {
			t.Error("bearer header missing")
		}
		_, _ = w.Write([]byte(`{
			"choices": [{
				"message": {
					"content": "",
					"tool_calls": [{"id":"call_1","type":"function","function":{"name":"search_by_tech","arguments":"{\"tech\":\"swagger\"}"}}]
				},
				"finish_reason": "tool_calls"
			}],
			"usage": {"prompt_tokens": 50, "completion_tokens": 10}
		}`))
	}))
	defer srv.Close()

	client, err := NewClient(llmScope("openai-compatible", srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	assistant, usage, err := client.Complete(context.Background(), "sys",
		[]Msg{{Role: "user", Text: "find swagger"}},
		[]ToolDef{{Name: "search_by_tech", Description: "d", Schema: map[string]any{"type": "object"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !assistant.StoppedOnTools || len(assistant.ToolCalls) != 1 ||
		assistant.ToolCalls[0].Arguments != `{"tech":"swagger"}` {
		t.Fatalf("assistant = %+v", assistant)
	}
	if usage.InputTokens != 50 || usage.OutputTokens != 10 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestNewClientRequiresKeyAndProvider(t *testing.T) {
	// Key missing → refused before any network action.
	s := llmScope("anthropic", "")
	if _, err := NewClient(s); err == nil {
		t.Fatal("missing env key must be refused")
	}
	t.Setenv("AR_TEST_KEY", "x")
	if _, err := NewClient(s); err != nil {
		t.Fatalf("with the key set the client must build: %v", err)
	}
	// openai-compatible without base_url → refused.
	oai := llmScope("openai-compatible", "")
	if _, err := NewClient(oai); err == nil {
		t.Fatal("openai-compatible without base_url must be refused")
	}
}
