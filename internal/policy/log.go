package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one immutable request_log line (README §11): every request —
// allowed or denied, executed or paced-out — produces one.
type Entry struct {
	TS         time.Time    `json:"ts"`
	Campaign   string       `json:"campaign,omitempty"`
	Actor      string       `json:"actor"`
	Tool       string       `json:"tool"`
	Target     string       `json:"target"`
	Risk       RiskLevel    `json:"risk"`
	Scope      ScopeVerdict `json:"scope"`
	Allowed    bool         `json:"allowed"`
	Reason     string       `json:"reason,omitempty"`
	Result     string       `json:"result"` // "200" | "denied:…" | "error:…" | "paced-out:…"
	ApprovedBy string       `json:"approved_by,omitempty"`
}

// Sink receives every request_log entry — the evidence-everything backbone.
// The store-backed implementation lands in R2; R1 ships JSONL and memory.
type Sink interface {
	Log(ctx context.Context, e Entry) error
}

// NopSink discards entries; use only in tests that assert nothing.
func NopSink() Sink { return nopSink{} }

type nopSink struct{}

func (nopSink) Log(context.Context, Entry) error { return nil }

// MemSink records entries in memory for assertions.
type MemSink struct {
	mu      sync.Mutex
	Entries []Entry
}

// Log implements Sink.
func (m *MemSink) Log(_ context.Context, e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Entries = append(m.Entries, e)
	return nil
}

// Len returns the recorded entry count.
func (m *MemSink) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Entries)
}

// JSONLSink appends entries to a JSONL file.
type JSONLSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewJSONLSink opens (creating parents) a JSONL evidence file for append.
func NewJSONLSink(path string) (*JSONLSink, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create evidence dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open evidence log: %w", err)
	}
	return &JSONLSink{f: f}, nil
}

// Log implements Sink.
func (j *JSONLSink) Log(_ context.Context, e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.f.Write(append(b, '\n'))
	return err
}

// Close releases the evidence file.
func (j *JSONLSink) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}
