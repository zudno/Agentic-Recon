package policy

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONLSinkAppendsAndReadsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "request.jsonl")
	sink, err := NewJSONLSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	for i, target := range []string{"https://a.example.com/1", "https://b.example.com/2"} {
		err := sink.Log(context.Background(), Entry{
			TS:      time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
			Actor:   "module:test",
			Tool:    "probe",
			Target:  target,
			Risk:    RiskLowImpact,
			Scope:   ScopeIn,
			Allowed: true,
			Result:  "200",
		})
		if err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var entries []Entry
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("corrupt JSONL line: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[1].Target != "https://b.example.com/2" || !entries[1].Allowed {
		t.Fatalf("entry = %+v", entries[1])
	}
}

func TestMemSinkRecords(t *testing.T) {
	m := &MemSink{}
	if err := m.Log(context.Background(), Entry{Actor: "x", Tool: "y", Result: "denied:test"}); err != nil {
		t.Fatal(err)
	}
	if m.Len() != 1 || !strings.HasPrefix(m.Entries[0].Result, "denied:") {
		t.Fatalf("entries = %+v", m.Entries)
	}
}

func TestNewEngineRequiresSink(t *testing.T) {
	scope := mustParse(t, defaultScopeYAML)
	if _, err := NewEngine(EngineConfig{Scope: scope}); err == nil ||
		!strings.Contains(err.Error(), "evidence-everything") {
		t.Fatalf("err = %v", err)
	}
}
