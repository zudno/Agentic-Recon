package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"

	"agenticrecon/internal/store"
)

func TestAvailableDetectsBinaries(t *testing.T) {
	avail := Available()
	if len(avail) != len(registry) {
		t.Fatalf("available = %v, want %d entries", avail, len(registry))
	}
	for _, w := range registry {
		if _, ok := avail[w.Name]; !ok {
			t.Fatalf("wrapper %q missing from availability map", w.Name)
		}
	}
}

func TestExtractHostFromURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://api.example.com/path", "api.example.com"},
		{"http://www.example.com", "www.example.com"},
		{"https://sub.example.com:8080/x", "sub.example.com"},
		{"not-a-url", "not-a-url"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := extractHostFromURL(tc.in); got != tc.want {
			t.Errorf("extractHostFromURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestToStrings(t *testing.T) {
	in := []any{"a", "b", 42, "c"}
	out := toStrings(in)
	if len(out) != 3 || out[0] != "a" || out[2] != "c" {
		t.Fatalf("toStrings = %v", out)
	}
}

func TestParseJSONLines(t *testing.T) {
	input := `{"host":"a.example.com","source":"crt.sh"}
{"host":"b.example.com","source":"virustotal"}
not-json-noise
{"host":"c.example.com"}`
	lines := parseJSONLines([]byte(input))
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3 (noise skipped)", len(lines))
	}
	if lines[0]["host"] != "a.example.com" || lines[2]["host"] != "c.example.com" {
		t.Fatalf("parsed = %+v", lines)
	}
}

func TestPreFlightTargetsRejectsOutOfScope(t *testing.T) {
	eg := &routingEgress{} // unused: PreFlight doesn't egress
	_, eng, _, _ := setup(t, eg.do)

	err := eng.PreFlightTargets(context.Background(), []string{"api.example.com", "other.com"})
	if err == nil || !strings.Contains(err.Error(), "other.com") {
		t.Fatalf("err = %v", err)
	}

	err = eng.PreFlightTargets(context.Background(), []string{"api.example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("in-scope targets must pass: %v", err)
	}
}

func TestUpsertDiscoveredClassifiesScope(t *testing.T) {
	scope, _, st, cid := setup(t, nil)
	ctx := context.Background()

	inScope, err := upsertDiscovered(ctx, scope, st, cid, "api.example.com", "subfinder")
	if err != nil || inScope.State != store.StateDiscovered {
		t.Fatalf("in-scope = %+v err=%v", inScope, err)
	}
	excluded, err := upsertDiscovered(ctx, scope, st, cid, "partner.example.com", "subfinder")
	if err != nil || excluded.State != store.StateOutOfScope {
		t.Fatalf("excluded = %+v err=%v", excluded, err)
	}
	foreign, err := upsertDiscovered(ctx, scope, st, cid, "evil.net", "subfinder")
	if err != nil || foreign.State != store.StateOutOfScope {
		t.Fatalf("foreign = %+v err=%v", foreign, err)
	}
}

func TestSubfinderSkipsGracefullyWhenAbsent(t *testing.T) {
	// Point execLookPath at nothing.
	orig := execLookPath
	execLookPath = func(string) (string, error) {
		return "", errors.New("not found")
	}
	defer func() { execLookPath = orig }()

	scope, eng, st, cid := setup(t, nil)
	err := Subfinder(context.Background(), scope, eng, st, cid)
	if err == nil || !isNotInstalled(err) {
		t.Fatalf("err = %v, want not-installed", err)
	}
}

func TestIsNotInstalled(t *testing.T) {
	if !isNotInstalled(errors.New("subfinder not found on PATH — install with: go install...")) {
		t.Fatal("should detect")
	}
	if isNotInstalled(errors.New("subfinder: exit status 1")) {
		t.Fatal("should not detect runtime errors as missing")
	}
	if isNotInstalled(nil) {
		t.Fatal("nil is not an error")
	}
}
