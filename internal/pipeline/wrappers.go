// Package pipeline — wrappers.go: the wrapper framework for proven external
// tools (README §8). The policy engine cannot intercept a binary's own
// sockets, so enforcement is triple: (1) PreFlightTargets validates the
// full target-list before invocation, (2) the binary's own rate-limit flags
// are set, (3) the persistence layer scope-checks every discovered asset.
package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// execLookPath is a variable so tests can stub binary detection.
var execLookPath = exec.LookPath

// Wrapper describes one wrapped external tool.
type Wrapper struct {
	Name        string // e.g. "subfinder"
	Binary      string // e.g. "subfinder"
	Description string
	Install     string // hint for the operator
}

// Registry of known wrappers. Add new tools here.
var registry = []Wrapper{
	{
		Name:        "subfinder",
		Binary:      "subfinder",
		Description: "Passive subdomain enumeration from 20+ sources (CT, VirusTotal, Shodan, etc.)",
		Install:     "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
	},
	{
		Name:        "dnsx",
		Binary:      "dnsx",
		Description: "DNS resolution and enumeration (all record types, CNAME chains, brute-force)",
		Install:     "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
	},
}

// Available reports which wrapper binaries are on PATH.
func Available() map[string]bool {
	out := make(map[string]bool, len(registry))
	for _, w := range registry {
		_, err := exec.LookPath(w.Binary)
		out[w.Name] = err == nil
	}
	return out
}

// Registry returns the known wrappers.
func Registry() []Wrapper { return registry }

// invoke runs a wrapper binary with pre-validated targets, capturing its
// JSON output. The engine's PreFlightTargets has already cleared the list.
func invoke(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", binary, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// parseJSONLines reads a stream of one-JSON-object-per-line output (the
// projectdiscovery tools' standard format).
func parseJSONLines(data []byte) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue // tolerate noise
		}
		out = append(out, obj)
	}
	return out
}

// upsertDiscovered stores a discovered subdomain, classifying in-scope vs
// out-of-scope through the scope's verdict — the persistence layer of the
// triple enforcement.
func upsertDiscovered(ctx context.Context, scope *policy.Scope, st *store.Store,
	campaignID int64, name, source string) (store.Asset, error) {
	out := scope.HostVerdict(name) != policy.ScopeIn
	return st.UpsertAsset(ctx, campaignID, store.KindSubdomain, name, source, out, nil)
}
