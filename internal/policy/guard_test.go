package policy

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNativeEgressOnlyInPolicy enforces the R1 criterion: no non-test Go
// file outside internal/policy may import "net" or "net/http" — the engine
// is the only native egress in the codebase (README §6.1). The check fails
// closed: a suspicious-looking string also trips it.
func TestNativeEgressOnlyInPolicy(t *testing.T) {
	root := findRepoRoot(t)
	var violations []string

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "policy" {
					return filepath.SkipDir // the engine lives here — allowed
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == `"net"` || trimmed == `"net/http"` {
					rel, _ := filepath.Rel(root, path)
					violations = append(violations, rel+" imports "+trimmed)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("native network code outside internal/policy — the engine is the only egress:\n%s",
			strings.Join(violations, "\n"))
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up")
		}
		dir = parent
	}
}
