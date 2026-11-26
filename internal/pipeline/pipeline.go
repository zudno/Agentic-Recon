package pipeline

import (
	"context"
	"fmt"
	"strings"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// RunPassive executes the deterministic passive pipeline (README §8):
// Certificate-Transparency subdomain discovery, then HTTP probing of what
// it found, then wrapper enrichment when the external tools are installed.
// Every network action flows through the policy engine into the campaign's
// request_log; every discovery flows through the store, so the campaign is
// pausable and resumable by construction.
func RunPassive(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) error {
	if err := CTSubdomains(ctx, scope, eng, st, campaignID); err != nil {
		return err
	}

	// Wrapper enrichment — each no-ops gracefully if the binary is absent.
	if err := Subfinder(ctx, scope, eng, st, campaignID); err != nil {
		if isNotInstalled(err) {
			// Not installed: not an error — the native module already covered CT.
			_ = err
		} else {
			return fmt.Errorf("subfinder wrapper: %w", err)
		}
	}
	if err := DNSx(ctx, scope, eng, st, campaignID); err != nil {
		if isNotInstalled(err) {
			_ = err
		} else {
			return fmt.Errorf("dnsx wrapper: %w", err)
		}
	}

	return HTTPProbe(ctx, eng, st, campaignID)
}

// isNotInstalled reports whether a wrapper error is just "binary missing".
func isNotInstalled(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found on PATH")
}
