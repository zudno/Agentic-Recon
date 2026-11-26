package pipeline

import (
	"context"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// RunPassive executes the deterministic passive pipeline (README §8):
// Certificate-Transparency subdomain discovery, then HTTP probing of what
// it found. Every network action flows through the policy engine into the
// campaign's request_log; every discovery flows through the store, so the
// campaign is pausable and resumable by construction.
func RunPassive(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) error {
	if err := CTSubdomains(ctx, scope, eng, st, campaignID); err != nil {
		return err
	}
	return HTTPProbe(ctx, eng, st, campaignID)
}
