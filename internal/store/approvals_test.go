package store

import (
	"context"
	"strings"
	"testing"
)

func TestApprovalLifecycle(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	cid := mustCampaign(t, s)

	// Malformed requests are rejected before touching the queue.
	if _, err := s.RequestApproval(ctx, cid, "", "host", "r", "who"); err == nil {
		t.Fatal("empty tool must be rejected")
	}

	a, err := s.RequestApproval(ctx, cid, "dir-probe", "api.example.com",
		"content discovery on the API host", "agent:test")
	if err != nil || a.Token == "" || a.State != ApprovalPending {
		t.Fatalf("approval = %+v err=%v", a, err)
	}
	if !strings.HasPrefix(a.Token, "appr-") {
		t.Fatalf("token %q must be opaque-prefixed", a.Token)
	}

	// The pending queue shows it.
	pending, err := s.ListApprovals(ctx, cid, true)
	if err != nil || len(pending) != 1 || pending[0].Token != a.Token {
		t.Fatalf("pending = %+v err=%v", pending, err)
	}

	// Decisions are single-shot: a resolved approval cannot be re-decided.
	if _, err := s.ResolveApproval(ctx, a.Token, true, "operator:x"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := s.ResolveApproval(ctx, a.Token, false, "operator:y"); err == nil ||
		!strings.Contains(err.Error(), "already APPROVED") {
		t.Fatalf("re-decide err = %v", err)
	}

	// Validation binds (token, tool, host) and state.
	if err := s.ValidateApproval(ctx, a.Token, "dir-probe", "api.example.com"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := s.ValidateApproval(ctx, a.Token, "other-tool", "api.example.com"); err == nil {
		t.Fatal("tool mismatch must be rejected")
	}
	if err := s.ValidateApproval(ctx, a.Token, "dir-probe", "www.example.com"); err == nil {
		t.Fatal("host mismatch must be rejected")
	}

	// Rejection path leaves the token unusable.
	b, _ := s.RequestApproval(ctx, cid, "dir-probe", "www.example.com", "second", "agent:test")
	if _, err := s.ResolveApproval(ctx, b.Token, false, "operator:x"); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateApproval(ctx, b.Token, "dir-probe", "www.example.com"); err == nil ||
		!strings.Contains(err.Error(), "REJECTED") {
		t.Fatalf("rejected token validated: %v", err)
	}

	// Consumption is atomic and terminal.
	if err := s.ConsumeApproval(ctx, a.Token, "dir-probe", "api.example.com"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	got, _ := s.GetApprovalByToken(ctx, a.Token)
	if got.State != ApprovalConsumed || got.ConsumedAt == nil {
		t.Fatalf("approval = %+v", got)
	}
	if err := s.ConsumeApproval(ctx, a.Token, "dir-probe", "api.example.com"); err == nil {
		t.Fatal("double consumption must fail")
	}
	if err := s.ValidateApproval(ctx, a.Token, "dir-probe", "api.example.com"); err == nil ||
		!strings.Contains(err.Error(), "CONSUMED") {
		t.Fatalf("consumed token still validates: %v", err)
	}

	// Unknown tokens are an error, not a silent pass.
	if _, err := s.GetApprovalByToken(ctx, "appr-nope"); err == nil {
		t.Fatal("unknown token must error")
	}
}
