package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ApprovalState is the approval gate lifecycle (README §6.2): PENDING →
// APPROVED/REJECTED, and an approved token is CONSUMED exactly once by the
// executing tool.
type ApprovalState string

const (
	ApprovalPending  ApprovalState = "PENDING"
	ApprovalApproved ApprovalState = "APPROVED"
	ApprovalRejected ApprovalState = "REJECTED"
	ApprovalConsumed ApprovalState = "CONSUMED"
)

// Approval is one operator decision gate over an INTRUSIVE action: the
// (tool, target host) pair, who requested it, who decided, and when.
type Approval struct {
	ID          int64
	Token       string
	CampaignID  int64
	Tool        string
	Target      string
	Reason      string
	RequestedBy string
	State       ApprovalState
	DecidedBy   string
	DecidedAt   *time.Time
	ConsumedAt  *time.Time
	CreatedAt   time.Time
}

// RequestApproval files a PENDING approval for an INTRUSIVE (tool, host)
// action. The operator resolves it via the CLI (`recon approve`).
func (s *Store) RequestApproval(ctx context.Context, campaignID int64, tool, target, reason, requestedBy string) (Approval, error) {
	if tool == "" || target == "" || reason == "" || requestedBy == "" {
		return Approval{}, errors.New("store: approval requires tool, target, reason, and requester")
	}
	tok, err := approvalToken()
	if err != nil {
		return Approval{}, err
	}
	now := nowRFC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO approvals (token, campaign_id, tool, target, reason, requested_by, state, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tok, campaignID, tool, target, reason, requestedBy, ApprovalPending, now)
	if err != nil {
		return Approval{}, fmt.Errorf("insert approval: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Approval{}, err
	}
	created, _ := parseTimeRFC(now)
	return Approval{
		ID: id, Token: tok, CampaignID: campaignID, Tool: tool, Target: target,
		Reason: reason, RequestedBy: requestedBy, State: ApprovalPending, CreatedAt: created,
	}, nil
}

// ResolveApproval applies the operator's decision to a PENDING approval.
// Already-decided approvals are refused — every y/n is a deliberate act.
func (s *Store) ResolveApproval(ctx context.Context, token string, approve bool, decidedBy string) (Approval, error) {
	if decidedBy == "" {
		return Approval{}, errors.New("store: the operator identity (decided_by) is required")
	}
	cur, err := s.GetApprovalByToken(ctx, token)
	if err != nil {
		return Approval{}, err
	}
	if cur.State != ApprovalPending {
		return cur, fmt.Errorf("store: approval %s is already %s — refusing to re-decide", token, cur.State)
	}
	state := ApprovalRejected
	if approve {
		state = ApprovalApproved
	}
	now := nowRFC()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE approvals SET state = ?, decided_by = ?, decided_at = ? WHERE token = ?`,
		state, decidedBy, now, token); err != nil {
		return cur, fmt.Errorf("resolve approval: %w", err)
	}
	updated := cur
	updated.State = state
	updated.DecidedBy = decidedBy
	at, _ := parseTimeRFC(now)
	updated.DecidedAt = &at
	return updated, nil
}

// ListApprovals returns the campaign's approvals; pendingOnly narrows to
// the operator's queue.
func (s *Store) ListApprovals(ctx context.Context, campaignID int64, pendingOnly bool) ([]Approval, error) {
	q := `SELECT id, token, campaign_id, tool, target, reason, requested_by, state,
	             COALESCE(decided_by, ''), decided_at, consumed_at, created_at
	      FROM approvals WHERE campaign_id = ?`
	if pendingOnly {
		q += ` AND state = 'PENDING'`
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetApprovalByToken fetches one approval by its opaque token.
func (s *Store) GetApprovalByToken(ctx context.Context, token string) (Approval, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token, campaign_id, tool, target, reason, requested_by, state,
		        COALESCE(decided_by, ''), decided_at, consumed_at, created_at
		 FROM approvals WHERE token = ?`, token)
	a, err := scanApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, fmt.Errorf("store: approval %q not found", token)
	}
	return a, err
}

// ValidateApproval implements policy.Approvals: the token must be APPROVED
// for exactly this tool+host. Non-consuming — every request of a logical
// action re-validates.
func (s *Store) ValidateApproval(ctx context.Context, token, tool, host string) error {
	a, err := s.GetApprovalByToken(ctx, token)
	if err != nil {
		return err
	}
	if a.Tool != tool || a.Target != host {
		return fmt.Errorf("token %s approves %s against %q — not %s against %q",
			token, a.Tool, a.Target, tool, host)
	}
	if a.State != ApprovalApproved {
		return fmt.Errorf("token %s is %s (not APPROVED)", token, a.State)
	}
	return nil
}

// ConsumeApproval implements policy.Approvals: atomically marks the token
// CONSUMED — one approval, one logical action.
func (s *Store) ConsumeApproval(ctx context.Context, token, tool, host string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE approvals SET state = ?, consumed_at = ?
		 WHERE token = ? AND tool = ? AND target = ? AND state = ?`,
		ApprovalConsumed, nowRFC(), token, tool, host, ApprovalApproved)
	if err != nil {
		return fmt.Errorf("consume approval: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if err := s.ValidateApproval(ctx, token, tool, host); err != nil {
			return err
		}
		return fmt.Errorf("token %s could not be consumed", token)
	}
	return nil
}

// LastRequestLogID returns the newest request_log id of the campaign —
// tools attach it to their results as the evidence reference.
func (s *Store) LastRequestLogID(ctx context.Context, campaignID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(id), 0) FROM request_log WHERE campaign_id = ?`, campaignID).Scan(&id)
	return id, err
}

func scanApproval(row interface{ Scan(...any) error }) (Approval, error) {
	var a Approval
	var decidedAt, consumedAt, createdAt sql.NullString
	var reason, requestedBy string
	if err := row.Scan(&a.ID, &a.Token, &a.CampaignID, &a.Tool, &a.Target, &reason,
		&requestedBy, &a.State, &a.DecidedBy, &decidedAt, &consumedAt, &createdAt); err != nil {
		return Approval{}, err
	}
	a.Reason = reason
	a.RequestedBy = requestedBy
	if createdAt.Valid {
		a.CreatedAt, _ = parseTimeRFC(createdAt.String)
	}
	if decidedAt.Valid {
		t, _ := parseTimeRFC(decidedAt.String)
		a.DecidedAt = &t
	}
	if consumedAt.Valid {
		t, _ := parseTimeRFC(consumedAt.String)
		a.ConsumedAt = &t
	}
	return a, nil
}

// approvalToken mints an opaque, non-enumerable id for the operator queue.
func approvalToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mint approval token: %w", err)
	}
	return "appr-" + hex.EncodeToString(b), nil
}
