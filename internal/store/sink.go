package store

import (
	"context"
	"fmt"
	"time"

	"agenticrecon/internal/policy"
)

// dbSink persists policy entries into the campaign's request_log table —
// the store-backed implementation of the evidence backbone (README §11).
type dbSink struct {
	store    *Store
	campaign int64
}

// Sink returns a policy.Sink bound to one campaign. The sink assigns the
// campaign's numeric id; Entry.Campaign (a free-form label used by file
// sinks) is preserved in nothing here — the binding is authoritative.
func (s *Store) Sink(campaignID int64) policy.Sink {
	return dbSink{store: s, campaign: campaignID}
}

// Log implements policy.Sink.
func (d dbSink) Log(ctx context.Context, e policy.Entry) error {
	allowed := 0
	if e.Allowed {
		allowed = 1
	}
	_, err := d.store.db.ExecContext(ctx,
		`INSERT INTO request_log
		 (ts, campaign_id, actor, tool, target, risk, scope, allowed, reason, result, approved_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.Format(time.RFC3339Nano), d.campaign, e.Actor, e.Tool, e.Target,
		e.Risk, e.Scope, allowed, e.Reason, e.Result, e.ApprovedBy)
	if err != nil {
		return fmt.Errorf("insert request_log: %w", err)
	}
	return nil
}

// LogRow is one persisted request_log line, with its evidence id.
type LogRow struct {
	ID         int64
	CampaignID int64
	TS         time.Time
	Actor      string
	Tool       string
	Target     string
	Risk       policy.RiskLevel
	Scope      policy.ScopeVerdict
	Allowed    bool
	Reason     string
	Result     string
	ApprovedBy string
}

// ListRequestLog returns the campaign's evidence trail, newest first.
func (s *Store) ListRequestLog(ctx context.Context, campaignID int64, limit int) ([]LogRow, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, campaign_id, ts, actor, tool, target, risk, scope, allowed, reason, result, approved_by
		 FROM request_log WHERE campaign_id = ? ORDER BY id DESC LIMIT ?`,
		campaignID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogRow
	for rows.Next() {
		var r LogRow
		var ts string
		var allowed int
		if err := rows.Scan(&r.ID, &r.CampaignID, &ts, &r.Actor, &r.Tool, &r.Target,
			&r.Risk, &r.Scope, &allowed, &r.Reason, &r.Result, &r.ApprovedBy); err != nil {
			return nil, err
		}
		r.TS, _ = parseTimeRFC(ts)
		r.Allowed = allowed == 1
		out = append(out, r)
	}
	return out, rows.Err()
}
