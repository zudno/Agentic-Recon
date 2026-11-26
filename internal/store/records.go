package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AssetLink is one typed graph edge between assets (README §7):
// resolves_to, served_by, belongs_to, uses_tech…
type AssetLink struct {
	FromID   int64
	ToID     int64
	LinkType string
}

// Observation is a raw, normalized finding from the deterministic pipeline,
// kept before and independent of triage decisions.
type Observation struct {
	ID         int64
	CampaignID int64
	AssetID    int64
	Source     string
	Attrs      map[string]any
	ObservedAt time.Time
}

// Hypothesis is a reasoned, scored conjecture about an asset (human or agent).
type Hypothesis struct {
	ID         int64
	CampaignID int64
	AssetID    int64
	CreatedBy  string
	Reasoning  string
	Score      float64
	CreatedAt  time.Time
}

// Finding is a promoted hypothesis with evidence (request_log references).
type Finding struct {
	ID           int64
	CampaignID   int64
	AssetID      int64
	HypothesisID int64
	Severity     string
	EvidenceRefs []int64
	CreatedAt    time.Time
}

// LinkAssets creates a typed edge (idempotent). Foreign keys guarantee both
// endpoints exist and belong to the same database.
func (s *Store) LinkAssets(ctx context.Context, fromID, toID int64, linkType string) error {
	if fromID == toID {
		return errors.New("store: an asset cannot link to itself")
	}
	if linkType == "" {
		return errors.New("store: link type is required")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO asset_links (from_id, to_id, link_type) VALUES (?, ?, ?)`,
		fromID, toID, linkType); err != nil {
		return fmt.Errorf("link assets: %w", err)
	}
	return nil
}

// LinksOf returns the asset's outgoing edges.
func (s *Store) LinksOf(ctx context.Context, assetID int64) ([]AssetLink, error) {
	return s.linksWhere(ctx, `from_id = ?`, assetID)
}

// LinksTo returns the asset's incoming edges — e.g. every subdomain that
// resolves_to a given IP.
func (s *Store) LinksTo(ctx context.Context, assetID int64) ([]AssetLink, error) {
	return s.linksWhere(ctx, `to_id = ?`, assetID)
}

func (s *Store) linksWhere(ctx context.Context, where string, arg int64) ([]AssetLink, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT from_id, to_id, link_type FROM asset_links WHERE `+where, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssetLink
	for rows.Next() {
		var l AssetLink
		if err := rows.Scan(&l.FromID, &l.ToID, &l.LinkType); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// AddObservation records a pipeline observation against an asset.
func (s *Store) AddObservation(ctx context.Context, campaignID, assetID int64, source string, attrs map[string]any) (Observation, error) {
	if source == "" {
		return Observation{}, errors.New("store: observation source is required")
	}
	attrsJSON, err := marshalAttrs(attrs)
	if err != nil {
		return Observation{}, err
	}
	now := nowRFC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO observations (campaign_id, asset_id, source, observed_at, attrs)
		 VALUES (?, ?, ?, ?, ?)`,
		campaignID, assetID, source, now, attrsJSON)
	if err != nil {
		return Observation{}, fmt.Errorf("insert observation: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Observation{}, err
	}
	observed, _ := parseTimeRFC(now)
	return Observation{
		ID: id, CampaignID: campaignID, AssetID: assetID,
		Source: source, Attrs: unmarshalAttrs(attrsJSON), ObservedAt: observed,
	}, nil
}

// ObservationsOf lists an asset's raw observations, oldest first.
func (s *Store) ObservationsOf(ctx context.Context, assetID int64) ([]Observation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, campaign_id, asset_id, source, observed_at, attrs
		 FROM observations WHERE asset_id = ? ORDER BY id`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Observation
	for rows.Next() {
		var o Observation
		var attrsJSON, at string
		if err := rows.Scan(&o.ID, &o.CampaignID, &o.AssetID, &o.Source, &at, &attrsJSON); err != nil {
			return nil, err
		}
		o.Attrs = unmarshalAttrs(attrsJSON)
		o.ObservedAt, _ = parseTimeRFC(at)
		out = append(out, o)
	}
	return out, rows.Err()
}

// AddHypothesis saves a scored conjecture about an asset.
func (s *Store) AddHypothesis(ctx context.Context, campaignID, assetID int64, createdBy, reasoning string, score float64) (Hypothesis, error) {
	if createdBy == "" {
		return Hypothesis{}, errors.New("store: hypothesis author (created_by) is required")
	}
	if reasoning == "" {
		return Hypothesis{}, errors.New("store: hypothesis reasoning is required")
	}
	now := nowRFC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO hypotheses (campaign_id, asset_id, created_by, reasoning, score, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		campaignID, assetID, createdBy, reasoning, score, now)
	if err != nil {
		return Hypothesis{}, fmt.Errorf("insert hypothesis: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Hypothesis{}, err
	}
	created, _ := parseTimeRFC(now)
	return Hypothesis{
		ID: id, CampaignID: campaignID, AssetID: assetID,
		CreatedBy: createdBy, Reasoning: reasoning, Score: score, CreatedAt: created,
	}, nil
}

// AddFinding promotes a hypothesis with severity and evidence (ids into
// request_log — the evidence backbone of the engagement report).
func (s *Store) AddFinding(ctx context.Context, campaignID, assetID, hypothesisID int64, severity string, evidenceRefs []int64) (Finding, error) {
	if severity == "" {
		return Finding{}, errors.New("store: finding severity is required")
	}
	// The hypothesis must reference the same asset — findings never drift.
	var hAsset int64
	err := s.db.QueryRowContext(ctx,
		`SELECT asset_id FROM hypotheses WHERE id = ?`, hypothesisID).Scan(&hAsset)
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, fmt.Errorf("store: hypothesis %d not found", hypothesisID)
	}
	if err != nil {
		return Finding{}, err
	}
	if hAsset != assetID {
		return Finding{}, errors.New("store: finding asset does not match its hypothesis asset")
	}
	if len(evidenceRefs) == 0 {
		return Finding{}, errors.New("store: a finding requires at least one evidence reference")
	}
	refs, err := json.Marshal(evidenceRefs)
	if err != nil {
		return Finding{}, err
	}
	now := nowRFC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO findings (campaign_id, asset_id, hypothesis_id, severity, evidence_refs, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		campaignID, assetID, hypothesisID, severity, string(refs), now)
	if err != nil {
		return Finding{}, fmt.Errorf("insert finding: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Finding{}, err
	}
	created, _ := parseTimeRFC(now)
	return Finding{
		ID: id, CampaignID: campaignID, AssetID: assetID, HypothesisID: hypothesisID,
		Severity: severity, EvidenceRefs: append([]int64(nil), evidenceRefs...), CreatedAt: created,
	}, nil
}

// GetHypothesis fetches one hypothesis by id (the report joins findings
// back to their origin).
func (s *Store) GetHypothesis(ctx context.Context, id int64) (Hypothesis, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, campaign_id, asset_id, created_by, reasoning, score, created_at
		 FROM hypotheses WHERE id = ?`, id)
	var h Hypothesis
	var createdAt string
	if err := row.Scan(&h.ID, &h.CampaignID, &h.AssetID, &h.CreatedBy,
		&h.Reasoning, &h.Score, &createdAt); err != nil {
		return Hypothesis{}, fmt.Errorf("get hypothesis: %w", err)
	}
	h.CreatedAt, _ = parseTimeRFC(createdAt)
	return h, nil
}

// GetRequestLogByID fetches one request_log row — the evidence backbone of
// findings and the report.
func (s *Store) GetRequestLogByID(ctx context.Context, id int64) (LogRow, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, campaign_id, ts, actor, tool, target, risk, scope, allowed, reason, result, approved_by
		 FROM request_log WHERE id = ?`, id)
	var r LogRow
	var ts string
	var allowed int
	if err := row.Scan(&r.ID, &r.CampaignID, &ts, &r.Actor, &r.Tool, &r.Target,
		&r.Risk, &r.Scope, &allowed, &r.Reason, &r.Result, &r.ApprovedBy); err != nil {
		return LogRow{}, fmt.Errorf("get request_log %d: %w", id, err)
	}
	r.TS, _ = parseTimeRFC(ts)
	r.Allowed = allowed == 1
	return r, nil
}

// ListFindings returns a campaign's findings, oldest first.
func (s *Store) ListFindings(ctx context.Context, campaignID int64) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, campaign_id, asset_id, hypothesis_id, severity, evidence_refs, created_at
		 FROM findings WHERE campaign_id = ? ORDER BY id`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var refsJSON, at string
		if err := rows.Scan(&f.ID, &f.CampaignID, &f.AssetID, &f.HypothesisID,
			&f.Severity, &refsJSON, &at); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(refsJSON), &f.EvidenceRefs)
		f.CreatedAt, _ = parseTimeRFC(at)
		out = append(out, f)
	}
	return out, rows.Err()
}
