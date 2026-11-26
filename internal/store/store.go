// Package store is the campaign state layer (README §7): SQLite behind a
// versioned schema, the asset state machine, and the store-backed
// request_log sink. It is the shared memory that decouples the deterministic
// pipeline from the agents — a campaign can pause and resume without losing
// progress.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver; registers database/sql name "sqlite"
)

// AssetKind enumerates the unified asset node types (README §7).
type AssetKind string

const (
	KindDomain     AssetKind = "domain"
	KindSubdomain  AssetKind = "subdomain"
	KindIP         AssetKind = "ip"
	KindWebService AssetKind = "web_service"
	KindEndpoint   AssetKind = "endpoint"
	KindTech       AssetKind = "tech"
)

// AssetState is the asset lifecycle (README §7). OUT_OF_SCOPE is terminal:
// such assets persist only for the exclusions report and no tool may
// return them as actionable.
type AssetState string

const (
	StateDiscovered    AssetState = "DISCOVERED"
	StateTriaged       AssetState = "TRIAGED"
	StateInvestigating AssetState = "INVESTIGATING"
	StateValidated     AssetState = "VALIDATED"
	StateDiscarded     AssetState = "DISCARDED"
	StateOutOfScope    AssetState = "OUT_OF_SCOPE"
)

// assetTransitions defines the legal state machine. Terminal states map to
// empty (or absent) destination sets.
var assetTransitions = map[AssetState]map[AssetState]bool{
	StateDiscovered: {StateTriaged: true, StateDiscarded: true, StateOutOfScope: true},
	StateTriaged:    {StateInvestigating: true, StateValidated: true, StateDiscarded: true, StateOutOfScope: true},
	// INVESTIGATING → TRIAGED releases a reservation (e.g. an agent died
	// mid-investigation) so another can pick the asset up.
	StateInvestigating: {StateValidated: true, StateDiscarded: true, StateTriaged: true},
}

// CanTransition reports whether the state machine allows from → to.
func (from AssetState) CanTransition(to AssetState) bool {
	return assetTransitions[from][to]
}

// CampaignState tracks campaign lifecycle for pause/resume.
type CampaignState string

const (
	CampaignRunning CampaignState = "RUNNING"
	CampaignPaused  CampaignState = "PAUSED"
	CampaignDone    CampaignState = "DONE"
)

// Campaign is one engagement against one signed scope.
type Campaign struct {
	ID                     int64
	Name                   string
	AuthorizationReference string
	ScopeHash              string
	State                  CampaignState
	CreatedAt              time.Time
}

// Asset is a node in the campaign's mini-graph.
type Asset struct {
	ID          int64
	CampaignID  int64
	Kind        AssetKind
	Value       string
	State       AssetState
	Source      string
	Attrs       map[string]any
	FirstSeen   time.Time
	LastTouched time.Time
}

// Store wraps the campaign database.
type Store struct {
	db *sql.DB
}

// Open opens (creating parents) and migrates the SQLite database.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// nowRFC is the storage timestamp format (injectable for tests).
var nowRFC = func() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// ─── campaigns ─────────────────────────────────────────────────────────────

// CreateCampaign registers a new engagement against a signed scope. The
// scope hash pins the exact contract the campaign runs under.
func (s *Store) CreateCampaign(ctx context.Context, name, authorizationReference, scopeHash string) (Campaign, error) {
	if strings.TrimSpace(name) == "" {
		return Campaign{}, errors.New("store: campaign name is required")
	}
	if strings.TrimSpace(authorizationReference) == "" {
		return Campaign{}, errors.New("store: authorization reference is required")
	}
	if strings.TrimSpace(scopeHash) == "" {
		return Campaign{}, errors.New("store: scope hash is required")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO campaigns (name, authorization_reference, scope_hash, state, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		name, authorizationReference, scopeHash, CampaignRunning, nowRFC())
	if err != nil {
		return Campaign{}, fmt.Errorf("insert campaign: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Campaign{}, err
	}
	created, err := s.parseTime(nowRFC())
	if err != nil {
		return Campaign{}, err
	}
	return Campaign{
		ID:                     id,
		Name:                   name,
		AuthorizationReference: authorizationReference,
		ScopeHash:              scopeHash,
		State:                  CampaignRunning,
		CreatedAt:              created,
	}, nil
}

// GetCampaign fetches a campaign by id.
func (s *Store) GetCampaign(ctx context.Context, id int64) (Campaign, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, authorization_reference, scope_hash, state, created_at
		 FROM campaigns WHERE id = ?`, id)
	var c Campaign
	var created string
	if err := row.Scan(&c.ID, &c.Name, &c.AuthorizationReference, &c.ScopeHash, &c.State, &created); err != nil {
		return Campaign{}, fmt.Errorf("get campaign: %w", err)
	}
	c.CreatedAt, _ = s.parseTime(created)
	return c, nil
}

// ListCampaigns returns every campaign, oldest first.
func (s *Store) ListCampaigns(ctx context.Context) ([]Campaign, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, authorization_reference, scope_hash, state, created_at
		 FROM campaigns ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Campaign
	for rows.Next() {
		var c Campaign
		var created string
		if err := rows.Scan(&c.ID, &c.Name, &c.AuthorizationReference, &c.ScopeHash, &c.State, &created); err != nil {
			return nil, err
		}
		c.CreatedAt, _ = s.parseTime(created)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetCampaignState moves a campaign between RUNNING/PAUSED/DONE — the
// pause/resume backbone (README §7).
func (s *Store) SetCampaignState(ctx context.Context, id int64, state CampaignState) error {
	switch state {
	case CampaignRunning, CampaignPaused, CampaignDone:
	default:
		return fmt.Errorf("store: unknown campaign state %q", state)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE campaigns SET state = ? WHERE id = ?`, state, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: campaign %d not found", id)
	}
	return nil
}

// ─── assets ─────────────────────────────────────────────────────────────────

// UpsertAsset inserts or refreshes an asset, normalizing its value. Repeated
// discoveries merge attributes and touch the timestamp. The out-of-scope flag
// marks (and keeps) the asset OUT_OF_SCOPE: sticky, terminal, and invisible
// to every default listing (README §7).
func (s *Store) UpsertAsset(ctx context.Context, campaignID int64, kind AssetKind, value, source string, outOfScope bool, attrs map[string]any) (Asset, error) {
	if kind == "" {
		return Asset{}, errors.New("store: asset kind is required")
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return Asset{}, errors.New("store: asset value is required")
	}
	if source == "" {
		source = "unknown"
	}
	now := nowRFC()

	existing, err := s.GetAssetByValue(ctx, campaignID, kind, value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		state := StateDiscovered
		if outOfScope {
			state = StateOutOfScope
		}
		attrsJSON, err := marshalAttrs(attrs)
		if err != nil {
			return Asset{}, err
		}
		res, err := s.db.ExecContext(ctx,
			`INSERT INTO assets (campaign_id, kind, value, state, source, attrs, first_seen, last_touched)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			campaignID, kind, value, state, source, attrsJSON, now, now)
		if err != nil {
			return Asset{}, fmt.Errorf("insert asset: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return Asset{}, err
		}
		created, _ := s.parseTime(now)
		// Return the round-tripped representation so inserted and updated
		// assets expose identical Attrs types (JSON: numbers → float64).
		return Asset{
			ID: id, CampaignID: campaignID, Kind: kind, Value: value,
			State: state, Source: source, Attrs: unmarshalAttrs(attrsJSON),
			FirstSeen: created, LastTouched: created,
		}, nil
	case err != nil:
		return Asset{}, err
	}

	// Existing asset: merge attrs, refresh the timestamp, and never unstick
	// an OUT_OF_SCOPE mark.
	merged := existing.Attrs
	if merged == nil {
		merged = map[string]any{}
	}
	for k, v := range attrs {
		if v != nil {
			merged[k] = v
		}
	}
	state := existing.State
	if outOfScope && (state == StateDiscovered || state == StateTriaged) {
		state = StateOutOfScope
	}
	attrsJSON, err := marshalAttrs(merged)
	if err != nil {
		return Asset{}, err
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE assets SET state = ?, attrs = ?, last_touched = ? WHERE id = ?`,
		state, attrsJSON, now, existing.ID); err != nil {
		return Asset{}, fmt.Errorf("update asset: %w", err)
	}
	touched, _ := s.parseTime(now)
	existing.State = state
	existing.Attrs = merged
	existing.LastTouched = touched
	return existing, nil
}

// GetAsset fetches an asset by id.
func (s *Store) GetAsset(ctx context.Context, id int64) (Asset, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, campaign_id, kind, value, state, source, attrs, first_seen, last_touched
		 FROM assets WHERE id = ?`, id)
	return scanAsset(row)
}

// GetAssetByValue looks an asset up by its campaign-scoped identity.
func (s *Store) GetAssetByValue(ctx context.Context, campaignID int64, kind AssetKind, value string) (Asset, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, campaign_id, kind, value, state, source, attrs, first_seen, last_touched
		 FROM assets WHERE campaign_id = ? AND kind = ? AND value = ?`,
		campaignID, kind, strings.ToLower(strings.TrimSpace(value)))
	return scanAsset(row)
}

// ListFilter narrows ListAssets. Out-of-scope assets are invisible unless
// the caller explicitly asks for them (the exclusions report does; tools
// never do — README §7).
type ListFilter struct {
	CampaignID        int64
	Kind              AssetKind
	States            []AssetState
	IncludeOutOfScope bool
	Limit             int
}

// ListAssets returns assets ordered by discovery. Requesting OUT_OF_SCOPE
// without IncludeOutOfScope yields nothing — the invariant is enforced here
// so no caller can bypass it.
func (s *Store) ListAssets(ctx context.Context, f ListFilter) ([]Asset, error) {
	var q strings.Builder
	var args []any
	q.WriteString(`SELECT id, campaign_id, kind, value, state, source, attrs, first_seen, last_touched
		FROM assets WHERE campaign_id = ?`)
	args = append(args, f.CampaignID)
	if f.Kind != "" {
		q.WriteString(` AND kind = ?`)
		args = append(args, f.Kind)
	}
	if len(f.States) > 0 {
		states := make([]AssetState, 0, len(f.States))
		for _, st := range f.States {
			if st == StateOutOfScope && !f.IncludeOutOfScope {
				continue // silently enforced invariant
			}
			states = append(states, st)
		}
		if len(states) == 0 {
			// Every requested state was out-of-scope and the caller may not
			// see those — the honest result is nothing, not a fallback to all.
			return []Asset{}, nil
		}
		q.WriteString(` AND state IN (`)
		for i, st := range states {
			if i > 0 {
				q.WriteString(`,`)
			}
			q.WriteString(`?`)
			args = append(args, st)
		}
		q.WriteString(`)`)
	}
	if !f.IncludeOutOfScope {
		q.WriteString(` AND state != 'OUT_OF_SCOPE'`)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	q.WriteString(` ORDER BY id LIMIT ?`)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAssetState moves an asset through the state machine, rejecting
// illegal transitions.
func (s *Store) UpdateAssetState(ctx context.Context, id int64, to AssetState) (Asset, error) {
	cur, err := s.GetAsset(ctx, id)
	if err != nil {
		return cur, err
	}
	if !cur.State.CanTransition(to) {
		return cur, fmt.Errorf("store: illegal transition %s → %s for asset %d", cur.State, to, id)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE assets SET state = ?, last_touched = ? WHERE id = ?`,
		to, nowRFC(), id); err != nil {
		return cur, fmt.Errorf("update asset state: %w", err)
	}
	cur.State = to
	return cur, nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func scanAsset(row interface{ Scan(...any) error }) (Asset, error) {
	var a Asset
	var attrsJSON, first, last string
	if err := row.Scan(&a.ID, &a.CampaignID, &a.Kind, &a.Value, &a.State, &a.Source,
		&attrsJSON, &first, &last); err != nil {
		return Asset{}, err
	}
	a.Attrs = unmarshalAttrs(attrsJSON)
	a.FirstSeen, _ = parseTimeRFC(first)
	a.LastTouched, _ = parseTimeRFC(last)
	return a, nil
}

func (s *Store) parseTime(v string) (time.Time, error) {
	return parseTimeRFC(v)
}

func parseTimeRFC(v string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, v)
}

func marshalAttrs(attrs map[string]any) (string, error) {
	if len(attrs) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return "", fmt.Errorf("marshal attrs: %w", err)
	}
	return string(b), nil
}

func unmarshalAttrs(s string) map[string]any {
	out := map[string]any{}
	if strings.TrimSpace(s) != "" {
		_ = json.Unmarshal([]byte(s), &out)
	}
	return out
}
