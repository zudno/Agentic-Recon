package store

import (
	"database/sql"
	"fmt"
)

// migrate applies pending schema migrations, each in a transaction, and
// records every applied version. Migrations are append-only: never edit an
// already-shipped one — add the next instead.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER NOT NULL PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	var cur int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&cur); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for v := cur; v < len(migrations); v++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
			v+1, nowRFC()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// migrations holds the schema history; index i is version i+1.
var migrations = []string{migrationV1}

const migrationV1 = `
CREATE TABLE campaigns (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	authorization_reference TEXT NOT NULL,
	scope_hash TEXT NOT NULL,
	state TEXT NOT NULL DEFAULT 'RUNNING',
	created_at TEXT NOT NULL
);

CREATE TABLE assets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
	kind TEXT NOT NULL,
	value TEXT NOT NULL,
	state TEXT NOT NULL,
	source TEXT NOT NULL,
	attrs TEXT NOT NULL DEFAULT '{}',
	first_seen TEXT NOT NULL,
	last_touched TEXT NOT NULL,
	UNIQUE(campaign_id, kind, value)
);
CREATE INDEX idx_assets_campaign_state ON assets(campaign_id, state);

CREATE TABLE asset_links (
	from_id INTEGER NOT NULL REFERENCES assets(id),
	to_id INTEGER NOT NULL REFERENCES assets(id),
	link_type TEXT NOT NULL,
	UNIQUE(from_id, to_id, link_type)
);

CREATE TABLE observations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
	asset_id INTEGER NOT NULL REFERENCES assets(id),
	source TEXT NOT NULL,
	observed_at TEXT NOT NULL,
	attrs TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE hypotheses (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
	asset_id INTEGER NOT NULL REFERENCES assets(id),
	created_by TEXT NOT NULL,
	reasoning TEXT NOT NULL,
	score REAL NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);

CREATE TABLE findings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
	asset_id INTEGER NOT NULL REFERENCES assets(id),
	hypothesis_id INTEGER NOT NULL REFERENCES hypotheses(id),
	severity TEXT NOT NULL,
	evidence_refs TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL
);

CREATE TABLE request_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
	actor TEXT NOT NULL,
	tool TEXT NOT NULL,
	target TEXT NOT NULL,
	risk TEXT NOT NULL,
	scope TEXT NOT NULL,
	allowed INTEGER NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	result TEXT NOT NULL,
	approved_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_request_log_campaign ON request_log(campaign_id, id);
`
