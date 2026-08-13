// Package store persists Head-Control's UI-local state in SQLite: admin
// sessions, the audit log of UI actions, ACL policy version history, DNS
// extra-records history, pre-auth key labels, registration handoffs, and a
// small kv table. None of this is tailnet state — losing the database never
// loses headscale data.
package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  action      TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT '',
  target_id   TEXT NOT NULL DEFAULT '',
  target_name TEXT NOT NULL DEFAULT '',
  summary     TEXT NOT NULL DEFAULT '',
  outcome     TEXT NOT NULL DEFAULT 'ok',
  error       TEXT NOT NULL DEFAULT '',
  cli         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log(ts);
CREATE TABLE IF NOT EXISTS policy_versions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  saved_at     INTEGER NOT NULL,
  source       TEXT NOT NULL,             -- 'ui' | 'external-snapshot'
  mode         TEXT NOT NULL DEFAULT '',  -- 'database' | 'file'
  content      TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  comment      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS policy_versions_hash ON policy_versions(content_hash);
CREATE TABLE IF NOT EXISTS extra_records_versions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  saved_at     INTEGER NOT NULL,
  content      TEXT NOT NULL,
  content_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_labels (
  key_id TEXT PRIMARY KEY,
  label  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS registration_handoffs (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  auth_id   TEXT NOT NULL,
  kind      TEXT NOT NULL,   -- 'register' | 'approve' | 'reject'
  user_name TEXT NOT NULL DEFAULT '',
  status    TEXT NOT NULL,   -- 'ok' | 'failed'
  detail    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS kv (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`

// Open opens (creating if needed) the database in dataDir.
func Open(dataDir string) (*Store, error) {
	path := filepath.Join(dataDir, "headcontrol.db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db: %w", err)
	}
	// modernc/sqlite is single-writer; avoid SQLITE_BUSY churn.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}
	return &Store{db: db}, nil
}

// OpenMemory opens an in-memory store for tests.
func OpenMemory() (*Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

// ---- kv ----

// GetKV returns the value for k, or "" if unset.
func (s *Store) GetKV(k string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM kv WHERE k = ?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetKV stores k=v.
func (s *Store) SetKV(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}
