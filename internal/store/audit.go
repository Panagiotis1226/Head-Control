package store

import (
	"strings"
	"time"
)

// AuditEntry records one mutating action performed through the UI. Secrets
// (API keys, pre-auth keys, passwords) must never be placed in any field.
type AuditEntry struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"time"`
	Action     string    `json:"action"`
	TargetType string    `json:"targetType,omitempty"`
	TargetID   string    `json:"targetId,omitempty"`
	TargetName string    `json:"targetName,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error,omitempty"`
	CLI        string    `json:"cli,omitempty"`
}

// AppendAudit stores an audit entry.
func (s *Store) AppendAudit(e AuditEntry) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Outcome == "" {
		e.Outcome = "ok"
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_log (ts, action, target_type, target_id, target_name, summary, outcome, error, cli)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Time.Unix(), e.Action, e.TargetType, e.TargetID, e.TargetName, e.Summary, e.Outcome, e.Error, e.CLI,
	)
	return err
}

// AuditFilter narrows ListAudit.
type AuditFilter struct {
	Action  string // prefix match, e.g. "node."
	Outcome string // "ok" | "error"
	Since   time.Time
	Limit   int
}

// ListAudit returns entries newest-first.
func (s *Store) ListAudit(f AuditFilter) ([]AuditEntry, error) {
	q := `SELECT id, ts, action, target_type, target_id, target_name, summary, outcome, error, cli FROM audit_log WHERE 1=1`
	var args []any
	if f.Action != "" {
		q += ` AND action LIKE ?`
		args = append(args, strings.TrimSuffix(f.Action, "%")+"%")
	}
	if f.Outcome != "" {
		q += ` AND outcome = ?`
		args = append(args, f.Outcome)
	}
	if !f.Since.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, f.Since.Unix())
	}
	q += ` ORDER BY id DESC`
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q += ` LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.TargetType, &e.TargetID, &e.TargetName, &e.Summary, &e.Outcome, &e.Error, &e.CLI); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit removes entries older than the retention window.
func (s *Store) PruneAudit(retention time.Duration) error {
	_, err := s.db.Exec(`DELETE FROM audit_log WHERE ts < ?`, time.Now().Add(-retention).Unix())
	return err
}

// PurgeAudit removes all entries.
func (s *Store) PurgeAudit() error {
	_, err := s.db.Exec(`DELETE FROM audit_log`)
	return err
}
