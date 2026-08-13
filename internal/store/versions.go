package store

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// PolicyVersion is one snapshot of the ACL policy document.
type PolicyVersion struct {
	ID      int64     `json:"id"`
	SavedAt time.Time `json:"savedAt"`
	Source  string    `json:"source"` // "ui" | "external-snapshot"
	Mode    string    `json:"mode,omitempty"`
	Content string    `json:"content,omitempty"` // omitted in listings
	Hash    string    `json:"hash"`
	Comment string    `json:"comment,omitempty"`
}

// HashContent returns the canonical content hash used for change detection.
func HashContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// SavePolicyVersion appends a snapshot and returns its ID.
func (s *Store) SavePolicyVersion(v PolicyVersion) (int64, error) {
	if v.SavedAt.IsZero() {
		v.SavedAt = time.Now()
	}
	if v.Hash == "" {
		v.Hash = HashContent(v.Content)
	}
	res, err := s.db.Exec(
		`INSERT INTO policy_versions (saved_at, source, mode, content, content_hash, comment) VALUES (?, ?, ?, ?, ?, ?)`,
		v.SavedAt.Unix(), v.Source, v.Mode, v.Content, v.Hash, v.Comment,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LatestPolicyHash returns the hash of the newest stored snapshot ("" when none).
func (s *Store) LatestPolicyHash() (string, error) {
	var h string
	err := s.db.QueryRow(`SELECT content_hash FROM policy_versions ORDER BY id DESC LIMIT 1`).Scan(&h)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return h, nil
}

// ListPolicyVersions returns snapshots newest-first, without content.
func (s *Store) ListPolicyVersions(limit int) ([]PolicyVersion, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, saved_at, source, mode, content_hash, comment FROM policy_versions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyVersion
	for rows.Next() {
		var v PolicyVersion
		var ts int64
		if err := rows.Scan(&v.ID, &ts, &v.Source, &v.Mode, &v.Hash, &v.Comment); err != nil {
			return nil, err
		}
		v.SavedAt = time.Unix(ts, 0).UTC()
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetPolicyVersion returns one snapshot including content, or nil.
func (s *Store) GetPolicyVersion(id int64) (*PolicyVersion, error) {
	var v PolicyVersion
	var ts int64
	err := s.db.QueryRow(
		`SELECT id, saved_at, source, mode, content, content_hash, comment FROM policy_versions WHERE id = ?`, id).
		Scan(&v.ID, &ts, &v.Source, &v.Mode, &v.Content, &v.Hash, &v.Comment)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	v.SavedAt = time.Unix(ts, 0).UTC()
	return &v, nil
}

// PurgePolicyVersions removes all snapshots.
func (s *Store) PurgePolicyVersions() error {
	_, err := s.db.Exec(`DELETE FROM policy_versions`)
	return err
}

// SaveExtraRecordsVersion snapshots the DNS extra-records file.
func (s *Store) SaveExtraRecordsVersion(content string) error {
	_, err := s.db.Exec(
		`INSERT INTO extra_records_versions (saved_at, content, content_hash) VALUES (?, ?, ?)`,
		time.Now().Unix(), content, HashContent(content),
	)
	return err
}

// ---- key labels ----

// SetKeyLabel stores a UI-side label for a pre-auth key ("" deletes).
func (s *Store) SetKeyLabel(keyID, label string) error {
	if label == "" {
		_, err := s.db.Exec(`DELETE FROM key_labels WHERE key_id = ?`, keyID)
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO key_labels (key_id, label) VALUES (?, ?) ON CONFLICT(key_id) DO UPDATE SET label = excluded.label`,
		keyID, label,
	)
	return err
}

// KeyLabels returns all labels keyed by key ID.
func (s *Store) KeyLabels() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key_id, label FROM key_labels`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, label string
		if err := rows.Scan(&id, &label); err != nil {
			return nil, err
		}
		out[id] = label
	}
	return out, rows.Err()
}

// ---- registration handoffs ----

// Handoff is one auth-ID interaction the UI performed (headscale has no
// pending-registration list API, so this is the UI's own history).
type Handoff struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	AuthID   string    `json:"authId"`
	Kind     string    `json:"kind"`
	UserName string    `json:"userName,omitempty"`
	Status   string    `json:"status"`
	Detail   string    `json:"detail,omitempty"`
}

// AppendHandoff records an auth-ID interaction.
func (s *Store) AppendHandoff(h Handoff) error {
	if h.Time.IsZero() {
		h.Time = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO registration_handoffs (ts, auth_id, kind, user_name, status, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		h.Time.Unix(), h.AuthID, h.Kind, h.UserName, h.Status, h.Detail,
	)
	return err
}

// ListHandoffs returns handoffs newest-first.
func (s *Store) ListHandoffs(limit int) ([]Handoff, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts, auth_id, kind, user_name, status, detail FROM registration_handoffs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Handoff
	for rows.Next() {
		var h Handoff
		var ts int64
		if err := rows.Scan(&h.ID, &ts, &h.AuthID, &h.Kind, &h.UserName, &h.Status, &h.Detail); err != nil {
			return nil, err
		}
		h.Time = time.Unix(ts, 0).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}
