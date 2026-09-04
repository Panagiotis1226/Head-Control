package store

import "time"

// RuleMeta is UI-local metadata for one ACL rule (the ACLs Beta editor).
// Headscale's policy format has no name, description or enabled flag, so
// they live here, keyed by the rule's content fingerprint. Disabled rules
// are removed from the live policy and kept here in full.
type RuleMeta struct {
	Fingerprint string
	Name        string
	Description string
	Enabled     bool
	RuleJSON    string // canonical rule JSON; may be "" for enabled rows
	Position    int
}

// ListRuleMeta returns all rows ordered by position.
func (s *Store) ListRuleMeta() ([]RuleMeta, error) {
	rows, err := s.db.Query(
		`SELECT fingerprint, name, description, enabled, rule_json, position FROM acl_rule_meta ORDER BY position, fingerprint`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleMeta
	for rows.Next() {
		var m RuleMeta
		var enabled int
		if err := rows.Scan(&m.Fingerprint, &m.Name, &m.Description, &enabled, &m.RuleJSON, &m.Position); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// ReplaceRuleMeta replaces the whole table in one transaction (the editor
// always submits the full rule list, which also prunes orphaned rows).
func (s *Store) ReplaceRuleMeta(rows []RuleMeta) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM acl_rule_meta`); err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, m := range rows {
		enabled := 0
		if m.Enabled {
			enabled = 1
		}
		if _, err := tx.Exec(
			`INSERT INTO acl_rule_meta (fingerprint, name, description, enabled, rule_json, position, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(fingerprint) DO UPDATE SET name = excluded.name, description = excluded.description,
			   enabled = excluded.enabled, rule_json = excluded.rule_json, position = excluded.position, updated_at = excluded.updated_at`,
			m.Fingerprint, m.Name, m.Description, enabled, m.RuleJSON, m.Position, now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}
