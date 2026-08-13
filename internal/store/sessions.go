package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

// Session is an authenticated admin session. The raw token lives only in the
// browser cookie; the database stores its SHA-256.
type Session struct {
	CSRFToken string
	ExpiresAt time.Time
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return hex.EncodeToString(buf)
}

// CreateSession mints a session and returns the raw cookie token.
func (s *Store) CreateSession(lifetime time.Duration) (token string, sess *Session, err error) {
	token = randomToken()
	csrf := randomToken()
	exp := time.Now().Add(lifetime)
	_, err = s.db.Exec(
		`INSERT INTO sessions (token_hash, csrf_token, created_at, expires_at, last_seen) VALUES (?, ?, ?, ?, ?)`,
		hashToken(token), csrf, now(), exp.Unix(), now(),
	)
	if err != nil {
		return "", nil, err
	}
	return token, &Session{CSRFToken: csrf, ExpiresAt: exp}, nil
}

// GetSession resolves a cookie token to a live session, applying sliding
// renewal: touching a session pushes its expiry forward by lifetime.
func (s *Store) GetSession(token string, lifetime time.Duration) (*Session, error) {
	h := hashToken(token)
	var csrf string
	var expiresAt int64
	err := s.db.QueryRow(`SELECT csrf_token, expires_at FROM sessions WHERE token_hash = ?`, h).Scan(&csrf, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > expiresAt {
		s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, h)
		return nil, nil
	}
	newExp := time.Now().Add(lifetime)
	s.db.Exec(`UPDATE sessions SET last_seen = ?, expires_at = ? WHERE token_hash = ?`, now(), newExp.Unix(), h)
	return &Session{CSRFToken: csrf, ExpiresAt: newExp}, nil
}

// DeleteSession logs one session out.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// DeleteAllSessions logs every session out.
func (s *Store) DeleteAllSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions`)
	return err
}

// PruneSessions drops expired sessions.
func (s *Store) PruneSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now())
	return err
}
