// Package auth implements Head-Control's single-admin login: constant-time
// password verification (bcrypt hash preferred), server-side revocable
// sessions in SQLite, per-session CSRF tokens, and login rate limiting.
package auth

import (
	"crypto/subtle"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/panagiotis1226/claude-head/internal/store"
)

// CookieName variants: the __Host- prefix enforces Secure+Path=/ semantics
// in browsers; a plain name is used when COOKIE_SECURE=false (HTTP LAN use).
const (
	secureCookieName = "__Host-headcontrol_session"
	plainCookieName  = "headcontrol_session"
)

// Manager owns password verification and sessions.
type Manager struct {
	st           *store.Store
	password     string // plaintext comparison (constant-time), if set
	passwordHash string // bcrypt, preferred
	lifetime     time.Duration
	secure       bool

	mu       sync.Mutex
	failures map[string][]time.Time // per-IP login failures
}

// New builds a Manager.
func New(st *store.Store, password, passwordHash string, lifetime time.Duration, secureCookies bool) *Manager {
	return &Manager{
		st:           st,
		password:     password,
		passwordHash: passwordHash,
		lifetime:     lifetime,
		secure:       secureCookies,
		failures:     map[string][]time.Time{},
	}
}

func (m *Manager) cookieName() string {
	if m.secure {
		return secureCookieName
	}
	return plainCookieName
}

// VerifyPassword checks a login attempt in constant time.
func (m *Manager) VerifyPassword(candidate string) bool {
	if m.passwordHash != "" {
		return bcrypt.CompareHashAndPassword([]byte(m.passwordHash), []byte(candidate)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(m.password), []byte(candidate)) == 1
}

// Login rate limiting: max 5 failures per IP per minute, 20 globally.
const (
	perIPLimit   = 5
	globalLimit  = 20
	limitWindow  = time.Minute
	failureDelay = 300 * time.Millisecond // uniform delay on failure
)

// AllowAttempt reports whether ip may attempt a login now.
func (m *Manager) AllowAttempt(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-limitWindow)
	total := 0
	for k, times := range m.failures {
		var kept []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(m.failures, k)
			continue
		}
		m.failures[k] = kept
		total += len(kept)
	}
	if total >= globalLimit {
		return false
	}
	return len(m.failures[ip]) < perIPLimit
}

// RecordFailure notes a failed attempt and applies the uniform delay.
func (m *Manager) RecordFailure(ip string) {
	m.mu.Lock()
	m.failures[ip] = append(m.failures[ip], time.Now())
	m.mu.Unlock()
	time.Sleep(failureDelay)
}

// StartSession mints a session and sets its cookie. Returns the CSRF token.
func (m *Manager) StartSession(w http.ResponseWriter, basePath string) (string, error) {
	token, sess, err := m.st.CreateSession(m.lifetime)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(),
		Value:    token,
		Path:     cookiePath(basePath, m.secure),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	return sess.CSRFToken, nil
}

// Session resolves the request's session, or nil.
func (m *Manager) Session(r *http.Request) *store.Session {
	c, err := r.Cookie(m.cookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := m.st.GetSession(c.Value, m.lifetime)
	if err != nil {
		return nil
	}
	return sess
}

// Logout revokes the request's session and clears the cookie.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request, basePath string) {
	if c, err := r.Cookie(m.cookieName()); err == nil && c.Value != "" {
		m.st.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(),
		Value:    "",
		Path:     cookiePath(basePath, m.secure),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// cookiePath: __Host- cookies require Path=/; otherwise scope to the base path.
func cookiePath(basePath string, secure bool) string {
	if secure || basePath == "" {
		return "/"
	}
	return basePath
}

// HashPassword generates a bcrypt hash for the hash-password subcommand.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}
