// Package auth implements Head-Control's single-admin login: constant-time
// password verification (bcrypt hash preferred), server-side revocable
// sessions in SQLite, per-session CSRF tokens, and login rate limiting.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/panagiotis1226/head-control/internal/store"
)

// CookieName variants: the __Host- prefix enforces Secure+Path=/ semantics
// in browsers; a plain name is used when COOKIE_SECURE=false (HTTP LAN use).
const (
	secureCookieName = "__Host-headcontrol_session"
	plainCookieName  = "headcontrol_session"
)

// kv keys for state that must survive restarts.
const (
	kvCredential = "auth.credential_fingerprint"
	kvKnownIPs   = "auth.known_ips"
)

// Manager owns password verification and sessions.
type Manager struct {
	st           *store.Store
	password     string // plaintext comparison (constant-time), if set
	passwordHash string // bcrypt, preferred
	lifetime     time.Duration
	maxAge       time.Duration // absolute session cap; 0 = none
	secure       bool

	mu       sync.Mutex
	attempts map[string][]time.Time // per-IP login attempts inside the window
	knownIPs map[string]time.Time   // IPs that logged in successfully → last success
}

// New builds a Manager. maxAge caps how long one session can live no matter
// how often it is used (0 disables the cap).
func New(st *store.Store, password, passwordHash string, lifetime, maxAge time.Duration, secureCookies bool) *Manager {
	m := &Manager{
		st:           st,
		password:     password,
		passwordHash: passwordHash,
		lifetime:     lifetime,
		maxAge:       maxAge,
		secure:       secureCookies,
		attempts:     map[string][]time.Time{},
		knownIPs:     map[string]time.Time{},
	}
	m.loadKnownIPs()
	return m
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

// Login rate limiting. Every attempt takes a slot BEFORE its password is
// checked, so a parallel burst cannot outrun the counter; a successful login
// gives its slot back.
//
//   - per IP: 5 attempts per minute, always enforced.
//   - global: 20 attempts per minute across all IPs, as a brake on
//     distributed guessing. It is not applied to IPs that logged in
//     successfully in the last 30 days — otherwise anyone able to reach the
//     login page could keep every admin out with 20 bad guesses a minute.
const (
	perIPLimit   = 5
	globalLimit  = 20
	limitWindow  = time.Minute
	failureDelay = 300 * time.Millisecond // uniform delay on failure

	knownIPTTL  = 30 * 24 * time.Hour
	maxKnownIPs = 64
)

// BeginAttempt reserves a login slot for ip and reports whether the attempt
// may proceed. Follow it with AttemptSucceeded or AttemptFailed.
func (m *Manager) BeginAttempt(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-limitWindow)
	total := 0
	for k, times := range m.attempts {
		var kept []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(m.attempts, k)
			continue
		}
		m.attempts[k] = kept
		total += len(kept)
	}
	if len(m.attempts[ip]) >= perIPLimit {
		return false
	}
	if total >= globalLimit && !m.knownLocked(ip, now) {
		return false
	}
	m.attempts[ip] = append(m.attempts[ip], now)
	return true
}

// AttemptFailed applies the uniform failure delay. The slot taken by
// BeginAttempt stays counted until it ages out of the window.
func (m *Manager) AttemptFailed() {
	time.Sleep(failureDelay)
}

// AttemptSucceeded returns the slot taken by BeginAttempt (successful logins
// do not count against the limits) and remembers ip as a known-good address.
func (m *Manager) AttemptSucceeded(ip string) {
	m.mu.Lock()
	if times := m.attempts[ip]; len(times) > 0 {
		if len(times) == 1 {
			delete(m.attempts, ip)
		} else {
			m.attempts[ip] = times[:len(times)-1]
		}
	}
	now := time.Now()
	m.knownIPs[ip] = now
	m.trimKnownLocked(now)
	buf, err := json.Marshal(m.knownUnixLocked())
	m.mu.Unlock()
	if err == nil {
		m.st.SetKV(kvKnownIPs, string(buf)) // best-effort; only affects lockout resilience
	}
}

func (m *Manager) knownLocked(ip string, now time.Time) bool {
	last, ok := m.knownIPs[ip]
	return ok && now.Sub(last) < knownIPTTL
}

// trimKnownLocked drops expired entries and keeps only the most recent
// maxKnownIPs.
func (m *Manager) trimKnownLocked(now time.Time) {
	for ip, last := range m.knownIPs {
		if now.Sub(last) >= knownIPTTL {
			delete(m.knownIPs, ip)
		}
	}
	if len(m.knownIPs) <= maxKnownIPs {
		return
	}
	ips := make([]string, 0, len(m.knownIPs))
	for ip := range m.knownIPs {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return m.knownIPs[ips[i]].After(m.knownIPs[ips[j]]) })
	for _, ip := range ips[maxKnownIPs:] {
		delete(m.knownIPs, ip)
	}
}

func (m *Manager) knownUnixLocked() map[string]int64 {
	out := make(map[string]int64, len(m.knownIPs))
	for ip, last := range m.knownIPs {
		out[ip] = last.Unix()
	}
	return out
}

func (m *Manager) loadKnownIPs() {
	raw, err := m.st.GetKV(kvKnownIPs)
	if err != nil || raw == "" {
		return
	}
	var saved map[string]int64
	if json.Unmarshal([]byte(raw), &saved) != nil {
		return
	}
	now := time.Now()
	for ip, ts := range saved {
		m.knownIPs[ip] = time.Unix(ts, 0)
	}
	m.trimKnownLocked(now)
}

// RevokeSessionsIfCredentialChanged signs every session out when the
// configured admin password differs from the one in effect at the previous
// start (or when no fingerprint was recorded yet, i.e. the first start on a
// version that tracks it). Sessions live in SQLite and otherwise survive
// restarts, so without this a stolen session cookie would keep working after
// the password is rotated. Reports whether sessions were revoked.
func (m *Manager) RevokeSessionsIfCredentialChanged() (bool, error) {
	stored, err := m.st.GetKV(kvCredential)
	if err != nil {
		return false, err
	}
	if m.credentialMatches(stored) {
		return false, nil
	}
	// Revoke first: if recording the fingerprint fails, the next start simply
	// revokes again.
	if err := m.st.DeleteAllSessions(); err != nil {
		return false, err
	}
	fp, err := m.credentialFingerprint()
	if err != nil {
		return true, err
	}
	return true, m.st.SetKV(kvCredential, fp)
}

// The fingerprint never allows recovering the password: a configured bcrypt
// hash is stored as its SHA-256; a plaintext password is stored as a fresh
// bcrypt hash (over its SHA-256, so bcrypt's 72-byte input limit is moot).
func (m *Manager) credentialFingerprint() (string, error) {
	if m.passwordHash != "" {
		return "sha256:" + sha256Hex(m.passwordHash), nil
	}
	h, err := bcrypt.GenerateFromPassword([]byte(sha256Hex(m.password)), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return "bcrypt:" + string(h), nil
}

func (m *Manager) credentialMatches(stored string) bool {
	if m.passwordHash != "" {
		return stored == "sha256:"+sha256Hex(m.passwordHash)
	}
	h, ok := strings.CutPrefix(stored, "bcrypt:")
	return ok && bcrypt.CompareHashAndPassword([]byte(h), []byte(sha256Hex(m.password))) == nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// StartSession mints a session and sets its cookie. Returns the CSRF token.
func (m *Manager) StartSession(w http.ResponseWriter, basePath string) (string, error) {
	token, sess, err := m.st.CreateSession(m.lifetime, m.maxAge)
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
	sess, err := m.st.GetSession(c.Value, m.lifetime, m.maxAge)
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
