package server

import (
	"net/http"

	"github.com/panagiotis1226/head-control/internal/store"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	// The attempt takes its rate-limit slot before anything else happens, so
	// parallel requests cannot all slip past the check together. Malformed
	// bodies keep their slot too.
	if !s.auth.BeginAttempt(ip) {
		s.log.Warn("login attempt rate-limited", "ip", ip)
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts — wait a minute and try again")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if !s.auth.VerifyPassword(req.Password) {
		s.auth.AttemptFailed()
		s.log.Info("failed login attempt", "ip", ip)
		writeErr(w, http.StatusUnauthorized, "bad_credentials", "incorrect password")
		return
	}
	s.auth.AttemptSucceeded(ip)
	csrf, err := s.auth.StartSession(w, s.cfg.BasePath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
	s.log.Info("login", "ip", ip)
	s.audit(store.AuditEntry{Action: "auth.login", Summary: "from " + ip})
	writeJSON(w, http.StatusOK, map[string]any{"csrfToken": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(w, r, s.cfg.BasePath)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSession lets the SPA discover login state + its CSRF token.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := s.auth.Session(r)
	if sess == nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"csrfToken":     sess.CSRFToken,
	})
}
