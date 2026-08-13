package server

import (
	"net/http"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.auth.AllowAttempt(ip) {
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
		s.auth.RecordFailure(ip)
		s.log.Info("failed login attempt", "ip", ip)
		writeErr(w, http.StatusUnauthorized, "bad_credentials", "incorrect password")
		return
	}
	csrf, err := s.auth.StartSession(w, s.cfg.BasePath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
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
