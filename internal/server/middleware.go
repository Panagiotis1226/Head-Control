package server

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/panagiotis1226/head-control/internal/store"
)

type ctxKey int

const sessionKey ctxKey = iota

// securityHeaders sets a strict CSP and friends on every response.
// style-src 'unsafe-inline' is required by CodeMirror's injected styles;
// img-src https: allows OIDC profile picture URLs.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: https:; connect-src 'self'; font-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// requireAuth gates the API behind a valid session and stashes it in context.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := s.auth.Session(r)
		if sess == nil {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "not logged in")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

// requireCSRF enforces the per-session CSRF token on mutating methods.
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		sess, _ := r.Context().Value(sessionKey).(*store.Session)
		token := r.Header.Get("X-CSRF-Token")
		if sess == nil || token == "" ||
			subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) != 1 {
			writeErr(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the peer IP for login rate limiting. Head-Control sits
// behind the operator's reverse proxy; we take the last X-Forwarded-For hop
// only when the direct peer is a private/loopback address (the proxy).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer != nil && (peer.IsLoopback() || peer.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			candidate := strings.TrimSpace(parts[len(parts)-1])
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}
	return host
}
