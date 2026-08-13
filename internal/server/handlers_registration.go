package server

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/panagiotis1226/head-control/internal/store"
)

// authIDRe extracts an auth/registration key from a raw ID or a pasted
// registration URL. Real headscale v0.29.3 registration auth IDs use the
// prefix "hskey-authreq-" (verified against a live server); older/other
// variants are matched permissively. IDs may contain hyphens, like API keys.
var authIDRe = regexp.MustCompile(`hskey-[A-Za-z]+-[0-9A-Za-z-]+`)

func extractAuthID(input string) string {
	if m := authIDRe.FindString(input); m != "" {
		return m
	}
	return input
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User   string `json:"user"` // user NAME (auth/register addresses by name)
		AuthID string `json:"authId"`
		Legacy bool   `json:"legacy,omitempty"` // troubleshooting fallback via deprecated endpoint
	}
	if !decodeBody(w, r, &req) {
		return
	}
	authID := extractAuthID(req.AuthID)
	if req.User == "" || authID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "user and authId are required")
		return
	}

	var (
		node any
		err  error
		cli  string
	)
	if req.Legacy {
		node, err = s.hs.RegisterNode(r.Context(), req.User, authID)
		cli = fmt.Sprintf("headscale nodes register --user %s --key %s (deprecated)", req.User, authID)
	} else {
		node, err = s.hs.AuthRegister(r.Context(), req.User, authID)
		cli = fmt.Sprintf("headscale auth register --user %s --auth-id %s", req.User, authID)
	}

	status, detail := "ok", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	s.st.AppendHandoff(store.Handoff{AuthID: authID, Kind: "register", UserName: req.User, Status: status, Detail: detail})
	if err != nil {
		s.audit(store.AuditEntry{Action: "auth.register", TargetName: req.User, Summary: "authId " + authID, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "auth.register", TargetName: req.User, Summary: "authId " + authID, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"node": node})
}

func (s *Server) handleAuthApprove(w http.ResponseWriter, r *http.Request) {
	s.handleAuthDecision(w, r, "approve")
}

func (s *Server) handleAuthReject(w http.ResponseWriter, r *http.Request) {
	s.handleAuthDecision(w, r, "reject")
}

func (s *Server) handleAuthDecision(w http.ResponseWriter, r *http.Request, kind string) {
	var req struct {
		AuthID string `json:"authId"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	authID := extractAuthID(req.AuthID)
	if authID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "authId is required")
		return
	}
	var err error
	if kind == "approve" {
		err = s.hs.AuthApprove(r.Context(), authID)
	} else {
		err = s.hs.AuthReject(r.Context(), authID)
	}
	cli := fmt.Sprintf("headscale auth %s --auth-id %s", kind, authID)

	status, detail := "ok", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	s.st.AppendHandoff(store.Handoff{AuthID: authID, Kind: kind, Status: status, Detail: detail})
	if err != nil {
		s.audit(store.AuditEntry{Action: "auth." + kind, Summary: "authId " + authID, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "auth." + kind, Summary: "authId " + authID, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListHandoffs(w http.ResponseWriter, r *http.Request) {
	handoffs, err := s.st.ListHandoffs(100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if handoffs == nil {
		handoffs = []store.Handoff{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"handoffs": handoffs})
}
