package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/panagiotis1226/claude-head/internal/store"
)

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	state, err := s.policy.Get(r.Context())
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleCheckPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policy string `json:"policy"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.policy.Check(r.Context(), req.Policy); err != nil {
		writeUpstreamErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policy  string `json:"policy"`
		Comment string `json:"comment,omitempty"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	res, err := s.policy.Save(r.Context(), req.Policy, req.Comment)
	if err != nil {
		s.audit(store.AuditEntry{Action: "policy.set", Outcome: "error", Error: err.Error(), CLI: "headscale policy set -f policy.hujson"})
		writeUpstreamErr(w, err)
		return
	}
	summary := "mode " + res.Mode
	if res.Warning != "" {
		summary += " (warning: " + res.Warning + ")"
	}
	s.audit(store.AuditEntry{Action: "policy.set", Summary: summary, CLI: "headscale policy set -f policy.hujson"})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListPolicyVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := s.policy.Versions(100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if versions == nil {
		versions = []store.PolicyVersion{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func (s *Server) handleGetPolicyVersion(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid version id")
		return
	}
	v, err := s.policy.Version(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if v == nil {
		writeErr(w, http.StatusNotFound, "not_found", "no such policy version")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": v})
}
