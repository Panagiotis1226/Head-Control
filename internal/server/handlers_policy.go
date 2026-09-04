package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/panagiotis1226/head-control/internal/aclmodel"
	"github.com/panagiotis1226/head-control/internal/policy"
	"github.com/panagiotis1226/head-control/internal/store"
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

// ---- ACLs Beta: structured model ----

func (s *Server) handleGetPolicyModel(w http.ResponseWriter, r *http.Request) {
	st, err := s.policy.GetModel(r.Context())
	if err != nil {
		writeModelErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSavePolicyModel(w http.ResponseWriter, r *http.Request) {
	var req policy.ModelInput
	if !decodeBody(w, r, &req) {
		return
	}
	res, err := s.policy.SaveModel(r.Context(), &req)
	if err != nil {
		var conflict *policy.ModelConflictError
		if errors.As(err, &conflict) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   map[string]any{"code": "conflict", "message": conflict.Error()},
				"current": conflict.Current,
			})
			return
		}
		s.audit(store.AuditEntry{Action: "policy.model_set", Outcome: "error", Error: err.Error(), CLI: "headscale policy set -f policy.hujson"})
		writeModelErr(w, err)
		return
	}
	summary := modelSummary(&req)
	if res.PolicyChanged {
		summary += "; mode " + res.Mode
	} else {
		summary += "; names/descriptions only, policy unchanged"
	}
	if res.Warning != "" {
		summary += " (warning: " + res.Warning + ")"
	}
	s.audit(store.AuditEntry{Action: "policy.model_set", Summary: summary, CLI: "headscale policy set -f policy.hujson"})
	writeJSON(w, http.StatusOK, res)
}

// writeModelErr maps aclmodel errors: shape validation → 400, documents the
// structured editor cannot represent → 422, everything else upstream.
func writeModelErr(w http.ResponseWriter, err error) {
	var ve *aclmodel.ValidationError
	if errors.As(err, &ve) {
		writeErr(w, http.StatusBadRequest, "model_invalid", ve.Error())
		return
	}
	var ue *aclmodel.UnsupportedError
	if errors.As(err, &ue) {
		writeErr(w, http.StatusUnprocessableEntity, "model_unsupported",
			ue.Error()+" — this policy can still be edited in Access Controls (raw editor)")
		return
	}
	writeUpstreamErr(w, err)
}

func modelSummary(in *policy.ModelInput) string {
	enabled, disabled := 0, 0
	for _, r := range in.Rules {
		if r.Enabled {
			enabled++
		} else {
			disabled++
		}
	}
	return fmt.Sprintf("%d rules (%d disabled), %d groups, %d tagOwners, %d hosts",
		enabled+disabled, disabled, len(in.Groups), len(in.TagOwners), len(in.Hosts))
}
