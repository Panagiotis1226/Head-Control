package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/panagiotis1226/claude-head/internal/hsclient"
	"github.com/panagiotis1226/claude-head/internal/store"
)

// ---- pre-auth keys ----

func (s *Server) handleListPreAuthKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.hs.ListPreAuthKeys(r.Context())
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	if keys == nil {
		keys = []hsclient.PreAuthKey{}
	}
	labels, _ := s.st.KeyLabels()
	writeJSON(w, http.StatusOK, map[string]any{"preAuthKeys": keys, "labels": labels})
}

func (s *Server) handleCreatePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User       string     `json:"user"` // numeric user ID as string
		Reusable   bool       `json:"reusable"`
		Ephemeral  bool       `json:"ephemeral"`
		Expiration *time.Time `json:"expiration,omitempty"`
		ACLTags    []string   `json:"aclTags,omitempty"`
		Label      string     `json:"label,omitempty"` // UI-local label
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.User == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "user (numeric ID) is required")
		return
	}
	key, err := s.hs.CreatePreAuthKey(r.Context(), hsclient.CreatePreAuthKeyRequest{
		User: req.User, Reusable: req.Reusable, Ephemeral: req.Ephemeral,
		Expiration: req.Expiration, ACLTags: req.ACLTags,
	})
	cli := fmt.Sprintf("headscale preauthkeys create --user %s", req.User)
	if req.Reusable {
		cli += " --reusable"
	}
	if req.Ephemeral {
		cli += " --ephemeral"
	}
	if len(req.ACLTags) > 0 {
		cli += " --tags " + strings.Join(req.ACLTags, ",")
	}
	if err != nil {
		s.audit(store.AuditEntry{Action: "preauthkey.create", Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	if req.Label != "" {
		s.st.SetKeyLabel(key.ID, req.Label)
	}
	// The audit entry records metadata only — never the key secret.
	s.audit(store.AuditEntry{
		Action: "preauthkey.create", TargetType: "preauthkey", TargetID: key.ID,
		Summary: fmt.Sprintf("user %s, reusable=%t, ephemeral=%t, tags=%v", req.User, req.Reusable, req.Ephemeral, req.ACLTags),
		CLI:     cli,
	})
	// The full secret is in key.Key — shown once by the UI, never stored.
	writeJSON(w, http.StatusOK, map[string]any{"preAuthKey": key})
}

func (s *Server) handleExpirePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	err := s.hs.ExpirePreAuthKey(r.Context(), req.ID)
	cli := fmt.Sprintf("headscale preauthkeys expire --id %s", req.ID)
	if err != nil {
		s.audit(store.AuditEntry{Action: "preauthkey.expire", TargetType: "preauthkey", TargetID: req.ID, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "preauthkey.expire", TargetType: "preauthkey", TargetID: req.ID, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeletePreAuthKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.hs.DeletePreAuthKey(r.Context(), id)
	cli := fmt.Sprintf("headscale preauthkeys delete --id %s", id)
	if err != nil {
		s.audit(store.AuditEntry{Action: "preauthkey.delete", TargetType: "preauthkey", TargetID: id, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.st.SetKeyLabel(id, "")
	s.audit(store.AuditEntry{Action: "preauthkey.delete", TargetType: "preauthkey", TargetID: id, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetKeyLabel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Label string `json:"label"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.st.SetKeyLabel(id, req.Label); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- API keys ----

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.hs.ListAPIKeys(r.Context())
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	if keys == nil {
		keys = []hsclient.APIKey{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"apiKeys":        keys,
		"uiApiKeyPrefix": s.hs.APIKeyPrefix(),
	})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Expiration *time.Time `json:"expiration,omitempty"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	exp := time.Now().Add(90 * 24 * time.Hour)
	if req.Expiration != nil {
		if req.Expiration.Before(time.Now()) {
			writeErr(w, http.StatusBadRequest, "bad_request", "expiration must be in the future")
			return
		}
		exp = *req.Expiration
	}
	secret, err := s.hs.CreateAPIKey(r.Context(), exp)
	cli := "headscale apikeys create --expiration " + exp.UTC().Format(time.RFC3339)
	if err != nil {
		s.audit(store.AuditEntry{Action: "apikey.create", Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "apikey.create", TargetType: "apikey", Summary: "expires " + exp.UTC().Format(time.RFC3339), CLI: cli})
	// Secret shown once by the UI; never persisted here.
	writeJSON(w, http.StatusOK, map[string]any{"apiKey": secret})
}

func (s *Server) handleExpireAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prefix string `json:"prefix,omitempty"`
		ID     string `json:"id,omitempty"`
		// Confirm must be true to expire the key this UI itself uses.
		ConfirmSelfLockout bool `json:"confirmSelfLockout,omitempty"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Prefix == "" && req.ID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "prefix or id is required")
		return
	}
	if req.Prefix != "" && req.Prefix == s.hs.APIKeyPrefix() && !req.ConfirmSelfLockout {
		writeErr(w, http.StatusConflict, "self_lockout",
			"this is the API key Head-Control itself uses — expiring it will break this UI until HEADSCALE_API_KEY is updated. Pass confirmSelfLockout to proceed.")
		return
	}
	err := s.hs.ExpireAPIKey(r.Context(), req.Prefix, req.ID)
	cli := "headscale apikeys expire --prefix " + req.Prefix
	if err != nil {
		s.audit(store.AuditEntry{Action: "apikey.expire", TargetType: "apikey", TargetName: req.Prefix, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "apikey.expire", TargetType: "apikey", TargetName: req.Prefix, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	prefix := chi.URLParam(r, "prefix")
	if prefix == s.hs.APIKeyPrefix() && r.URL.Query().Get("confirmSelfLockout") != "true" {
		writeErr(w, http.StatusConflict, "self_lockout",
			"this is the API key Head-Control itself uses — deleting it will break this UI until HEADSCALE_API_KEY is updated. Pass confirmSelfLockout=true to proceed.")
		return
	}
	err := s.hs.DeleteAPIKey(r.Context(), prefix)
	cli := "headscale apikeys delete --prefix " + prefix
	if err != nil {
		s.audit(store.AuditEntry{Action: "apikey.delete", TargetType: "apikey", TargetName: prefix, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "apikey.delete", TargetType: "apikey", TargetName: prefix, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
