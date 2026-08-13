package server

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/panagiotis1226/head-control/internal/hsclient"
	"github.com/panagiotis1226/head-control/internal/store"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	users, err := s.hs.ListUsers(r.Context(), hsclient.UserFilter{
		ID: q.Get("id"), Name: q.Get("name"), Email: q.Get("email"),
	})
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	if users == nil {
		users = []hsclient.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req hsclient.CreateUserRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "user name is required")
		return
	}
	user, err := s.hs.CreateUser(r.Context(), req)
	cli := fmt.Sprintf("headscale users create %s", req.Name)
	if err != nil {
		s.audit(store.AuditEntry{Action: "user.create", TargetName: req.Name, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "user.create", TargetType: "user", TargetID: user.ID, TargetName: user.Name, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleRenameUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		NewName string `json:"newName"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.NewName == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "newName is required")
		return
	}
	user, err := s.hs.RenameUser(r.Context(), id, req.NewName)
	cli := fmt.Sprintf("headscale users rename --identifier %s %s", id, req.NewName)
	if err != nil {
		s.audit(store.AuditEntry{Action: "user.rename", TargetType: "user", TargetID: id, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "user.rename", TargetType: "user", TargetID: id, TargetName: user.Name, Summary: "renamed to " + req.NewName, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// Capture the name for the audit trail before it disappears.
	name := ""
	if users, err := s.hs.ListUsers(r.Context(), hsclient.UserFilter{ID: id}); err == nil && len(users) == 1 {
		name = users[0].Name
	}
	err := s.hs.DeleteUser(r.Context(), id)
	cli := fmt.Sprintf("headscale users destroy --identifier %s", id)
	if err != nil {
		s.audit(store.AuditEntry{Action: "user.delete", TargetType: "user", TargetID: id, TargetName: name, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "user.delete", TargetType: "user", TargetID: id, TargetName: name, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
