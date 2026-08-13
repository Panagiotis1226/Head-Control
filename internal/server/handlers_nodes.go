package server

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/panagiotis1226/claude-head/internal/hsclient"
	"github.com/panagiotis1226/claude-head/internal/store"
)

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.hs.ListNodes(r.Context(), r.URL.Query().Get("user"))
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	if nodes == nil {
		nodes = []hsclient.Node{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	node, err := s.hs.GetNode(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": node})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name := ""
	if n, err := s.hs.GetNode(r.Context(), id); err == nil {
		name = n.GivenName
	}
	err := s.hs.DeleteNode(r.Context(), id)
	cli := fmt.Sprintf("headscale nodes delete --identifier %s", id)
	if err != nil {
		s.audit(store.AuditEntry{Action: "node.delete", TargetType: "node", TargetID: id, TargetName: name, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "node.delete", TargetType: "node", TargetID: id, TargetName: name, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Hostname rules enforced by headscale 0.27+: 2–63 chars, lowercase
// alphanumeric + hyphens, no leading/trailing hyphen.
var hostnameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$`)

func (s *Server) handleRenameNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		NewName string `json:"newName"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if !hostnameRe.MatchString(req.NewName) {
		writeErr(w, http.StatusBadRequest, "bad_request",
			"node names must be 2-63 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
		return
	}
	node, err := s.hs.RenameNode(r.Context(), id, req.NewName)
	cli := fmt.Sprintf("headscale nodes rename --identifier %s %s", id, req.NewName)
	if err != nil {
		s.audit(store.AuditEntry{Action: "node.rename", TargetType: "node", TargetID: id, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "node.rename", TargetType: "node", TargetID: id, TargetName: node.GivenName, Summary: "renamed to " + req.NewName, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"node": node})
}

func (s *Server) handleSetTags(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Tags []string `json:"tags"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	for _, tag := range req.Tags {
		if !strings.HasPrefix(tag, "tag:") || strings.ContainsAny(tag, " \t") || tag != strings.ToLower(tag) {
			writeErr(w, http.StatusBadRequest, "bad_request",
				fmt.Sprintf("%q is not a valid tag — tags are lowercase, contain no spaces, and start with \"tag:\"", tag))
			return
		}
	}
	node, err := s.hs.SetTags(r.Context(), id, req.Tags)
	cli := fmt.Sprintf("headscale nodes tag --identifier %s --tags %s", id, strings.Join(req.Tags, ","))
	if err != nil {
		s.audit(store.AuditEntry{Action: "node.tags", TargetType: "node", TargetID: id, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "node.tags", TargetType: "node", TargetID: id, TargetName: node.GivenName, Summary: "tags: " + strings.Join(req.Tags, ", "), CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"node": node})
}

func (s *Server) handleExpireNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Mode   string     `json:"mode"` // "now" | "at" | "never"
		Expiry *time.Time `json:"expiry,omitempty"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	var spec hsclient.ExpireSpec
	cli := fmt.Sprintf("headscale nodes expire --identifier %s", id)
	switch req.Mode {
	case "now", "":
	case "at":
		if req.Expiry == nil || req.Expiry.Before(time.Now()) {
			writeErr(w, http.StatusBadRequest, "bad_request", "expiry must be a future timestamp")
			return
		}
		spec.At = req.Expiry
		cli += " --expiry " + req.Expiry.UTC().Format(time.RFC3339)
	case "never":
		spec.Never = true
		cli += " --disable-expiry"
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", `mode must be "now", "at" or "never"`)
		return
	}
	node, err := s.hs.ExpireNode(r.Context(), id, spec)
	if err != nil {
		s.audit(store.AuditEntry{Action: "node.expire", TargetType: "node", TargetID: id, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "node.expire", TargetType: "node", TargetID: id, TargetName: node.GivenName, Summary: "mode: " + req.Mode, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"node": node})
}

// handleSetRoutes performs a guarded read-merge-replace over headscale's
// full-replacement approve_routes: the client states its view of the current
// approved set; if reality moved (another admin, an autoApprover), we answer
// 409 with the fresh node instead of clobbering.
func (s *Server) handleSetRoutes(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Approve          []string `json:"approve"`
		Revoke           []string `json:"revoke"`
		ExpectedApproved []string `json:"expectedApproved"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	node, err := s.hs.GetNode(r.Context(), id)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	if !sameRouteSet(node.ApprovedRoutes, req.ExpectedApproved) {
		var e apiError
		e.Error.Code = "route_conflict"
		e.Error.Message = "the node's approved routes changed since you loaded them — review and retry"
		writeJSON(w, http.StatusConflict, map[string]any{"error": e.Error, "node": node})
		return
	}

	// Exit routes travel as a pair (headscale pairs them server-side since
	// 0.26; mirroring it here keeps the confirm-diff truthful).
	expandExit := func(list []string) map[string]bool {
		set := map[string]bool{}
		for _, route := range list {
			set[route] = true
		}
		if set["0.0.0.0/0"] || set["::/0"] {
			set["0.0.0.0/0"], set["::/0"] = true, true
		}
		return set
	}
	desired := map[string]bool{}
	for _, route := range node.ApprovedRoutes {
		desired[route] = true
	}
	for route := range expandExit(req.Approve) {
		desired[route] = true
	}
	for route := range expandExit(req.Revoke) {
		delete(desired, route)
	}
	full := make([]string, 0, len(desired))
	for route := range desired {
		full = append(full, route)
	}
	sort.Strings(full)

	updated, err := s.hs.SetApprovedRoutes(r.Context(), id, full)
	cli := fmt.Sprintf("headscale nodes approve-routes --identifier %s --routes %s", id, strings.Join(full, ","))
	if err != nil {
		s.audit(store.AuditEntry{Action: "node.approve_routes", TargetType: "node", TargetID: id, Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{
		Action: "node.approve_routes", TargetType: "node", TargetID: id, TargetName: updated.GivenName,
		Summary: fmt.Sprintf("approve %v, revoke %v", req.Approve, req.Revoke), CLI: cli,
	})
	writeJSON(w, http.StatusOK, map[string]any{"node": updated})
}

func sameRouteSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if !set[x] {
			return false
		}
	}
	return true
}

func (s *Server) handleBackfillIPs(w http.ResponseWriter, r *http.Request) {
	confirmed := r.URL.Query().Get("confirmed") == "true"
	changes, err := s.hs.BackfillNodeIPs(r.Context(), confirmed)
	cli := "headscale nodes backfillips"
	if confirmed {
		cli += " --confirmed"
	}
	if err != nil {
		s.audit(store.AuditEntry{Action: "node.backfillips", Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	if confirmed {
		s.audit(store.AuditEntry{Action: "node.backfillips", Summary: fmt.Sprintf("%d changes applied", len(changes)), CLI: cli})
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": changes, "confirmed": confirmed})
}

func (s *Server) handleDebugCreateNode(w http.ResponseWriter, r *http.Request) {
	var req hsclient.DebugCreateNodeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	node, err := s.hs.DebugCreateNode(r.Context(), req)
	cli := fmt.Sprintf("headscale debug create-node --user %s --key %s --name %s", req.User, req.Key, req.Name)
	if err != nil {
		s.audit(store.AuditEntry{Action: "node.debug_create", Outcome: "error", Error: err.Error(), CLI: cli})
		writeUpstreamErr(w, err)
		return
	}
	s.audit(store.AuditEntry{Action: "node.debug_create", TargetType: "node", TargetID: node.ID, TargetName: node.GivenName, CLI: cli})
	writeJSON(w, http.StatusOK, map[string]any{"node": node})
}
