package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/panagiotis1226/claude-head/internal/store"
)

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{
		Action:  q.Get("action"),
		Outcome: q.Get("outcome"),
	}
	if v := q.Get("sinceHours"); v != "" {
		if hours, err := strconv.Atoi(v); err == nil && hours > 0 {
			f.Since = time.Now().Add(-time.Duration(hours) * time.Hour)
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	entries, err := s.st.ListAudit(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) handlePurgeAudit(w http.ResponseWriter, r *http.Request) {
	if err := s.st.PurgeAudit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(store.AuditEntry{Action: "audit.purge", Summary: "audit log purged"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
