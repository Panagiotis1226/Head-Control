package server

import (
	"context"
	"net/http"
	"time"

	"github.com/panagiotis1226/claude-head/internal/dockerint"
	"github.com/panagiotis1226/claude-head/internal/hsclient"
	"github.com/panagiotis1226/claude-head/internal/store"
)

// handleMeta reports server status + capabilities; the SPA polls it for the
// status banner and to decide which features to show.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	hsStatus := s.health.get()
	// Right after startup the background monitor may not have completed its
	// first probe yet; a zero-value status would read as "headscale down".
	// Probe synchronously once instead of reporting a false outage.
	if hsStatus.CheckedAt == nil {
		s.health.probe(r.Context())
		hsStatus = s.health.get()
	}

	caps := map[string]any{
		"policyFileMounted":    s.cfg.PolicyFilePath != "",
		"extraRecords":         s.dns.Enabled(),
		"extraRecordsWritable": s.dns.Enabled() && s.dns.Writable(),
		"configView":           s.cfg.ConfigPath != "",
		"docker":               s.docker != nil,
	}
	var dockerStatus *dockerint.Status
	if s.docker != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		st := s.docker.Probe(ctx)
		dockerStatus = &st
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":         Version,
		"headscale":       hsStatus,
		"headscaleUrl":    s.cfg.HeadscaleURL,
		"publicServerUrl": s.cfg.PublicServerURL,
		"basePath":        s.cfg.BasePath,
		"capabilities":    caps,
		"docker":          dockerStatus,
		"uiApiKeyPrefix":  s.hs.APIKeyPrefix(),
	})
}

// handleOverview aggregates dashboard counts in one round trip.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nodes, err := s.hs.ListNodes(ctx, "")
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	users, err := s.hs.ListUsers(ctx, hsclient.UserFilter{})
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	preAuthKeys, err := s.hs.ListPreAuthKeys(ctx)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	apiKeys, err := s.hs.ListAPIKeys(ctx)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}

	now := time.Now()
	soon := now.Add(7 * 24 * time.Hour)
	keySoon := now.Add(14 * 24 * time.Hour)

	var online, expired, expiringSoon, pendingRoutes int
	for _, n := range nodes {
		if n.Online {
			online++
		}
		if n.Expiry != nil && n.Expiry.Before(now) {
			expired++
		} else if n.Expiry != nil && n.Expiry.Before(soon) {
			expiringSoon++
		}
		approved := map[string]bool{}
		for _, route := range n.ApprovedRoutes {
			approved[route] = true
		}
		for _, route := range n.AvailableRoutes {
			if !approved[route] {
				pendingRoutes++
			}
		}
	}

	var activeKeys, keysExpiringSoon int
	for _, k := range preAuthKeys {
		expired := k.Expiration != nil && k.Expiration.Before(now)
		if !expired && (!k.Used || k.Reusable) {
			activeKeys++
			if k.Expiration != nil && k.Expiration.Before(keySoon) {
				keysExpiringSoon++
			}
		}
	}
	var apiKeysExpiringSoon int
	uiKeyExpiring := false
	uiPrefix := s.hs.APIKeyPrefix()
	for _, k := range apiKeys {
		if k.Expiration != nil && k.Expiration.After(now) && k.Expiration.Before(keySoon) {
			apiKeysExpiringSoon++
			if uiPrefix != "" && k.Prefix == uiPrefix {
				uiKeyExpiring = true
			}
		}
	}

	recent, _ := s.st.ListAudit(store.AuditFilter{Limit: 10})

	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":                 map[string]int{"total": len(nodes), "online": online, "expired": expired, "expiringSoon": expiringSoon},
		"users":                 len(users),
		"preAuthKeys":           map[string]int{"active": activeKeys, "expiringSoon": keysExpiringSoon},
		"apiKeys":               map[string]any{"total": len(apiKeys), "expiringSoon": apiKeysExpiringSoon, "uiKeyExpiring": uiKeyExpiring},
		"pendingRouteApprovals": pendingRoutes,
		"recentAudit":           recent,
	})
}
