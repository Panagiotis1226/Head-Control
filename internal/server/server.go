// Package server wires Head-Control's HTTP surface: the session-guarded JSON
// API under /api and the embedded SPA everywhere else. Everything is
// same-origin — the headscale API key never leaves this process.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/panagiotis1226/claude-head/internal/auth"
	"github.com/panagiotis1226/claude-head/internal/config"
	"github.com/panagiotis1226/claude-head/internal/dnsrecords"
	"github.com/panagiotis1226/claude-head/internal/dockerint"
	"github.com/panagiotis1226/claude-head/internal/hsclient"
	"github.com/panagiotis1226/claude-head/internal/policy"
	"github.com/panagiotis1226/claude-head/internal/store"
	"github.com/panagiotis1226/claude-head/internal/webui"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

// Server holds all wiring.
type Server struct {
	cfg    *config.Config
	log    *slog.Logger
	hs     *hsclient.Client
	st     *store.Store
	auth   *auth.Manager
	policy *policy.Manager
	dns    *dnsrecords.Manager
	docker *dockerint.Client // nil when integration disabled
	health *healthMonitor
}

// New assembles a Server from configuration.
func New(cfg *config.Config, log *slog.Logger, hs *hsclient.Client, st *store.Store) *Server {
	var docker *dockerint.Client
	if cfg.DockerEnabled() {
		docker = dockerint.New(cfg.DockerSock, cfg.DockerContainerLabel, cfg.DockerContainerName)
	}
	var reloader policy.Reloader
	if docker != nil {
		reloader = docker
	}
	s := &Server{
		cfg:    cfg,
		log:    log,
		hs:     hs,
		st:     st,
		auth:   auth.New(st, cfg.AdminPassword, cfg.AdminPasswordHash, cfg.SessionLifetime, cfg.CookieSecure),
		policy: policy.New(hs, st, log, cfg.PolicyMode, cfg.PolicyFilePath, reloader),
		dns:    dnsrecords.New(cfg.ExtraRecordsPath, st),
		docker: docker,
		health: newHealthMonitor(hs, log),
	}
	return s
}

// Run starts background workers and serves HTTP until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	go s.health.run(ctx, s.cfg.HealthInterval)
	go s.housekeeping(ctx)

	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	s.log.Info("head-control listening", "addr", s.cfg.ListenAddr, "basePath", s.cfg.BasePath, "version", Version)

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.st.PruneSessions()
			s.st.PruneAudit(90 * 24 * time.Hour)
		}
	}
}

// Handler builds the full HTTP handler (API + SPA), honoring BASE_PATH.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(securityHeaders)

	r.Route("/api", s.apiRoutes)
	r.NotFound(webui.SPAHandler(s.cfg.BasePath, s.log))

	if s.cfg.BasePath == "" {
		return r
	}
	// Serve everything under BASE_PATH; redirect the bare root there.
	outer := chi.NewRouter()
	outer.Mount(s.cfg.BasePath, http.StripPrefix(s.cfg.BasePath, r))
	outer.Get("/", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, s.cfg.BasePath+"/", http.StatusTemporaryRedirect)
	})
	return outer
}

func (s *Server) apiRoutes(r chi.Router) {
	// Unauthenticated: login + session introspection.
	r.Post("/auth/login", s.handleLogin)
	r.Get("/auth/session", s.handleSession)

	// Everything else requires a session; mutations also need CSRF.
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Use(s.requireCSRF)

		r.Post("/auth/logout", s.handleLogout)

		r.Get("/meta", s.handleMeta)
		r.Get("/overview", s.handleOverview)

		r.Get("/hs/users", s.handleListUsers)
		r.Post("/hs/users", s.handleCreateUser)
		r.Post("/hs/users/{id}/rename", s.handleRenameUser)
		r.Delete("/hs/users/{id}", s.handleDeleteUser)

		r.Get("/hs/nodes", s.handleListNodes)
		r.Get("/hs/nodes/{id}", s.handleGetNode)
		r.Delete("/hs/nodes/{id}", s.handleDeleteNode)
		r.Post("/hs/nodes/{id}/rename", s.handleRenameNode)
		r.Post("/hs/nodes/{id}/tags", s.handleSetTags)
		r.Post("/hs/nodes/{id}/expire", s.handleExpireNode)
		r.Post("/hs/nodes/{id}/routes", s.handleSetRoutes)
		r.Post("/hs/nodes/backfillips", s.handleBackfillIPs)
		r.Post("/hs/debug/node", s.handleDebugCreateNode)

		r.Post("/hs/register", s.handleRegister)
		r.Post("/hs/auth/approve", s.handleAuthApprove)
		r.Post("/hs/auth/reject", s.handleAuthReject)
		r.Get("/handoffs", s.handleListHandoffs)

		r.Get("/hs/preauthkeys", s.handleListPreAuthKeys)
		r.Post("/hs/preauthkeys", s.handleCreatePreAuthKey)
		r.Post("/hs/preauthkeys/expire", s.handleExpirePreAuthKey)
		r.Delete("/hs/preauthkeys/{id}", s.handleDeletePreAuthKey)
		r.Put("/keylabels/{id}", s.handleSetKeyLabel)

		r.Get("/hs/apikeys", s.handleListAPIKeys)
		r.Post("/hs/apikeys", s.handleCreateAPIKey)
		r.Post("/hs/apikeys/expire", s.handleExpireAPIKey)
		r.Delete("/hs/apikeys/{prefix}", s.handleDeleteAPIKey)

		r.Get("/policy", s.handleGetPolicy)
		r.Put("/policy", s.handleSetPolicy)
		r.Post("/policy/check", s.handleCheckPolicy)
		r.Get("/policy/versions", s.handleListPolicyVersions)
		r.Get("/policy/versions/{id}", s.handleGetPolicyVersion)

		r.Get("/dns", s.handleGetDNS)
		r.Put("/dns/records", s.handleSaveDNSRecords)

		r.Get("/audit", s.handleListAudit)
		r.Post("/audit/purge", s.handlePurgeAudit)
	})
}

// audit records a UI action; failures to write audit rows are logged, never
// surfaced (the action itself already succeeded or failed on its own).
func (s *Server) audit(e store.AuditEntry) {
	if err := s.st.AppendAudit(e); err != nil {
		s.log.Warn("audit write failed", "err", err)
	}
}
