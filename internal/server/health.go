package server

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/panagiotis1226/head-control/internal/config"
	"github.com/panagiotis1226/head-control/internal/hsclient"
)

// HeadscaleStatus is the cached result of background health probing,
// surfaced through /api/meta and the UI status banner.
type HeadscaleStatus struct {
	Reachable   bool       `json:"reachable"`
	APIKeyValid bool       `json:"apiKeyValid"`
	DatabaseOK  bool       `json:"databaseOk"`
	Version     string     `json:"version,omitempty"`
	Supported   bool       `json:"supported"`
	SupportNote string     `json:"supportNote,omitempty"`
	LatencyMs   int64      `json:"latencyMs"`
	CheckedAt   *time.Time `json:"checkedAt,omitempty"`
	LastError   string     `json:"lastError,omitempty"`
}

type healthMonitor struct {
	hs  *hsclient.Client
	log *slog.Logger

	mu     sync.RWMutex
	status HeadscaleStatus
}

func newHealthMonitor(hs *hsclient.Client, log *slog.Logger) *healthMonitor {
	return &healthMonitor{hs: hs, log: log}
}

// run probes until ctx is done.
func (h *healthMonitor) run(ctx context.Context, interval time.Duration) {
	h.probe(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.probe(ctx)
		}
	}
}

func (h *healthMonitor) probe(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var s HeadscaleStatus
	start := time.Now()

	version, verr := h.hs.ServerVersion(ctx)
	if verr == nil {
		s.Reachable = true
		s.Version = version
		s.Supported, s.SupportNote = evaluateSupport(version)
	}

	health, herr := h.hs.Health(ctx)
	switch {
	case herr == nil:
		s.Reachable = true
		s.APIKeyValid = true
		s.DatabaseOK = health.DatabaseConnectivity
	case hsclient.IsUnauthenticated(herr):
		s.Reachable = true
		s.APIKeyValid = false
		s.LastError = "headscale rejected the configured API key (expired or revoked?)"
	default:
		if verr != nil {
			s.LastError = verr.Error()
		} else {
			s.LastError = herr.Error()
		}
	}

	s.LatencyMs = time.Since(start).Milliseconds()
	now := time.Now().UTC()
	s.CheckedAt = &now

	h.mu.Lock()
	prev := h.status
	h.status = s
	h.mu.Unlock()

	if prev.Reachable != s.Reachable || prev.APIKeyValid != s.APIKeyValid {
		h.log.Info("headscale status changed",
			"reachable", s.Reachable, "apiKeyValid", s.APIKeyValid, "version", s.Version, "err", s.LastError)
	}
}

func (h *healthMonitor) get() HeadscaleStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.status
}

// evaluateSupport compares a headscale version against the supported range.
func evaluateSupport(version string) (bool, string) {
	parts := strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3)
	if len(parts) < 2 {
		return false, fmt.Sprintf("could not parse headscale version %q; this UI targets v0.%d.x", version, config.MaxHeadscaleMinor)
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(strings.SplitN(parts[1], "-", 2)[0])
	if err1 != nil || err2 != nil {
		return false, fmt.Sprintf("could not parse headscale version %q", version)
	}
	if major != 0 || minor < config.MinHeadscaleMinor || minor > config.MaxHeadscaleMinor {
		note := fmt.Sprintf("headscale v%s detected; this UI targets v0.%d.x — some operations may fail.", version, config.MaxHeadscaleMinor)
		if major > 0 || minor > config.MaxHeadscaleMinor {
			note += " Newer headscale releases change the API (0.30 removes gRPC and reworks errors)."
		}
		return false, note
	}
	return true, ""
}
