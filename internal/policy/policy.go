// Package policy orchestrates ACL reads and writes across headscale's two
// policy modes.
//
//   - database mode: PUT /api/v1/policy applies and pushes immediately.
//   - file mode: Head-Control writes the mounted policy file atomically
//     (tmp + fsync + rename, keeping a .bak), then reloads headscale via the
//     optional docker integration (SIGHUP) or reports "reload pending" for a
//     manual `docker kill -s HUP headscale`.
//
// Mode is resolved without ever probing with writes: explicit config wins;
// otherwise it is learned lazily from the first save attempt and remembered.
// Every save (and every externally-observed change) is snapshotted into the
// store for history/diff/rollback.
package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/panagiotis1226/head-control/internal/hsclient"
	"github.com/panagiotis1226/head-control/internal/store"
)

// Mode of policy management, as currently known.
type Mode string

const (
	ModeUnknown  Mode = "unknown" // auto, not yet learned
	ModeDatabase Mode = "database"
	ModeFile     Mode = "file"
)

const kvDetectedMode = "policy.detected_mode"

// Reloader triggers a headscale policy reload (implemented by dockerint).
type Reloader interface {
	SignalHUP(ctx context.Context) error
}

// Manager coordinates policy state.
type Manager struct {
	hs       *hsclient.Client
	st       *store.Store
	log      *slog.Logger
	filePath string   // "" = no mount
	reloader Reloader // nil = no docker integration

	mu   sync.Mutex
	mode Mode // resolved or learned
}

// New builds a Manager. configuredMode is POLICY_MODE ("auto"/"database"/"file").
func New(hs *hsclient.Client, st *store.Store, log *slog.Logger, configuredMode, filePath string, reloader Reloader) *Manager {
	m := &Manager{hs: hs, st: st, log: log, filePath: filePath, reloader: reloader}
	switch configuredMode {
	case "database":
		m.mode = ModeDatabase
	case "file":
		m.mode = ModeFile
	default:
		m.mode = ModeUnknown
		if saved, _ := st.GetKV(kvDetectedMode); saved == string(ModeDatabase) || saved == string(ModeFile) {
			m.mode = Mode(saved)
		}
		// A policy file mount strongly implies file mode.
		if m.mode == ModeUnknown && filePath != "" {
			m.mode = ModeFile
		}
	}
	return m
}

// State is the policy page's server-side state.
type State struct {
	Policy        string     `json:"policy"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
	Mode          string     `json:"mode"`     // unknown|database|file
	Writable      bool       `json:"writable"` // can Save succeed at all
	FileMounted   bool       `json:"fileMounted"`
	FileWritable  bool       `json:"fileWritable"`
	ReloadPending bool       `json:"reloadPending"`
	DockerReload  bool       `json:"dockerReload"` // integration configured
}

// Get returns the current policy plus mode/capability state, snapshotting
// externally-made changes into history as a side effect.
func (m *Manager) Get(ctx context.Context) (*State, error) {
	p, err := m.hs.GetPolicy(ctx)
	if err != nil {
		// A fresh database-mode headscale that has never had a policy set
		// answers GET /api/v1/policy with an error (verified against a live
		// v0.29.3). Treat that as an empty policy so the editor opens
		// instead of the whole page erroring.
		if isNoPolicyYet(err) {
			p = &hsclient.Policy{Policy: ""}
		} else {
			return nil, err
		}
	}
	m.snapshotIfChanged(p.Policy, "external-snapshot", "")

	m.mu.Lock()
	mode := m.mode
	m.mu.Unlock()

	st := &State{
		Policy:       p.Policy,
		UpdatedAt:    p.UpdatedAt,
		Mode:         string(mode),
		FileMounted:  m.filePath != "",
		FileWritable: m.fileWritable(),
		DockerReload: m.reloader != nil,
	}
	// updatedAt is only ever set in database mode; learn from it.
	if p.UpdatedAt != nil && mode == ModeUnknown {
		m.setMode(ModeDatabase)
		st.Mode = string(ModeDatabase)
	}
	st.ReloadPending = m.reloadPending(p.Policy)
	st.Writable = m.writable()
	return st, nil
}

// Check dry-run-validates a policy document against live server state.
func (m *Manager) Check(ctx context.Context, policy string) error {
	return m.hs.CheckPolicy(ctx, policy)
}

// SaveResult reports what a save did.
type SaveResult struct {
	Mode          string     `json:"mode"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
	ReloadPending bool       `json:"reloadPending"`
	Reloaded      bool       `json:"reloaded"`
	VersionID     int64      `json:"versionId"`
	Warning       string     `json:"warning,omitempty"`
}

// Save validates then applies a policy document via whichever mode is active.
// In auto mode the first save learns the real mode from the server's answer.
func (m *Manager) Save(ctx context.Context, policyDoc, comment string) (*SaveResult, error) {
	if err := m.hs.CheckPolicy(ctx, policyDoc); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	m.mu.Lock()
	mode := m.mode
	m.mu.Unlock()

	if mode != ModeFile {
		// Database mode, or unknown (try the API first — a plain PUT is the
		// designed path and its failure is the documented file-mode signal).
		p, err := m.hs.SetPolicy(ctx, policyDoc)
		if err == nil {
			m.setMode(ModeDatabase)
			id, _ := m.st.SavePolicyVersion(store.PolicyVersion{
				Source: "ui", Mode: string(ModeDatabase), Content: policyDoc, Comment: comment,
			})
			return &SaveResult{Mode: string(ModeDatabase), UpdatedAt: p.UpdatedAt, Reloaded: true, VersionID: id}, nil
		}
		if !hsclient.IsPolicyUpdateDisabled(err) {
			return nil, err
		}
		m.setMode(ModeFile)
		mode = ModeFile
	}

	// File mode.
	if m.filePath == "" {
		return nil, &NotWritableError{Reason: "headscale runs with policy.mode: file and no policy file is mounted. Mount the policy file into this container (POLICY_FILE_PATH) or switch headscale to policy.mode: database."}
	}
	if err := m.writeFileAtomic(policyDoc); err != nil {
		return nil, err
	}
	id, _ := m.st.SavePolicyVersion(store.PolicyVersion{
		Source: "ui", Mode: string(ModeFile), Content: policyDoc, Comment: comment,
	})
	res := &SaveResult{Mode: string(ModeFile), VersionID: id}

	if m.reloader == nil {
		res.ReloadPending = true
		return res, nil
	}
	if err := m.reloader.SignalHUP(ctx); err != nil {
		res.ReloadPending = true
		res.Warning = "policy file written, but the reload signal failed: " + err.Error() +
			". Reload manually: docker kill -s HUP <headscale-container>"
		return res, nil
	}
	// Verify the reload took: headscale should now serve the new content.
	deadline := time.Now().Add(5 * time.Second)
	want := store.HashContent(policyDoc)
	for time.Now().Before(deadline) {
		p, err := m.hs.GetPolicy(ctx)
		if err == nil && store.HashContent(p.Policy) == want {
			res.Reloaded = true
			return res, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	res.ReloadPending = true
	res.Warning = "policy file written and SIGHUP sent, but headscale still serves the previous policy. Check the headscale logs."
	return res, nil
}

// NotWritableError marks saves that cannot proceed in the current setup.
type NotWritableError struct{ Reason string }

func (e *NotWritableError) Error() string { return e.Reason }

// isNoPolicyYet detects headscale's "no policy stored yet" GetPolicy failure.
// There is no dedicated code; match the known message shapes ("acl policy
// not found", gorm's "record not found", "empty policy").
func isNoPolicyYet(err error) bool {
	var he *hsclient.Error
	if !errors.As(err, &he) {
		return false
	}
	msg := strings.ToLower(he.Message)
	return strings.Contains(msg, "not found") || strings.Contains(msg, "empty policy")
}

// writeFileAtomic writes the policy file via tmp + fsync + rename, keeping
// the previous content in a .bak beside it. Temp files are created in the
// target's directory so the rename stays on one filesystem (the mount).
func (m *Manager) writeFileAtomic(content string) error {
	dir := filepath.Dir(m.filePath)
	if prev, err := os.ReadFile(m.filePath); err == nil {
		if err := os.WriteFile(m.filePath+".bak", prev, 0o644); err != nil {
			m.log.Warn("could not write policy backup", "err", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".policy-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp policy file (is the mount writable?): %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("writing policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		m.log.Warn("could not chmod policy file", "err", err)
	}
	if err := os.Rename(tmpName, m.filePath); err != nil {
		return fmt.Errorf("replacing policy file: %w", err)
	}
	return nil
}

// Versions lists stored snapshots (without content).
func (m *Manager) Versions(limit int) ([]store.PolicyVersion, error) {
	return m.st.ListPolicyVersions(limit)
}

// Version fetches one snapshot including content.
func (m *Manager) Version(id int64) (*store.PolicyVersion, error) {
	return m.st.GetPolicyVersion(id)
}

func (m *Manager) setMode(mode Mode) {
	m.mu.Lock()
	changed := m.mode != mode
	m.mode = mode
	m.mu.Unlock()
	if changed {
		m.st.SetKV(kvDetectedMode, string(mode))
		m.log.Info("policy mode resolved", "mode", mode)
	}
}

func (m *Manager) writable() bool {
	m.mu.Lock()
	mode := m.mode
	m.mu.Unlock()
	switch mode {
	case ModeDatabase:
		return true
	case ModeFile:
		return m.fileWritable()
	default:
		return true // optimistic until learned; the first save resolves it
	}
}

func (m *Manager) fileWritable() bool {
	if m.filePath == "" {
		return false
	}
	f, err := os.OpenFile(m.filePath, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// reloadPending reports whether the mounted file differs from what headscale
// currently serves (file written, reload not yet happened).
func (m *Manager) reloadPending(served string) bool {
	if m.filePath == "" {
		return false
	}
	onDisk, err := os.ReadFile(m.filePath)
	if err != nil {
		return false
	}
	return store.HashContent(string(onDisk)) != store.HashContent(served)
}

// snapshotIfChanged appends a history row when content differs from the
// newest stored snapshot (captures CLI/API/file edits made outside the UI).
func (m *Manager) snapshotIfChanged(content, source, comment string) {
	latest, err := m.st.LatestPolicyHash()
	if err != nil {
		return
	}
	if latest == store.HashContent(content) {
		return
	}
	m.mu.Lock()
	mode := m.mode
	m.mu.Unlock()
	m.st.SavePolicyVersion(store.PolicyVersion{
		Source: source, Mode: string(mode), Content: content, Comment: comment,
	})
}
