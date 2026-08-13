// Package dnsrecords manages the JSON file behind headscale's
// dns.extra_records_path. Headscale watches that file and hot-reloads on
// change (checksum-based), so writes use stable, sorted serialization and
// atomic same-directory renames; no restart or signal is needed. Only A and
// AAAA records are supported — they are the only types Tailscale clients
// process.
package dnsrecords

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/panagiotis1226/claude-head/internal/store"
)

// Record is one extra DNS record ({name, type, value}).
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Manager edits one extra-records file.
type Manager struct {
	path string
	st   *store.Store
	mu   sync.Mutex
}

// New builds a Manager for the file at path ("" disables the feature).
func New(path string, st *store.Store) *Manager {
	return &Manager{path: path, st: st}
}

// Enabled reports whether an extra-records path is configured.
func (m *Manager) Enabled() bool { return m.path != "" }

// Writable reports whether the file can be written.
func (m *Manager) Writable() bool {
	if m.path == "" {
		return false
	}
	f, err := os.OpenFile(m.path, os.O_WRONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			// Creating the file counts as writable if the directory allows it.
			probe, err := os.CreateTemp(filepath.Dir(m.path), ".probe-*")
			if err != nil {
				return false
			}
			probe.Close()
			os.Remove(probe.Name())
			return true
		}
		return false
	}
	f.Close()
	return true
}

// State is what the DNS page renders.
type State struct {
	Records []Record `json:"records"`
	Hash    string   `json:"hash"` // conflict-detection token for saves
}

// Load reads the current records. A missing file is an empty list.
func (m *Manager) Load() (*State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadLocked()
}

func (m *Manager) loadLocked() (*State, error) {
	buf, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		return &State{Records: []Record{}, Hash: store.HashContent("")}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading extra-records file: %w", err)
	}
	var records []Record
	if len(strings.TrimSpace(string(buf))) > 0 {
		if err := json.Unmarshal(buf, &records); err != nil {
			return nil, fmt.Errorf("extra-records file is not a JSON array of {name,type,value}: %w", err)
		}
	}
	if records == nil {
		records = []Record{}
	}
	return &State{Records: records, Hash: store.HashContent(string(buf))}, nil
}

// ConflictError signals the file changed since the client loaded it.
type ConflictError struct{ Current *State }

func (e *ConflictError) Error() string {
	return "the extra-records file changed since you loaded it"
}

var hostnameLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// Validate checks one record.
func Validate(r Record) error {
	switch r.Type {
	case "A":
		ip := net.ParseIP(r.Value)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("record %q: value %q is not a valid IPv4 address", r.Name, r.Value)
		}
	case "AAAA":
		ip := net.ParseIP(r.Value)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("record %q: value %q is not a valid IPv6 address", r.Name, r.Value)
		}
	default:
		return fmt.Errorf("record %q: type must be A or AAAA (Tailscale clients only process those), got %q", r.Name, r.Type)
	}
	name := strings.TrimSuffix(r.Name, ".")
	if name == "" || len(name) > 253 {
		return fmt.Errorf("record name %q is not a valid DNS name", r.Name)
	}
	for _, label := range strings.Split(name, ".") {
		if !hostnameLabel.MatchString(label) {
			return fmt.Errorf("record name %q has an invalid label %q", r.Name, label)
		}
	}
	return nil
}

// Save validates and writes the full record set. expectedHash must match the
// file's current hash (from Load) or a ConflictError is returned; pass "" to
// force-overwrite.
func (m *Manager) Save(records []Record, expectedHash string) (*State, error) {
	for _, r := range records {
		if err := Validate(r); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	for _, r := range records {
		k := r.Name + "/" + r.Type
		if seen[k] {
			return nil, fmt.Errorf("duplicate record %s (%s)", r.Name, r.Type)
		}
		seen[k] = true
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.loadLocked()
	if err != nil {
		return nil, err
	}
	if expectedHash != "" && current.Hash != expectedHash {
		return nil, &ConflictError{Current: current}
	}

	// Stable output: sorted records, two-space indent, sorted keys (encoding/json
	// already emits struct fields in declaration order — stable across runs).
	sorted := append([]Record(nil), records...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Type < sorted[j].Type
	})
	buf, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return nil, err
	}
	buf = append(buf, '\n')

	dir := filepath.Dir(m.path)
	tmp, err := os.CreateTemp(dir, ".extra-records-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("creating temp file (is the mount writable?): %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmpName, 0o644); err == nil {
		// best-effort; headscale only needs read access
	}
	if err := os.Rename(tmpName, m.path); err != nil {
		return nil, fmt.Errorf("replacing extra-records file: %w", err)
	}
	if m.st != nil {
		m.st.SaveExtraRecordsVersion(string(buf))
	}
	return &State{Records: sorted, Hash: store.HashContent(string(buf))}, nil
}
