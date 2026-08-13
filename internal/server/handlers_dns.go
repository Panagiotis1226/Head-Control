package server

import (
	"errors"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/panagiotis1226/head-control/internal/dnsrecords"
	"github.com/panagiotis1226/head-control/internal/store"
)

// dnsConfigView is the read-only display of headscale's dns config block,
// available only when the operator mounts config.yaml (HEADSCALE_CONFIG_PATH).
type dnsConfigView struct {
	MagicDNS         *bool  `yaml:"magic_dns" json:"magicDns,omitempty"`
	BaseDomain       string `yaml:"base_domain" json:"baseDomain,omitempty"`
	OverrideLocalDNS *bool  `yaml:"override_local_dns" json:"overrideLocalDns,omitempty"`
	Nameservers      struct {
		Global []string            `yaml:"global" json:"global,omitempty"`
		Split  map[string][]string `yaml:"split" json:"split,omitempty"`
	} `yaml:"nameservers" json:"nameservers"`
	SearchDomains    []string            `yaml:"search_domains" json:"searchDomains,omitempty"`
	ExtraRecords     []dnsrecords.Record `yaml:"extra_records" json:"extraRecords,omitempty"`
	ExtraRecordsPath string              `yaml:"extra_records_path" json:"extraRecordsPath,omitempty"`
}

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"recordsEnabled":  s.dns.Enabled(),
		"recordsWritable": s.dns.Enabled() && s.dns.Writable(),
		"configMounted":   s.cfg.ConfigPath != "",
	}

	if s.dns.Enabled() {
		state, err := s.dns.Load()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "records_error", err.Error())
			return
		}
		out["records"] = state.Records
		out["recordsHash"] = state.Hash
	}

	if s.cfg.ConfigPath != "" {
		buf, err := os.ReadFile(s.cfg.ConfigPath)
		if err != nil {
			out["configError"] = "could not read mounted config: " + err.Error()
		} else {
			var cfg struct {
				DNS dnsConfigView `yaml:"dns"`
			}
			if err := yaml.Unmarshal(buf, &cfg); err != nil {
				out["configError"] = "could not parse mounted config: " + err.Error()
			} else {
				out["config"] = cfg.DNS
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSaveDNSRecords(w http.ResponseWriter, r *http.Request) {
	if !s.dns.Enabled() {
		writeErr(w, http.StatusConflict, "records_disabled",
			"extra-records editing is disabled — mount headscale's dns.extra_records_path file and set EXTRA_RECORDS_PATH")
		return
	}
	var req struct {
		Records      []dnsrecords.Record `json:"records"`
		ExpectedHash string              `json:"expectedHash"`
		Force        bool                `json:"force,omitempty"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	expected := req.ExpectedHash
	if req.Force {
		expected = ""
	}
	state, err := s.dns.Save(req.Records, expected)
	if err != nil {
		var conflict *dnsrecords.ConflictError
		if errors.As(err, &conflict) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   map[string]any{"code": "conflict", "message": conflict.Error()},
				"current": conflict.Current,
			})
			return
		}
		s.audit(store.AuditEntry{Action: "dns.records_save", Outcome: "error", Error: err.Error()})
		writeErr(w, http.StatusBadRequest, "records_invalid", err.Error())
		return
	}
	s.audit(store.AuditEntry{Action: "dns.records_save", Summary: "records saved (hot-reloaded by headscale)"})
	writeJSON(w, http.StatusOK, state)
}
