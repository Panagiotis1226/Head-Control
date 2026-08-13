package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/panagiotis1226/claude-head/internal/dnsrecords"
	"github.com/panagiotis1226/claude-head/internal/hsclient"
	"github.com/panagiotis1226/claude-head/internal/policy"
)

// apiError is the single error envelope the SPA consumes.
type apiError struct {
	Error struct {
		Code             string `json:"code"`
		Message          string `json:"message"`
		HeadscaleMessage string `json:"headscaleMessage,omitempty"`
		GRPCCode         int    `json:"grpcCode,omitempty"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, message string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	writeJSON(w, status, e)
}

// writeUpstreamErr maps an error from the headscale client (or the policy /
// dns managers) onto the SPA envelope. Headscale's own 401 becomes a 502 —
// an invalid upstream API key must never read as "your UI session expired".
func writeUpstreamErr(w http.ResponseWriter, err error) {
	var nw *policy.NotWritableError
	if errors.As(err, &nw) {
		writeErr(w, http.StatusConflict, "policy_not_writable", nw.Reason)
		return
	}
	var conflict *dnsrecords.ConflictError
	if errors.As(err, &conflict) {
		var e apiError
		e.Error.Code = "conflict"
		e.Error.Message = conflict.Error()
		writeJSON(w, http.StatusConflict, e)
		return
	}

	var he *hsclient.Error
	if errors.As(err, &he) {
		var e apiError
		e.Error.HeadscaleMessage = he.Message
		e.Error.GRPCCode = he.Code
		switch {
		case hsclient.IsUnauthenticated(err):
			e.Error.Code = "headscale_unauthenticated"
			e.Error.Message = "headscale rejected this server's API key (expired or revoked). Create a new key with `headscale apikeys create` and update HEADSCALE_API_KEY."
			writeJSON(w, http.StatusBadGateway, e)
		case he.Code == hsclient.CodeInvalidArgument:
			e.Error.Code = "invalid_argument"
			e.Error.Message = he.Message
			writeJSON(w, http.StatusBadRequest, e)
		case he.Code == hsclient.CodeNotFound:
			e.Error.Code = "not_found"
			e.Error.Message = he.Message
			writeJSON(w, http.StatusNotFound, e)
		default:
			e.Error.Code = "headscale_error"
			e.Error.Message = he.Message
			if e.Error.Message == "" {
				e.Error.Message = "headscale returned an unexpected response"
			}
			writeJSON(w, http.StatusBadGateway, e)
		}
		return
	}
	writeErr(w, http.StatusBadGateway, "upstream_error", err.Error())
}

// decodeBody reads a JSON request body into v (1MB cap).
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}
