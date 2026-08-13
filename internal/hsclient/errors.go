package hsclient

import (
	"encoding/json"
	"fmt"
	"strings"
)

// gRPC status codes that headscale's grpc-gateway surfaces in error bodies.
const (
	CodeInvalidArgument  = 3
	CodeNotFound         = 5
	CodePermissionDenied = 7
	CodeFailedPrecond    = 9
	CodeUnimplemented    = 12
	CodeInternal         = 13
	CodeUnavailable      = 14
	CodeUnauthenticated  = 16
)

// Error is a failure reported by the headscale API. Headscale answers errors
// as gRPC rpcStatus JSON: {"code": <grpc code>, "message": "...", "details": []}.
type Error struct {
	HTTPStatus int    `json:"httpStatus"`
	Code       int    `json:"code"`
	Message    string `json:"message"`
	Raw        string `json:"-"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("headscale: %s (grpc code %d, http %d)", e.Message, e.Code, e.HTTPStatus)
	}
	return fmt.Sprintf("headscale: http %d: %s", e.HTTPStatus, truncate(e.Raw, 200))
}

// IsNotFound reports whether err is a headscale NotFound error.
func IsNotFound(err error) bool { return hasCode(err, CodeNotFound) }

// IsInvalidArgument reports whether err is a headscale InvalidArgument error.
func IsInvalidArgument(err error) bool { return hasCode(err, CodeInvalidArgument) }

// IsUnauthenticated reports whether headscale rejected our API key.
func IsUnauthenticated(err error) bool {
	var he *Error
	if !asError(err, &he) {
		return false
	}
	return he.Code == CodeUnauthenticated || he.HTTPStatus == 401
}

// IsPolicyUpdateDisabled reports whether a SetPolicy call failed because
// headscale runs with policy.mode: file. There is no dedicated code for this;
// headscale returns types.ErrPolicyUpdateIsDisabled whose message text is the
// only reliable signal, so match on the message substring.
func IsPolicyUpdateDisabled(err error) bool {
	var he *Error
	if !asError(err, &he) {
		return false
	}
	msg := strings.ToLower(he.Message)
	return strings.Contains(msg, "policy update is disabled") ||
		strings.Contains(msg, "update is disabled for modes other than")
}

func hasCode(err error, code int) bool {
	var he *Error
	return asError(err, &he) && he.Code == code
}

func asError(err error, target **Error) bool {
	for err != nil {
		if he, ok := err.(*Error); ok {
			*target = he
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// parseError builds an *Error from a non-2xx response body, tolerating
// non-JSON bodies (e.g. HTML from a misconfigured reverse proxy).
func parseError(httpStatus int, body []byte) *Error {
	e := &Error{HTTPStatus: httpStatus, Raw: string(body)}
	var status struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &status) == nil && (status.Code != 0 || status.Message != "") {
		e.Code = status.Code
		e.Message = status.Message
	}
	return e
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
