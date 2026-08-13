package hsclient

import (
	"context"
	"net/http"
)

// GetPolicy reads the current ACL policy. Works in both policy modes: in
// database mode UpdatedAt is set; in file mode headscale returns the file
// contents as-is. GET /api/v1/policy
func (c *Client) GetPolicy(ctx context.Context) (*Policy, error) {
	var out Policy
	if err := c.do(ctx, http.MethodGet, "/policy", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetPolicy replaces the ACL policy. Only permitted when headscale runs with
// policy.mode: database — in file mode the server rejects the write (detect
// with IsPolicyUpdateDisabled). Headscale validates the policy, runs its
// tests/sshTests blocks, persists, reloads, and pushes to nodes immediately.
// PUT /api/v1/policy
func (c *Client) SetPolicy(ctx context.Context, policyHuJSON string) (*Policy, error) {
	body := struct {
		Policy string `json:"policy"`
	}{policyHuJSON}
	var out Policy
	if err := c.do(ctx, http.MethodPut, "/policy", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckPolicy dry-run-validates a policy against the server's live users and
// nodes (including the tests/sshTests blocks) without applying it. A nil
// return means the policy is valid; validation failures surface as *Error
// with InvalidArgument and the validation text in Message.
// POST /api/v1/policy/check (new in 0.29)
func (c *Client) CheckPolicy(ctx context.Context, policyHuJSON string) error {
	body := struct {
		Policy string `json:"policy"`
	}{policyHuJSON}
	return c.do(ctx, http.MethodPost, "/policy/check", nil, body, nil)
}
