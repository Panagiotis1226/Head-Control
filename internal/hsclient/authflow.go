package hsclient

import (
	"context"
	"net/http"
)

// AuthRegister registers a pending node (identified by the auth ID from the
// client's login URL) to a user, addressed by NAME (not numeric ID — unlike
// most 0.29 endpoints). Replaces the deprecated RegisterNode.
// POST /api/v1/auth/register (new in 0.29)
func (c *Client) AuthRegister(ctx context.Context, userName, authID string) (*Node, error) {
	body := struct {
		User   string `json:"user"`
		AuthID string `json:"authId"`
	}{userName, authID}
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodPost, "/auth/register", nil, body, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}

// AuthApprove approves a pending authentication session (interactive web
// auth or an SSH check-action session). NotFound means no pending session
// exists for that auth ID. POST /api/v1/auth/approve (new in 0.29)
func (c *Client) AuthApprove(ctx context.Context, authID string) error {
	body := struct {
		AuthID string `json:"authId"`
	}{authID}
	return c.do(ctx, http.MethodPost, "/auth/approve", nil, body, nil)
}

// AuthReject rejects a pending authentication session.
// POST /api/v1/auth/reject (new in 0.29)
func (c *Client) AuthReject(ctx context.Context, authID string) error {
	body := struct {
		AuthID string `json:"authId"`
	}{authID}
	return c.do(ctx, http.MethodPost, "/auth/reject", nil, body, nil)
}

// Health reports API health incl. database connectivity. Requires auth like
// every /api/v1 route, so it doubles as an API-key validity probe.
// GET /api/v1/health (new in 0.29)
func (c *Client) Health(ctx context.Context) (*Health, error) {
	var out Health
	if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
