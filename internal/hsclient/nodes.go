package hsclient

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// ListNodes returns all nodes, optionally filtered by user name.
// GET /api/v1/node
func (c *Client) ListNodes(ctx context.Context, userName string) ([]Node, error) {
	q := url.Values{}
	if userName != "" {
		q.Set("user", userName)
	}
	var out struct {
		Nodes []Node `json:"nodes"`
	}
	if err := c.do(ctx, http.MethodGet, "/node", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Nodes, nil
}

// GetNode returns one node. GET /api/v1/node/{nodeId}
func (c *Client) GetNode(ctx context.Context, nodeID string) (*Node, error) {
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodGet, "/node/"+url.PathEscape(nodeID), nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}

// DeleteNode removes a node from the tailnet. DELETE /api/v1/node/{nodeId}
func (c *Client) DeleteNode(ctx context.Context, nodeID string) error {
	return c.do(ctx, http.MethodDelete, "/node/"+url.PathEscape(nodeID), nil, nil, nil)
}

// ExpireSpec selects one of the three expiry actions of the 0.29 expire
// endpoint. Zero value = expire now. At and Never are mutually exclusive
// (the server rejects both together with InvalidArgument).
type ExpireSpec struct {
	// At expires the node key at a future time instead of immediately.
	At *time.Time
	// Never disables expiry entirely (expiry set to null).
	Never bool
}

// ExpireNode expires (logs out) a node, schedules a future expiry, or
// disables expiry. POST /api/v1/node/{nodeId}/expire
func (c *Client) ExpireNode(ctx context.Context, nodeID string, spec ExpireSpec) (*Node, error) {
	q := url.Values{}
	if spec.At != nil {
		q.Set("expiry", spec.At.UTC().Format(time.RFC3339))
	}
	if spec.Never {
		q.Set("disableExpiry", "true")
	}
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodPost, "/node/"+url.PathEscape(nodeID)+"/expire", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}

// RenameNode changes a node's given name.
// POST /api/v1/node/{nodeId}/rename/{newName}
func (c *Client) RenameNode(ctx context.Context, nodeID, newName string) (*Node, error) {
	var out struct {
		Node *Node `json:"node"`
	}
	path := "/node/" + url.PathEscape(nodeID) + "/rename/" + url.PathEscape(newName)
	if err := c.do(ctx, http.MethodPost, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}

// SetTags replaces the node's tag set. Since headscale 0.28 tagging a
// user-owned node converts it to tag ownership. POST /api/v1/node/{nodeId}/tags
func (c *Client) SetTags(ctx context.Context, nodeID string, tags []string) (*Node, error) {
	if tags == nil {
		tags = []string{}
	}
	body := struct {
		Tags []string `json:"tags"`
	}{tags}
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodPost, "/node/"+url.PathEscape(nodeID)+"/tags", nil, body, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}

// SetApprovedRoutes replaces the node's complete approved-route set (this is
// NOT incremental — pass the full desired list; an empty slice revokes all).
// POST /api/v1/node/{nodeId}/approve_routes
func (c *Client) SetApprovedRoutes(ctx context.Context, nodeID string, routes []string) (*Node, error) {
	if routes == nil {
		routes = []string{}
	}
	body := struct {
		Routes []string `json:"routes"`
	}{routes}
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodPost, "/node/"+url.PathEscape(nodeID)+"/approve_routes", nil, body, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}

// RegisterNode completes an interactive registration using the legacy
// endpoint (deprecated in 0.29 in favor of AuthRegister, kept for
// troubleshooting). POST /api/v1/node/register
func (c *Client) RegisterNode(ctx context.Context, userName, key string) (*Node, error) {
	q := url.Values{}
	q.Set("user", userName)
	q.Set("key", key)
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodPost, "/node/register", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}

// BackfillNodeIPs assigns missing IPv4/IPv6 addresses after a prefix-family
// config change. confirmed=false is a dry run returning planned changes.
// POST /api/v1/node/backfillips
func (c *Client) BackfillNodeIPs(ctx context.Context, confirmed bool) ([]string, error) {
	q := url.Values{}
	if confirmed {
		q.Set("confirmed", "true")
	}
	var out struct {
		Changes []string `json:"changes"`
	}
	if err := c.do(ctx, http.MethodPost, "/node/backfillips", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Changes, nil
}

// DebugCreateNode creates a node record without a real client (testing only).
// POST /api/v1/debug/node
func (c *Client) DebugCreateNode(ctx context.Context, req DebugCreateNodeRequest) (*Node, error) {
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodPost, "/debug/node", nil, req, &out); err != nil {
		return nil, err
	}
	return out.Node, nil
}
