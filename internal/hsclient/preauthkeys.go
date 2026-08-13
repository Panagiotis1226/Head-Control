package hsclient

import (
	"context"
	"net/http"
	"net/url"
)

// CreatePreAuthKey mints a pre-auth key. The response is the only place the
// full secret ever appears (bcrypt-hashed at rest since 0.28).
// POST /api/v1/preauthkey
func (c *Client) CreatePreAuthKey(ctx context.Context, req CreatePreAuthKeyRequest) (*PreAuthKey, error) {
	var out struct {
		PreAuthKey *PreAuthKey `json:"preAuthKey"`
	}
	if err := c.do(ctx, http.MethodPost, "/preauthkey", nil, req, &out); err != nil {
		return nil, err
	}
	return out.PreAuthKey, nil
}

// ListPreAuthKeys returns every pre-auth key across all users (the per-user
// filter was removed in 0.28). GET /api/v1/preauthkey
func (c *Client) ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	var out struct {
		PreAuthKeys []PreAuthKey `json:"preAuthKeys"`
	}
	if err := c.do(ctx, http.MethodGet, "/preauthkey", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.PreAuthKeys, nil
}

// ExpirePreAuthKey expires a key by numeric ID. POST /api/v1/preauthkey/expire
func (c *Client) ExpirePreAuthKey(ctx context.Context, id string) error {
	body := struct {
		ID string `json:"id"`
	}{id}
	return c.do(ctx, http.MethodPost, "/preauthkey/expire", nil, body, nil)
}

// DeletePreAuthKey deletes a key by numeric ID (passed as a query parameter —
// the endpoint has no path parameter). DELETE /api/v1/preauthkey
func (c *Client) DeletePreAuthKey(ctx context.Context, id string) error {
	q := url.Values{}
	q.Set("id", id)
	return c.do(ctx, http.MethodDelete, "/preauthkey", q, nil, nil)
}
