package hsclient

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// CreateAPIKey mints a new API key; the returned string is the only time the
// full secret is available. POST /api/v1/apikey
func (c *Client) CreateAPIKey(ctx context.Context, expiration time.Time) (string, error) {
	body := struct {
		Expiration string `json:"expiration"`
	}{expiration.UTC().Format(time.RFC3339)}
	var out struct {
		APIKey string `json:"apiKey"`
	}
	if err := c.do(ctx, http.MethodPost, "/apikey", nil, body, &out); err != nil {
		return "", err
	}
	return out.APIKey, nil
}

// ListAPIKeys returns key metadata (never secrets). GET /api/v1/apikey
func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var out struct {
		APIKeys []APIKey `json:"apiKeys"`
	}
	if err := c.do(ctx, http.MethodGet, "/apikey", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.APIKeys, nil
}

// ExpireAPIKey expires a key immediately, identified by prefix or numeric ID
// (either works; prefix wins if both set). POST /api/v1/apikey/expire
func (c *Client) ExpireAPIKey(ctx context.Context, prefix, id string) error {
	body := struct {
		Prefix string `json:"prefix,omitempty"`
		ID     string `json:"id,omitempty"`
	}{prefix, id}
	return c.do(ctx, http.MethodPost, "/apikey/expire", nil, body, nil)
}

// DeleteAPIKey deletes a key by prefix. DELETE /api/v1/apikey/{prefix}
func (c *Client) DeleteAPIKey(ctx context.Context, prefix string) error {
	return c.do(ctx, http.MethodDelete, "/apikey/"+url.PathEscape(prefix), nil, nil, nil)
}
