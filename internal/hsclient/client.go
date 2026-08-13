// Package hsclient is a typed client for the headscale v0.29.x REST API
// (the grpc-gateway JSON API under /api/v1).
//
// The client covers every operation in the pinned
// testdata/headscale-v0.29.3.swagger.json contract; a contract test asserts
// that coverage. All uint64 IDs are treated as opaque strings, timestamps are
// RFC3339, and errors are decoded from gRPC rpcStatus JSON bodies into *Error.
package hsclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Client talks to one headscale server with one API key.
type Client struct {
	base   *url.URL
	apiKey string
	hc     *http.Client
}

// Option customizes a Client.
type Option func(*Client) error

// WithHTTPClient replaces the underlying http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) error {
		c.hc = hc
		return nil
	}
}

// WithCACert adds a PEM CA bundle for the headscale server's TLS certificate.
func WithCACert(path string) Option {
	return func(c *Client) error {
		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates found in %s", path)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
		c.hc = &http.Client{Transport: transport, Timeout: c.hc.Timeout}
		return nil
	}
}

// New builds a Client for the headscale server at baseURL.
func New(baseURL, apiKey string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid headscale URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("headscale URL must be http(s), got %q", baseURL)
	}
	c := &Client{
		base:   u,
		apiKey: apiKey,
		hc:     &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// BaseURL returns the configured headscale base URL.
func (c *Client) BaseURL() string { return c.base.String() }

// APIKeyPrefix returns the prefix segment of the configured API key
// (hskey-api-{prefix}-{secret}), or "" if the key has another format.
// Used to mark "the key this UI uses" in API-key listings without ever
// exposing the secret.
func (c *Client) APIKeyPrefix() string {
	parts := strings.Split(c.apiKey, "-")
	if len(parts) == 4 && parts[0] == "hskey" && parts[1] == "api" {
		return parts[2]
	}
	// Pre-0.28 keys are "{prefix}.{secret}".
	if i := strings.IndexByte(c.apiKey, '.'); i > 0 {
		return c.apiKey[:i]
	}
	return ""
}

// do performs one API call. path is relative to /api/v1 (leading slash
// required). body (if non-nil) is JSON-encoded; out (if non-nil) receives the
// decoded response.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1" + path
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("calling headscale: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("reading headscale response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseError(resp.StatusCode, respBody)
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decoding headscale response: %w", err)
		}
	}
	return nil
}

var versionRe = regexp.MustCompile(`v?(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)`)

// ServerVersion fetches the unauthenticated /version endpoint (not part of
// /api/v1) and extracts a semver-looking version string. Returns the raw body
// as fallback when no version pattern is found.
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("headscale /version returned %d", resp.StatusCode)
	}
	text := strings.TrimSpace(string(body))
	// The body may be plain text or JSON ({"version": "..."}).
	var vj struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &vj) == nil && vj.Version != "" {
		text = vj.Version
	}
	if m := versionRe.FindStringSubmatch(text); m != nil {
		return m[1], nil
	}
	return text, nil
}
