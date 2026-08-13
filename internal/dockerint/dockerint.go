// Package dockerint talks to the Docker Engine API over a unix socket to
// send SIGHUP to the headscale container after file-mode policy writes.
// It uses plain net/http — no docker CLI or SDK — so it works from a
// distroless image. The integration is strictly opt-in (DOCKER_SOCK unset =
// disabled) and scoped to one container found by label or name; docs
// recommend exposing the socket through docker-socket-proxy.
package dockerint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client signals containers over the Docker Engine API.
type Client struct {
	hc            *http.Client
	containerLbl  string // "key=value" label selector
	containerName string // exact name match (preferred over label if set)
}

// New builds a Client for the socket at sockPath (e.g.
// "unix:///var/run/docker.sock" or a bare filesystem path).
func New(sockPath, containerLabel, containerName string) *Client {
	path := strings.TrimPrefix(sockPath, "unix://")
	return &Client{
		hc: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			},
		},
		containerLbl:  containerLabel,
		containerName: containerName,
	}
}

type container struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	State string   `json:"State"`
}

// FindContainer locates the target headscale container. Returns id, display
// name, error.
func (c *Client) FindContainer(ctx context.Context) (string, string, error) {
	filters := map[string][]string{}
	if c.containerName != "" {
		filters["name"] = []string{c.containerName}
	} else if c.containerLbl != "" {
		filters["label"] = []string{c.containerLbl}
	} else {
		return "", "", fmt.Errorf("no container label or name configured")
	}
	fj, _ := json.Marshal(filters)
	u := "http://docker/containers/json?filters=" + url.QueryEscape(string(fj))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("docker socket unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("docker API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var list []container
	if err := json.Unmarshal(body, &list); err != nil {
		return "", "", fmt.Errorf("decoding docker response: %w", err)
	}
	// Exact-name post-filter: the docker name filter is a substring match.
	if c.containerName != "" {
		var exact []container
		for _, ct := range list {
			for _, n := range ct.Names {
				if strings.TrimPrefix(n, "/") == c.containerName {
					exact = append(exact, ct)
					break
				}
			}
		}
		list = exact
	}
	if len(list) == 0 {
		return "", "", fmt.Errorf("no running container matched (label %q / name %q)", c.containerLbl, c.containerName)
	}
	if len(list) > 1 {
		return "", "", fmt.Errorf("%d containers matched — narrow the label or set DOCKER_CONTAINER_NAME", len(list))
	}
	name := list[0].ID[:12]
	if len(list[0].Names) > 0 {
		name = strings.TrimPrefix(list[0].Names[0], "/")
	}
	return list[0].ID, name, nil
}

// SignalHUP sends SIGHUP to the target container (headscale reloads its
// policy file on SIGHUP in file mode).
func (c *Client) SignalHUP(ctx context.Context) error {
	id, _, err := c.FindContainer(ctx)
	if err != nil {
		return err
	}
	u := "http://docker/containers/" + id + "/kill?signal=SIGHUP"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("signaling container: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker kill returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Status describes integration reachability for /api/meta.
type Status struct {
	Reachable     bool   `json:"reachable"`
	ContainerName string `json:"containerName,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Probe checks socket reachability and target resolution.
func (c *Client) Probe(ctx context.Context) Status {
	_, name, err := c.FindContainer(ctx)
	if err != nil {
		return Status{Reachable: false, Error: err.Error()}
	}
	return Status{Reachable: true, ContainerName: name}
}
