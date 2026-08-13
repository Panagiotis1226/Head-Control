// Package config reads Head-Control's configuration from environment
// variables and derives the capability set that drives progressive feature
// disclosure in the UI (policy file editing, DNS records, docker reload
// integration, config display).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Supported headscale range for the runtime compatibility banner.
const (
	MinHeadscaleMinor = 29
	MaxHeadscaleMinor = 29
)

// Config is the process configuration.
type Config struct {
	// Required.
	HeadscaleURL string
	APIKey       string
	// Exactly one of these two is required.
	AdminPassword     string
	AdminPasswordHash string // bcrypt

	ListenAddr      string
	BasePath        string // normalized: "" for root, else "/sub/path" (no trailing slash)
	DataDir         string
	CookieSecure    bool
	SessionLifetime time.Duration

	PolicyMode       string // "auto" | "database" | "file"
	PolicyFilePath   string
	ExtraRecordsPath string
	ConfigPath       string // headscale config.yaml, read-only display

	DockerSock           string
	DockerContainerLabel string
	DockerContainerName  string

	CAFile         string
	HealthInterval time.Duration
	LogLevel       string
	LogFormat      string
	// PublicServerURL is the client-facing headscale URL used in copyable
	// `tailscale up` commands (may differ from HeadscaleURL behind proxies).
	PublicServerURL string
}

// FromEnv loads and validates configuration.
func FromEnv() (*Config, error) {
	c := &Config{
		HeadscaleURL:         strings.TrimSpace(os.Getenv("HEADSCALE_URL")),
		AdminPassword:        os.Getenv("ADMIN_PASSWORD"),
		AdminPasswordHash:    os.Getenv("ADMIN_PASSWORD_HASH"),
		ListenAddr:           envDefault("LISTEN_ADDR", ":8000"),
		DataDir:              envDefault("DATA_DIR", "/data"),
		PolicyMode:           envDefault("POLICY_MODE", "auto"),
		PolicyFilePath:       os.Getenv("POLICY_FILE_PATH"),
		ExtraRecordsPath:     os.Getenv("EXTRA_RECORDS_PATH"),
		ConfigPath:           os.Getenv("HEADSCALE_CONFIG_PATH"),
		DockerSock:           os.Getenv("DOCKER_SOCK"),
		DockerContainerLabel: envDefault("DOCKER_CONTAINER_LABEL", "me.headcontrol.target=headscale"),
		DockerContainerName:  os.Getenv("DOCKER_CONTAINER_NAME"),
		CAFile:               os.Getenv("HEADSCALE_CA_FILE"),
		LogLevel:             envDefault("LOG_LEVEL", "info"),
		LogFormat:            envDefault("LOG_FORMAT", "text"),
		PublicServerURL:      os.Getenv("PUBLIC_SERVER_URL"),
	}

	var err error
	if c.APIKey, err = envOrFile("HEADSCALE_API_KEY"); err != nil {
		return nil, err
	}
	if c.AdminPassword == "" {
		if c.AdminPassword, err = envFileOnly("ADMIN_PASSWORD_FILE"); err != nil {
			return nil, err
		}
	}

	if c.HeadscaleURL == "" {
		return nil, fmt.Errorf("HEADSCALE_URL is required (e.g. https://headscale.example.com)")
	}
	if c.APIKey == "" {
		return nil, fmt.Errorf("HEADSCALE_API_KEY (or HEADSCALE_API_KEY_FILE) is required — create one with `headscale apikeys create`")
	}
	if c.AdminPassword == "" && c.AdminPasswordHash == "" {
		return nil, fmt.Errorf("ADMIN_PASSWORD or ADMIN_PASSWORD_HASH is required (generate a hash with the hash-password subcommand)")
	}
	if c.AdminPasswordHash != "" && !strings.HasPrefix(c.AdminPasswordHash, "$2") {
		return nil, fmt.Errorf("ADMIN_PASSWORD_HASH does not look like a bcrypt hash")
	}

	switch c.PolicyMode {
	case "auto", "database", "file":
	default:
		return nil, fmt.Errorf("POLICY_MODE must be auto, database, or file (got %q)", c.PolicyMode)
	}
	if c.PolicyMode == "file" && c.PolicyFilePath == "" {
		return nil, fmt.Errorf("POLICY_MODE=file requires POLICY_FILE_PATH (mount headscale's policy file into this container)")
	}

	if c.BasePath, err = normalizeBasePath(os.Getenv("BASE_PATH")); err != nil {
		return nil, err
	}
	if c.CookieSecure, err = envBool("COOKIE_SECURE", true); err != nil {
		return nil, err
	}
	if c.SessionLifetime, err = envDuration("SESSION_LIFETIME", 12*time.Hour); err != nil {
		return nil, err
	}
	if c.HealthInterval, err = envDuration("HEALTH_INTERVAL", 30*time.Second); err != nil {
		return nil, err
	}
	if c.PublicServerURL == "" {
		c.PublicServerURL = c.HeadscaleURL
	}
	return c, nil
}

// DockerEnabled reports whether the reload integration is configured.
func (c *Config) DockerEnabled() bool { return c.DockerSock != "" }

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false (got %q)", key, v)
	}
	return b, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 30s or 12h (got %q)", key, v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return d, nil
}

// envOrFile reads KEY, falling back to the path named by KEY_FILE.
func envOrFile(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return strings.TrimSpace(v), nil
	}
	return envFileOnly(key + "_FILE")
}

func envFileOnly(fileKey string) (string, error) {
	path := os.Getenv(fileKey)
	if path == "" {
		return "", nil
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s (%s): %w", fileKey, path, err)
	}
	return strings.TrimSpace(string(buf)), nil
}

func normalizeBasePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "", nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if strings.Contains(p, "//") || strings.ContainsAny(p, " ?#") {
		return "", fmt.Errorf("BASE_PATH %q is not a clean URL path", p)
	}
	return p, nil
}
