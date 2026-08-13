package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/panagiotis1226/head-control/internal/config"
	"github.com/panagiotis1226/head-control/internal/hsclient"
	"github.com/panagiotis1226/head-control/internal/hsclient/hstest"
	"github.com/panagiotis1226/head-control/internal/store"
)

const testPassword = "correct-horse-battery"

type testEnv struct {
	t     *testing.T
	fake  *hstest.Fake
	srv   *httptest.Server
	csrf  string
	http  *http.Client
	inner *Server
}

func newTestEnv(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()
	fake := hstest.New("hskey-api-uipfx-secret")
	t.Cleanup(fake.Close)

	cfg := &config.Config{
		HeadscaleURL:    fake.URL(),
		APIKey:          "hskey-api-uipfx-secret",
		AdminPassword:   testPassword,
		CookieSecure:    false, // httptest is plain HTTP
		SessionLifetime: time.Hour,
		PolicyMode:      "auto",
		HealthInterval:  time.Hour,
		PublicServerURL: fake.URL(),
	}
	if mutate != nil {
		mutate(cfg)
	}

	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	hs, err := hsclient.New(cfg.HeadscaleURL, cfg.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	inner := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), hs, st)
	srv := httptest.NewServer(inner.Handler())
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{t: t, fake: fake, srv: srv, http: &http.Client{Jar: jar}, inner: inner}
}

func (e *testEnv) login() {
	e.t.Helper()
	resp := e.do("POST", "/api/auth/login", map[string]string{"password": testPassword}, false)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("login failed: %d %s", resp.StatusCode, body)
	}
	var out struct {
		CSRFToken string `json:"csrfToken"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	e.csrf = out.CSRFToken
}

func (e *testEnv) do(method, path string, body any, withCSRF bool) *http.Response {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withCSRF {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAuthFlowAndCSRF(t *testing.T) {
	env := newTestEnv(t, nil)

	// Unauthenticated API calls are rejected.
	resp := env.do("GET", "/api/hs/nodes", nil, false)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 before login, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong password → 401.
	resp = env.do("POST", "/api/auth/login", map[string]string{"password": "wrong"}, false)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 for bad password, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	env.login()

	// Reads work with a session.
	resp = env.do("GET", "/api/hs/nodes", nil, false)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 after login, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Mutations without CSRF are rejected.
	resp = env.do("POST", "/api/hs/users", map[string]string{"name": "alice"}, false)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 without CSRF, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// With CSRF they succeed.
	resp = env.do("POST", "/api/hs/users", map[string]string{"name": "alice"}, true)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 with CSRF, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
}

func TestLoginRateLimit(t *testing.T) {
	env := newTestEnv(t, nil)
	for i := 0; i < 5; i++ {
		resp := env.do("POST", "/api/auth/login", map[string]string{"password": "wrong"}, false)
		resp.Body.Close()
	}
	resp := env.do("POST", "/api/auth/login", map[string]string{"password": testPassword}, false)
	defer resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("expected 429 after 5 failures, got %d", resp.StatusCode)
	}
}

func TestGuardedRouteMerge(t *testing.T) {
	env := newTestEnv(t, nil)
	env.login()
	user := env.fake.AddUser("alice")
	node := env.fake.AddNode(user, "router", "10.0.0.0/24", "192.168.1.0/24")

	// Approve one route with a correct expectation.
	resp := env.do("POST", "/api/hs/nodes/"+node.ID+"/routes", map[string]any{
		"approve":          []string{"10.0.0.0/24"},
		"revoke":           []string{},
		"expectedApproved": []string{},
	}, true)
	out := decode[struct {
		Node hsclient.Node `json:"node"`
	}](t, resp)
	if len(out.Node.ApprovedRoutes) != 1 || out.Node.ApprovedRoutes[0] != "10.0.0.0/24" {
		t.Fatalf("unexpected approved: %v", out.Node.ApprovedRoutes)
	}

	// Stale expectation → 409 with the fresh node.
	resp = env.do("POST", "/api/hs/nodes/"+node.ID+"/routes", map[string]any{
		"approve":          []string{"192.168.1.0/24"},
		"revoke":           []string{},
		"expectedApproved": []string{}, // stale: 10.0.0.0/24 is now approved
	}, true)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 on stale expectation, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPolicyDatabaseModeSave(t *testing.T) {
	env := newTestEnv(t, nil)
	env.login()

	resp := env.do("PUT", "/api/policy", map[string]string{
		"policy": `{"acls":[{"action":"accept","src":["group:eng"],"dst":["*:*"]}]}`,
	}, true)
	out := decode[struct {
		Mode     string `json:"mode"`
		Reloaded bool   `json:"reloaded"`
	}](t, resp)
	if out.Mode != "database" || !out.Reloaded {
		t.Fatalf("expected database-mode immediate save, got %+v", out)
	}

	// Invalid policy is rejected by the pre-save check.
	resp = env.do("PUT", "/api/policy", map[string]string{"policy": `{"acls":[{"src":["INVALID"]}]}`}, true)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for invalid policy, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// History recorded the save.
	resp = env.do("GET", "/api/policy/versions", nil, false)
	hist := decode[struct {
		Versions []store.PolicyVersion `json:"versions"`
	}](t, resp)
	if len(hist.Versions) == 0 {
		t.Fatal("expected at least one policy version")
	}
}

// A fresh database-mode headscale that never had a policy set errors on
// GET /api/v1/policy; the UI must see an empty editable policy instead.
func TestPolicyEmptyDatabaseIsEditable(t *testing.T) {
	env := newTestEnv(t, nil)
	env.fake.Mu.Lock()
	env.fake.Policy = ""
	env.fake.Mu.Unlock()
	env.login()

	resp := env.do("GET", "/api/policy", nil, false)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for never-set policy, got %d: %s", resp.StatusCode, body)
	}
	state := decode[struct {
		Policy   string `json:"policy"`
		Writable bool   `json:"writable"`
	}](t, resp)
	if state.Policy != "" || !state.Writable {
		t.Fatalf("expected empty writable policy, got %+v", state)
	}
}

func TestPolicyFileModeFallback(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.hujson")
	os.WriteFile(policyPath, []byte(`{"acls":[]}`), 0o644)

	env := newTestEnv(t, func(c *config.Config) {
		c.PolicyFilePath = policyPath
	})
	env.fake.Mu.Lock()
	env.fake.PolicyMode = "file"
	env.fake.Policy = `{"acls":[]}`
	env.fake.Mu.Unlock()
	env.login()

	// GET reports file mode capabilities.
	resp := env.do("GET", "/api/policy", nil, false)
	state := decode[struct {
		Mode         string `json:"mode"`
		FileMounted  bool   `json:"fileMounted"`
		FileWritable bool   `json:"fileWritable"`
		Writable     bool   `json:"writable"`
	}](t, resp)
	if !state.FileMounted || !state.FileWritable {
		t.Fatalf("file capabilities wrong: %+v", state)
	}

	// Save writes the file and reports reload pending (no docker integration).
	newPolicy := `{"acls":[{"action":"accept","src":["tag:web"],"dst":["tag:db:5432"]}]}`
	resp = env.do("PUT", "/api/policy", map[string]string{"policy": newPolicy}, true)
	out := decode[struct {
		Mode          string `json:"mode"`
		ReloadPending bool   `json:"reloadPending"`
	}](t, resp)
	if out.Mode != "file" || !out.ReloadPending {
		t.Fatalf("expected file-mode reload-pending save, got %+v", out)
	}
	onDisk, _ := os.ReadFile(policyPath)
	if string(onDisk) != newPolicy {
		t.Fatalf("policy file not updated: %s", onDisk)
	}
	// A backup of the previous content exists.
	if _, err := os.Stat(policyPath + ".bak"); err != nil {
		t.Fatalf("expected .bak: %v", err)
	}
}

func TestSelfLockoutGuard(t *testing.T) {
	env := newTestEnv(t, nil)
	env.login()

	// The fake accepts any expire for known prefixes; seed the UI's own key.
	env.fake.Mu.Lock()
	now := time.Now().UTC()
	env.fake.APIKeys = append(env.fake.APIKeys, &hsclient.APIKey{ID: "77", Prefix: "uipfx", CreatedAt: &now})
	env.fake.Mu.Unlock()

	resp := env.do("POST", "/api/hs/apikeys/expire", map[string]any{"prefix": "uipfx"}, true)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 self-lockout guard, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = env.do("POST", "/api/hs/apikeys/expire", map[string]any{"prefix": "uipfx", "confirmSelfLockout": true}, true)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 with confirmation, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
}

func TestPreAuthKeyCreateReturnsSecretOnceAndAuditsWithoutIt(t *testing.T) {
	env := newTestEnv(t, nil)
	env.login()
	user := env.fake.AddUser("alice")

	resp := env.do("POST", "/api/hs/preauthkeys", map[string]any{
		"user": user.ID, "reusable": true, "label": "build farm",
	}, true)
	out := decode[struct {
		PreAuthKey hsclient.PreAuthKey `json:"preAuthKey"`
	}](t, resp)
	if out.PreAuthKey.Key == "" {
		t.Fatal("create must return the full secret")
	}

	// The audit trail must never contain the secret.
	resp = env.do("GET", "/api/audit", nil, false)
	audit := decode[struct {
		Entries []store.AuditEntry `json:"entries"`
	}](t, resp)
	if len(audit.Entries) == 0 {
		t.Fatal("expected audit entries")
	}
	for _, e := range audit.Entries {
		blob, _ := json.Marshal(e)
		if bytes.Contains(blob, []byte(out.PreAuthKey.Key)) {
			t.Fatalf("audit entry leaks the key secret: %s", blob)
		}
	}
}

func TestBasePathServing(t *testing.T) {
	env := newTestEnv(t, func(c *config.Config) { c.BasePath = "/admin" })

	// API answers under the base path...
	resp, err := http.Get(env.srv.URL + "/admin/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 under /admin, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// ...and not at the root.
	req, _ := http.NewRequest("GET", env.srv.URL+"/api/auth/session", nil)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 200 {
		t.Fatal("root path should not serve the API when BASE_PATH is set")
	}
	resp.Body.Close()
}

func TestRegistrationHandoffs(t *testing.T) {
	env := newTestEnv(t, nil)
	env.login()
	env.fake.AddUser("alice")
	env.fake.Mu.Lock()
	env.fake.PendingAuth["hskey-reg-xyz123"] = true
	env.fake.Mu.Unlock()

	// A full registration URL is accepted and the auth ID extracted.
	resp := env.do("POST", "/api/hs/register", map[string]any{
		"user": "alice", "authId": "https://hs.example.com/register/hskey-reg-xyz123",
	}, true)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register failed: %d %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// The handoff history recorded it.
	resp = env.do("GET", "/api/handoffs", nil, false)
	out := decode[struct {
		Handoffs []store.Handoff `json:"handoffs"`
	}](t, resp)
	if len(out.Handoffs) != 1 || out.Handoffs[0].AuthID != "hskey-reg-xyz123" || out.Handoffs[0].Status != "ok" {
		t.Fatalf("unexpected handoffs: %+v", out.Handoffs)
	}
}
