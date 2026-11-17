package server

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/panagiotis1226/head-control/internal/config"
	"github.com/panagiotis1226/head-control/internal/hsclient"
	"github.com/panagiotis1226/head-control/internal/hsclient/hstest"
	"github.com/panagiotis1226/head-control/internal/store"
)

// rawLogin posts a login without the test env's cookie jar. xff sets the
// client IP: httptest peers are loopback, so the last X-Forwarded-For hop is
// trusted exactly like a reverse proxy's.
func rawLogin(t *testing.T, baseURL, password, xff string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", baseURL+"/api/auth/login",
		bytes.NewReader([]byte(fmt.Sprintf(`{"password":%q}`, password))))
	if err != nil {
		t.Fatal(err)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// A parallel burst must not get more password checks than the per-IP limit:
// the slot is taken before the (slow) bcrypt compare, not after it.
func TestLoginRateLimitHoldsUnderParallelBurst(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	env := newTestEnv(t, func(c *config.Config) {
		c.AdminPassword = ""
		c.AdminPasswordHash = string(hash)
	})

	const burst = 100
	var checked, limited int32
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := rawLogin(t, env.srv.URL, "wrong-guess", "")
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				atomic.AddInt32(&checked, 1)
			case http.StatusTooManyRequests:
				atomic.AddInt32(&limited, 1)
			}
		}()
	}
	wg.Wait()
	if checked != 5 || limited != burst-5 {
		t.Fatalf("burst of %d from one IP: %d passwords checked, %d rate-limited; want 5 and %d",
			burst, checked, limited, burst-5)
	}
}

// Successful logins hand their slot back, so a correct password never eats
// into the limit.
func TestSuccessfulLoginsDoNotCountAgainstLimit(t *testing.T) {
	env := newTestEnv(t, nil)
	for i := 0; i < 12; i++ {
		resp := rawLogin(t, env.srv.URL, testPassword, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login %d: got %d, want 200", i+1, resp.StatusCode)
		}
	}
}

// 20 bad guesses a minute from anywhere used to lock every admin out. An IP
// with a recent successful login must still get in; unknown IPs stay braked.
func TestGlobalLoginLimitSparesKnownIP(t *testing.T) {
	env := newTestEnv(t, nil)
	const adminIP, strangerIP = "198.51.100.7", "198.51.100.8"

	resp := rawLogin(t, env.srv.URL, testPassword, adminIP)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial admin login: got %d", resp.StatusCode)
	}

	// Attacker: 20 failures spread over 20 IPs (parallel — each failure
	// carries the uniform delay).
	var wg sync.WaitGroup
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := rawLogin(t, env.srv.URL, "wrong", fmt.Sprintf("203.0.113.%d", i))
			r.Body.Close()
		}(i)
	}
	wg.Wait()

	resp = rawLogin(t, env.srv.URL, testPassword, strangerIP)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unknown IP during an attack: got %d, want 429", resp.StatusCode)
	}
	resp = rawLogin(t, env.srv.URL, testPassword, adminIP)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("known admin IP during an attack: got %d, want 200", resp.StatusCode)
	}
}

// Sessions live in SQLite on the data volume. Restarting with the same
// password keeps them; restarting with a different one must revoke them.
func TestSessionsRevokedWhenPasswordChanges(t *testing.T) {
	dir := t.TempDir()
	fake := hstest.New("hskey-api-uipfx-secret")
	defer fake.Close()

	boot := func(password, passwordHash string) (*httptest.Server, func()) {
		st, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{
			HeadscaleURL: fake.URL(), APIKey: "hskey-api-uipfx-secret",
			AdminPassword: password, AdminPasswordHash: passwordHash,
			CookieSecure: false, SessionLifetime: time.Hour,
			PolicyMode: "auto", HealthInterval: time.Hour,
		}
		hs, err := hsclient.New(cfg.HeadscaleURL, cfg.APIKey)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), hs, st).Handler())
		return srv, func() { srv.Close(); st.Close() }
	}
	statusWith := func(srv *httptest.Server, cookie *http.Cookie) int {
		req, _ := http.NewRequest("GET", srv.URL+"/api/hs/apikeys", nil)
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	loginCookie := func(srv *httptest.Server, password string) *http.Cookie {
		resp := rawLogin(t, srv.URL, password, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(resp.Cookies()) == 0 {
			t.Fatalf("login failed: %d", resp.StatusCode)
		}
		return resp.Cookies()[0]
	}

	srv, stop := boot("old-password-1", "")
	cookie := loginCookie(srv, "old-password-1")
	stop()

	// Same password: the session survives the restart.
	srv, stop = boot("old-password-1", "")
	if got := statusWith(srv, cookie); got != http.StatusOK {
		t.Fatalf("same password after restart: got %d, want 200", got)
	}
	stop()

	// Rotated password: the old session is gone.
	srv, stop = boot("brand-new-password-2", "")
	if got := statusWith(srv, cookie); got != http.StatusUnauthorized {
		t.Fatalf("old session after password change: got %d, want 401", got)
	}
	cookie = loginCookie(srv, "brand-new-password-2")
	stop()

	// Switching to a bcrypt hash (even of the same password) is a credential
	// change too, and a stable hash keeps sessions across later restarts.
	hash, err := bcrypt.GenerateFromPassword([]byte("brand-new-password-2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv, stop = boot("", string(hash))
	if got := statusWith(srv, cookie); got != http.StatusUnauthorized {
		t.Fatalf("old session after switching to a hash: got %d, want 401", got)
	}
	cookie = loginCookie(srv, "brand-new-password-2")
	stop()
	srv, stop = boot("", string(hash))
	defer stop()
	if got := statusWith(srv, cookie); got != http.StatusOK {
		t.Fatalf("same hash after restart: got %d, want 200", got)
	}
}

// A successful login leaves an audit entry naming the client IP.
func TestLoginIsAudited(t *testing.T) {
	env := newTestEnv(t, nil)
	env.login()
	resp := env.do("GET", "/api/audit?action=auth.login", nil, false)
	out := decode[struct {
		Entries []store.AuditEntry `json:"entries"`
	}](t, resp)
	if len(out.Entries) != 1 || out.Entries[0].Summary != "from 127.0.0.1" {
		t.Fatalf("unexpected login audit entries: %+v", out.Entries)
	}
}
