// Package hstest provides an in-memory fake of the headscale v0.29.3 REST
// API for tests. It reproduces the quirks the real server has: Bearer auth on
// every /api/v1 route, uint64 IDs serialized as strings, gRPC rpcStatus JSON
// error bodies, one-time pre-auth key secrets, full-replacement route
// approval with exit-route pairing, and SetPolicy rejection in file mode.
package hstest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/panagiotis1226/claude-head/internal/hsclient"
)

// Fake is an in-memory headscale. Create with New, point an hsclient.Client
// at Server.URL, and manipulate state directly (guarded by Mu) in tests.
type Fake struct {
	Server *httptest.Server

	Mu          sync.Mutex
	APIKey      string // the key the fake accepts
	Version     string // reported by /version
	PolicyMode  string // "database" or "file"
	Policy      string
	PolicyAt    *time.Time
	Users       []*hsclient.User
	Nodes       []*hsclient.Node
	PreAuthKeys []*fakePreAuthKey
	APIKeys     []*hsclient.APIKey
	PendingAuth map[string]bool // authID -> pending

	nextID int64
}

type fakePreAuthKey struct {
	hsclient.PreAuthKey
	Secret string // full key, returned only at creation
}

// New starts a fake headscale accepting apiKey.
func New(apiKey string) *Fake {
	f := &Fake{
		APIKey:      apiKey,
		Version:     "0.29.3",
		PolicyMode:  "database",
		Policy:      `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
		PendingAuth: map[string]bool{},
		nextID:      1,
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

// Close shuts the fake down.
func (f *Fake) Close() { f.Server.Close() }

// URL returns the fake's base URL.
func (f *Fake) URL() string { return f.Server.URL }

func (f *Fake) id() string {
	v := f.nextID
	f.nextID++
	return strconv.FormatInt(v, 10)
}

// AddUser seeds a user and returns it.
func (f *Fake) AddUser(name string) *hsclient.User {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	u := &hsclient.User{ID: f.id(), Name: name, CreatedAt: &now}
	f.Users = append(f.Users, u)
	return u
}

// AddNode seeds a node owned by user and returns it.
func (f *Fake) AddNode(user *hsclient.User, name string, available ...string) *hsclient.Node {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	n := &hsclient.Node{
		ID:              f.id(),
		Name:            name,
		GivenName:       name,
		User:            user,
		CreatedAt:       &now,
		LastSeen:        &now,
		Online:          true,
		IPAddresses:     []string{fmt.Sprintf("100.64.0.%s", f.nextIDPeek()), "fd7a:115c:a1e0::" + f.nextIDPeek()},
		RegisterMethod:  hsclient.RegisterMethodAuthKey,
		AvailableRoutes: available,
		MachineKey:      "mkey:" + strings.Repeat("0", 8) + name,
		NodeKey:         "nodekey:" + strings.Repeat("0", 8) + name,
	}
	f.Nodes = append(f.Nodes, n)
	return n
}

func (f *Fake) nextIDPeek() string { return strconv.FormatInt(f.nextID, 10) }

// ---- HTTP plumbing ----

func writeStatus(w http.ResponseWriter, httpCode, grpcCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	json.NewEncoder(w).Encode(map[string]any{"code": grpcCode, "message": msg, "details": []any{}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

var (
	reNode       = regexp.MustCompile(`^/api/v1/node/(\d+)$`)
	reNodeExpire = regexp.MustCompile(`^/api/v1/node/(\d+)/expire$`)
	reNodeRename = regexp.MustCompile(`^/api/v1/node/(\d+)/rename/([^/]+)$`)
	reNodeTags   = regexp.MustCompile(`^/api/v1/node/(\d+)/tags$`)
	reNodeRoutes = regexp.MustCompile(`^/api/v1/node/(\d+)/approve_routes$`)
	reUserRename = regexp.MustCompile(`^/api/v1/user/(\d+)/rename/([^/]+)$`)
	reUser       = regexp.MustCompile(`^/api/v1/user/(\d+)$`)
	reAPIKeyDel  = regexp.MustCompile(`^/api/v1/apikey/([^/]+)$`)
)

func (f *Fake) handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/version" {
		w.Write([]byte(f.Version))
		return
	}
	if !strings.HasPrefix(path, "/api/v1/") {
		http.NotFound(w, r)
		return
	}
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+f.APIKey {
		writeStatus(w, http.StatusUnauthorized, hsclient.CodeUnauthenticated, "invalid or expired API key")
		return
	}

	f.Mu.Lock()
	defer f.Mu.Unlock()

	method := r.Method
	switch {
	case path == "/api/v1/health" && method == "GET":
		writeJSON(w, map[string]any{"databaseConnectivity": true})

	// ---- users ----
	case path == "/api/v1/user" && method == "GET":
		q := r.URL.Query()
		var out []*hsclient.User
		for _, u := range f.Users {
			if v := q.Get("id"); v != "" && u.ID != v {
				continue
			}
			if v := q.Get("name"); v != "" && u.Name != v {
				continue
			}
			if v := q.Get("email"); v != "" && u.Email != v {
				continue
			}
			out = append(out, u)
		}
		writeJSON(w, map[string]any{"users": out})
	case path == "/api/v1/user" && method == "POST":
		var req hsclient.CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeStatus(w, http.StatusBadRequest, hsclient.CodeInvalidArgument, "invalid user name")
			return
		}
		for _, u := range f.Users {
			if u.Name == req.Name {
				writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, "user already exists")
				return
			}
		}
		now := time.Now().UTC().Truncate(time.Second)
		u := &hsclient.User{ID: f.id(), Name: req.Name, DisplayName: req.DisplayName, Email: req.Email, ProfilePicURL: req.PictureURL, CreatedAt: &now}
		f.Users = append(f.Users, u)
		writeJSON(w, map[string]any{"user": u})
	case reUserRename.MatchString(path) && method == "POST":
		m := reUserRename.FindStringSubmatch(path)
		newName, _ := url.PathUnescape(m[2])
		u := f.findUser(m[1])
		if u == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "user not found")
			return
		}
		u.Name = newName
		writeJSON(w, map[string]any{"user": u})
	case reUser.MatchString(path) && method == "DELETE":
		m := reUser.FindStringSubmatch(path)
		u := f.findUser(m[1])
		if u == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "user not found")
			return
		}
		var nodes []*hsclient.Node
		for _, n := range f.Nodes {
			if n.User == nil || n.User.ID != u.ID {
				nodes = append(nodes, n)
			}
		}
		f.Nodes = nodes
		var users []*hsclient.User
		for _, x := range f.Users {
			if x.ID != u.ID {
				users = append(users, x)
			}
		}
		f.Users = users
		writeJSON(w, map[string]any{})

	// ---- preauthkeys ----
	case path == "/api/v1/preauthkey" && method == "POST":
		var req hsclient.CreatePreAuthKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeStatus(w, http.StatusBadRequest, hsclient.CodeInvalidArgument, "bad request")
			return
		}
		u := f.findUser(req.User)
		if u == nil {
			writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, "user not found")
			return
		}
		for _, tag := range req.ACLTags {
			if !strings.HasPrefix(tag, "tag:") {
				writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, fmt.Sprintf("tag must start with 'tag:', got: %q", tag))
				return
			}
		}
		now := time.Now().UTC().Truncate(time.Second)
		id := f.id()
		secret := "hskey-auth-pf" + id + "-secret" + id
		k := &fakePreAuthKey{
			PreAuthKey: hsclient.PreAuthKey{
				User: u, ID: id, Key: secret, Reusable: req.Reusable,
				Ephemeral: req.Ephemeral, Expiration: req.Expiration,
				CreatedAt: &now, ACLTags: req.ACLTags,
			},
			Secret: secret,
		}
		f.PreAuthKeys = append(f.PreAuthKeys, k)
		writeJSON(w, map[string]any{"preAuthKey": k.PreAuthKey})
	case path == "/api/v1/preauthkey" && method == "GET":
		out := make([]hsclient.PreAuthKey, 0, len(f.PreAuthKeys))
		for _, k := range f.PreAuthKeys {
			listed := k.PreAuthKey
			// Secrets are bcrypt-hashed at rest since 0.28: listings carry
			// only the prefix.
			listed.Key = prefixOf(k.Secret)
			out = append(out, listed)
		}
		writeJSON(w, map[string]any{"preAuthKeys": out})
	case path == "/api/v1/preauthkey/expire" && method == "POST":
		var req struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		k := f.findPreAuthKey(req.ID)
		if k == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "preauthkey not found")
			return
		}
		past := time.Now().UTC().Add(-time.Second)
		k.Expiration = &past
		writeJSON(w, map[string]any{})
	case path == "/api/v1/preauthkey" && method == "DELETE":
		id := r.URL.Query().Get("id")
		k := f.findPreAuthKey(id)
		if k == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "preauthkey not found")
			return
		}
		var keep []*fakePreAuthKey
		for _, x := range f.PreAuthKeys {
			if x.ID != id {
				keep = append(keep, x)
			}
		}
		f.PreAuthKeys = keep
		writeJSON(w, map[string]any{})

	// ---- nodes ----
	case path == "/api/v1/node" && method == "GET":
		userFilter := r.URL.Query().Get("user")
		out := make([]*hsclient.Node, 0, len(f.Nodes))
		for _, n := range f.Nodes {
			if userFilter != "" && (n.User == nil || n.User.Name != userFilter) {
				continue
			}
			out = append(out, n)
		}
		writeJSON(w, map[string]any{"nodes": out})
	case path == "/api/v1/node/register" && method == "POST":
		f.registerPending(w, r.URL.Query().Get("user"), r.URL.Query().Get("key"))
	case path == "/api/v1/node/backfillips" && method == "POST":
		changes := []string{"node 1: assigned 100.64.0.1"}
		if r.URL.Query().Get("confirmed") != "true" {
			changes = append([]string{"dry run"}, changes...)
		}
		writeJSON(w, map[string]any{"changes": changes})
	case path == "/api/v1/debug/node" && method == "POST":
		var req hsclient.DebugCreateNodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeStatus(w, http.StatusBadRequest, hsclient.CodeInvalidArgument, "bad request")
			return
		}
		var user *hsclient.User
		for _, u := range f.Users {
			if u.Name == req.User {
				user = u
			}
		}
		if user == nil {
			writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, "user not found")
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		n := &hsclient.Node{
			ID: f.id(), Name: req.Name, GivenName: req.Name, User: user,
			CreatedAt: &now, RegisterMethod: hsclient.RegisterMethodCLI,
			AvailableRoutes: req.Routes,
		}
		f.Nodes = append(f.Nodes, n)
		writeJSON(w, map[string]any{"node": n})
	case reNode.MatchString(path) && method == "GET":
		n := f.findNode(reNode.FindStringSubmatch(path)[1])
		if n == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "node not found")
			return
		}
		writeJSON(w, map[string]any{"node": n})
	case reNode.MatchString(path) && method == "DELETE":
		id := reNode.FindStringSubmatch(path)[1]
		if f.findNode(id) == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "node not found")
			return
		}
		var keep []*hsclient.Node
		for _, n := range f.Nodes {
			if n.ID != id {
				keep = append(keep, n)
			}
		}
		f.Nodes = keep
		writeJSON(w, map[string]any{})
	case reNodeExpire.MatchString(path) && method == "POST":
		n := f.findNode(reNodeExpire.FindStringSubmatch(path)[1])
		if n == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "node not found")
			return
		}
		q := r.URL.Query()
		expiry, disable := q.Get("expiry"), q.Get("disableExpiry") == "true"
		if expiry != "" && disable {
			writeStatus(w, http.StatusBadRequest, hsclient.CodeInvalidArgument, "expiry and disableExpiry are mutually exclusive")
			return
		}
		switch {
		case disable:
			n.Expiry = nil
		case expiry != "":
			t, err := time.Parse(time.RFC3339, expiry)
			if err != nil {
				writeStatus(w, http.StatusBadRequest, hsclient.CodeInvalidArgument, "invalid expiry timestamp")
				return
			}
			n.Expiry = &t
		default:
			now := time.Now().UTC()
			n.Expiry = &now
		}
		writeJSON(w, map[string]any{"node": n})
	case reNodeRename.MatchString(path) && method == "POST":
		m := reNodeRename.FindStringSubmatch(path)
		n := f.findNode(m[1])
		if n == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "node not found")
			return
		}
		newName, _ := url.PathUnescape(m[2])
		if !validHostname(newName) {
			writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, "invalid hostname")
			return
		}
		n.GivenName = newName
		writeJSON(w, map[string]any{"node": n})
	case reNodeTags.MatchString(path) && method == "POST":
		n := f.findNode(reNodeTags.FindStringSubmatch(path)[1])
		if n == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "node not found")
			return
		}
		var req struct {
			Tags []string `json:"tags"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		for _, tag := range req.Tags {
			if !strings.HasPrefix(tag, "tag:") {
				writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, fmt.Sprintf("tag must start with 'tag:', got: %q", tag))
				return
			}
		}
		n.Tags = req.Tags
		writeJSON(w, map[string]any{"node": n})
	case reNodeRoutes.MatchString(path) && method == "POST":
		n := f.findNode(reNodeRoutes.FindStringSubmatch(path)[1])
		if n == nil {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "node not found")
			return
		}
		var req struct {
			Routes []string `json:"routes"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		// Full replacement, with 0.26+ exit-route pairing: approving either
		// exit prefix approves both.
		set := map[string]bool{}
		for _, route := range req.Routes {
			set[route] = true
		}
		if set["0.0.0.0/0"] || set["::/0"] {
			set["0.0.0.0/0"], set["::/0"] = true, true
		}
		n.ApprovedRoutes = n.ApprovedRoutes[:0]
		for route := range set {
			n.ApprovedRoutes = append(n.ApprovedRoutes, route)
		}
		// subnetRoutes = approved ∩ advertised
		n.SubnetRoutes = n.SubnetRoutes[:0]
		for _, r := range n.AvailableRoutes {
			if set[r] {
				n.SubnetRoutes = append(n.SubnetRoutes, r)
			}
		}
		writeJSON(w, map[string]any{"node": n})

	// ---- auth flow ----
	case path == "/api/v1/auth/register" && method == "POST":
		var req struct {
			User   string `json:"user"`
			AuthID string `json:"authId"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		f.registerPending(w, req.User, req.AuthID)
	case path == "/api/v1/auth/approve" && method == "POST":
		var req struct {
			AuthID string `json:"authId"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if !f.PendingAuth[req.AuthID] {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "no pending authentication for auth id")
			return
		}
		delete(f.PendingAuth, req.AuthID)
		writeJSON(w, map[string]any{})
	case path == "/api/v1/auth/reject" && method == "POST":
		var req struct {
			AuthID string `json:"authId"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if !f.PendingAuth[req.AuthID] {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "no pending authentication for auth id")
			return
		}
		delete(f.PendingAuth, req.AuthID)
		writeJSON(w, map[string]any{})

	// ---- api keys ----
	case path == "/api/v1/apikey" && method == "POST":
		var req struct {
			Expiration *time.Time `json:"expiration"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		now := time.Now().UTC().Truncate(time.Second)
		id := f.id()
		k := &hsclient.APIKey{ID: id, Prefix: "pfx" + id, Expiration: req.Expiration, CreatedAt: &now}
		f.APIKeys = append(f.APIKeys, k)
		writeJSON(w, map[string]any{"apiKey": fmt.Sprintf("hskey-api-%s-secret%s", k.Prefix, id)})
	case path == "/api/v1/apikey" && method == "GET":
		out := f.APIKeys
		if out == nil {
			out = []*hsclient.APIKey{}
		}
		writeJSON(w, map[string]any{"apiKeys": out})
	case path == "/api/v1/apikey/expire" && method == "POST":
		var req struct {
			Prefix string `json:"prefix"`
			ID     string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		for _, k := range f.APIKeys {
			if (req.Prefix != "" && k.Prefix == req.Prefix) || (req.ID != "" && k.ID == req.ID) {
				past := time.Now().UTC().Add(-time.Second)
				k.Expiration = &past
				writeJSON(w, map[string]any{})
				return
			}
		}
		writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "api key not found")
	case reAPIKeyDel.MatchString(path) && method == "DELETE":
		prefix, _ := url.PathUnescape(reAPIKeyDel.FindStringSubmatch(path)[1])
		var keep []*hsclient.APIKey
		found := false
		for _, k := range f.APIKeys {
			if k.Prefix == prefix {
				found = true
				continue
			}
			keep = append(keep, k)
		}
		if !found {
			writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "api key not found")
			return
		}
		f.APIKeys = keep
		writeJSON(w, map[string]any{})

	// ---- policy ----
	case path == "/api/v1/policy" && method == "GET":
		// Real v0.29.3 quirk: a database-mode server that never had a policy
		// set errors on GET instead of returning an empty document.
		if f.PolicyMode == "database" && f.Policy == "" {
			writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, "acl policy not found: record not found")
			return
		}
		resp := map[string]any{"policy": f.Policy}
		if f.PolicyMode == "database" && f.PolicyAt != nil {
			resp["updatedAt"] = f.PolicyAt.Format(time.RFC3339)
		}
		writeJSON(w, resp)
	case path == "/api/v1/policy" && method == "PUT":
		if f.PolicyMode != "database" {
			writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, "update is disabled for modes other than 'database'; policy update is disabled")
			return
		}
		var req struct {
			Policy string `json:"policy"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if msg, ok := f.validatePolicy(req.Policy); !ok {
			writeStatus(w, http.StatusInternalServerError, hsclient.CodeInternal, msg)
			return
		}
		f.Policy = req.Policy
		now := time.Now().UTC().Truncate(time.Second)
		f.PolicyAt = &now
		writeJSON(w, map[string]any{"policy": f.Policy, "updatedAt": now.Format(time.RFC3339)})
	case path == "/api/v1/policy/check" && method == "POST":
		var req struct {
			Policy string `json:"policy"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if msg, ok := f.validatePolicy(req.Policy); !ok {
			writeStatus(w, http.StatusBadRequest, hsclient.CodeInvalidArgument, msg)
			return
		}
		writeJSON(w, map[string]any{})

	default:
		writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "unknown endpoint "+method+" "+path)
	}
}

func (f *Fake) registerPending(w http.ResponseWriter, userName, authID string) {
	if !f.PendingAuth[authID] {
		writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "no pending registration for auth id")
		return
	}
	var user *hsclient.User
	for _, u := range f.Users {
		if u.Name == userName {
			user = u
		}
	}
	if user == nil {
		writeStatus(w, http.StatusNotFound, hsclient.CodeNotFound, "user not found")
		return
	}
	delete(f.PendingAuth, authID)
	now := time.Now().UTC().Truncate(time.Second)
	n := &hsclient.Node{
		ID: f.id(), Name: "registered-" + authID, GivenName: "registered-" + authID,
		User: user, CreatedAt: &now, RegisterMethod: hsclient.RegisterMethodCLI, Online: false,
	}
	f.Nodes = append(f.Nodes, n)
	writeJSON(w, map[string]any{"node": n})
}

// validatePolicy is a shallow stand-in for headscale's policy validation:
// it must be valid JSON (the fake doesn't implement HuJSON comment
// stripping) and must not contain the marker "INVALID" (lets tests force
// failures with structurally valid JSON).
func (f *Fake) validatePolicy(policy string) (string, bool) {
	var v any
	if err := json.Unmarshal([]byte(policy), &v); err != nil {
		return "parsing policy, syntax error: " + err.Error(), false
	}
	if strings.Contains(policy, "INVALID") {
		return `verifying policy rules: invalid or unknown field in src=["INVALID"]`, false
	}
	return "", true
}

func (f *Fake) findUser(id string) *hsclient.User {
	for _, u := range f.Users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func (f *Fake) findNode(id string) *hsclient.Node {
	for _, n := range f.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func (f *Fake) findPreAuthKey(id string) *hsclient.PreAuthKey {
	for _, k := range f.PreAuthKeys {
		if k.ID == id {
			return &k.PreAuthKey
		}
	}
	return nil
}

func prefixOf(secret string) string {
	// hskey-auth-{prefix}-{secret} -> prefix
	parts := strings.Split(secret, "-")
	if len(parts) == 4 {
		return parts[2]
	}
	return secret
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validHostname(name string) bool {
	return len(name) >= 2 && hostnameRe.MatchString(name)
}
