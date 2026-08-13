package hsclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/panagiotis1226/head-control/internal/hsclient"
	"github.com/panagiotis1226/head-control/internal/hsclient/hstest"
)

func newClientAndFake(t *testing.T) (*hsclient.Client, *hstest.Fake) {
	t.Helper()
	fake := hstest.New("hskey-api-testpfx-secret")
	t.Cleanup(fake.Close)
	c, err := hsclient.New(fake.URL(), "hskey-api-testpfx-secret")
	if err != nil {
		t.Fatal(err)
	}
	return c, fake
}

func TestUserLifecycle(t *testing.T) {
	c, _ := newClientAndFake(t)
	ctx := context.Background()

	u, err := c.CreateUser(ctx, hsclient.CreateUserRequest{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.Name != "alice" {
		t.Fatalf("unexpected user %+v", u)
	}

	users, err := c.ListUsers(ctx, hsclient.UserFilter{Name: "alice"})
	if err != nil || len(users) != 1 {
		t.Fatalf("list by name: %v %v", users, err)
	}

	if _, err := c.RenameUser(ctx, u.ID, "alicia"); err != nil {
		t.Fatal(err)
	}
	users, _ = c.ListUsers(ctx, hsclient.UserFilter{})
	if users[0].Name != "alicia" {
		t.Fatalf("rename didn't stick: %+v", users[0])
	}

	if err := c.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, u.ID); !hsclient.IsNotFound(err) {
		t.Fatalf("expected NotFound on double delete, got %v", err)
	}
}

func TestRouteApprovalIsFullReplacementWithExitPairing(t *testing.T) {
	c, fake := newClientAndFake(t)
	ctx := context.Background()
	u := fake.AddUser("alice")
	n := fake.AddNode(u, "router", "10.0.0.0/24", "192.168.1.0/24", "0.0.0.0/0", "::/0")

	// Approving one exit prefix approves both.
	node, err := c.SetApprovedRoutes(ctx, n.ID, []string{"10.0.0.0/24", "0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(node.ApprovedRoutes, "::/0") {
		t.Fatalf("exit pairing missing: %v", node.ApprovedRoutes)
	}
	if !contains(node.SubnetRoutes, "10.0.0.0/24") || contains(node.SubnetRoutes, "192.168.1.0/24") {
		t.Fatalf("subnetRoutes should be approved∩advertised: %v", node.SubnetRoutes)
	}

	// Full replacement: sending a smaller set revokes what's absent.
	node, err = c.SetApprovedRoutes(ctx, n.ID, []string{"192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if contains(node.ApprovedRoutes, "10.0.0.0/24") || contains(node.ApprovedRoutes, "0.0.0.0/0") {
		t.Fatalf("replacement did not revoke: %v", node.ApprovedRoutes)
	}
}

func TestExpireNodeVariants(t *testing.T) {
	c, fake := newClientAndFake(t)
	ctx := context.Background()
	u := fake.AddUser("alice")
	n := fake.AddNode(u, "laptop")

	future := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	node, err := c.ExpireNode(ctx, n.ID, hsclient.ExpireSpec{At: &future})
	if err != nil {
		t.Fatal(err)
	}
	if node.Expiry == nil || !node.Expiry.Equal(future) {
		t.Fatalf("expiry-at failed: %v", node.Expiry)
	}

	node, err = c.ExpireNode(ctx, n.ID, hsclient.ExpireSpec{Never: true})
	if err != nil {
		t.Fatal(err)
	}
	if node.Expiry != nil {
		t.Fatalf("disable expiry failed: %v", node.Expiry)
	}

	node, err = c.ExpireNode(ctx, n.ID, hsclient.ExpireSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if node.Expiry == nil || node.Expiry.After(time.Now().Add(time.Minute)) {
		t.Fatalf("expire-now failed: %v", node.Expiry)
	}

	// Both At and Never is a client bug the server rejects.
	if _, err := c.ExpireNode(ctx, n.ID, hsclient.ExpireSpec{At: &future, Never: true}); !hsclient.IsInvalidArgument(err) {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestPreAuthKeySecretShownOnce(t *testing.T) {
	c, fake := newClientAndFake(t)
	ctx := context.Background()
	u := fake.AddUser("alice")

	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	k, err := c.CreatePreAuthKey(ctx, hsclient.CreatePreAuthKeyRequest{
		User: u.ID, Reusable: true, Expiration: &exp, ACLTags: []string{"tag:server"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if k.Key == "" || !contains(k.ACLTags, "tag:server") {
		t.Fatalf("create response must carry full secret + tags: %+v", k)
	}

	list, err := c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Key == k.Key {
		t.Fatalf("listing must not expose the full secret: %+v", list)
	}
}

func TestPolicyModes(t *testing.T) {
	c, fake := newClientAndFake(t)
	ctx := context.Background()

	// Database mode: set + get round-trips, updatedAt present.
	p, err := c.SetPolicy(ctx, `{"acls":[{"action":"accept","src":["group:eng"],"dst":["*:*"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.UpdatedAt == nil {
		t.Fatal("database mode must return updatedAt")
	}

	// Validation failures surface the server's message.
	if _, err := c.SetPolicy(ctx, `{"acls":[{"action":"accept","src":["INVALID"],"dst":["*:*"]}]}`); err == nil {
		t.Fatal("expected validation error")
	}
	if err := c.CheckPolicy(ctx, `{"acls":[{"action":"accept","src":["INVALID"],"dst":["*:*"]}]}`); !hsclient.IsInvalidArgument(err) {
		t.Fatalf("check should fail with InvalidArgument, got %v", err)
	}
	if err := c.CheckPolicy(ctx, `{"acls":[]}`); err != nil {
		t.Fatalf("valid policy should check clean: %v", err)
	}

	// File mode: GET works, PUT is rejected with the detectable error.
	fake.Mu.Lock()
	fake.PolicyMode = "file"
	fake.Mu.Unlock()
	if _, err := c.GetPolicy(ctx); err != nil {
		t.Fatalf("GetPolicy must work in file mode: %v", err)
	}
	_, err = c.SetPolicy(ctx, `{"acls":[]}`)
	if !hsclient.IsPolicyUpdateDisabled(err) {
		t.Fatalf("expected IsPolicyUpdateDisabled, got %v", err)
	}
}

func TestAuthFlow(t *testing.T) {
	c, fake := newClientAndFake(t)
	ctx := context.Background()
	fake.AddUser("alice")
	fake.Mu.Lock()
	fake.PendingAuth["hskey-reg-abc"] = true
	fake.PendingAuth["hskey-auth-ssh1"] = true
	fake.Mu.Unlock()

	node, err := c.AuthRegister(ctx, "alice", "hskey-reg-abc")
	if err != nil {
		t.Fatal(err)
	}
	if node.User == nil || node.User.Name != "alice" {
		t.Fatalf("registered node has wrong user: %+v", node)
	}
	// Same auth ID again -> NotFound.
	if _, err := c.AuthRegister(ctx, "alice", "hskey-reg-abc"); !hsclient.IsNotFound(err) {
		t.Fatalf("expected NotFound, got %v", err)
	}

	if err := c.AuthApprove(ctx, "hskey-auth-ssh1"); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthReject(ctx, "hskey-auth-ssh1"); !hsclient.IsNotFound(err) {
		t.Fatalf("expected NotFound after approval consumed it, got %v", err)
	}
}

func TestUnauthenticatedDetection(t *testing.T) {
	fake := hstest.New("right-key")
	defer fake.Close()
	c, _ := hsclient.New(fake.URL(), "wrong-key")
	_, err := c.ListUsers(context.Background(), hsclient.UserFilter{})
	if !hsclient.IsUnauthenticated(err) {
		t.Fatalf("expected IsUnauthenticated, got %v", err)
	}
}

func TestServerVersion(t *testing.T) {
	c, _ := newClientAndFake(t)
	v, err := c.ServerVersion(context.Background())
	if err != nil || v != "0.29.3" {
		t.Fatalf("version = %q, %v", v, err)
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
