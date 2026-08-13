package config

import (
	"strings"
	"testing"
)

func TestValidateBcryptHash(t *testing.T) {
	// A real hash produced by golang.org/x/crypto/bcrypt (structure only —
	// not a hash of any password in use).
	valid := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	if err := validateBcryptHash(valid); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}

	// The exact failure mode Docker Compose interpolation produces: the hash
	// is cut off after the cost segment because "$<salt...>" was substituted
	// as an (unset) variable.
	err := validateBcryptHash("$2b$10$")
	if err == nil {
		t.Fatal("truncated hash accepted")
	}
	if !strings.Contains(err.Error(), "single quotes") {
		t.Fatalf("truncation error should explain the compose fix, got: %v", err)
	}

	if err := validateBcryptHash("not-a-hash"); err == nil {
		t.Fatal("garbage accepted as hash")
	}
}
