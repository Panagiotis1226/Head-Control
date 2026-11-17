package store

import (
	"testing"
	"time"
)

// Sliding renewal must never carry a session past created_at + maxAge.
func TestSessionAbsoluteLifetimeCap(t *testing.T) {
	st, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const lifetime, maxAge = time.Hour, 24 * time.Hour
	token, _, err := st.CreateSession(lifetime, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	backdate := func(age time.Duration) {
		t.Helper()
		if _, err := st.db.Exec(`UPDATE sessions SET created_at = ?`, time.Now().Add(-age).Unix()); err != nil {
			t.Fatal(err)
		}
	}

	// Close to the cap: still valid, but the renewed expiry stops at the cap.
	backdate(maxAge - 10*time.Minute)
	sess, err := st.GetSession(token, lifetime, maxAge)
	if err != nil || sess == nil {
		t.Fatalf("session near the cap should be valid: %v %v", sess, err)
	}
	if left := time.Until(sess.ExpiresAt); left > 11*time.Minute {
		t.Fatalf("expiry slid past the cap: %v left, want <= ~10m", left)
	}

	// Past the cap: gone, even though it was just used.
	backdate(maxAge + time.Minute)
	if sess, _ := st.GetSession(token, lifetime, maxAge); sess != nil {
		t.Fatal("session older than maxAge should be rejected")
	}
	var n int
	st.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Fatalf("expired session should be deleted, %d rows left", n)
	}

	// maxAge 0 disables the cap.
	token, _, _ = st.CreateSession(lifetime, 0)
	backdate(1000 * time.Hour)
	if sess, _ := st.GetSession(token, lifetime, 0); sess == nil {
		t.Fatal("with no cap an old but active session stays valid")
	}
}
