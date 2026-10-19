package session

import (
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
)

// A second redemption of an authorization code means the code leaked: the
// session the first redemption created is revoked (OAuth 2.1 section
// 4.1.3) and the reuse is recorded.
func TestAuthorizationCodeReuseRevokesSession(t *testing.T) {
	f := newOAuthFixture(t, authguard.Config{})
	c := f.code()
	st, body := f.redeem(c, verifier, redirect)
	if st != 200 {
		t.Fatalf("redeem: %d %v", st, body)
	}
	tok, _ := body["access_token"].(string)
	if _, err := f.store.Authenticate(tok, listenerTLS); err != nil {
		t.Fatalf("fresh session: %v", err)
	}
	if st, body := f.redeem(c, verifier, redirect); st != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", st, body)
	}
	if _, err := f.store.Authenticate(tok, listenerTLS); err == nil {
		t.Fatal("session created by a reused code is still valid")
	}
	found := false
	for _, ev := range f.rec.Events() {
		if ev.ReasonCode == "AUTH_CODE_REUSE" && ev.SessionID != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("no AUTH_CODE_REUSE event")
	}
	// Records of redeemed codes end when the code would have expired.
	f.now = f.now.Add(codeLifetime + time.Second)
	f.oauth.Prune()
	f.oauth.mu.Lock()
	n := len(f.oauth.redeemed)
	f.oauth.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d redeemed-code records after prune", n)
	}
}
