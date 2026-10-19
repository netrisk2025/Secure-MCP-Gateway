package remote_test

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestRemoteRequiresApprovedClientToken(t *testing.T) {
	reqtest.Verifies(t, "SR-4.14-2")
	e := newEnv(t, "")
	e.enable()
	list := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
	if r, _ := e.mcp(e.public, "", list); r.StatusCode != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), e.public+"/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("no token: %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
	if r, _ := e.mcp(e.public, "forged", list); r.StatusCode != 401 {
		t.Fatalf("forged token: %d", r.StatusCode)
	}
	// A pending client cannot obtain a token at all
	// (TestDynamicRegistrationNeedsApproval); an approved client's token is
	// accepted.
	_, tok := e.signIn(gwtest.PreClientID, gwtest.PreSecret, "smcp:template:remote")
	if r, _ := e.mcp(e.public, tok["access_token"].(string), list); r.StatusCode != 200 {
		t.Fatalf("approved token: %d", r.StatusCode)
	}
	// Metadata and authorization need no token.
	for _, p := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/oauth/authorize?client_id=x"} {
		if r, _ := e.get(e.public + p); r.StatusCode == 401 {
			t.Fatalf("%s demanded a token", p)
		}
	}
}
