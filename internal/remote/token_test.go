package remote_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestTokenValidationFixtures is SR-2.11-1: the authorization fixtures of
// the MCP 2026-07-28 authorization specification against both resource
// URIs the Gateway serves (the local listener's CP-41 resource and the
// Remote Access listener's public resource). Access tokens are opaque and
// validated by lookup in the session table; each is bound at issue to the
// listener, and so to the resource URI, it was requested for.
//
//   - a token for the right resource is accepted;
//   - wrong audience: a token issued for one resource is refused at the
//     other, in both directions;
//   - an authorization or token request naming another resource is
//     refused, so no token for another audience is issued;
//   - forged, refresh-token-as-access-token, wrong-scheme and missing
//     tokens are refused;
//   - revoked: a token of a terminated session is refused;
//   - expired: a token past its idle deadline is refused.
//
// Every refusal is HTTP 401 with WWW-Authenticate naming the listener's
// protected-resource metadata (RFC 9728), as the specification requires.
func TestTokenValidationFixtures(t *testing.T) {
	reqtest.Verifies(t, "SR-2.11-1")
	e := newEnv(t, "")
	e.enable()
	local := e.Config.Listener.PublicURL
	list := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
	refused := func(name, base, token string) {
		t.Helper()
		r, _ := e.mcp(base, token, list)
		if r.StatusCode != http.StatusUnauthorized || !strings.Contains(r.Header.Get("WWW-Authenticate"), base+"/.well-known/oauth-protected-resource") {
			t.Fatalf("%s: %d %q", name, r.StatusCode, r.Header.Get("WWW-Authenticate"))
		}
	}
	accepted := func(name, base, token string) {
		t.Helper()
		if r, _ := e.mcp(base, token, list); r.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", name, r.StatusCode)
		}
	}

	// A local token (session API, issued secret) and a remote token.
	req, _ := http.NewRequest("POST", local+"/smcp/v1/sessions", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(gwtest.HelperClientID, gwtest.HelperSecret)
	resp, body := e.do(req)
	if resp.StatusCode != 201 {
		t.Fatalf("local session: %d %s", resp.StatusCode, body)
	}
	localTok := jsonField(t, body, "access_token")
	localRefresh := jsonField(t, body, "refresh_token")
	_, rt := e.signIn(gwtest.PreClientID, gwtest.PreSecret, "smcp:template:remote")
	remoteTok, _ := rt["access_token"].(string)
	remoteRefresh, _ := rt["refresh_token"].(string)
	if remoteTok == "" || remoteRefresh == "" {
		t.Fatalf("remote token response %v", rt)
	}
	accepted("local token at local resource", local, localTok)
	accepted("remote token at remote resource", e.public, remoteTok)

	// Wrong audience.
	refused("local token at remote resource", e.public, localTok)
	refused("remote token at local resource", local, remoteTok)

	// No token is issued for another resource.
	_, challenge := pkce()
	q := authorizeQuery(gwtest.PublicClientID, "http://127.0.0.1/callback", challenge, "", "https://other.example/mcp")
	q.Set("username", gwtest.ApproverUser)
	q.Set("password", gwtest.ApproverPassword)
	r, _ := e.postForm(local+"/oauth/authorize", q, "", "")
	if loc, _ := url.Parse(r.Header.Get("Location")); r.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("code") != "" {
		t.Fatalf("authorize for another resource: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	verifier, challenge := pkce()
	q = authorizeQuery(gwtest.PublicClientID, "http://127.0.0.1/callback", challenge, "", e.MCPURL())
	q.Set("username", gwtest.ApproverUser)
	q.Set("password", gwtest.ApproverPassword)
	r, _ = e.postForm(local+"/oauth/authorize", q, "", "")
	loc, _ := url.Parse(r.Header.Get("Location"))
	tr, tb := e.postForm(local+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {"http://127.0.0.1/callback"},
		"code_verifier": {verifier}, "client_id": {gwtest.PublicClientID}, "resource": {e.public + "/mcp"}}, "", "")
	if tr.StatusCode != 400 || tb["error"] != "invalid_target" || tb["access_token"] != nil {
		t.Fatalf("token for another resource: %d %v", tr.StatusCode, tb)
	}

	// Malformed and forged tokens.
	refused("forged", local, "forged-token")
	refused("missing", local, "")
	refused("refresh token as access token (local)", local, localRefresh)
	refused("refresh token as access token (remote)", e.public, remoteRefresh)
	req, _ = http.NewRequest("POST", local+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Basic "+localTok)
	if resp, _ := e.do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token in the Basic scheme: %d", resp.StatusCode)
	}

	// Revoked.
	var localID string
	for _, s := range e.App.Store.Active() {
		if s.ClientID == gwtest.HelperClientID {
			localID = s.ID
		}
	}
	if localID == "" || !e.App.Store.Terminate(localID) {
		t.Fatal("terminate the local session")
	}
	refused("revoked local token", local, localTok)

	// Expired: past the idle deadline (CP-18), the remote token is refused.
	accepted("remote token before expiry", e.public, remoteTok)
	later := time.Now().Add(e.Config.Limits.SessionIdleTimeout.Duration + time.Minute)
	e.App.Store.SetNow(func() time.Time { return later })
	t.Cleanup(func() { e.App.Store.SetNow(time.Now) })
	refused("expired remote token", e.public, remoteTok)
}

func jsonField(t *testing.T, body []byte, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	s, _ := m[key].(string)
	if s == "" {
		t.Fatalf("no %s in %s", key, body)
	}
	return s
}
