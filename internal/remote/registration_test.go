package remote_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestClientRegistrationPaths is FR-2.18: a framework instance becomes an
// OAuth client by each of the three paths, and each client ID maps to
// exactly one principal.
//
//   - Client ID Metadata Document: a URL on the CP-52 allowlist is fetched
//     at authorization, its redirect URI is honoured, and the session is
//     bound to the allowlist entry's principal. A metadata URL outside the
//     allowlist on the same server is refused without any request reaching
//     that server.
//   - Issued secret: the configured secret clients create sessions for
//     their own principals.
//   - Dynamic Client Registration under the Remote Access Profile: an
//     approved registration signs in and is bound to the principal the
//     operator approved it for.
//   - One principal per client ID: a configuration that gives the same
//     client ID to a second principal, through [[client]] or
//     [[client_metadata]], is refused.
//
// The CP-52 fetch bounds (size, timeout, redirects, public addresses only,
// cache) are in internal/session.TestClientMetadataFetchBounds.
func TestClientRegistrationPaths(t *testing.T) {
	reqtest.Verifies(t, "FR-2.18")
	var hits atomic.Int64
	var docURL string
	doc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Metadata Agent","redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none"}`, docURL)
	}))
	defer doc.Close()
	docURL = doc.URL + "/agent/client.json"
	e := newEnv(t, fmt.Sprintf("\n[[client_metadata]]\nurl = %q\nprincipal = \"cloud\"\n", docURL))
	e.App.OAuth.SetMetadataTransport(doc.Client().Transport)

	local := e.Config.Listener.PublicURL
	principalOf := func(clientID string) string {
		t.Helper()
		for _, s := range e.App.Store.Active() {
			if s.ClientID == clientID {
				return s.PrincipalID
			}
		}
		t.Fatalf("no session for client %s", clientID)
		return ""
	}

	// Metadata URL outside the allowlist: refused, nothing fetched.
	_, challenge := pkce()
	q := authorizeQuery(doc.URL+"/agent/other.json", "http://127.0.0.1/callback", challenge, "", e.MCPURL())
	if resp, body := e.get(local + "/oauth/authorize?" + q.Encode()); resp.StatusCode != 400 || !strings.Contains(string(body), "unknown client_id") {
		t.Fatalf("unlisted metadata URL: %d %s", resp.StatusCode, body)
	}
	if hits.Load() != 0 {
		t.Fatalf("an unlisted metadata URL caused %d fetches", hits.Load())
	}

	// Allowlisted metadata URL: fetched, signed in, bound to "cloud".
	verifier, challenge := pkce()
	q = authorizeQuery(docURL, "http://127.0.0.1/callback", challenge, "", e.MCPURL())
	if resp, body := e.get(local + "/oauth/authorize?" + q.Encode()); resp.StatusCode != 200 || !strings.Contains(string(body), "Session Approver") {
		t.Fatalf("allowlisted metadata URL: %d %s", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("metadata document fetched %d times, want 1", hits.Load())
	}
	q.Set("username", gwtest.ApproverUser)
	q.Set("password", gwtest.ApproverPassword)
	resp, _ := e.postForm(local+"/oauth/authorize", q, "", "")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("metadata client authorize: %d %s", resp.StatusCode, loc)
	}
	tr, tok := e.postForm(local+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"http://127.0.0.1/callback"}, "code_verifier": {verifier}, "client_id": {docURL}, "resource": {e.MCPURL()}}, "", "")
	if tr.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("metadata client token: %d %v", tr.StatusCode, tok)
	}
	if p := principalOf(docURL); p != "cloud" {
		t.Fatalf("metadata client bound to %q", p)
	}
	if hits.Load() != 1 {
		t.Fatalf("cached metadata document refetched: %d", hits.Load())
	}
	// A redirect URI the document does not list is refused.
	q.Set("redirect_uri", "http://127.0.0.1/elsewhere")
	if resp, _ := e.get(local + "/oauth/authorize?" + q.Encode()); resp.StatusCode != 400 {
		t.Fatalf("unlisted redirect URI: %d", resp.StatusCode)
	}

	// Issued secrets.
	for id, secret := range map[string]string{gwtest.HelperClientID: gwtest.HelperSecret, gwtest.PreClientID: gwtest.PreSecret} {
		req, _ := http.NewRequest("POST", local+"/smcp/v1/sessions", strings.NewReader(`{"harness_version":"1"}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(id, secret)
		if resp, body := e.do(req); resp.StatusCode != 201 {
			t.Fatalf("%s session: %d %s", id, resp.StatusCode, body)
		}
	}
	if p := principalOf(gwtest.HelperClientID); p != "cc" {
		t.Fatalf("helper bound to %q", p)
	}
	if p := principalOf(gwtest.PreClientID); p != "cloud" {
		t.Fatalf("pre-remote bound to %q", p)
	}

	// Approved Dynamic Client Registration.
	e.enable()
	reg := e.register("http://127.0.0.1/callback")
	id := reg["client_id"].(string)
	if st, body := e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{"principal": "cc"}); st != 200 || body["principal"] != "cc" {
		t.Fatalf("approve %d %v", st, body)
	}
	if resp, tok := e.signIn(id, "", "smcp:template:remote"); resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("registered client sign-in: %d %v", resp.StatusCode, tok)
	}
	if p := principalOf(id); p != "cc" {
		t.Fatalf("registered client bound to %q", p)
	}

	// A second principal cannot claim a client ID already bound.
	base := `
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[principal]]
id = "a"
framework = "claude-code"
profile = "dev"
[[principal]]
id = "b"
framework = "codex"
profile = "dev"
`
	for name, extra := range map[string]string{
		"client twice": `
[[client]]
client_id = "x"
principal = "a"
redirect_uris = ["http://127.0.0.1/cb"]
[[client]]
client_id = "x"
principal = "b"
redirect_uris = ["http://127.0.0.1/cb"]`,
		"client and metadata": `
[[client]]
client_id = "https://agent.example/c.json"
principal = "a"
redirect_uris = ["http://127.0.0.1/cb"]
[[client_metadata]]
url = "https://agent.example/c.json"
principal = "b"`,
		"metadata twice": `
[[client_metadata]]
url = "https://agent.example/c.json"
principal = "a"
[[client_metadata]]
url = "https://agent.example/c.json"
principal = "b"`,
	} {
		if _, err := config.Parse([]byte(base + extra)); err == nil || !strings.Contains(err.Error(), "duplicate client_id") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
