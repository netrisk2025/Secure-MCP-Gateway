package remote_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

const remoteTable = `
[remote]
address = "%REMOTE%"
clients = ["pre-remote"]
default_principal = "cloud"
templates = ["remote"]
`

// callerAddr is the address the fake tunnel reports.
var callerAddr atomic.Value

// env is a Gateway with the Remote Access Profile behind a fake tunnel
// (gwtest.Tunnel).
type env struct {
	*gwtest.Gateway
	public string // tunnel public URL
}

func newEnv(t *testing.T, extra string) *env {
	t.Helper()
	callerAddr.Store("203.0.113.7")
	g := gwtest.Start(t, remoteTable+extra)
	return &env{Gateway: g, public: g.Tunnel(func() string { return callerAddr.Load().(string) })}
}

func (e *env) enable() { e.T.Helper(); e.EnableRemote(e.public) }

func (e *env) do(req *http.Request) (*http.Response, []byte) {
	e.T.Helper()
	resp, err := e.HTTP.Do(req)
	if err != nil {
		e.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) get(u string) (*http.Response, []byte) {
	req, _ := http.NewRequest("GET", u, nil)
	return e.do(req)
}

func (e *env) postForm(u string, v url.Values, basicUser, basicPass string) (*http.Response, map[string]any) {
	e.T.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	resp, b := e.do(req)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp, out
}

func (e *env) mcp(base, token string, msg map[string]any) (*http.Response, map[string]any) {
	e.T.Helper()
	b, _ := json.Marshal(msg)
	req, _ := http.NewRequest("POST", base+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, raw := e.do(req)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 50)
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

func (e *env) register(redirect string) map[string]any {
	e.T.Helper()
	b, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirect}, "client_name": "Test Agent", "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}})
	req, _ := http.NewRequest("POST", e.public+"/oauth/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, raw := e.do(req)
	if resp.StatusCode != 201 {
		e.T.Fatalf("register: %d %s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func authorizeQuery(clientID, redirect, challenge, scope, resource string) url.Values {
	return url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "state": {"st"}, "scope": {scope}, "resource": {resource}}
}

// signIn runs the authorization-code flow for clientID and returns the
// token response.
func (e *env) signIn(clientID, secret, scope string) (*http.Response, map[string]any) {
	e.T.Helper()
	redirect := "http://127.0.0.1/callback"
	verifier, challenge := pkce()
	q := authorizeQuery(clientID, redirect, challenge, scope, e.public+"/mcp")
	q.Set("username", gwtest.ApproverUser)
	q.Set("password", gwtest.ApproverPassword)
	resp, _ := e.postForm(e.public+"/oauth/authorize", q, "", "")
	if resp.StatusCode != http.StatusFound {
		e.T.Fatalf("authorize: %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		e.T.Fatalf("no code in %s", loc)
	}
	if loc.Query().Get("iss") != e.public {
		e.T.Fatalf("iss %q", loc.Query().Get("iss"))
	}
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "client_id": {clientID}}
	return e.postForm(e.public+"/oauth/token", v, map[bool]string{true: clientID}[secret != ""], secret)
}

func TestDisabledByDefaultAndAdministratorEnable(t *testing.T) {
	reqtest.Partial(t, "FR-16.11")
	// Partial: the Operator role of Appendix C does not exist in the
	// control API yet; this proves the default, that a non-Administrator
	// token is refused, and the recorded event.
	e := newEnv(t, "")
	if st := e.Remote.Status(); st.Enabled || st.Listening || e.Remote.Addr() != "" {
		t.Fatalf("enabled by default: %+v", st)
	}
	if _, err := http.Get("http://" + e.Config.Remote.Address); err == nil {
		t.Fatal("remote listener open while disabled")
	}
	if st, _ := e.AdminAs("not-a-token", "POST", "/api/v1/remote/enable", map[string]any{"public_url": e.public}); st != 401 {
		t.Fatalf("unauthenticated enable: %d", st)
	}
	if st, _ := e.Admin("POST", "/api/v1/remote/enable", map[string]any{"public_url": "http://insecure.example"}); st != 400 {
		t.Fatalf("http public URL accepted: %d", st)
	}
	e.enable()
	ev := e.WaitEvent(func(ev audit.Event) bool { return ev.Outcome == "remote_access_enabled" })
	if d, _ := ev.Detail.(map[string]any); d["actor"] != "operator-token" || d["public_url"] != e.public {
		t.Fatalf("event detail %v", ev.Detail)
	}
	st, body := e.Admin("GET", "/api/v1/remote", nil)
	if st != 200 || body["enabled"] != true || body["listening"] != true || body["resource_uri"] != e.public+"/mcp" {
		t.Fatalf("status %d %v", st, body)
	}
	// The state survives a restart of the service.
	raw, err := os.ReadFile(filepath.Join(e.Config.State.Dir, "remote", "state.json"))
	if err != nil || !strings.Contains(string(raw), `"enabled": true`) {
		t.Fatalf("state %s %v", raw, err)
	}
	if st, body := e.Admin("POST", "/api/v1/remote/disable", map[string]any{}); st != 200 || body["enabled"] != false || body["listening"] != false {
		t.Fatalf("disable %d %v", st, body)
	}
	e.WaitEvent(func(ev audit.Event) bool { return ev.Outcome == "remote_access_disabled" })
}

func TestPublicNameAndMetadata(t *testing.T) {
	reqtest.Verifies(t, "FR-16.3")
	e := newEnv(t, "")
	e.enable()
	var prm, asm map[string]any
	_, b := e.get(e.public + "/.well-known/oauth-protected-resource/mcp")
	_ = json.Unmarshal(b, &prm)
	_, b = e.get(e.public + "/.well-known/oauth-authorization-server")
	_ = json.Unmarshal(b, &asm)
	if prm["resource"] != e.public+"/mcp" || prm["authorization_servers"].([]any)[0] != e.public {
		t.Fatalf("PRM %v", prm)
	}
	if asm["issuer"] != e.public || asm["registration_endpoint"] != e.public+"/oauth/register" || asm["token_endpoint"] != e.public+"/oauth/token" {
		t.Fatalf("ASM %v", asm)
	}
	// Another name for the same tunnel is refused with 421.
	req, _ := http.NewRequest("GET", e.public+"/.well-known/oauth-authorization-server", nil)
	req.Host = "attacker.example"
	if resp, _ := e.do(req); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("other host: %d", resp.StatusCode)
	}
	// So is the listener's own address, which a tunnel pointed at the
	// wrong name would send.
	if resp, _ := e.get("https://" + e.Config.Remote.Address + "/.well-known/oauth-authorization-server"); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("listener address as host: %d", resp.StatusCode)
	}
}

func TestRemoteEndpointSet(t *testing.T) {
	reqtest.Verifies(t, "FR-16.4")
	e := newEnv(t, "")
	e.enable()
	for _, p := range []string{"/smcp/v1/sessions", "/healthz", "/metrics", "/console", "/admin/v1/health", "/api/v1/approvals", "/"} {
		if resp, _ := e.get(e.public + p); resp.StatusCode != 404 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest("POST", e.public+"/smcp/v1/sessions", strings.NewReader(`{}`))
	if resp, _ := e.do(req); resp.StatusCode != 404 {
		t.Errorf("POST session API: %d", resp.StatusCode)
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"} {
		if resp, _ := e.get(e.public + p); resp.StatusCode != 200 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

func TestDynamicRegistrationNeedsApproval(t *testing.T) {
	reqtest.Verifies(t, "FR-16.5", "SR-2.11-2")
	e := newEnv(t, "")
	// Outside the profile there is no registration endpoint anywhere.
	req, _ := http.NewRequest("POST", e.MCPURL()[:len(e.MCPURL())-4]+"/oauth/register", strings.NewReader(`{"redirect_uris":["http://127.0.0.1/callback"]}`))
	req.Header.Set("Content-Type", "application/json")
	if resp, _ := e.do(req); resp.StatusCode != 404 && resp.StatusCode != 405 {
		t.Fatalf("local registration: %d", resp.StatusCode)
	}
	e.enable()
	reg := e.register("http://127.0.0.1/callback")
	id := reg["client_id"].(string)
	if reg["smcp_registration_status"] != "pending" {
		t.Fatalf("registration %v", reg)
	}
	e.WaitEvent(func(ev audit.Event) bool {
		return ev.Class == "client_registration" && ev.Outcome == "pending" && ev.ClientID == id
	})
	// Pending: authorization is refused with the pending message.
	_, challenge := pkce()
	q := authorizeQuery(id, "http://127.0.0.1/callback", challenge, "", e.public+"/mcp")
	resp, _ := e.get(e.public + "/oauth/authorize?" + q.Encode())
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "unauthorized_client" || !strings.Contains(loc.Query().Get("error_description"), "pending operator approval") {
		t.Fatalf("pending authorize: %d %s", resp.StatusCode, loc)
	}
	// Pending: the token endpoint refuses too.
	tr, body := e.postForm(e.public+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {id}}, "", "")
	if tr.StatusCode != 401 || !strings.Contains(fmt.Sprint(body["error_description"]), "pending operator approval") {
		t.Fatalf("pending token: %d %v", tr.StatusCode, body)
	}
	// The registration is listed for the operator.
	st, list := e.Admin("GET", "/api/v1/clients?status=pending", nil)
	if st != 200 || len(list["clients"].([]any)) != 1 {
		t.Fatalf("list %d %v", st, list)
	}
	if st, body := e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{"principal": "nobody"}); st != 400 {
		t.Fatalf("approve to unknown principal: %d %v", st, body)
	}
	if st, body := e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{}); st != 200 || body["status"] != "approved" || body["principal"] != "cloud" {
		t.Fatalf("approve %d %v", st, body)
	}
	if st, _ := e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{}); st != 409 {
		t.Fatalf("second approve: %d", st)
	}
	resp2, tok := e.signIn(id, "", "smcp:template:remote")
	if resp2.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("approved sign-in: %d %v", resp2.StatusCode, tok)
	}
	// Revocation ends the session.
	if st, _ := e.Admin("POST", "/api/v1/clients/"+id+"/revoke", map[string]any{}); st != 200 {
		t.Fatalf("revoke %d", st)
	}
	if r, _ := e.mcp(e.public, tok["access_token"].(string), map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); r.StatusCode != 401 {
		t.Fatalf("revoked client still served: %d", r.StatusCode)
	}
}

func TestRemoteSessionAndOriginEvidence(t *testing.T) {
	reqtest.Partial(t, "FR-16.1", "FR-16.8")
	// FR-16.1: proves the separate listener, remote binding of sessions and
	// that local sessions are refused there. FR-16.8: proves the fields on
	// every event of a remote call and session; events written by the
	// Approval Service (E-07) for remote calls do not yet carry them.
	// FR-16.12 is TestRemoteAllowedTemplates.
	e := newEnv(t, "")
	e.enable()
	if e.Config.Remote.Address == e.Config.Listener.Address {
		t.Fatal("remote listener is the harness listener")
	}
	// A template that is not remote-allowed is refused.
	if resp, body := e.signIn(gwtest.PreClientID, gwtest.PreSecret, "smcp:template:ro"); resp.StatusCode != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("non-remote template: %d %v", resp.StatusCode, body)
	}
	// The default template (ro) is not remote-allowed either.
	if resp, _ := e.signIn(gwtest.PreClientID, gwtest.PreSecret, ""); resp.StatusCode != 400 {
		t.Fatalf("default template: %d", resp.StatusCode)
	}
	resp, tok := e.signIn(gwtest.PreClientID, gwtest.PreSecret, "smcp:template:remote")
	if resp.StatusCode != 200 {
		t.Fatalf("sign-in %d %v", resp.StatusCode, tok)
	}
	if tok["expires_in"].(float64) != 900 {
		t.Fatalf("remote access lifetime %v", tok["expires_in"])
	}
	exp, _ := time.Parse(time.RFC3339, tok["expires_at"].(string))
	if d := time.Until(exp); d > 2*time.Hour+time.Minute || d < 2*time.Hour-time.Minute {
		t.Fatalf("remote maximum lifetime %v", d)
	}
	access := tok["access_token"].(string)
	// The remote token is not accepted on the local listener.
	if r, _ := e.mcp(strings.TrimSuffix(e.MCPURL(), "/mcp"), access, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); r.StatusCode != 401 {
		t.Fatalf("remote token on local listener: %d", r.StatusCode)
	}
	r, body := e.mcp(e.public, access, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "t_echo", "arguments": map[string]any{"text": "hi"}}})
	if r.StatusCode != 200 || !strings.Contains(fmt.Sprint(body["result"]), "echo:hi") {
		t.Fatalf("remote call %d %v", r.StatusCode, body)
	}
	corr := ""
	e.WaitEvent(func(ev audit.Event) bool {
		if ev.Class == "call" && ev.Outcome == "delivered" || ev.Phase == "delivered" {
			corr = ev.CorrelationID
			return true
		}
		return false
	})
	n := 0
	for _, ev := range e.Events() {
		if ev.CorrelationID == corr || ev.ReasonCode == "OAUTH_CODE" {
			n++
			if ev.Channel != "remote" || ev.ClientID != gwtest.PreClientID || ev.ClientAddress != "203.0.113.7" || ev.ClientAddressSource != "server-asserted" {
				t.Errorf("event %s/%s missing remote origin: %+v", ev.Class, ev.Phase, ev)
			}
		}
	}
	if n < 3 {
		t.Fatalf("only %d events checked", n)
	}
	// Local sessions keep no channel.
	for _, ev := range e.Events() {
		if ev.Class == "gateway" && ev.Channel != "" {
			t.Fatalf("local event marked remote: %+v", ev)
		}
	}
	// Refresh keeps the remote binding.
	rr, rt := e.postForm(e.public+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}}, gwtest.PreClientID, gwtest.PreSecret)
	if rr.StatusCode != 200 || rt["access_token"] == nil {
		t.Fatalf("refresh %d %v", rr.StatusCode, rt)
	}
}

// TestRemoteAllowedTemplates is FR-16.12: through the remote listener a
// session is created only for a template that the principal's Framework
// Profile marks remote_allowed, even when the configuration's
// remote.templates lists another; the session gets the CP-49 remote
// lifetimes (15 minutes idle, 2 hours at most); and a policy revision that
// removes the mark refuses the next sign-in. Every session through the
// remote listener is created by the same issue path (authorization code
// and device grants), which sets session.CreateParams.Remote.
func TestRemoteAllowedTemplates(t *testing.T) {
	reqtest.Verifies(t, "FR-16.12")
	callerAddr.Store("203.0.113.7")
	// remote.templates lists both; the policy marks only "remote".
	g := gwtest.Start(t, strings.Replace(remoteTable, `templates = ["remote"]`, `templates = ["ro", "remote"]`, 1))
	e := &env{Gateway: g, public: g.Tunnel(func() string { return callerAddr.Load().(string) })}
	e.enable()
	if resp, body := e.signIn(gwtest.PreClientID, gwtest.PreSecret, "smcp:template:ro"); resp.StatusCode != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("template without remote_allowed: %d %v", resp.StatusCode, body)
	}
	e.WaitEvent(func(ev audit.Event) bool {
		return ev.ReasonCode == "REMOTE_TEMPLATE_REFUSED" && ev.Outcome == "deny" && fmt.Sprint(ev.Detail) == "map[template:ro]"
	})
	// The default template (ro) is refused the same way.
	if resp, _ := e.signIn(gwtest.PreClientID, gwtest.PreSecret, ""); resp.StatusCode != 400 {
		t.Fatalf("default template: %d", resp.StatusCode)
	}
	resp, tok := e.signIn(gwtest.PreClientID, gwtest.PreSecret, "smcp:template:remote")
	if resp.StatusCode != 200 {
		t.Fatalf("remote_allowed template: %d %v", resp.StatusCode, tok)
	}
	if tok["expires_in"].(float64) != 900 {
		t.Fatalf("remote idle lifetime %v, want 900 s (CP-49)", tok["expires_in"])
	}
	exp, _ := time.Parse(time.RFC3339, tok["expires_at"].(string))
	if d := time.Until(exp); d > 2*time.Hour+time.Minute || d < 2*time.Hour-time.Minute {
		t.Fatalf("remote maximum lifetime %v, want 2 h (CP-49)", d)
	}
	// A local session of the same principal gets the longer CP-18 lifetime.
	local, _, err := g.App.Store.Create(session.CreateParams{PrincipalID: "cloud", ClientID: "local", Listener: "tls", Claims: session.Claims{Template: "ro"}})
	if err != nil {
		t.Fatal(err)
	}
	if !local.MaxDeadline.After(time.Now().Add(2*time.Hour + time.Minute)) {
		t.Fatalf("local session max deadline %v is not longer than the remote one", local.MaxDeadline)
	}
	// Without the mark in the active policy, the template is refused.
	unmarked := strings.Replace(gwtest.Policy, `, "remote_allowed": ["remote"]`, "", 1)
	snap, err := policy.Compile([]byte(strings.Replace(unmarked, `"r1"`, `"r2"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.App.Gateway.ActivatePolicy("test", snap); err != nil {
		t.Fatal(err)
	}
	if resp, body := e.signIn(gwtest.PreClientID, gwtest.PreSecret, "smcp:template:remote"); resp.StatusCode != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("template after its mark was removed: %d %v", resp.StatusCode, body)
	}
	// The session store refuses a remote session for an unmarked template
	// whatever the caller.
	if _, _, err := g.App.Store.Create(session.CreateParams{PrincipalID: "cloud", ClientID: "x", Listener: "remote", Remote: true, Claims: session.Claims{Template: "remote"}}); !errors.Is(err, session.ErrNoTemplate) {
		t.Fatalf("store: %v", err)
	}
}

func TestLockoutAndRates(t *testing.T) {
	reqtest.Partial(t, "FR-16.6")
	// Partial: per-source rate and per-client call rate and lockout are
	// proven; the forwarded source used for OAuth rates is the tunnel's
	// header, so the fake tunnel stands in for a real one.
	e := newEnv(t, "[remote.limits]\ncalls_per_minute = 1\ncalls_burst = 1\nlockout_failures = 3\nlockout = \"1m\"\n")
	e.enable()
	redirect := "http://127.0.0.1/callback"
	_, challenge := pkce()
	for i := range 3 {
		q := authorizeQuery(gwtest.PreClientID, redirect, challenge, "smcp:template:remote", e.public+"/mcp")
		q.Set("username", gwtest.ApproverUser)
		q.Set("password", "wrong password")
		if resp, _ := e.postForm(e.public+"/oauth/authorize", q, "", ""); resp.StatusCode != 401 {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	e.WaitEvent(func(ev audit.Event) bool {
		return ev.ReasonCode == "REMOTE_LOCKOUT" && ev.ClientID == gwtest.PreClientID && ev.Channel == "remote"
	})
	q := authorizeQuery(gwtest.PreClientID, redirect, challenge, "smcp:template:remote", e.public+"/mcp")
	q.Set("username", gwtest.ApproverUser)
	q.Set("password", gwtest.ApproverPassword)
	if resp, _ := e.postForm(e.public+"/oauth/authorize", q, "", ""); resp.StatusCode != 429 {
		t.Fatalf("locked sign-in with the right password: %d", resp.StatusCode)
	}
	if resp, _ := e.postForm(e.public+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, gwtest.PreClientID, gwtest.PreSecret); resp.StatusCode != 429 {
		t.Fatalf("locked token request: %d", resp.StatusCode)
	}

	// Call rate per client: a second client from another address is not
	// locked.
	callerAddr.Store("198.51.100.9")
	reg := e.register(redirect)
	id := reg["client_id"].(string)
	e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{})
	_, tok := e.signIn(id, "", "smcp:template:remote")
	call := map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "t_echo", "arguments": map[string]any{"text": "a"}}}
	if r, _ := e.mcp(e.public, tok["access_token"].(string), call); r.StatusCode != 200 {
		t.Fatalf("first call %d", r.StatusCode)
	}
	r, body := e.mcp(e.public, tok["access_token"].(string), call)
	if r.StatusCode != 429 || body["error"].(map[string]any)["code"].(float64) != -31005 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("second call %d %v", r.StatusCode, body)
	}
}

// TestRemoteLimitKeys is FR-16.6 with TestLockoutAndRates and
// TestOAuthSourceRate: the OAuth rate is per forwarded source address (a
// second address is served while the first gets 429); the call rate is
// per client ID (a second client from the same address is served while
// the first gets -31005 with HTTP 429); failed token requests, like failed
// sign-ins, lock after the CP-49 number of consecutive failures, with a
// REMOTE_LOCKOUT event; and the lockout holds both the client ID (refused
// from another address) and the source address (another client refused
// from it) for the lockout period.
func TestRemoteLimitKeys(t *testing.T) {
	reqtest.Verifies(t, "FR-16.6")
	e := newEnv(t, "[remote.limits]\ncalls_per_minute = 1\ncalls_burst = 1\nlockout_failures = 3\nlockout = \"1m\"\noauth_per_second = 1\noauth_burst = 6\n")
	e.enable()
	redirect := "http://127.0.0.1/callback"
	metadata := e.public + "/.well-known/oauth-authorization-server"

	// OAuth rate per source address.
	callerAddr.Store("198.51.100.20")
	limited := false
	for range 12 {
		if resp, _ := e.get(metadata); resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("OAuth source rate not applied")
	}
	callerAddr.Store("198.51.100.21")
	if resp, _ := e.get(metadata); resp.StatusCode != http.StatusOK {
		t.Fatalf("another source address was limited too: %d", resp.StatusCode)
	}
	time.Sleep(6 * time.Second) // refill the OAuth buckets (1 per second)

	// Call rate per client ID: two approved clients from one address.
	callerAddr.Store("198.51.100.22")
	tokens := []string{}
	for range 2 {
		reg := e.register(redirect)
		id := reg["client_id"].(string)
		if st, body := e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{}); st != 200 {
			t.Fatalf("approve %d %v", st, body)
		}
		resp, tok := e.signIn(id, "", "smcp:template:remote")
		if resp.StatusCode != 200 {
			t.Fatalf("sign-in %d %v", resp.StatusCode, tok)
		}
		tokens = append(tokens, tok["access_token"].(string))
		time.Sleep(3 * time.Second)
	}
	call := map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "t_echo", "arguments": map[string]any{"text": "a"}}}
	if r, _ := e.mcp(e.public, tokens[0], call); r.StatusCode != 200 {
		t.Fatalf("first client, first call: %d", r.StatusCode)
	}
	if r, body := e.mcp(e.public, tokens[0], call); r.StatusCode != 429 || body["error"].(map[string]any)["code"].(float64) != -31005 {
		t.Fatalf("first client, second call: %d %v", r.StatusCode, body)
	}
	if r, _ := e.mcp(e.public, tokens[1], call); r.StatusCode != 200 {
		t.Fatalf("second client from the same address was limited: %d", r.StatusCode)
	}

	// Failed token requests lock the client and the source.
	callerAddr.Store("198.51.100.23")
	for i := range 3 {
		time.Sleep(time.Second)
		resp, body := e.postForm(e.public+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {fmt.Sprintf("not-a-token-%d", i)}}, gwtest.PreClientID, gwtest.PreSecret)
		if resp.StatusCode != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("failed token request %d: %d %v", i, resp.StatusCode, body)
		}
	}
	e.WaitEvent(func(ev audit.Event) bool {
		return ev.ReasonCode == "REMOTE_LOCKOUT" && ev.Outcome == "locked" && ev.ClientID == gwtest.PreClientID && ev.Channel == "remote"
	})
	time.Sleep(time.Second)
	if resp, _ := e.postForm(e.public+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, gwtest.PreClientID, gwtest.PreSecret); resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("locked client, same address: %d", resp.StatusCode)
	}
	// The client ID is locked from another address.
	callerAddr.Store("198.51.100.24")
	if resp, _ := e.postForm(e.public+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, gwtest.PreClientID, gwtest.PreSecret); resp.StatusCode != 429 {
		t.Fatalf("locked client from another address: %d", resp.StatusCode)
	}
	// The source address is locked for another client.
	reg := e.register(redirect)
	other := reg["client_id"].(string)
	e.Admin("POST", "/api/v1/clients/"+other+"/approve", map[string]any{})
	callerAddr.Store("198.51.100.23")
	time.Sleep(time.Second)
	if resp, _ := e.postForm(e.public+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {other}}, "", ""); resp.StatusCode != 429 {
		t.Fatalf("another client from the locked address: %d", resp.StatusCode)
	}
}

func TestOAuthSourceRate(t *testing.T) {
	reqtest.Partial(t, "FR-16.6")
	e := newEnv(t, "[remote.limits]\noauth_per_second = 1\noauth_burst = 2\n")
	e.enable()
	got429 := false
	for range 6 {
		if resp, _ := e.get(e.public + "/.well-known/oauth-authorization-server"); resp.StatusCode == 429 {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("OAuth source rate not applied")
	}
}

func TestRequestBounds(t *testing.T) {
	reqtest.Verifies(t, "FR-16.7")
	e := newEnv(t, "[remote.limits]\nbody_bytes = 2048\nheader_bytes = 2048\n")
	e.enable()
	big := bytes.Repeat([]byte("x"), 4096)
	req, _ := http.NewRequest("POST", e.public+"/mcp", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	if resp, _ := e.do(req); resp.StatusCode != 413 {
		t.Fatalf("large body: %d", resp.StatusCode)
	}
	// Without Content-Length (chunked) the bound applies while reading.
	req, _ = http.NewRequest("POST", e.public+"/mcp", io.MultiReader(bytes.NewReader(big)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer x")
	if resp, _ := e.do(req); resp.StatusCode != 413 {
		t.Fatalf("chunked large body: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", e.public+"/.well-known/oauth-authorization-server", nil)
	req.Header.Set("X-Pad", strings.Repeat("p", 3000))
	if resp, _ := e.do(req); resp.StatusCode != 431 {
		t.Fatalf("large headers: %d", resp.StatusCode)
	}
}

func TestDeviceGrant(t *testing.T) {
	reqtest.Partial(t, "FR-16.9")
	// Partial: the device authorization grant smcp-connect uses; the relay
	// itself is tested in internal/adapter.
	// The remote service's clock stands still unless the test moves it, so
	// the poll-interval rule does not depend on how long a poll takes
	// (client authentication hashes a secret, slow under -race).
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	callerAddr.Store("203.0.113.7")
	g := gwtest.StartWithRemoteClock(t, remoteTable, now)
	e := &env{Gateway: g, public: g.Tunnel(func() string { return callerAddr.Load().(string) })}
	e.enable()
	resp, da := e.postForm(e.public+"/oauth/device_authorization", url.Values{"scope": {"smcp:template:remote"}}, gwtest.PreClientID, gwtest.PreSecret)
	if resp.StatusCode != 200 || da["user_code"] == nil || da["verification_uri"] != e.public+"/oauth/device" {
		t.Fatalf("device authorization %d %v", resp.StatusCode, da)
	}
	poll := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da["device_code"].(string)}}
	if r, b := e.postForm(e.public+"/oauth/token", poll, gwtest.PreClientID, gwtest.PreSecret); r.StatusCode != 400 || b["error"] != "authorization_pending" {
		t.Fatalf("pending poll %d %v", r.StatusCode, b)
	}
	if r, b := e.postForm(e.public+"/oauth/token", poll, gwtest.PreClientID, gwtest.PreSecret); b["error"] != "slow_down" {
		t.Fatalf("fast poll %d %v", r.StatusCode, b)
	}
	advance(6 * time.Second) // past the 5 s interval: polling is allowed again
	if r, b := e.postForm(e.public+"/oauth/token", poll, gwtest.PreClientID, gwtest.PreSecret); r.StatusCode != 400 || b["error"] != "authorization_pending" {
		t.Fatalf("poll after the interval %d %v", r.StatusCode, b)
	}
	page, body := e.get(e.public + "/oauth/device?user_code=" + url.QueryEscape(da["user_code"].(string)))
	if page.StatusCode != 200 || !bytes.Contains(body, []byte(gwtest.PreClientID)) {
		t.Fatalf("verification page %d", page.StatusCode)
	}
	if r, _ := e.postForm(e.public+"/oauth/device", url.Values{"user_code": {da["user_code"].(string)}, "username": {gwtest.ApproverUser},
		"password": {gwtest.ApproverPassword}, "decision": {"approve"}}, "", ""); r.StatusCode != 200 {
		t.Fatalf("approve code %d", r.StatusCode)
	}
	r, tok := e.postForm(e.public+"/oauth/token", poll, gwtest.PreClientID, gwtest.PreSecret)
	if r.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("device token %d %v", r.StatusCode, tok)
	}
	if r, b := e.mcp(e.public, tok["access_token"].(string), map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); r.StatusCode != 200 || !strings.Contains(fmt.Sprint(b), "t_echo") {
		t.Fatalf("tools/list %d %v", r.StatusCode, b)
	}
}
