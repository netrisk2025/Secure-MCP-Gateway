package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

const testPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ro", "rw"], "default_template": "ro"}},
  "templates": {
    "ro": {"rules": [{"id": "ro-t", "server": "t", "tools": ["echo", "dotted.name", "rpcerror", "slow", "big", "ghost", "noisy"]},
                     {"id": "ro-approve", "server": "t", "tools": ["write"], "approval": true}]},
    "rw": {"rules": [{"id": "rw-t", "server": "t", "tools": ["echo", "write"]}]}
  }
}`

const (
	approverPassword = "approver password 1"
	clientID         = "https://claude.ai/api/mcp/oauth/client-metadata"
)

// fixture is one running Gateway with its own state directory.
type fixture struct {
	t        *testing.T
	cfg      *config.Config
	app      *app.App
	base     string
	client   *http.Client // trusts the Gateway CA, does not follow redirects
	stateDir string
	operator string
	cancel   context.CancelFunc
	served   chan error
}

func freePort(t *testing.T) int {
	t.Helper()
	return testport.Free(t)
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := keys.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// e2eLimits is the fixture's [limits] body: the defaults below, with any
// key that extra sets taken from extra instead.
func e2eLimits(extra string) string {
	var out []string
	for _, d := range []string{`upstream_timeout = "2s"`, `client_deadline = "3s"`, `result_bytes = 65536`, `tool_queue = 1`,
		`tool_concurrency_total = 1`, `tool_concurrency_per_principal = 1`} {
		key := strings.TrimSpace(strings.SplitN(d, "=", 2)[0])
		if !strings.Contains(extra, key+" ") && !strings.Contains(extra, key+"=") {
			out = append(out, d)
		}
	}
	return strings.Join(append(out, extra), "\n")
}

func start(t *testing.T, extraLimits string) *fixture {
	t.Helper()
	return startWith(t, extraLimits, "")
}

// startWith is start with extraTOML appended to the configuration.
func startWith(t *testing.T, extraLimits, extraTOML string) *fixture {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	port, adminPort := freePort(t), freePort(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf(`
[listener]
address = "127.0.0.1:%d"
public_url = "https://127.0.0.1:%d"
[admin_listener]
address = "127.0.0.1:%d"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[[approver]]
username = "approver"
password_hash = %q
[policy]
file = %q
[limits]
%s
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = %q
principal = "cc"
redirect_uris = ["http://localhost:*/callback"]
[[client]]
client_id = "helper"
client_secret_hash = %q
principal = "cc"
redirect_uris = ["http://localhost/unused"]
[[server]]
alias = "t"
command = %q
args = ["-test.run=NONE"]
[server.env]
SMCP_E2E_BACKEND = "1"
%s
`, port, port, adminPort, stateDir, mustHash(t, "admin password 12"), mustHash(t, approverPassword), filepath.Join(dir, "policy.json"),
		e2eLimits(extraLimits), clientID, mustHash(t, "helper-secret-123"), exe, extraTOML)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), JanitorInterval: 200 * time.Millisecond,
		// The observation objects smcpd reports when none is published.
		ObservationContext: func() (string, string, string) { return "audit_profile@file", "default", "anomaly_response@file" }})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	// Listen binds both sockets before Serve, so no readiness polling is
	// needed: connections wait in the backlog.
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	f := &fixture{t: t, cfg: cfg, app: a, base: cfg.Listener.PublicURL, stateDir: stateDir, cancel: cancel, served: make(chan error, 1)}
	go func() { f.served <- a.Serve(ctx) }()
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(stateDir, keys.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(ca)
	f.client = &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if f.operator, err = keys.LoadAdminToken(stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.stop)
	return f
}

// stop shuts the Gateway down and seals the journal.
func (f *fixture) stop() {
	if f.cancel == nil {
		return
	}
	f.cancel()
	select {
	case err := <-f.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			f.t.Errorf("serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		f.t.Error("serve did not return")
	}
	f.app.Close()
	f.cancel = nil
}

// do sends a request and fails the test on transport errors.
func (f *fixture) do(req *http.Request) (*http.Response, []byte) {
	f.t.Helper()
	r, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return r, b
}

func (f *fixture) get(u string) (*http.Response, []byte) {
	f.t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	return f.do(req)
}

func (f *fixture) postForm(u string, v url.Values) (*http.Response, []byte) {
	f.t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(req)
}

func (f *fixture) getJSON(u string, v any) {
	f.t.Helper()
	r, b := f.get(u)
	if r.StatusCode != 200 {
		f.t.Fatalf("GET %s: %d", u, r.StatusCode)
	}
	if err := json.Unmarshal(b, v); err != nil {
		f.t.Fatal(err)
	}
}

// admin calls the control API with the operator token (or token).
func (f *fixture) admin(method, path, token string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.cfg.AdminURL()+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r, b := f.do(req)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return r.StatusCode, out
}

// oauthLogin runs the full authorization-code flow as a registered
// metadata-URL client with a loopback redirect, signing in as the Session
// Approver.
func (f *fixture) oauthLogin(scope string) (access, refresh string, tokenBody map[string]any) {
	f.t.Helper()
	return f.oauthLoginClient(scope, clientID)
}

// oauthLoginClient is oauthLogin for another registered public client.
func (f *fixture) oauthLoginClient(scope, clientID string) (access, refresh string, tokenBody map[string]any) {
	f.t.Helper()
	return f.oauthLoginAs(scope, clientID, "approver", approverPassword, nil)
}

// oauthLoginAs is oauthLoginClient signing in as the given Session
// Approver; page, when set, receives the sign-in page.
func (f *fixture) oauthLoginAs(scope, clientID, user, password string, page func(string)) (access, refresh string, tokenBody map[string]any) {
	t := f.t
	t.Helper()
	r, b := f.oauthTokenResponse(scope, clientID, user, password, page)
	if r.StatusCode != 200 {
		t.Fatalf("token: %d %s", r.StatusCode, b)
	}
	if err := json.Unmarshal(b, &tokenBody); err != nil {
		t.Fatal(err)
	}
	return tokenBody["access_token"].(string), tokenBody["refresh_token"].(string), tokenBody
}

// oauthTokenResponse runs the authorization-code flow and returns the
// token endpoint's response, whatever its status.
func (f *fixture) oauthTokenResponse(scope, clientID, user, password string, page func(string)) (*http.Response, []byte) {
	t := f.t
	t.Helper()
	// Discovery (FR-2.17).
	var prm map[string]any
	f.getJSON(f.base+"/.well-known/oauth-protected-resource/mcp", &prm)
	if prm["resource"] != f.cfg.ResourceURI() {
		t.Fatalf("PRM resource %v", prm["resource"])
	}
	var asm map[string]any
	f.getJSON(prm["authorization_servers"].([]any)[0].(string)+"/.well-known/oauth-authorization-server", &asm)
	if asm["issuer"] != f.base || asm["code_challenge_methods_supported"].([]any)[0] != "S256" {
		t.Fatalf("ASM %v", asm)
	}
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirect := "http://localhost:51234/callback"
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"xyz"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.cfg.ResourceURI()}, "scope": {scope}}
	r, body := f.get(asm["authorization_endpoint"].(string) + "?" + q.Encode())
	if r.StatusCode != 200 || !strings.Contains(string(body), "<form") {
		t.Fatalf("authorize GET: %d %s", r.StatusCode, body)
	}
	if page != nil {
		page(string(body))
	}
	form := q
	form.Set("username", user)
	form.Set("password", password)
	r, _ = f.postForm(asm["authorization_endpoint"].(string), form)
	if r.StatusCode != 302 {
		t.Fatalf("authorize POST: %d", r.StatusCode)
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	if loc.Query().Get("iss") != f.base || loc.Query().Get("state") != "xyz" || loc.Query().Get("code") == "" || !strings.HasPrefix(loc.String(), redirect) {
		t.Fatalf("redirect %s", loc)
	}
	tf := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier}, "resource": {f.cfg.ResourceURI()}}
	return f.postForm(asm["token_endpoint"].(string), tf)
}

type bearerRT struct {
	token string
	base  http.RoundTripper
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func (f *fixture) mcpClient(access string) *mcp.ClientSession {
	f.t.Helper()
	hc := &http.Client{Transport: bearerRT{access, f.client.Transport}}
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e-harness", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: f.cfg.ResourceURI(), HTTPClient: hc}, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { cs.Close() })
	return cs
}

// post sends one raw JSON-RPC message with the given headers.
func (f *fixture) post(body string, hdr map[string]string) (int, http.Header, string) {
	f.t.Helper()
	req, _ := http.NewRequest("POST", f.cfg.ResourceURI(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, b := f.do(req)
	return r.StatusCode, r.Header, string(b)
}

func modernHeaders(access, method string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + access, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
}

const modernMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

func rpcErr(t *testing.T, err error) (*jsonrpc.Error, map[string]any) {
	t.Helper()
	var we *jsonrpc.Error
	if !errors.As(err, &we) {
		t.Fatalf("expected JSON-RPC error, got %v", err)
	}
	var data map[string]any
	_ = json.Unmarshal(we.Data, &data)
	return we, data
}

func callErr(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (*jsonrpc.Error, map[string]any) {
	t.Helper()
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	return rpcErr(t, err)
}

func TestOAuthSessionAndToolCall(t *testing.T) {
	reqtest.Verifies(t, "FR-2.19", "FR-2.20", "FR-1.2", "FR-1.25", "FR-1.26", "FR-1.50", "FR-1.29", "FR-1.30", "FR-4.12", "SR-5.4-1", "SR-5.13-1")
	// Partial here: FR-2.17 (TestAuthorizationMetadataDocuments), FR-2.18
	// (internal/remote.TestClientRegistrationPaths), FR-2.4
	// (internal/session.TestSessionContextKey), FR-2.5 and SR-2.11-1
	// (internal/remote.TestTokenValidationFixtures) are proven elsewhere;
	// this test exercises them on one registered client's sign-in.
	reqtest.Partial(t, "FR-2.17", "FR-2.18", "FR-2.4", "FR-2.5", "SR-2.11-1")
	f := start(t, "")
	access, _, body := f.oauthLogin("")
	for _, k := range []string{"session_id", "expires_in", "template_id", "policy_revision_id", "refresh_token"} {
		if _, ok := body[k]; !ok {
			t.Errorf("token response lacks %s", k)
		}
	}
	if body["template_id"] != "ro" || body["policy_revision_id"] != "r1" {
		t.Fatalf("%v", body)
	}
	if s := f.app.Store.Get(body["session_id"].(string)); s == nil || s.ApprovedBy != "approver" {
		t.Fatalf("approving person not recorded: %+v", s)
	}
	cs := f.mcpClient(access)
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var approvalHint bool
	for _, tool := range lt.Tools {
		names = append(names, tool.Name)
		if tool.Name == "t_write" {
			approvalHint = tool.Meta[edge.MetaRequiresUserInteraction] == true && tool.Meta[edge.MetaApprovalRequired] == true
		} else if tool.Meta[edge.MetaRequiresUserInteraction] != nil || tool.Meta[edge.MetaApprovalRequired] != nil {
			t.Errorf("%s carries an approval hint", tool.Name)
		}
	}
	want := "t_big t_dotted_name t_echo t_noisy t_rpcerror t_slow t_write"
	if strings.Join(names, " ") != want {
		t.Fatalf("catalog %q, want %q", strings.Join(names, " "), want)
	}
	if !approvalHint {
		t.Fatal("t_write lacks the approval hints")
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); !ok || tc.Text != "echo:hi" {
		t.Fatalf("%+v", res.Content)
	}
	prov, _ := res.Meta["local.smcpgw/provenance"].(map[string]any)
	if prov["untrusted"] != true || prov["serverId"] != "t" || prov["decisionId"] == "" || prov["manifest"] != "live" {
		t.Fatalf("provenance %v", res.Meta)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_dotted_name"}); err != nil {
		t.Fatal(err)
	}
	// Not in the catalog: unknown tool, even though the backend has it.
	we, _ := callErr(t, cs, "t_secret", nil)
	if we.Code != -32602 || we.Message != "Unknown tool" {
		t.Fatalf("%+v", we)
	}
}

func TestPolicyDecisionsAndErrorMapping(t *testing.T) {
	reqtest.Verifies(t, "FR-1.20", "FR-1.32", "FR-4.9", "FR-4.14")
	// FR-4.3 is verified by TestStageOrder, SR-1.17-1 by
	// edge.TestPreLaunchRecheck. FR-4.5: only schema-validate exists.
	// SR-2.10-1 is verified by TestSouthboundCarriesNoNorthboundCredentials.
	reqtest.Partial(t, "FR-4.5", "SR-2.10-1")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	// Approval obligation without an approval service: -31002 with
	// plain-language retry text and a console link.
	we, data := callErr(t, cs, "t_write", nil)
	if we.Code != edge.CodeApprovalRequired || data["reasonCode"] != "APPROVAL_REQUIRED" || data["correlationId"] == "" || data["decisionId"] == "" ||
		data["retry"] == "" || !strings.HasPrefix(fmt.Sprint(data["consoleUrl"]), f.cfg.AdminURL()) {
		t.Fatalf("%+v %v", we, data)
	}
	// Backend JSON-RPC error: code relayed, message withheld.
	we, data = callErr(t, cs, "t_rpcerror", nil)
	if we.Code != edge.CodeBackendError || data["backendCode"] != float64(-32001) || strings.Contains(we.Message, "detail") {
		t.Fatalf("%+v %v", we, data)
	}
	// Schema validation blocks bad arguments before dispatch.
	we, data = callErr(t, cs, "t_echo", map[string]any{"text": 7})
	if we.Code != -32602 || data["reasonCode"] != "SCHEMA_INVALID" {
		t.Fatalf("%+v %v", we, data)
	}
	// Upstream timeout (2s configured; tool sleeps 5s): -31009 with reason
	// UPSTREAM_TIMEOUT (Appendix B), since the backend may have acted.
	if we, data = callErr(t, cs, "t_slow", nil); we.Code != edge.CodeIndeterminate || data["reasonCode"] != "UPSTREAM_TIMEOUT" {
		t.Fatalf("%+v", we)
	}
	// Result size bound (64 KiB configured).
	if we, _ = callErr(t, cs, "t_big", map[string]any{"kib": 128}); we.Code != edge.CodeResponseWithheld {
		t.Fatalf("%+v", we)
	}
	// Emergency stop through the control API: a harness token cannot stop or
	// resume, the operator can, and the endpoint fails closed meanwhile.
	if st, _ := f.admin("POST", "/admin/v1/stop", access, map[string]any{"reason": "x"}); st != 401 {
		t.Fatalf("harness token stopped the Gateway: %d", st)
	}
	if st, _ := f.admin("POST", "/admin/v1/stop", f.operator, map[string]any{"reason": "drill"}); st != 200 {
		t.Fatalf("stop: %d", st)
	}
	status, _, body := f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{%s}}`, modernMeta), modernHeaders(access, "tools/list"))
	if status != 503 || !strings.Contains(body, fmt.Sprint(edge.CodeGatewayFailClosed)) || !strings.Contains(body, edge.ReasonEmergencyStop) {
		t.Fatalf("stopped: %d %s", status, body)
	}
	if st, _ := f.admin("POST", "/admin/v1/resume", access, map[string]any{}); st != 401 {
		t.Fatalf("harness token resumed: %d", st)
	}
	if st, _ := f.admin("POST", "/admin/v1/resume", f.operator, map[string]any{}); st != 200 {
		t.Fatalf("resume: %d", st)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "again"}}); err != nil {
		t.Fatal(err)
	}
}

// TestUnknownMethodsAnswer404: FR-1.10's verification, with the baseline
// profile in the 2026-07-28 era. A legacy-era session keeps HTTP 200 with
// -32601, since a legacy client reads 404 as an expired session.
func TestUnknownMethodsAnswer404(t *testing.T) {
	reqtest.Verifies(t, "FR-1.10")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	for i, m := range []string{"prompts/list", "resources/read", "foo/bar"} {
		params, hdr := modernMeta, modernHeaders(access, m)
		if m == "resources/read" { // the request is well formed, so only the method is unknown
			params += `,"uri":"file:///x"`
			hdr["Mcp-Name"] = "file:///x"
		}
		status, _, body := f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":{%s}}`, i+1, m, params), hdr)
		if status != 404 || !strings.Contains(body, `"code":-32601`) {
			t.Fatalf("%s: %d %s", m, status, body)
		}
	}
	// A qualified method on the same session is unaffected.
	if status, _, body := f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{%s}}`, modernMeta), modernHeaders(access, "tools/list")); status != 200 {
		t.Fatalf("tools/list: %d %s", status, body)
	}
	// Legacy era: -32601 with HTTP 200.
	hdr := map[string]string{"Authorization": "Bearer " + access}
	if status, _, body := f.post(`{"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"legacy","version":"0"}}}`, hdr); status != 200 {
		t.Fatalf("initialize: %d %s", status, body)
	}
	hdr["MCP-Protocol-Version"] = "2025-11-25"
	if status, _, body := f.post(`{"jsonrpc":"2.0","id":11,"method":"prompts/list"}`, hdr); status != 200 || !strings.Contains(body, `"code":-32601`) {
		t.Fatalf("legacy prompts/list: %d %s", status, body)
	}
}

func TestTransportAndAuthenticationRules(t *testing.T) {
	reqtest.Verifies(t, "FR-1.3", "FR-1.9", "FR-1.12", "FR-1.13", "FR-1.46", "FR-1.17", "SR-2.1-3", "SR-2.9-1", "SR-2.9-2", "SR-5.1-1", "SR-5.5-1", "FR-2.2", "FR-2.22")
	// FR-1.14 and FR-1.15 are checked on server/discover only; FR-1.42
	// checks the capability, not notification withholding; SR-2.8-1 checks
	// the harness listener only; SR-5.3-1 checks one authentication-error
	// case; FR-9.17 has no Data Server gate yet.
	reqtest.Partial(t, "FR-1.14", "FR-1.15", "FR-1.42", "SR-2.8-1", "SR-5.3-1", "FR-9.17")
	f := start(t, "")
	access, refresh, _ := f.oauthLogin("")

	// No bearer: 401 with resource metadata; bad bearer: 401 (-31006).
	req, _ := http.NewRequest("POST", f.cfg.ResourceURI(), strings.NewReader(`{}`))
	r, _ := f.do(req)
	if r.StatusCode != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("no bearer: %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
	status, _, body := f.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}`, map[string]string{"Authorization": "Bearer nope"})
	if status != 401 || !strings.Contains(body, fmt.Sprint(edge.CodeSessionInvalid)) {
		t.Fatalf("bad bearer on a legacy handshake: %d %s", status, body)
	}
	// GET and DELETE: 405.
	for _, m := range []string{"GET", "DELETE"} {
		req, _ := http.NewRequest(m, f.cfg.ResourceURI(), nil)
		req.Header.Set("Authorization", "Bearer "+access)
		if r, _ := f.do(req); r.StatusCode != 405 {
			t.Fatalf("%s: %d", m, r.StatusCode)
		}
	}
	// Origin not allowlisted: 403. Wrong Host: 421.
	if status, _, _ = f.post(`{}`, map[string]string{"Authorization": "Bearer " + access, "Origin": "https://evil.example"}); status != 403 {
		t.Fatalf("origin: %d", status)
	}
	req, _ = http.NewRequest("POST", f.cfg.ResourceURI(), strings.NewReader(`{}`))
	req.Host = "gateway.example:8443"
	req.Header.Set("Authorization", "Bearer "+access)
	if r, _ = f.do(req); r.StatusCode != 421 {
		t.Fatalf("host: %d", r.StatusCode)
	}
	// TLS 1.2 refused.
	tc := f.client.Transport.(*http.Transport).TLSClientConfig.Clone()
	tc.MinVersion, tc.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: tc}}).Get(f.base + "/healthz"); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}

	// server/discover: CP-04 versions, tools-only capabilities, cache hints, serverInfo.
	status, _, body = f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{%s}}`, modernMeta), modernHeaders(access, "server/discover"))
	type cacheable struct {
		TTLMs      int            `json:"ttlMs"`
		CacheScope string         `json:"cacheScope"`
		ResultType string         `json:"resultType"`
		Meta       map[string]any `json:"_meta"`
	}
	var disc struct {
		Result struct {
			cacheable
			SupportedVersions []string       `json:"supportedVersions"`
			Capabilities      map[string]any `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &disc); err != nil {
		t.Fatal(err)
	}
	d := disc.Result
	if status != 200 || strings.Join(d.SupportedVersions, ",") != "2026-07-28,2025-11-25" || d.Capabilities["logging"] != nil || d.Capabilities["tools"] == nil || d.TTLMs != 60000 || d.CacheScope != "private" || d.ResultType != "complete" || d.Meta["io.modelcontextprotocol/serverInfo"] == nil {
		t.Fatalf("discover: %d %s", status, body)
	}
	// tools/list carries the same cache hints (FR-1.13).
	status, _, body = f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{%s}}`, modernMeta), modernHeaders(access, "tools/list"))
	var tl struct {
		Result cacheable `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &tl); err != nil || status != 200 || tl.Result.TTLMs != 60000 || tl.Result.CacheScope != "private" || tl.Result.ResultType != "complete" {
		t.Fatalf("tools/list cache hints: %d %s", status, body)
	}
	// Unsupported modern version: -32022 with supported and requested.
	status, _, body = f.post(`{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`, map[string]string{"Authorization": "Bearer " + access, "MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "server/discover"})
	if status != 400 || !strings.Contains(body, `"code":-32022`) || !strings.Contains(body, `"requested":"2099-01-01"`) {
		t.Fatalf("unsupported: %d %s", status, body)
	}
	// Unqualified method: -32601.
	if _, _, body = f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{%s}}`, modernMeta), modernHeaders(access, "resources/list")); !strings.Contains(body, `"code":-32601`) {
		t.Fatalf("resources/list: %s", body)
	}
	// Legacy era on the same endpoint, no Mcp-Session-Id required, and a
	// tools/call evaluated without any prior tools/list (SR-5.5-1).
	hdr := map[string]string{"Authorization": "Bearer " + access}
	status, h, body := f.post(`{"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy","version":"0"}}}`, hdr)
	if status != 200 || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) || strings.Contains(body, "logging") {
		t.Fatalf("initialize: %d %s %v", status, body, h)
	}
	if status, _, _ = f.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, hdr); status != 202 {
		t.Fatalf("initialized: %d", status)
	}
	status, _, body = f.post(`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"legacy"}}}`, map[string]string{"Authorization": "Bearer " + access, "MCP-Protocol-Version": "2025-11-25"})
	if status != 200 || !strings.Contains(body, "echo:legacy") {
		t.Fatalf("legacy call: %d %s", status, body)
	}

	// Refresh: new access and refresh tokens, old ones invalid.
	tf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}}
	r, b := f.postForm(f.base+"/oauth/token", tf)
	var tok map[string]any
	if err := json.Unmarshal(b, &tok); err != nil {
		t.Fatal(err)
	}
	newAccess, _ := tok["access_token"].(string)
	if r.StatusCode != 200 || newAccess == "" || newAccess == access || tok["refresh_token"] == refresh {
		t.Fatalf("refresh: %v", tok)
	}
	if status, _, _ = f.post(`{}`, map[string]string{"Authorization": "Bearer " + access}); status != 401 {
		t.Fatalf("old token still valid: %d", status)
	}
	// Session API with a confidential client, then DELETE ends the session.
	req, _ = http.NewRequest("POST", f.base+"/smcp/v1/sessions", strings.NewReader(`{"harness_version":"x","purpose":"ci","template_id":"rw"}`))
	req.SetBasicAuth("helper", "helper-secret-123")
	r, b = f.do(req)
	var created map[string]any
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 201 || created["template_id"] != "rw" {
		t.Fatalf("session api: %d %v", r.StatusCode, created)
	}
	helperAccess := created["access_token"].(string)
	cs := f.mcpClient(helperAccess)
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "rw"}}); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest("GET", f.base+"/smcp/v1/sessions/"+created["session_id"].(string), nil)
	req.Header.Set("Authorization", "Bearer "+helperAccess)
	if r, b = f.do(req); r.StatusCode != 200 || !strings.Contains(string(b), `"state":"active"`) {
		t.Fatalf("session status: %d %s", r.StatusCode, b)
	}
	req, _ = http.NewRequest("DELETE", f.base+"/smcp/v1/sessions/"+created["session_id"].(string), nil)
	req.Header.Set("Authorization", "Bearer "+helperAccess)
	if r, _ = f.do(req); r.StatusCode != 204 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
	if status, _, _ = f.post(`{}`, map[string]string{"Authorization": "Bearer " + helperAccess}); status != 401 {
		t.Fatalf("terminated session accepted: %d", status)
	}
}

func TestScopesSelectTemplate(t *testing.T) {
	reqtest.Verifies(t, "FR-2.21")
	reqtest.Partial(t, "FR-2.6")
	f := start(t, "")
	access, _, body := f.oauthLogin("smcp:template:rw smcp:purpose:tests")
	if body["template_id"] != "rw" || body["scope"] != "smcp:template:rw smcp:purpose:tests" {
		t.Fatalf("%v", body)
	}
	lt, err := f.mcpClient(access).ListTools(context.Background(), nil)
	if err != nil || len(lt.Tools) != 2 {
		t.Fatalf("rw catalog: %v %v", lt, err)
	}
}

func TestQueueBound(t *testing.T) {
	reqtest.Verifies(t, "FR-4.8")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_slow"})
			errs <- err
		}()
	}
	queueFull := 0
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			if we, _ := rpcErr(t, err); we.Code == edge.CodeRateLimited {
				queueFull++
			}
		}
	}
	if queueFull == 0 {
		t.Fatal("no call was rejected by the queue bound")
	}
}

func TestRateLimitThroughEdge(t *testing.T) {
	reqtest.Verifies(t, "FR-3.13")
	f := start(t, "principal_calls_per_minute = 3")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	for i := 0; i < 3; i++ {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	we, data := callErr(t, cs, "t_echo", map[string]any{"text": "x"})
	if we.Code != edge.CodeRateLimited || data["reasonCode"] != "RATE_LIMITED" || data["callsPerMinute"] != float64(3) {
		t.Fatalf("%+v %v", we, data)
	}
}

func TestPolicyReloadThroughControlAPI(t *testing.T) {
	reqtest.Verifies(t, "FR-3.10", "SR-5.7-1")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	if lt, err := f.mcpClient(access).ListTools(context.Background(), nil); err != nil || len(lt.Tools) != 7 {
		t.Fatalf("%v %v", lt, err)
	}
	// An invalid document is refused and the active revision stays.
	if err := os.WriteFile(f.cfg.Policy.File, []byte(`{"revision": "r2", "framework_profiles": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.admin("POST", "/admin/v1/policy/reload", f.operator, map[string]any{}); st != 422 {
		t.Fatalf("invalid policy: %d", st)
	}
	r2 := strings.Replace(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1), `"echo", "dotted.name", "rpcerror", "slow", "big", "ghost", "noisy"`, `"echo"`, 1)
	if err := os.WriteFile(f.cfg.Policy.File, []byte(r2), 0o644); err != nil {
		t.Fatal(err)
	}
	if st, body := f.admin("POST", "/admin/v1/policy/reload", f.operator, map[string]any{}); st != 200 || body["revision"] != "r2" || body["changed"] != true {
		t.Fatalf("reload: %d %v", st, body)
	}
	lt, err := f.mcpClient(access).ListTools(context.Background(), nil)
	if err != nil || len(lt.Tools) != 2 {
		t.Fatalf("catalog after reload: %v %v", lt, err)
	}
	if st, body := f.admin("GET", "/admin/v1/health", f.operator, nil); st != 200 || body["policy_revision"] != "r2" {
		t.Fatalf("health: %d %v", st, body)
	}
}

func TestSubscriptionsListenEndsWithSession(t *testing.T) {
	reqtest.Partial(t, "FR-2.11")
	f := start(t, "")
	access, _, tb := f.oauthLogin("")
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"L1","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},%s}}`, modernMeta)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", f.cfg.ResourceURI(), strings.NewReader(body))
	for k, v := range modernHeaders(access, "subscriptions/listen") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	r, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("listen: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	acked := false
	for !acked {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("stream closed before acknowledgement")
			}
			acked = strings.Contains(l, "acknowledged")
		case <-ctx.Done():
			t.Fatal("no acknowledgement")
		}
	}
	if f.app.Gateway.ListenStreams() != 1 {
		t.Fatalf("%d listen streams tracked", f.app.Gateway.ListenStreams())
	}
	// Ending the session closes the stream (FR-2.11).
	f.app.Store.Terminate(tb["session_id"].(string))
	for {
		select {
		case _, ok := <-lines:
			if !ok {
				return
			}
		case <-ctx.Done():
			t.Fatal("listen stream survived the session")
		}
	}
}

func TestJournalAfterShutdown(t *testing.T) {
	reqtest.Verifies(t, "FR-7.5")
	reqtest.Partial(t, "SR-6.1-1", "FR-7.2")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err != nil {
		t.Fatal(err)
	}
	callErr(t, cs, "t_echo", map[string]any{"text": 1})
	f.stop()
	pub, err := keys.LoadEvidencePublicKey(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.stateDir, "journal")
	rep, err := audit.Verify(dir, pub)
	if err != nil || rep.Open != "" || rep.AnchorSegment == 0 || len(rep.Findings()) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	evs, err := audit.ReadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range evs {
		seen[e.Class+"/"+string(e.Phase)+"/"+e.Outcome] = true
	}
	for _, want := range []string{"gateway//started", "session//created", "call/requested/", "decision/authorized/permit", "call/dispatched/", "call/completed/ok", "call/delivered/release", "filter/filtered/block", "gateway//stopped"} {
		if !seen[want] {
			t.Errorf("journal lacks %s", want)
		}
	}
}
