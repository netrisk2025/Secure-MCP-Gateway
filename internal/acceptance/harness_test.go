package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// binDir holds smcpd, smcpctl and smcp-refserver built by TestMain.
var binDir string

const (
	adminPassword    = "acceptance admin password 1"
	approverPassword = "acceptance approver password 1"
	// clientID is the OAuth client of the bootstrap configuration.
	clientID = "https://claude.ai/api/mcp/oauth/client-metadata"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run()) // every test skips without the binaries
	}
	dir, err := os.MkdirTemp("", "smcp-acceptance-")
	if err != nil {
		panic(err)
	}
	binDir = dir
	goTool, err := exec.LookPath("go")
	if err != nil {
		os.RemoveAll(dir)
		panic("go tool: " + err.Error())
	}
	// The reference server and the hostile fixture are linked statically
	// so that the Enforced profile can run them in a container.
	for _, pkg := range []string{"smcpd", "smcpctl", "smcp-refserver", "smcp-hostile"} {
		cmd := exec.Command(goTool, "build", "-trimpath", "-o", filepath.Join(dir, pkg), "../../cmd/"+pkg)
		cmd.Stderr = os.Stderr
		if pkg == "smcp-refserver" || pkg == "smcp-hostile" {
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		}
		if err := cmd.Run(); err != nil {
			os.RemoveAll(dir)
			panic("build " + pkg + ": " + err.Error())
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// needBinaries skips the calling test in -short mode, where TestMain builds
// nothing.
func needBinaries(t *testing.T) {
	t.Helper()
	if binDir == "" {
		t.Skip("acceptance scenarios build and run the real binaries; skipped with -short")
	}
}

// requestedProfile is the profile the suite is asked to run in.
func requestedProfile() string {
	if os.Getenv("SMCP_ACCEPTANCE_PROFILE") == reqtest.Enforced {
		return reqtest.Enforced
	}
	return reqtest.Standalone
}

// gateway is one bootstrapped instance of the real binaries.
type gateway struct {
	t         *testing.T
	dir       string
	cfg       string
	state     string
	sandbox   string
	port      int
	adminPort int
	publicURL string
	adminURL  string
	caFile    string

	cmd    *exec.Cmd
	logs   *lockedBuffer
	exited chan struct{}

	mu     sync.Mutex
	tokens map[string]string
	// refresh maps each access token signInAt obtained to its refresh
	// token and the token endpoint.
	refresh map[string][2]string
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// options adjust a bootstrapped configuration: limits are added to its
// [limits] table, extra is appended as further tables.
type options struct {
	limits string
	extra  string
	// dir is the instance directory (default a new temporary directory).
	dir string
}

// newGateway bootstraps an instance with ephemeral loopback ports and
// approval notifications off, and applies o. In the Enforced profile the
// reference server runs in rootless Podman.
func newGateway(t *testing.T, o options) *gateway {
	t.Helper()
	needBinaries(t)
	dir := o.dir
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	priv := t.TempDir()
	g := &gateway{t: t, dir: dir, cfg: filepath.Join(dir, "smcp.toml"), state: filepath.Join(dir, "state"), sandbox: filepath.Join(dir, "sandbox"),
		port: testport.Free(t), adminPort: testport.Free(t), tokens: map[string]string{}}
	adminPW := writeFile(t, priv, "admin.pw", adminPassword+"\n", 0o600)
	approverPW := writeFile(t, priv, "approver.pw", approverPassword+"\n", 0o600)
	g.mustCtl("bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", strconv.Itoa(g.port), "--admin-port", strconv.Itoa(g.adminPort),
		"--metrics-port", "0", "--notify", "off")
	g.publicURL = fmt.Sprintf("https://127.0.0.1:%d", g.port)
	g.adminURL = fmt.Sprintf("https://127.0.0.1:%d", g.adminPort)
	g.caFile = filepath.Join(g.state, "tls", "ca.crt")
	// Tests sign in several times as one principal and make bursts of
	// calls; the CP-11 burst and session limits are tested elsewhere.
	g.appendConfig("\n[limits]\nsessions_per_principal = 64\nprincipal_call_burst = 0\n" + o.limits + "\n")
	if requestedProfile() == reqtest.Enforced {
		// Server instances run under subordinate UIDs: the sandbox and the
		// directories above it (0700 from t.TempDir) must be searchable.
		// The sandbox reserves /tmp, so the job sets TMPDIR elsewhere.
		for _, d := range []string{filepath.Dir(dir), dir, g.sandbox} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		g.appendConfig(fmt.Sprintf("\n[profile]\nmode = \"enforced\"\n\n[runtime]\nsandbox = \"podman\"\n%s\n[[runtime.server]]\nalias = \"ref\"\n[[runtime.server.mount]]\nsource = %q\n",
			cgroupLine(), g.sandbox))
	}
	if o.extra != "" {
		g.appendConfig(o.extra)
	}
	return g
}

func cgroupLine() string {
	if m := os.Getenv("SMCP_ENFORCED_CGROUP_MANAGER"); m != "" {
		return fmt.Sprintf("cgroup_manager = %q", m)
	}
	return ""
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// appendConfig adds TOML to smcp.toml. Tables named again later in the file
// are not merged by TOML, so tests add a table only once.
func (g *gateway) appendConfig(toml string) {
	g.t.Helper()
	f, err := os.OpenFile(g.cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		g.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(toml); err != nil {
		g.t.Fatal(err)
	}
}

// writePolicy replaces the configured policy file.
func (g *gateway) writePolicy(doc string) string {
	g.t.Helper()
	return writeFile(g.t, g.dir, "policy.json", doc, 0o644)
}

// ctl runs smcpctl with the instance's configuration where the command
// takes one.
func (g *gateway) ctl(args ...string) (string, error) {
	g.t.Helper()
	if len(args) > 0 && !noConfig(args) && !hasFlag(args, "--config") && !hasFlag(args, "--dir") {
		args = append(args, "--config", g.cfg)
	}
	cmd := exec.Command(filepath.Join(binDir, "smcpctl"), args...)
	cmd.Dir = g.dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// sudoCtl runs smcpctl as root through passwordless sudo (sudo -n), with
// the instance's configuration.
func (g *gateway) sudoCtl(args ...string) (string, error) {
	g.t.Helper()
	args = append(args, "--config", g.cfg)
	cmd := exec.Command("sudo", append([]string{"-n", filepath.Join(binDir, "smcpctl")}, args...)...)
	cmd.Dir = g.dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (g *gateway) mustSudoCtl(args ...string) string {
	g.t.Helper()
	out, err := g.sudoCtl(args...)
	if err != nil {
		g.t.Fatalf("sudo smcpctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (g *gateway) mustCtl(args ...string) string {
	g.t.Helper()
	out, err := g.ctl(args...)
	if err != nil {
		g.t.Fatalf("smcpctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// noConfig reports commands that take no --config flag.
func noConfig(args []string) bool {
	switch {
	case args[0] == "bootstrap" || args[0] == "version":
		return true
	case args[0] == "package" && len(args) > 1 && (args[1] == "keygen" || args[1] == "sign" || args[1] == "build"):
		return true
	}
	return false
}

var keyIDRe = regexp.MustCompile(`key ID ([0-9A-F]{16})`)

// trustAdd enrolls a trust anchor. Enrollment needs the key ID the
// operator compared with the publisher's (FR-7.10); the test takes it from
// smcpctl's refusal, which names the displayed key ID, as an operator reads
// it from the screen.
func (g *gateway) trustAdd(pub, name string, extra ...string) {
	g.t.Helper()
	args := append([]string{"trust", "add", pub, "--name", name}, extra...)
	out, err := g.ctl(args...)
	if err == nil {
		g.t.Fatalf("trust add without a confirmed key ID succeeded:\n%s", out)
	}
	m := keyIDRe.FindStringSubmatch(out)
	if m == nil {
		g.t.Fatalf("trust add did not show the key ID:\n%s", out)
	}
	g.mustCtl(append(args, "--key-id", m[1])...)
}

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f || strings.HasPrefix(a, f+"=") {
			return true
		}
	}
	return false
}

// start runs smcpd and waits until the control API answers health.
func (g *gateway) start() {
	g.t.Helper()
	if err := g.tryStart(60 * time.Second); err != nil {
		g.t.Fatalf("%v\n%s", err, g.logs.String())
	}
}

// launch starts smcpd without waiting for it.
func (g *gateway) launch() error {
	g.t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "smcpd"), "--config", g.cfg)
	cmd.Dir = g.dir
	logs := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	g.cmd, g.logs, g.exited = cmd, logs, exited
	g.t.Cleanup(func() { g.kill() })
	return nil
}

// tryStart starts smcpd and reports whether it became healthy within d.
func (g *gateway) tryStart(d time.Duration) error {
	g.t.Helper()
	if err := g.launch(); err != nil {
		return err
	}
	cmd, exited := g.cmd, g.exited
	deadline := time.Now().Add(d)
	for {
		if _, err := g.ctl("health"); err == nil {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("smcpd exited during startup: %v", cmd.ProcessState)
		case <-time.After(150 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("smcpd did not become healthy")
		}
	}
}

// stop sends SIGTERM and waits for a clean exit.
func (g *gateway) stop() {
	g.t.Helper()
	if g.cmd == nil {
		return
	}
	_ = g.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-g.exited:
	case <-time.After(30 * time.Second):
		g.t.Fatalf("smcpd did not exit on SIGTERM\n%s", g.logs.String())
	}
	if code := g.cmd.ProcessState.ExitCode(); code != 0 {
		g.t.Fatalf("smcpd exited with %d\n%s", code, g.logs.String())
	}
	g.cmd = nil
	g.mu.Lock()
	g.tokens = map[string]string{}
	g.mu.Unlock()
}

// kill ends smcpd with SIGKILL (a crash).
func (g *gateway) kill() {
	if g.cmd == nil {
		return
	}
	_ = g.cmd.Process.Kill()
	<-g.exited
	g.cmd = nil
	g.mu.Lock()
	g.tokens = map[string]string{}
	g.mu.Unlock()
}

// tlsConfig trusts the instance's CA only.
func (g *gateway) tlsConfig() *tls.Config {
	g.t.Helper()
	pem, err := os.ReadFile(g.caFile)
	if err != nil {
		g.t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		g.t.Fatal("CA certificate unreadable")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// httpClient trusts the instance's CA and does not follow redirects.
func (g *gateway) httpClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: g.tlsConfig()},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// health returns the control API health report.
func (g *gateway) health() map[string]any {
	g.t.Helper()
	_, body := g.api("GET", "/api/v1/health/status", nil)
	return body
}

// profile is the profile the running Gateway reports (info.profile).
func (g *gateway) profile() string {
	g.t.Helper()
	info, _ := g.health()["info"].(map[string]any)
	p, _ := info["profile"].(string)
	if p != reqtest.Enforced {
		return reqtest.Standalone
	}
	return reqtest.Enforced
}

// scenario claims the scenario in the profile the instance reports. A run
// asked for the Enforced profile that did not get it fails, so a standalone
// result is never reported as an enforced one.
func (g *gateway) scenario(ids ...string) {
	g.t.Helper()
	p := g.profile()
	if requestedProfile() == reqtest.Enforced && p != reqtest.Enforced {
		g.t.Fatalf("SMCP_ACCEPTANCE_PROFILE=enforced but the Gateway reports the %s profile", p)
	}
	reqtest.Scenario(g.t, p, ids...)
}

// api sends a control API request with the operator token.
func (g *gateway) api(method, path string, body any) (int, map[string]any) {
	g.t.Helper()
	tok, err := os.ReadFile(filepath.Join(g.state, "keys", "admin.token"))
	if err != nil {
		g.t.Fatal(err)
	}
	return g.apiAs(strings.TrimSpace(string(tok)), method, path, body)
}

func (g *gateway) apiAs(token, method, path string, body any) (int, map[string]any) {
	g.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.adminURL+path, rd)
	if err != nil {
		g.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		g.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// token signs in through the OAuth authorization-code flow with PKCE as
// the Session Approver and returns an access token. scope may name a
// session template ("smcp:template:<id>").
func (g *gateway) token(scope string) string {
	g.t.Helper()
	g.mu.Lock()
	tok, ok := g.tokens[scope]
	g.mu.Unlock()
	if ok {
		return tok
	}
	tok, err := g.signIn(scope, approverPassword)
	if err != nil {
		g.t.Fatalf("sign-in: %v\n%s", err, g.logs.String())
	}
	g.mu.Lock()
	g.tokens[scope] = tok
	g.mu.Unlock()
	return tok
}

// freshToken signs in again: a new session for each call.
func (g *gateway) freshToken() string {
	g.t.Helper()
	tok, err := g.signIn("", approverPassword)
	if err != nil {
		g.t.Fatalf("sign-in: %v", err)
	}
	return tok
}

func (g *gateway) signIn(scope, password string) (string, error) {
	return g.signInAt(g.publicURL, clientID, "http://127.0.0.1:51234/callback", scope, password)
}

// signInAt runs the authorization-code flow against the authorization
// server at base (the harness listener or the remote public URL).
func (g *gateway) signInAt(base, clientID, redirect, scope, password string) (string, error) {
	return g.signInAtAs(base, clientID, redirect, scope, "approver", password)
}

// signInAtAs is signInAt with the account name typed on the sign-in page.
func (g *gateway) signInAtAs(base, clientID, redirect, scope, user, password string) (string, error) {
	hc := g.httpClient()
	var asm struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := getJSON(hc, base+"/.well-known/oauth-authorization-server", &asm); err != nil {
		return "", err
	}
	resource := base + "/mcp"
	verifier := randomString(48)
	sum := sha256.Sum256([]byte(verifier))
	state := randomString(16)
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "resource": {resource}}
	if scope != "" {
		q.Set("scope", scope)
	}
	authURL, err := url.Parse(asm.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	authURL.RawQuery = q.Encode()
	resp, err := hc.Get(authURL.String())
	if err != nil {
		return "", err
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authorization page: %d %s", resp.StatusCode, page)
	}
	action, fields, err := parseForm(string(page))
	if err != nil {
		return "", err
	}
	fields.Set("username", user)
	fields.Set("password", password)
	actionURL, err := authURL.Parse(action)
	if err != nil {
		return "", err
	}
	resp, err = hc.PostForm(actionURL.String(), fields)
	if err != nil {
		return "", err
	}
	drain(resp)
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		return "", fmt.Errorf("sign-in: status %d, location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if loc.Query().Get("state") != state {
		return "", errors.New("state mismatch")
	}
	resp, err = hc.PostForm(asm.TokenEndpoint, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {verifier}, "resource": {resource}})
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &tok) != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("token: %d %s", resp.StatusCode, body)
	}
	g.mu.Lock()
	if g.refresh == nil {
		g.refresh = map[string][2]string{}
	}
	g.refresh[tok.AccessToken] = [2]string{tok.RefreshToken, asm.TokenEndpoint}
	g.mu.Unlock()
	return tok.AccessToken, nil
}

// session opens an MCP client session with token.
func (g *gateway) session(token string) *mcp.ClientSession {
	g.t.Helper()
	tr := &http.Transport{TLSClientConfig: g.tlsConfig()}
	client := mcp.NewClient(&mcp.Implementation{Name: "smcp-acceptance", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: g.publicURL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token, tr}}}, nil)
	if err != nil {
		g.t.Fatalf("MCP connect: %v\n%s", err, g.logs.String())
	}
	g.t.Cleanup(func() { cs.Close() })
	return cs
}

// call calls a tool and returns the result text, whether it is a tool error
// and the protocol error.
func call(cs *mcp.ClientSession, name string, args map[string]any) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", false, err
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError, nil
}

// mustCall fails unless the call returns a successful result containing
// want.
func (g *gateway) mustCall(cs *mcp.ClientSession, name string, args map[string]any, want string) string {
	g.t.Helper()
	text, isErr, err := call(cs, name, args)
	if err != nil || isErr || !strings.Contains(text, want) {
		g.t.Fatalf("%s %v: err %v, tool error %v, text %q (want %q)\n%s", name, args, err, isErr, text, want, g.logs.String())
	}
	return text
}

// mcpPost sends one raw JSON-RPC POST to the MCP endpoint.
func (g *gateway) mcpPost(token, body string, header map[string]string) (*http.Response, string) {
	g.t.Helper()
	resp, raw, err := g.tryMCPPost(token, body, header)
	if err != nil {
		g.t.Fatalf("POST /mcp: %v", err)
	}
	return resp, raw
}

// tryMCPPost is mcpPost returning the transport error.
func (g *gateway) tryMCPPost(token, body string, header map[string]string) (*http.Response, string, error) {
	g.t.Helper()
	req, err := http.NewRequest("POST", g.publicURL+"/mcp", strings.NewReader(body))
	if err != nil {
		g.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return nil, "", err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	return resp, string(raw), nil
}

// event is one Evidence Journal event.
type event map[string]any

func (e event) str(k string) string { s, _ := e[k].(string); return s }

func (e event) detail() map[string]any { d, _ := e["detail"].(map[string]any); return d }

// events reads every event of the journal in order.
func (g *gateway) events() []event {
	g.t.Helper()
	segs, _ := filepath.Glob(filepath.Join(g.state, "journal", "segment-*.jsonl"))
	var out []event
	for _, s := range segs {
		f, err := os.Open(s)
		if err != nil {
			g.t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var e event
			if json.Unmarshal(sc.Bytes(), &e) == nil && e["type"] == "event" {
				out = append(out, e)
			}
		}
		f.Close()
	}
	return out
}

// journalText is the raw content of every journal segment.
func (g *gateway) journalText() string {
	g.t.Helper()
	segs, _ := filepath.Glob(filepath.Join(g.state, "journal", "segment-*.jsonl"))
	var b strings.Builder
	for _, s := range segs {
		raw, err := os.ReadFile(s)
		if err != nil {
			g.t.Fatal(err)
		}
		b.Write(raw)
	}
	return b.String()
}

// dispatched reports whether any call with a dispatched event has a
// correlation ID accepted by match.
func dispatchedCorrelations(evs []event) map[string]bool {
	out := map[string]bool{}
	for _, e := range evs {
		if e.str("class") == "call" && e.str("phase") == "dispatched" {
			out[e.str("correlation_id")] = true
		}
	}
	return out
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func getJSON(hc *http.Client, u string, v any) error {
	resp, err := hc.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

var (
	formRe  = regexp.MustCompile(`(?is)<form[^>]*\baction="([^"]*)"`)
	inputRe = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRe  = regexp.MustCompile(`(?is)\b(type|name|value)="([^"]*)"`)
)

func parseForm(page string) (string, url.Values, error) {
	m := formRe.FindStringSubmatch(page)
	if m == nil {
		return "", nil, errors.New("authorization page has no form")
	}
	fields := url.Values{}
	for _, in := range inputRe.FindAllString(page, -1) {
		attrs := map[string]string{}
		for _, a := range attrRe.FindAllStringSubmatch(in, -1) {
			attrs[strings.ToLower(a[1])] = html.UnescapeString(a[2])
		}
		if strings.EqualFold(attrs["type"], "hidden") && attrs["name"] != "" {
			fields.Set(attrs["name"], attrs["value"])
		}
	}
	return html.UnescapeString(m[1]), fields, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
