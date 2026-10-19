// Package gwtest starts a complete Gateway for tests of the adapter kit and
// the Remote Access Profile: a fresh state directory, keys, a policy, an
// in-process backend MCP server, the control API, and (when asked) the
// remote listener. It is test support only; nothing in a release binary
// imports it.
package gwtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/remote"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// Fixed credentials of the fixture.
const (
	ApproverUser     = "approver"
	ApproverPassword = "approver password 1"
	HelperClientID   = "helper"
	HelperSecret     = "helper-secret-123"
	PreClientID      = "pre-remote"
	PreSecret        = "pre-remote-secret-1"
	PublicClientID   = "public-native"
)

// Policy permits echo in template "ro" and "remote"; "secret" is never
// permitted.
const Policy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ro", "remote"], "default_template": "ro", "remote_allowed": ["remote"]}},
  "templates": {
    "ro": {"rules": [{"id": "ro-t", "server": "t", "tools": ["echo"]}]},
    "remote": {"rules": [{"id": "remote-t", "server": "t", "tools": ["echo"]}]}
  }
}`

// Gateway is a running fixture.
type Gateway struct {
	T        *testing.T
	Dir      string
	Config   *config.Config
	CfgPath  string
	App      *app.App
	Remote   *remote.Service
	HTTP     *http.Client // trusts the Gateway CA, does not follow redirects
	CAFile   string
	Operator string

	mu     sync.Mutex
	events []audit.Event

	cancel context.CancelFunc
	served chan error
}

// FreePort returns an unused loopback port.
func FreePort(t testing.TB) int {
	t.Helper()
	return testport.Free(t)
}

func mustHash(t testing.TB, pw string) string {
	t.Helper()
	h, err := keys.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Backend is the in-process MCP server: echo and secret.
func Backend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "gwtest-backend", Version: "1"}, nil)
	type echoArgs struct {
		Text string `json:"text" jsonschema:"text to echo"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echo text"}, func(_ context.Context, _ *mcp.CallToolRequest, a echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "secret", Description: "never permitted"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "leak"}}}, nil, nil
	})
	return s
}

// Start runs a Gateway. remoteTOML is appended to the configuration (for
// example a [remote] table); %REMOTE% in it is replaced by a free loopback
// address.
func Start(t *testing.T, remoteTOML string) *Gateway {
	t.Helper()
	return StartWithRemoteClock(t, remoteTOML, nil)
}

// StartWithRemoteClock is Start with the clock of the remote access
// service replaced (nil: the real clock), for tests of its time rules
// (device-code poll interval) that must not depend on how fast the test
// machine is.
func StartWithRemoteClock(t *testing.T, remoteTOML string, now func() time.Time) *Gateway {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	port, adminPort := FreePort(t), FreePort(t)
	remoteTOML = replaceAll(remoteTOML, "%REMOTE%", fmt.Sprintf("127.0.0.1:%d", FreePort(t)))
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
username = %q
password_hash = %q
[policy]
file = "policy.json"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[principal]]
id = "cloud"
framework = "grok-bot"
profile = "dev"
[[client]]
client_id = %q
client_secret_hash = %q
principal = "cc"
redirect_uris = ["http://localhost/unused"]
[[client]]
client_id = %q
client_secret_hash = %q
principal = "cloud"
redirect_uris = ["http://127.0.0.1/callback"]
[[client]]
client_id = %q
principal = "cc"
redirect_uris = ["http://127.0.0.1/callback"]
[[server]]
alias = "t"
command = "/gwtest/backend"
%s
`, port, port, adminPort, stateDir, mustHash(t, "admin password 12"), ApproverUser, mustHash(t, ApproverPassword),
		HelperClientID, mustHash(t, HelperSecret), PreClientID, mustHash(t, PreSecret), PublicClientID, remoteTOML)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(Policy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := &Gateway{T: t, Dir: dir, Config: cfg, CfgPath: cfgPath, CAFile: filepath.Join(stateDir, keys.CACertFile), served: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), JanitorInterval: 200 * time.Millisecond,
		Launcher:  pipeline.InProcessLauncher{Servers: map[string]func() *mcp.Server{"/gwtest/backend": Backend}},
		Observers: map[string]audit.Observer{"gwtest": audit.ObserverFunc(g.observe)}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	g.App = a
	if g.Remote, err = remote.New(remote.Options{Config: cfg, Store: a.Store, Evidence: a.Evidence, Gateway: a.Gateway, Log: diag.Discard(), Now: now}); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	g.Remote.Register(a.Admin)
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	go func() { g.served <- a.Serve(ctx) }()
	if err := g.Remote.Start(ctx); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(g.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(ca)
	g.HTTP = &http.Client{Timeout: 30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if g.Operator, err = keys.LoadAdminToken(stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Stop)
	return g
}

func replaceAll(s, old, new string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(old), []byte(new)))
}

func (g *Gateway) observe(e audit.Event) {
	g.mu.Lock()
	g.events = append(g.events, e)
	g.mu.Unlock()
}

// Events returns the events observed so far.
func (g *Gateway) Events() []audit.Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]audit.Event(nil), g.events...)
}

// WaitEvent waits until an observed event satisfies match.
func (g *Gateway) WaitEvent(match func(audit.Event) bool) audit.Event {
	g.T.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range g.Events() {
			if match(e) {
				return e
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	g.T.Fatal("event not observed")
	return audit.Event{}
}

// Stop shuts the Gateway down.
func (g *Gateway) Stop() {
	if g.cancel == nil {
		return
	}
	g.Remote.Close()
	g.cancel()
	select {
	case err := <-g.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.T.Errorf("serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		g.T.Error("serve did not return")
	}
	g.App.Close()
	g.cancel = nil
}

// MCPURL is the local MCP endpoint.
func (g *Gateway) MCPURL() string { return g.Config.ResourceURI() }

// Admin calls the control API with the operator token.
func (g *Gateway) Admin(method, path string, body any) (int, map[string]any) {
	g.T.Helper()
	return g.AdminAs(g.Operator, method, path, body)
}

// AdminAs calls the control API with token.
func (g *Gateway) AdminAs(token, method, path string, body any) (int, map[string]any) {
	g.T.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, g.Config.AdminURL()+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		g.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

// Tunnel starts a fake tunnel: a TLS reverse proxy (with the Gateway's
// certificate) to the remote listener that keeps the Host header and sets
// X-Forwarded-For to caller(), as Tailscale Funnel and cloudflared do. It
// returns the public URL.
func (g *Gateway) Tunnel(caller func() string) string {
	g.T.Helper()
	return g.TunnelTo(g.Config.Remote.Address, caller)
}

// TunnelTo is Tunnel to another loopback address (for example the local
// harness listener, to test misconfiguration).
func (g *Gateway) TunnelTo(addr string, caller func() string) string {
	g.T.Helper()
	cert, err := tls.LoadX509KeyPair(g.Config.Listener.TLSCert, g.Config.Listener.TLSKey)
	if err != nil {
		g.T.Fatal(err)
	}
	target, _ := url.Parse("https://" + addr)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header["X-Forwarded-For"] = []string{caller()}
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // like Funnel's https+insecure to the loopback listener
	}
	ts := httptest.NewUnstartedServer(proxy)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	g.T.Cleanup(ts.Close)
	return ts.URL
}

// EnableRemote enables the Remote Access Profile for publicURL.
func (g *Gateway) EnableRemote(publicURL string) {
	g.T.Helper()
	if st, body := g.Admin("POST", "/api/v1/remote/enable", map[string]any{"public_url": publicURL, "provider": "manual"}); st != 200 {
		g.T.Fatalf("enable remote: %d %v", st, body)
	}
}
