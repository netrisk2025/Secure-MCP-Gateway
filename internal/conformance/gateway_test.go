package conformance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/remote"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// alias is the backend's server alias; public names are alias_<tool>.
const alias = "s"

// gateway is a running Gateway with one session.
type gateway struct {
	t     *testing.T
	app   *app.App
	url   string
	http  *http.Client
	token string

	cfg    *config.Config
	caFile string
	// public is the Remote Access public URL (a test tunnel to the remote
	// listener) when the gateway was started with the profile enabled.
	public string
}

// remoteClientID is the pre-registered public client that may sign in
// through the remote listener (startGatewayWith remote).
const remoteClientID = "conformance-remote"

func startGateway(t *testing.T, b *scripted) *gateway { return startGatewayWith(t, b, false) }

// startGatewayWith starts the Gateway; with withRemote, the Remote Access
// Profile is configured and enabled behind a test tunnel (FR-16), with
// limits high enough for the suite's request count.
func startGatewayWith(t *testing.T, b *scripted, withRemote bool) *gateway {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	hash, err := keys.HashPassword("admin password 12")
	if err != nil {
		t.Fatal(err)
	}
	port, adminPort := gwtest.FreePort(t), gwtest.FreePort(t)
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
[approvals]
notify = "off"
[policy]
file = "policy.json"
[filters.content_types]
allow = ["image/png", "audio/wav"]
[limits]
upstream_timeout = "5s"
client_deadline = "6s"
principal_calls_per_minute = 100000
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[server]]
alias = %q
command = "/conformance/backend"
`, port, port, adminPort, stateDir, hash, alias)
	if withRemote {
		toml += fmt.Sprintf(`
[[client]]
client_id = %q
principal = "cc"
redirect_uris = ["http://127.0.0.1/callback"]
[remote]
address = "127.0.0.1:%d"
clients = [%q]
templates = ["all"]
[remote.limits]
calls_per_minute = 100000
calls_burst = 100000
oauth_per_second = 1000
oauth_burst = 1000
`, remoteClientID, gwtest.FreePort(t), remoteClientID)
	}
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	tools, _ := json.Marshal(b.names())
	pol := fmt.Sprintf(`{"revision": "r1", "framework_profiles": {"dev": {"templates": ["all"], "default_template": "all", "remote_allowed": ["all"]}},
  "templates": {"all": {"rules": [{"id": "all", "server": %q, "tools": %s}]}}}`, alias, tools)
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), JanitorInterval: time.Second,
		Launcher: pipeline.InProcessLauncher{Raw: map[string]func(context.Context, io.Reader, io.Writer) error{"/conformance/backend": b.serve}}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var rs *remote.Service
	if withRemote {
		if rs, err = remote.New(remote.Options{Config: cfg, Store: a.Store, Evidence: a.Evidence, Gateway: a.Gateway, Log: diag.Discard()}); err != nil {
			cancel()
			a.Close()
			t.Fatal(err)
		}
		rs.Register(a.Admin)
	}
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- a.Serve(ctx) }()
	if rs != nil {
		if err := rs.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if rs != nil {
			rs.Close()
		}
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
		}
		a.Close()
	})
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(stateDir, keys.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(ca)
	_, tok, err := a.Store.Create(session.CreateParams{PrincipalID: "cc", ClientID: "conformance", Listener: "tls", Claims: session.Claims{Template: "all"}})
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{t: t, app: a, url: cfg.ResourceURI(), token: tok.Access, cfg: cfg, caFile: filepath.Join(stateDir, keys.CACertFile),
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}}
	if withRemote {
		g.public = g.tunnel(cfg.Remote.Address)
		g.enableRemote(stateDir)
	}
	return g
}

// tunnel starts a test tunnel: a TLS reverse proxy with the Gateway's
// certificate to addr that keeps the Host header and sets X-Forwarded-For,
// as Tailscale Funnel and cloudflared do. It returns the public URL.
func (g *gateway) tunnel(addr string) string {
	g.t.Helper()
	cert, err := tls.LoadX509KeyPair(g.cfg.Listener.TLSCert, g.cfg.Listener.TLSKey)
	if err != nil {
		g.t.Fatal(err)
	}
	target, _ := url.Parse("https://" + addr)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header["X-Forwarded-For"] = []string{"203.0.113.7"}
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // like Funnel's https+insecure to the loopback listener
	}
	ts := httptest.NewUnstartedServer(proxy)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	g.t.Cleanup(ts.Close)
	return ts.URL
}

// enableRemote enables the Remote Access Profile for the tunnel's public
// URL through the control API, as smcpctl remote enable does.
func (g *gateway) enableRemote(stateDir string) {
	g.t.Helper()
	op, err := keys.LoadAdminToken(stateDir)
	if err != nil {
		g.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"public_url": g.public, "provider": "manual"})
	req, _ := http.NewRequest("POST", g.cfg.AdminURL()+"/api/v1/remote/enable", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+op)
	resp, err := g.http.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		g.t.Fatalf("enable remote: %d %s", resp.StatusCode, b)
	}
}

// public is the presented name of a backend tool.
func public(tool string) string { return backend.PublicName(alias, tool) }

// headersFor derives the 2026-07-28 request headers from a message.
func headersFor(msg map[string]any) map[string]string {
	h := map[string]string{}
	params, _ := msg["params"].(map[string]any)
	meta, _ := params["_meta"].(map[string]any)
	if v, ok := meta["io.modelcontextprotocol/protocolVersion"].(string); ok {
		h["MCP-Protocol-Version"] = v
	}
	if m, ok := msg["method"].(string); ok {
		h["Mcp-Method"] = m
	}
	if n, ok := params["name"].(string); ok {
		h["Mcp-Name"] = n
	} else if u, ok := params["uri"].(string); ok {
		h["Mcp-Name"] = u
	}
	return h
}

// response is one HTTP answer: its status, content type and the JSON-RPC
// messages it carried (the body, or each event's data).
type response struct {
	Status      int
	ContentType string
	Messages    []json.RawMessage
	Body        string
}

// post sends a raw body with headers (the session's bearer is added).
func (g *gateway) post(body []byte, hdr map[string]string) response {
	g.t.Helper()
	req, err := http.NewRequest("POST", g.url, strings.NewReader(string(body)))
	if err != nil {
		g.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+g.token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := response{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: string(raw)}
	if strings.HasPrefix(r.ContentType, "text/event-stream") {
		for _, line := range strings.Split(string(raw), "\n") {
			if d, ok := strings.CutPrefix(line, "data:"); ok {
				r.Messages = append(r.Messages, json.RawMessage(strings.TrimSpace(d)))
			}
		}
	} else if len(strings.TrimSpace(string(raw))) > 0 && json.Valid(raw) {
		r.Messages = append(r.Messages, json.RawMessage(raw))
	}
	return r
}

// last is the final JSON-RPC message of a response decoded as a map.
func (r response) last() map[string]any {
	if len(r.Messages) == 0 {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(r.Messages[len(r.Messages)-1], &m)
	return m
}

// errorCode returns the JSON-RPC error code of a message, or 0.
func errorCode(m map[string]any) int {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return int(c)
}
