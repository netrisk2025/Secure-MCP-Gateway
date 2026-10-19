//go:build hostile

package hostile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// The suite runs the Gateway in one of two profiles, chosen with
// SMCP_HOSTILE_PROFILE:
//
//   - standalone (default): servers are ordinary child processes;
//   - enforced: [runtime] sandbox = "podman" (Linux with rootless Podman;
//     the test binary must be statically linked, CGO_ENABLED=0, because it
//     is the server inside the sandbox). [profile] mode is
//     SMCP_HOSTILE_MODE (default "auto").
func suiteProfile() string {
	if p := os.Getenv("SMCP_HOSTILE_PROFILE"); p == "enforced" {
		return p
	}
	return "standalone"
}

// enforcedUnavailable returns why the enforced profile cannot run here, or
// "" when it can: the sandbox prerequisites the container needs, and a
// statically linked test binary (it runs inside an empty root file system).
func enforcedUnavailable() string {
	if runtime.GOOS != "linux" {
		return "the enforced profile needs Linux"
	}
	exe, err := os.Executable()
	if err != nil {
		return err.Error()
	}
	if f, err := elf.Open(exe); err == nil {
		defer f.Close()
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				return "the test binary is dynamically linked; build it with CGO_ENABLED=0"
			}
		}
	}
	var missing []string
	for _, c := range sandbox.Failed(sandbox.Doctor(context.Background(), sandbox.DoctorOptions{})) {
		if slices.Contains(sandbox.SandboxEssential, c.ID) {
			missing = append(missing, c.ID)
		}
	}
	if len(missing) > 0 {
		return "sandbox prerequisites missing: " + strings.Join(missing, ", ")
	}
	return ""
}

const (
	helperClient = "helper"
	helperSecret = "helper-secret-123"
	secretName   = "hostile-token"
	secretEnv    = "HOSTILE_TOKEN_FILE"
)

// serverSpec is one [[server]] entry running a fixture.
type serverSpec struct {
	alias   string
	fixture string
	args    []string // extra fixture flags
	// pkg, when set, makes the server a signed package whose manifest holds
	// these tools (the fixture's live list may differ).
	pkg []*mcp.Tool
}

// gwSpec describes one Gateway run.
type gwSpec struct {
	servers  []serverSpec
	toml     string // appended to the configuration
	secrets  bool   // vault, a test secret and an S3 binding to server "h"
	upstream string // [limits] upstream_timeout, default 2s
}

// gw is a running Gateway built with the same element wiring as smcpd for
// every defense the fixtures exercise (filters, metadata scan, signed
// packages, secrets, egress, sandbox).
type gw struct {
	t       *testing.T
	dir     string
	cfg     *config.Config
	app     *app.App
	http    *http.Client
	exe     string
	secret  string // the test secret value (spec.secrets)
	sec     *secrets.Service
	rt      *sandbox.Launcher
	cancel  context.CancelFunc
	served  chan error
	mu      sync.Mutex
	events  []audit.Event
	stopped bool
}

func freePort(t *testing.T) int {
	t.Helper()
	return testport.Free(t)
}

func hash(t *testing.T, pw string) string {
	t.Helper()
	h, err := keys.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func toolNamesOf(s serverSpec, c Config) []string {
	names := ToolNames(s.fixture, c)
	for _, tl := range s.pkg {
		if !slices.Contains(names, tl.Name) {
			names = append(names, tl.Name)
		}
	}
	return names
}

// mcpTools converts fixture tool objects to SDK tools.
func mcpTools(t *testing.T, ts []map[string]any) []*mcp.Tool {
	t.Helper()
	raw, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	var out []*mcp.Tool
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// startGateway starts a Gateway for sp. It returns the error of app.Start
// instead of failing, for fixtures whose expected outcome is a refusal.
func startGateway(t *testing.T, sp gwSpec) (*gw, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	g := &gw{t: t, dir: dir, exe: exe, served: make(chan error, 1)}
	if sp.upstream == "" {
		sp.upstream = "2s"
	}
	upstream, err := time.ParseDuration(sp.upstream)
	if err != nil {
		t.Fatal(err)
	}
	port, adminPort := freePort(t), freePort(t)
	var servers, rules strings.Builder
	var pkgKey *pkgtest.Key
	for _, s := range sp.servers {
		args := append([]string{SelfFlag, "-fixture", s.fixture}, s.args...)
		names := toolNamesOf(s, Config{})
		qn, _ := json.Marshal(names)
		fmt.Fprintf(&rules, `,{"id": "r-%s", "server": %q, "tools": %s, "side_effect": "read", "source_trust": "untrusted"}`, s.alias, s.alias, qn)
		if s.pkg == nil {
			qa, _ := json.Marshal(args)
			fmt.Fprintf(&servers, "[[server]]\nalias = %q\ncommand = %q\nargs = %s\n", s.alias, exe, qa)
			continue
		}
		if pkgKey == nil {
			k := pkgtest.NewKey(t)
			pkgKey = &k
			pkgtest.Enroll(t, stateDir, "hostile-suite", k, []string{"low"}, time.Now().Add(24*time.Hour))
		}
		art, err := os.ReadFile(exe)
		if err != nil {
			t.Fatal(err)
		}
		id := "hostile-" + strings.ToLower(strings.ReplaceAll(s.fixture, "-", ""))
		pkgDir := pkgtest.Signed(t, filepath.Join(t.TempDir(), "pkg"), *pkgKey, pkgtest.Spec{ID: id, Revision: "1", Alias: s.alias,
			Tools: s.pkg, Artifact: art, ArtifactName: "hostile", Argv: append([]string{"hostile"}, args...),
			Edit: func(m *packaging.Manifest, _ *packaging.Provenance) {
				for i := range m.Tools {
					m.Tools[i].SourceTrust = "untrusted"
				}
			}})
		lib, err := library.Open(library.Options{StateDir: stateDir, Log: diag.Discard()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lib.Import(pkgDir, library.ImportOptions{Actor: "hostile-suite"}); err != nil {
			lib.Close()
			t.Fatal(err)
		}
		if _, err := lib.Enable(id, "1", library.EnableOptions{Actor: "hostile-suite", Standalone: suiteProfile() == "standalone"}); err != nil {
			lib.Close()
			t.Fatal(err)
		}
		lib.Close()
		fmt.Fprintf(&servers, "[[server]]\nalias = %q\npackage = %q\n", s.alias, id)
	}
	extra := sp.toml
	if suiteProfile() == "enforced" {
		mode := os.Getenv("SMCP_HOSTILE_MODE")
		if mode == "" {
			mode = "auto"
		}
		extra += fmt.Sprintf("\n[profile]\nmode = %q\n[runtime]\nsandbox = \"podman\"\npids = 32\nmemory_bytes = 134217728\nmonitor_interval = \"200ms\"\n", mode)
		if m := os.Getenv("SMCP_SANDBOX_IT_CGROUP_MANAGER"); m != "" {
			extra += fmt.Sprintf("cgroup_manager = %q\n", m)
		}
	}
	if sp.secrets && suiteProfile() == "enforced" {
		// The broker's secret files are mode 0600 of the Gateway user; only
		// a keep-id user namespace can read them inside the sandbox.
		extra += "\n[[runtime.server]]\nalias = \"h\"\nuserns = \"keep-id\"\n"
	}
	if sp.secrets {
		extra += "\n[secrets]\nkey_source = \"passphrase\"\npassphrase_file = \"vault-pass\"\nuse_policy_file = \"secret-use.json\"\nruntime_dir = \"run\"\n"
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
[approvals]
notify = "off"
[policy]
file = "policy.json"
[limits]
upstream_timeout = %q
client_deadline = %q
result_bytes = 65536
principal_call_burst = 0
[[principal]]
id = "suite"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = %q
client_secret_hash = %q
principal = "suite"
redirect_uris = ["http://localhost/unused"]
%s
%s
`, port, port, adminPort, stateDir, hash(t, "admin password 12"), sp.upstream, (upstream + 10*time.Second).String(),
		helperClient, hash(t, helperSecret), servers.String(), extra)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := fmt.Sprintf(`{"revision": "hostile-1", "framework_profiles": {"dev": {"templates": ["h"], "default_template": "h"}},
"templates": {"h": {"rules": [{"id": "none", "server": "none", "tools": ["none"]}%s]}}}`, rules.String())
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	if sp.secrets {
		g.secret = "smcp-test-" + randomHex(16)
		g.setupVault(dir, stateDir)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("configuration: %v\n%s", err, toml)
	}
	g.cfg = cfg
	opts, err := g.options()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, opts)
	if err != nil {
		cancel()
		g.closeExtras()
		return nil, err
	}
	g.app, g.cancel = a, cancel
	if g.rt != nil {
		g.rt.SetEvidence(a.Evidence)
	}
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	go func() { g.served <- a.Serve(ctx) }()
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(stateDir, keys.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(ca)
	g.http = &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	t.Cleanup(g.stop)
	return g, nil
}

// options builds app.Options the way cmd/smcpd does for the elements that
// carry the defenses under test: the signed package library (E-13, E-14),
// the secret broker (E-19, E-20), the sandbox launcher in the enforced
// profile (E-15 to E-17), and an evidence observer for the assertions.
// Filters, the metadata scan and the Egress Broker are built by app.Start
// itself.
func (g *gw) options() (app.Options, error) {
	log := diag.Discard()
	o := app.Options{Log: log, JanitorInterval: 200 * time.Millisecond,
		Observers: map[string]audit.Observer{"hostile-suite": audit.ObserverFunc(g.observe)}}
	pkgs, err := library.OpenRuntime(g.cfg, log)
	if err != nil {
		return o, fmt.Errorf("packages: %w", err)
	}
	o.Packages = pkgs
	if g.rt, err = sandbox.FromConfig(context.Background(), g.cfg, sandbox.SetupOptions{Log: log}); err != nil {
		pkgs.Close()
		return o, err
	}
	if g.rt != nil {
		o.Launcher = g.rt
		g.rt.Start(context.Background())
	}
	if g.sec, err = secrets.Configure(g.cfg, &o, nil, log); err != nil {
		pkgs.Close()
		g.closeExtras()
		return o, fmt.Errorf("secrets: %w", err)
	}
	return o, nil
}

func (g *gw) closeExtras() {
	g.sec.Close()
	if g.rt != nil {
		g.rt.Close()
		g.rt = nil
	}
}

// setupVault creates a passphrase vault holding the test secret and a
// Secret Use Policy that delivers it to server "h" as an S3 file.
func (g *gw) setupVault(dir, stateDir string) {
	t := g.t
	pass := "hostile suite passphrase " + randomHex(4)
	if err := os.WriteFile(filepath.Join(dir, "vault-pass"), []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	use := fmt.Sprintf(`{"revision": "hostile-u1",
"slots": [{"server": "h", "name": "token", "modes": ["S3"], "file_env": %q}],
"policies": [{"id": "h-token", "secret": %q, "server": "h", "slot": "token", "mode": "S3", "tools": ["*"], "purpose": "hostile fixture test"}]}`,
		secretEnv, secretName)
	if err := os.WriteFile(filepath.Join(dir, "secret-use.json"), []byte(use), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(stateDir, "vault")
	ks := secrets.Passphrase{Path: filepath.Join(vaultDir, secrets.MasterKeyFile), Passphrase: func() (string, error) { return pass, nil }, WorkFactor: 10}
	if _, err := secrets.Init(vaultDir, ks); err != nil {
		t.Fatal(err)
	}
	v, err := secrets.Open(vaultDir, ks, secrets.VaultOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v.SetEvidence(&audit.Memory{}) // offline creation, as `smcpctl secrets init` plus set would record
	if _, err := v.Create("hostile-suite", secrets.CreateParams{Name: secretName, Type: "token", Owner: "hostile-suite", Value: []byte(g.secret)}); err != nil {
		t.Fatal(err)
	}
}

func (g *gw) observe(e audit.Event) {
	g.mu.Lock()
	g.events = append(g.events, e)
	g.mu.Unlock()
}

// evidence returns the events observed so far with Detail normalized to
// JSON types.
func (g *gw) evidence() []audit.Event {
	g.mu.Lock()
	evs := append([]audit.Event(nil), g.events...)
	g.mu.Unlock()
	for i := range evs {
		if evs[i].Detail != nil {
			raw, _ := json.Marshal(evs[i].Detail)
			var d any
			_ = json.Unmarshal(raw, &d)
			evs[i].Detail = d
		}
	}
	return evs
}

// waitEvent waits up to d for an event that satisfies match.
func (g *gw) waitEvent(d time.Duration, match func(audit.Event) bool) (audit.Event, bool) {
	deadline := time.Now().Add(d)
	for {
		for _, e := range g.evidence() {
			if match(e) {
				return e, true
			}
		}
		if time.Now().After(deadline) {
			return audit.Event{}, false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (g *gw) stop() {
	if g.stopped {
		return
	}
	g.stopped = true
	g.cancel()
	select {
	case <-g.served:
	case <-time.After(15 * time.Second):
		g.t.Error("serve did not return")
	}
	g.app.Close()
	g.closeExtras()
}

// session opens a session through the session API with the confidential
// helper client and returns its access token and session ID.
func (g *gw) session() (string, string) {
	t := g.t
	t.Helper()
	req, _ := http.NewRequest("POST", g.cfg.Listener.PublicURL+"/smcp/v1/sessions", strings.NewReader(`{"harness_version":"hostile-suite","purpose":"hostile fixtures"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(helperClient, helperSecret)
	r, err := g.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil || r.StatusCode != 201 {
		t.Fatalf("session API: %d %s", r.StatusCode, b)
	}
	return out["access_token"].(string), out["session_id"].(string)
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

// client connects an MCP client with a new session. It returns the client
// session and the Gateway session ID.
func (g *gw) client(opts *mcp.ClientOptions) (*mcp.ClientSession, string) {
	g.t.Helper()
	access, sid := g.session()
	hc := &http.Client{Transport: bearer{access, g.http.Transport}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "hostile-suite", Version: "1"}, opts).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: g.cfg.ResourceURI(), HTTPClient: hc}, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { cs.Close() })
	return cs, sid
}

// catalog lists the session's tools by public name with their
// descriptions.
func (g *gw) catalog(cs *mcp.ClientSession) map[string]string {
	g.t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		g.t.Fatal(err)
	}
	out := map[string]string{}
	for _, tl := range res.Tools {
		out[tl.Name] = tl.Description
	}
	return out
}

// callOutcome is the result of one tools/call through the Gateway.
type callOutcome struct {
	res     *mcp.CallToolResult
	code    int64          // JSON-RPC error code, 0 on success
	data    map[string]any // error data
	err     error          // transport error (not a JSON-RPC error)
	text    string         // concatenated text content
	elapsed time.Duration
}

func (c callOutcome) reason() string { s, _ := c.data["reasonCode"].(string); return s }

func (c callOutcome) String() string {
	switch {
	case c.err != nil:
		return "transport error: " + c.err.Error()
	case c.code != 0:
		return fmt.Sprintf("error %d %s", c.code, c.reason())
	case c.res != nil && c.res.IsError:
		return "tool error result"
	default:
		return "result released"
	}
}

func (g *gw) call(cs *mcp.ClientSession, name string, args map[string]any, meta mcp.Meta) callOutcome {
	start := time.Now()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args, Meta: meta})
	out := callOutcome{res: res, elapsed: time.Since(start)}
	var we *jsonrpc.Error
	switch {
	case errors.As(err, &we):
		out.code = we.Code
		_ = json.Unmarshal(we.Data, &out.data)
	case err != nil:
		out.err = err
	}
	if res != nil {
		var sb strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		out.text = sb.String()
	}
	return out
}

// instance calls the fixture's echo tool and returns the instance nonce,
// or "" when the call fails.
func (g *gw) instance(cs *mcp.ClientSession, alias string) string {
	o := g.call(cs, alias+"_echo", map[string]any{"text": "probe"}, nil)
	if o.code != 0 || o.err != nil {
		return ""
	}
	_, nonce, ok := strings.Cut(o.text, "nonce=")
	if !ok {
		return ""
	}
	return nonce
}

// dispatched reports whether the call with this correlation ID reached the
// Tool Dispatcher.
func (g *gw) dispatched(corr string) bool {
	for _, e := range g.evidence() {
		if e.CorrelationID == corr && e.Phase == audit.PhaseDispatched {
			return true
		}
	}
	return false
}

// filterFindings returns the findings of the filter events of a stage
// ("request" or "response") for a correlation ID ("" for any).
func (g *gw) filterFindings(stage, corr string) (findings []map[string]any, params map[string]any) {
	params = map[string]any{}
	for _, e := range g.evidence() {
		if e.Class != "filter" || (corr != "" && e.CorrelationID != corr) {
			continue
		}
		d, _ := e.Detail.(map[string]any)
		if d["stage"] != stage {
			continue
		}
		if p, ok := d["parameters"].(map[string]any); ok {
			for k, v := range p {
				params[k] = v
			}
		}
		fs, _ := d["filters"].([]any)
		for _, f := range fs {
			fm, _ := f.(map[string]any)
			items, _ := fm["findings"].([]any)
			for _, it := range items {
				if m, ok := it.(map[string]any); ok {
					m["filter_id"] = fm["id"]
					findings = append(findings, m)
				}
			}
		}
	}
	return findings, params
}

// provenance returns the provenance metadata of a released result.
func provenance(res *mcp.CallToolResult) map[string]any {
	if res == nil {
		return nil
	}
	p, _ := res.Meta["local.smcpgw/provenance"].(map[string]any)
	return p
}

// correlation returns the correlation ID of a result or refusal.
func correlation(o callOutcome) string {
	if c, ok := o.data["correlationId"].(string); ok {
		return c
	}
	if p := provenance(o.res); p != nil {
		if c, ok := p["correlationId"].(string); ok {
			return c
		}
	}
	return ""
}

// canary listeners -----------------------------------------------------

// tcpCanary accepts loopback connections and counts them.
type tcpCanary struct {
	ln   net.Listener
	mu   sync.Mutex
	hits int
}

func newTCPCanary(t *testing.T) *tcpCanary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &tcpCanary{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.hits++
			c.mu.Unlock()
			conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *tcpCanary) addr() string { return c.ln.Addr().String() }
func (c *tcpCanary) count() int   { c.mu.Lock(); defer c.mu.Unlock(); return c.hits }

// udpCanary receives loopback datagrams (DNS queries) and counts them; it
// never answers.
type udpCanary struct {
	pc   net.PacketConn
	mu   sync.Mutex
	hits int
}

func newUDPCanary(t *testing.T) *udpCanary {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &udpCanary{pc: pc}
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			c.mu.Lock()
			c.hits++
			c.mu.Unlock()
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return c
}

func (c *udpCanary) addr() string { return c.pc.LocalAddr().String() }
func (c *udpCanary) count() int   { c.mu.Lock(); defer c.mu.Unlock(); return c.hits }

// httpCanary serves the HF-10 $ref target and counts requests.
type httpCanary struct {
	srv  *http.Server
	ln   net.Listener
	mu   sync.Mutex
	hits int
}

func newHTTPCanary(t *testing.T) *httpCanary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &httpCanary{ln: ln}
	c.srv = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/schema+json")
		_, _ = io.Copy(w, bytes.NewReader([]byte(`{"type":"string","description":"SMCP-CANARY-REF-10"}`)))
	})}
	go func() { _ = c.srv.Serve(ln) }()
	t.Cleanup(func() { c.srv.Close() })
	return c
}

func (c *httpCanary) url() string { return "http://" + c.ln.Addr().String() + "/schema.json" }
func (c *httpCanary) count() int  { c.mu.Lock(); defer c.mu.Unlock(); return c.hits }
