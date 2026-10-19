package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Secret values used by the broker tests. Every test scans evidence, logs
// and harness-visible errors for them.
const (
	envValue  = "ENV-secret-value-0123456789abcdef"
	fileValue = "FILE-secret-value-fedcba9876543210"
	callValue = "CALL-secret-value-a1b2c3d4e5f6a7b8"
	hdrValue  = "HDR-secret-value-9f8e7d6c5b4a3210"
)

var allValues = []string{envValue, fileValue, callValue, hdrValue, envValue + "-v2", fileValue + "-v2", callValue + "-v2"}

const brokerUsePolicy = `{
  "revision": "use-1",
  "slots": [
    {"server": "t", "name": "db", "modes": ["S3"], "file_env": "DB_PASS_FILE"},
    {"server": "t", "name": "callkey", "modes": ["S2", "S3"], "file_env": "CALL_KEY_FILE"},
    {"server": "t", "name": "apikey", "modes": ["S1"], "header": "Authorization", "header_template": "Bearer {secret}", "destination": "api.example.com"},
    {"server": "t", "name": "approved", "modes": ["S2"], "file_env": "APPROVED_FILE"}
  ],
  "policies": [
    {"id": "env", "secret": "env-secret", "server": "t", "slot": "API_TOKEN", "mode": "S4", "tools": ["*"], "purpose": "legacy client",
     "s4_waiver": {"approved_by": "admin:alice", "reason": "server reads only its environment"}},
    {"id": "db", "secret": "file-secret", "server": "t", "slot": "db", "mode": "S3", "tools": ["*"], "purpose": "database session"},
    {"id": "call", "secret": "call-secret", "server": "t", "slot": "callkey", "mode": "S2", "tools": ["readcall", "hold"], "purpose": "signing", "calls_per_minute": 3},
    {"id": "hdr", "secret": "hdr-secret", "server": "t", "slot": "apikey", "mode": "S1", "tools": ["*"], "purpose": "HTTP API"},
    {"id": "approved", "secret": "call-secret", "server": "t", "slot": "approved", "mode": "S2", "tools": ["needsapproval"], "purpose": "approved use", "approval": true}
  ]
}`

const brokerPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["all"], "default_template": "all"}},
  "templates": {"all": {"rules": [{"id": "all", "server": "t", "tools": ["getenv", "readfile", "readcall", "hold", "echo", "needsapproval"]}]}}
}`

// fixtureServer exposes the launch environment and files to the tests.
func fixtureServer(env map[string]string, seen *sync.Map) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "secrets-fixture", Version: "1"}, nil)
	type args struct {
		Name string `json:"name,omitempty"`
		Enc  string `json:"enc,omitempty"`
		Text string `json:"text,omitempty"`
		MS   int    `json:"ms,omitempty"`
	}
	encode := func(v, enc string) string {
		switch enc {
		case "b64":
			return base64.StdEncoding.EncodeToString([]byte(v))
		case "frag":
			return "..." + v[3:15] + "..."
		case "len":
			return fmt.Sprintf("len=%d", len(v))
		}
		return v
	}
	readFile := func(envName, enc string) string {
		p := env[envName]
		if p == "" {
			return "novar"
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "absent"
		}
		seen.Store(envName, p)
		if enc == "" {
			enc = "len"
		}
		return encode(string(b), enc)
	}
	mcp.AddTool(s, &mcp.Tool{Name: "getenv"}, func(_ context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: encode(env[a.Name], a.Enc)}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "readfile"}, func(_ context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: readFile(a.Name, a.Enc)}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "readcall"}, func(_ context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: readFile("CALL_KEY_FILE", a.Enc)}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "needsapproval"}, func(_ context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: readFile("APPROVED_FILE", "")}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "hold"}, func(ctx context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		r := readFile("CALL_KEY_FILE", "")
		holdStarted.Add(1)
		select {
		case <-time.After(time.Duration(a.MS) * time.Millisecond):
		case <-ctx.Done():
			holdCancelled.Add(1)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: r}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
	})
	return s
}

// envLauncher runs the fixture in process with the launch environment.
type envLauncher struct {
	mu   sync.Mutex
	envs []map[string]string
	seen sync.Map
}

func (*envLauncher) Name() string   { return "in-process" }
func (*envLauncher) Confined() bool { return false }
func (l *envLauncher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	l.mu.Lock()
	l.envs = append(l.envs, spec.Env)
	l.mu.Unlock()
	return pipeline.InProcessLauncher{Servers: map[string]func() *mcp.Server{spec.Command: func() *mcp.Server { return fixtureServer(spec.Env, &l.seen) }}}.Launch(ctx, spec)
}

// fakeInjector is an Egress Broker S1 seam.
type fakeInjector struct {
	mu     sync.Mutex
	grants map[string]pipeline.HeaderGrant
	fail   bool
}

func (f *fakeInjector) BindHeader(_ context.Context, g pipeline.HeaderGrant) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("egress broker down")
	}
	if f.grants == nil {
		f.grants = map[string]pipeline.HeaderGrant{}
	}
	f.grants[g.GrantID] = g
	return nil
}

func (f *fakeInjector) Withdraw(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g, ok := f.grants[id]; ok {
		clear(g.Value)
		delete(f.grants, id)
	}
}

func (f *fakeInjector) active() []pipeline.HeaderGrant {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []pipeline.HeaderGrant
	for _, g := range f.grants {
		out = append(out, g)
	}
	return out
}

type brokerHarness struct {
	t        *testing.T
	tv       *testVault
	broker   *Broker
	launcher *envLauncher
	inj      *fakeInjector
	reg      *backend.Registry
	gw       *edge.Gateway
	store    *session.Store
	srv      *httptest.Server
	mem      *audit.Memory
	logs     *bytes.Buffer
	runtime  string
}

func newBrokerHarness(t *testing.T) *brokerHarness {
	t.Helper()
	h := &brokerHarness{t: t, tv: newTestVault(t), launcher: &envLauncher{}, inj: &fakeInjector{}, logs: &bytes.Buffer{}}
	h.mem = h.tv.mem
	for name, v := range map[string]string{"env-secret": envValue, "file-secret": fileValue, "call-secret": callValue, "hdr-secret": hdrValue} {
		h.tv.create(t, name, v)
	}
	h.srv = httptest.NewUnstartedServer(nil)
	addr := h.srv.Listener.Addr().String()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
[listener]
address = %q
public_url = "https://%s"
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[limits]
upstream_timeout = "2s"
client_deadline = "3s"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[server]]
alias = "t"
command = "/inproc/t"
[server.secret_env]
API_TOKEN = "env-secret"
`, addr, addr)))
	if err != nil {
		t.Fatal(err)
	}
	use, err := CompileUsePolicy([]byte(brokerUsePolicy), cfg.Servers)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.runtime = filepath.Join(t.TempDir(), "run")
	h.broker, err = NewBroker(BrokerOptions{Vault: h.tv.v, Use: use, Servers: cfg.Servers, RuntimeDir: h.runtime, Injector: h.inj, Log: log, Now: h.tv.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	// As app.Start does: evidence first, then the launch.
	fan := audit.NewFanout(h.mem, log)
	fan.AddObserver("secret-broker", h.broker, 0)
	h.broker.AttachEvidence(fan)
	filters := pipeline.NewFilters()
	if err := h.broker.RegisterFilters(filters); err != nil {
		t.Fatal(err)
	}
	caps := pipeline.NewCapabilities(time.Minute)
	h.reg, err = backend.Start(context.Background(), cfg.Servers, backend.Options{
		Limits:   backend.Limits{PerPrincipal: 4, Total: 4, Queue: 4, UpstreamTimeout: 2 * time.Second, ResultBytes: 65536},
		Launcher: h.broker.WrapLauncher(h.launcher), Secrets: h.broker, Capabilities: caps, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.broker.SetRevisions(func() map[string]string {
		out := map[string]string{}
		for a, s := range h.reg.Servers() {
			out[a] = s.Revision
		}
		return out
	})
	snap, err := policy.Compile([]byte(brokerPolicy))
	if err != nil {
		t.Fatal(err)
	}
	dec := policy.NewDecider(snap, 1000)
	h.store = session.NewStore(cfg, dec.Snapshot)
	oauth := session.NewOAuth(cfg, h.store, fan, authguard.New(authguard.Config{}))
	prof, _ := profile.Resolve("auto", "in-process", false, profile.Host{OS: "darwin", Arch: "arm64"})
	h.gw, err = edge.New(edge.Deps{Config: cfg, Store: h.store, OAuth: oauth, Decider: dec, Registry: h.reg, Evidence: fan,
		EvidenceErr: func() error { return nil }, Log: log, Profile: prof, Filters: filters, Capabilities: caps, ConsoleURL: "https://127.0.0.1:8444"})
	if err != nil {
		t.Fatal(err)
	}
	h.srv.Config.Handler = h.gw.Handler()
	h.srv.StartTLS()
	t.Cleanup(func() {
		h.srv.Close()
		h.gw.Close()
		h.reg.Close()
		fan.Close()
	})
	return h
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

func (h *brokerHarness) client() *mcp.ClientSession {
	h.t.Helper()
	_, tok, err := h.store.Create(session.CreateParams{PrincipalID: "cc", ClientID: "c", Listener: "tls", Claims: session.Claims{Template: "all"}})
	if err != nil {
		h.t.Fatal(err)
	}
	hc := &http.Client{Transport: bearerRT{tok.Access, h.srv.Client().Transport}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "secrets-test", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: h.srv.URL + "/mcp", HTTPClient: hc}, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { cs.Close() })
	return cs
}

// call returns the text result or the JSON-RPC error (with its data).
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, *jsonrpc.Error, map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_" + name, Arguments: args})
	if err != nil {
		var we *jsonrpc.Error
		if !errors.As(err, &we) {
			t.Fatalf("%s: %v", name, err)
		}
		var data map[string]any
		json.Unmarshal(we.Data, &data)
		return "", we, data
	}
	if len(res.Content) == 0 {
		return "", nil, nil
	}
	return res.Content[0].(*mcp.TextContent).Text, nil, nil
}

// assertNoValues checks evidence, the diagnostic log and extra texts for
// every secret value, its Base64 form and a 12-byte fragment.
func (h *brokerHarness) assertNoValues(extra ...string) {
	h.t.Helper()
	ev, _ := json.Marshal(h.mem.Events())
	surfaces := map[string]string{"evidence": string(ev), "diagnostic log": h.logs.String()}
	for i, e := range extra {
		surfaces[fmt.Sprintf("text %d", i)] = e
	}
	for where, text := range surfaces {
		for _, v := range allValues {
			for _, needle := range []string{v, base64.StdEncoding.EncodeToString([]byte(v)), v[4:16]} {
				if strings.Contains(text, needle) {
					h.t.Fatalf("%s contains secret material %q", where, needle)
				}
			}
		}
	}
}

func useEvents(mem *audit.Memory, outcome string) []audit.Event {
	return eventsWith(mem, "secret_use", outcome)
}

func detail(e audit.Event) map[string]any { d, _ := e.Detail.(map[string]any); return d }

func TestBrokerLaunchDeliveryModes(t *testing.T) {
	reqtest.Partial(t, "FR-6.8", "FR-6.9", "FR-6.11", "FR-6.6", "SR-2.14-1")
	h := newBrokerHarness(t)
	if len(h.launcher.envs) != 1 {
		t.Fatalf("launches: %d", len(h.launcher.envs))
	}
	env := h.launcher.envs[0]
	// S4: the value in the environment, only for the waived slot.
	if env["API_TOKEN"] != envValue {
		t.Fatal("S4 value not in the launch environment")
	}
	// S3: a path to an owner-only file inside the runtime directory.
	p := env["DB_PASS_FILE"]
	if !strings.HasPrefix(p, h.runtime) {
		t.Fatalf("S3 path %q outside the runtime dir", p)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != fileValue {
		t.Fatalf("S3 file: %v", err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("S3 file mode %o", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Dir(p)); st.Mode().Perm() != 0o700 {
		t.Fatalf("instance dir mode %o", st.Mode().Perm())
	}
	// S2: the path is known at launch, the file is not there yet.
	if _, err := os.Stat(env["CALL_KEY_FILE"]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("S2 file exists before any call")
	}
	// No other variable carries a value.
	for k, v := range env {
		if k != "API_TOKEN" && slicesContainsValue(v) {
			t.Fatalf("variable %s carries a secret", k)
		}
	}
	// S1: the header grant is with the egress broker, not in the instance.
	g := h.inj.active()
	if len(g) != 1 || g[0].Destination != "api.example.com" || g[0].Header != "Authorization" || g[0].Template != "Bearer {secret}" || string(g[0].Value) != hdrValue {
		t.Fatalf("S1 grant: %+v", g)
	}
	// One delivered event per launch-time binding, with the FR-6.11 fields.
	del := useEvents(h.mem, "delivered")
	if len(del) != 3 {
		t.Fatalf("delivered events: %d", len(del))
	}
	modes := map[string]bool{}
	for _, e := range del {
		d := detail(e)
		modes[d["mode"].(string)] = true
		if e.Origin != "E-20" || e.CorrelationID == "" || e.DecisionID == "" || e.PolicyRevision != "use-1" || d["secret_ref"] == "" || d["version"] != 1 || d["slot"] == "" || d["tool"] != "*" {
			t.Fatalf("event fields: %+v", e)
		}
	}
	if !modes["S1"] || !modes["S3"] || !modes["S4"] {
		t.Fatalf("modes: %v", modes)
	}
	// Teardown deletes the S3 file and withdraws the S1 grant.
	h.reg.Close()
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("S3 file survives instance teardown")
	}
	if _, err := os.Stat(filepath.Dir(p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance dir survives teardown")
	}
	if len(h.inj.active()) != 0 {
		t.Fatal("S1 grant survives teardown")
	}
	if len(useEvents(h.mem, "withdrawn")) != 3 {
		t.Fatalf("withdrawn events: %d", len(useEvents(h.mem, "withdrawn")))
	}
	h.assertNoValues()
}

func slicesContainsValue(s string) bool {
	for _, v := range allValues {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

func TestBrokerLeakDetectionNorthbound(t *testing.T) {
	reqtest.Partial(t, "FR-6.10", "SR-2-1", "SR-5.8-1", "FR-17.3")
	h := newBrokerHarness(t)
	cs := h.client()
	var harnessTexts []string
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"getenv", map[string]any{"name": "API_TOKEN"}},                    // S4 raw
		{"getenv", map[string]any{"name": "API_TOKEN", "enc": "b64"}},      // Base64
		{"getenv", map[string]any{"name": "API_TOKEN", "enc": "frag"}},     // 12-byte fragment
		{"readfile", map[string]any{"name": "DB_PASS_FILE", "enc": "raw"}}, // S3 raw
		{"readcall", map[string]any{"enc": "b64"}},                         // S2 Base64
	} {
		text, rpcErr, data := call(t, cs, c.tool, c.args)
		if rpcErr == nil {
			t.Fatalf("%s %v released: %q", c.tool, c.args, text)
		}
		if data["reasonCode"] != ReasonLeak {
			t.Fatalf("%s %v: %v %v", c.tool, c.args, rpcErr, data)
		}
		raw, _ := json.Marshal(rpcErr)
		harnessTexts = append(harnessTexts, string(raw))
	}
	// A secret in the arguments is blocked before dispatch.
	_, rpcErr, data := call(t, cs, "echo", map[string]any{"text": "send " + envValue[2:20] + " please"})
	if rpcErr == nil || data["reasonCode"] != ReasonInArguments {
		t.Fatalf("argument leak: %v %v", rpcErr, data)
	}
	raw, _ := json.Marshal(rpcErr)
	harnessTexts = append(harnessTexts, string(raw))
	// Ordinary results pass.
	if text, rpcErr, _ := call(t, cs, "echo", map[string]any{"text": "hello"}); rpcErr != nil || text != "echo:hello" {
		t.Fatalf("clean call: %v %q", rpcErr, text)
	}
	if text, rpcErr, _ := call(t, cs, "readfile", map[string]any{"name": "DB_PASS_FILE"}); rpcErr != nil || text != fmt.Sprintf("len=%d", len(fileValue)) {
		t.Fatalf("S3 read: %v %q", rpcErr, text)
	}
	// The leak suspended the S2 secret: further S2 delivery is refused.
	if len(useEvents(h.mem, "suspended")) == 0 {
		t.Fatal("no suspension event")
	}
	if _, rpcErr, data := call(t, cs, "readcall", nil); rpcErr == nil || data["reasonCode"] != ReasonSuspended {
		t.Fatalf("suspended S2: %v %v", rpcErr, data)
	}
	ref := h.tv.v.find("call-secret").Ref
	if !h.broker.Unsuspend(ref) {
		t.Fatal("unsuspend")
	}
	if text, rpcErr, _ := call(t, cs, "readcall", nil); rpcErr != nil || text != fmt.Sprintf("len=%d", len(callValue)) {
		t.Fatalf("after review: %v %q", rpcErr, text)
	}
	h.assertNoValues(harnessTexts...)
}

func TestBrokerPerCallFileLifetime(t *testing.T) {
	reqtest.Partial(t, "FR-6.7", "FR-6.11") // not on tmpfs on macOS
	h := newBrokerHarness(t)
	cs := h.client()
	p := h.launcher.envs[0]["CALL_KEY_FILE"]
	// During a call the file exists; the tool sees the value.
	type result struct {
		text string
		err  *jsonrpc.Error
	}
	done := make(chan result, 1)
	go func() {
		text, e, _ := call(t, cs, "hold", map[string]any{"ms": 300})
		done <- result{text, e}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("S2 file never appeared during the call")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r := <-done
	if r.err != nil || r.text != fmt.Sprintf("len=%d", len(callValue)) {
		t.Fatalf("hold: %v %q", r.err, r.text)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("S2 file survives the call")
	}
	// Tools the binding does not name get no file.
	if text, _, _ := call(t, cs, "readfile", map[string]any{"name": "CALL_KEY_FILE"}); text != "absent" {
		t.Fatalf("unbound tool saw the S2 file: %q", text)
	}
	// The delivery event carries call identifiers and the server revision.
	var s2 *audit.Event
	for _, e := range useEvents(h.mem, "delivered") {
		if detail(e)["mode"] == ModeS2 {
			s2 = &e
		}
	}
	if s2 == nil || s2.CorrelationID == "" || s2.DecisionID == "" || s2.ServerRevision == "" || detail(*s2)["tool"] != "hold" || detail(*s2)["version"] != 1 {
		t.Fatalf("S2 event: %+v", s2)
	}
	// calls_per_minute = 3: the third S2 call in the minute is denied.
	call(t, cs, "readcall", nil)
	call(t, cs, "readcall", nil)
	if _, rpcErr, data := call(t, cs, "readcall", nil); rpcErr == nil || data["reasonCode"] != ReasonRateLimited {
		t.Fatalf("rate: %v %v", rpcErr, data)
	}
	h.tv.clock.Advance(time.Minute)
	if _, rpcErr, _ := call(t, cs, "readcall", nil); rpcErr != nil {
		t.Fatalf("after the window: %v", rpcErr)
	}
	// A binding that requires approval is denied when the decision carries none.
	if _, rpcErr, data := call(t, cs, "needsapproval", nil); rpcErr == nil || data["reasonCode"] != ReasonApproval {
		t.Fatalf("approval: %v %v", rpcErr, data)
	}
	den := useEvents(h.mem, "denied")
	if len(den) < 2 {
		t.Fatalf("denied events: %d", len(den))
	}
	for _, e := range den {
		if e.CorrelationID == "" || e.DecisionID == "" || detail(e)["slot"] == "" || e.ReasonCode == "" {
			t.Fatalf("denied event fields: %+v", e)
		}
	}
	h.assertNoValues()
}

// holdStarted counts hold calls the server began; holdCancelled counts
// those whose context the server saw cancelled.
var holdStarted, holdCancelled atomic.Int32

// TestEmergencyStopCancelsCallsAndWithdrawsGrants is SR-7.6-2: an
// emergency stop with a call in flight (holding its S2 per-call secret
// file) and an active S1 header grant cancels the call (the server sees
// the cancellation and the harness gets the call refused with
// EMERGENCY_STOP instead of a result) and withdraws both grants: the S2
// file is removed and the S1 header grant leaves the Egress Broker.
func TestEmergencyStopCancelsCallsAndWithdrawsGrants(t *testing.T) {
	reqtest.Verifies(t, "SR-7.6-2")
	h := newBrokerHarness(t)
	cs := h.client()
	p := h.launcher.envs[0]["CALL_KEY_FILE"]
	if len(h.inj.active()) != 1 {
		t.Fatalf("S1 grants before the stop: %v", h.inj.active())
	}
	before, started := holdCancelled.Load(), holdStarted.Load()
	type result struct {
		err  *jsonrpc.Error
		data map[string]any
		took time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		_, e, d := call(t, cs, "hold", map[string]any{"ms": 20000})
		done <- result{e, d, time.Since(start)}
	}()
	waitFor(t, func() bool { _, err := os.Stat(p); return err == nil }, "S2 file during the call")
	// The S2 file is written before launch authorization; a stop before
	// that point refuses the call without dispatching it (SR-7.6-1), so
	// the stop waits until the server runs the call.
	waitFor(t, func() bool { return holdStarted.Load() > started }, "the server running the call")
	if err := h.gw.Stop("admin:alice", "drill"); err != nil {
		t.Fatal(err)
	}
	var r result
	select {
	case r = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight call was not cancelled")
	}
	if r.err == nil || r.data["reasonCode"] != "EMERGENCY_STOP" {
		t.Fatalf("in-flight call after the stop: %v %v", r.err, r.data)
	}
	waitFor(t, func() bool { return holdCancelled.Load() > before }, "server-side cancellation")
	waitFor(t, func() bool { _, err := os.Stat(p); return errors.Is(err, os.ErrNotExist) }, "S2 file removed")
	waitFor(t, func() bool { return len(h.inj.active()) == 0 }, "S1 grant withdrawn")
	h.assertNoValues()
}

func TestBrokerEmergencyStopWithdraws(t *testing.T) {
	reqtest.Partial(t, "SR-7.6-2")
	h := newBrokerHarness(t)
	cs := h.client()
	if err := h.gw.Stop("admin:alice", "drill"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(h.inj.active()) == 0 }, "S1 grant withdrawn on stop")
	if err := h.gw.Resume("admin:alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(h.inj.active()) == 1 }, "S1 grant rebound on resume")
	if _, rpcErr, _ := call(t, cs, "readcall", nil); rpcErr != nil {
		t.Fatalf("after resume: %v", rpcErr)
	}
	// While stopped (observer state), S2 deliveries are refused.
	h.broker.Observe(audit.Event{Class: "admin", Outcome: "stopped"})
	f := s2Filter{h.broker}
	v, err := f.FilterRequest(context.Background(), &pipeline.Call{Server: "t", Tool: "readcall", CorrelationID: "c1", DecisionID: "d1"}, nil)
	if err != nil || v.Action != pipeline.Block || v.ReasonCode != ReasonStopped {
		t.Fatalf("S2 while stopped: %+v %v", v, err)
	}
	h.assertNoValues()
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out: " + what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBrokerRotationRedeliversAtOverlapLimit(t *testing.T) {
	reqtest.Verifies(t, "FR-6.3")
	h := newBrokerHarness(t)
	cs := h.client()
	p := h.launcher.envs[0]["DB_PASS_FILE"]
	for _, name := range []string{"file-secret", "call-secret"} {
		if _, err := h.tv.v.Rotate("admin:alice", name, []byte(map[string]string{"file-secret": fileValue, "call-secret": callValue}[name]+"-v2"), 10*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	// The new version is delivered from the next delivery on.
	if text, rpcErr, _ := call(t, cs, "readcall", nil); rpcErr != nil || text != fmt.Sprintf("len=%d", len(callValue)+3) {
		t.Fatalf("S2 after rotation: %v %q", rpcErr, text)
	}
	// The running instance keeps the previous version within the overlap.
	if b, _ := os.ReadFile(p); string(b) != fileValue {
		t.Fatal("S3 file changed before the overlap ended")
	}
	h.tv.clock.Advance(10 * time.Minute)
	if n, err := h.tv.v.Sweep(); n != 2 || err != nil {
		t.Fatalf("sweep: %d %v", n, err)
	}
	// At the overlap limit the old version stops: the S3 file now holds v2.
	if b, _ := os.ReadFile(p); string(b) != fileValue+"-v2" {
		t.Fatal("S3 file still holds the retired version")
	}
	if _, err := h.tv.v.open("file-secret", 1); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired version deliverable: %v", err)
	}
	var v2 bool
	for _, e := range useEvents(h.mem, "delivered") {
		if detail(e)["slot"] == "db" && detail(e)["version"] == 2 {
			v2 = true
		}
	}
	if !v2 {
		t.Fatal("no delivery event for the rotated S3 version")
	}
	h.assertNoValues()
}

func TestBrokerDenialsFailLaunch(t *testing.T) {
	reqtest.Partial(t, "FR-6.11", "FR-6")
	tv := newTestVault(t)
	servers := []config.Server{{Alias: "t", Command: "/inproc/t", SecretEnv: map[string]string{"API_TOKEN": "env-secret", "OTHER": "nope"}}}
	use, err := CompileUsePolicy([]byte(`{"revision": "u", "policies": [{"id": "env", "secret": "env-secret", "server": "t", "slot": "API_TOKEN", "mode": "S4", "tools": ["*"], "purpose": "p",
	  "s4_waiver": {"approved_by": "a", "reason": "r"}}]}`), servers)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBroker(BrokerOptions{Vault: tv.v, Use: use, Servers: servers, RuntimeDir: filepath.Join(t.TempDir(), "run"), Evidence: tv.mem, Now: tv.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	// A secret_env reference without a binding is denied.
	_, err = b.Resolve(context.Background(), pipeline.SecretRequest{Server: "t", Refs: servers[0].SecretEnv})
	var de *DeniedError
	if !errors.As(err, &de) || de.Reason != ReasonNotGranted || de.Slot != "OTHER" {
		t.Fatalf("ungranted: %v", err)
	}
	// A bound secret that does not exist is denied.
	_, err = b.Resolve(context.Background(), pipeline.SecretRequest{Server: "t", Refs: map[string]string{"API_TOKEN": "env-secret"}})
	if !errors.As(err, &de) || de.Reason != ReasonNotFound {
		t.Fatalf("missing secret: %v", err)
	}
	tv.create(t, "env-secret", envValue)
	env, err := b.Resolve(context.Background(), pipeline.SecretRequest{Server: "t", Refs: map[string]string{"API_TOKEN": "env-secret"}})
	if err != nil || env["API_TOKEN"] != envValue {
		t.Fatalf("granted: %v", err)
	}
	// S1 without an egress broker is denied.
	servers2 := []config.Server{{Alias: "u", Command: "/x"}}
	use2, err := CompileUsePolicy([]byte(`{"revision": "u", "slots": [{"server": "u", "name": "h", "modes": ["S1"], "header": "X-Key", "destination": "d.example"}],
	  "policies": [{"id": "h", "secret": "env-secret", "server": "u", "slot": "h", "mode": "S1", "tools": ["*"], "purpose": "p"}]}`), servers2)
	if err != nil {
		t.Fatal(err)
	}
	b.SetUsePolicy(use2)
	if _, err := b.Resolve(context.Background(), pipeline.SecretRequest{Server: "u"}); !errors.As(err, &de) || de.Reason != ReasonModeUnavailable {
		t.Fatalf("S1 without egress: %v", err)
	}
	if len(useEvents(tv.mem, "denied")) != 3 {
		t.Fatalf("denied events: %d", len(useEvents(tv.mem, "denied")))
	}
	// Without evidence, nothing is delivered.
	b.SetUsePolicy(use)
	tv.mem.Fail(errors.New("journal down"))
	if env, err := b.Resolve(context.Background(), pipeline.SecretRequest{Server: "t", Refs: map[string]string{"API_TOKEN": "env-secret"}}); err == nil || env != nil {
		t.Fatal("delivered without evidence")
	}
	for _, e := range []error{err} {
		if e != nil && strings.Contains(e.Error(), envValue) {
			t.Fatal("error text carries the value")
		}
	}
}

func TestBrokerImpactReport(t *testing.T) {
	reqtest.Verifies(t, "FR-6.12")
	h := newBrokerHarness(t)
	refs := h.broker.Impact("call-secret")
	if len(refs) != 2 {
		t.Fatalf("references: %+v", refs)
	}
	for _, r := range refs {
		if r.Server != "t" || r.ServerRevision == "" || r.UsePolicy == "" || r.Mode != ModeS2 || r.Source != "use_policy" {
			t.Fatalf("reference: %+v", r)
		}
	}
	if refs[0].Slot != "approved" || refs[1].Slot != "callkey" {
		t.Fatalf("slots: %+v", refs)
	}
	env := h.broker.Impact("env-secret")
	if len(env) != 1 || env[0].Slot != "API_TOKEN" || !env[0].Active {
		t.Fatalf("env impact: %+v", env)
	}
	if len(h.broker.Impact("unbound")) != 0 {
		t.Fatal("phantom reference")
	}
}
