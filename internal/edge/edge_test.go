package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// recorder is an audit.Recorder with fault injection and a commit hook.
type recorder struct {
	mu       sync.Mutex
	events   []audit.Event
	failWhen func(audit.Event) error
	onCommit func(audit.Event)
}

func (r *recorder) add(ev audit.Event, durable bool) error {
	r.mu.Lock()
	fail, hook := r.failWhen, r.onCommit
	r.mu.Unlock()
	if fail != nil {
		if err := fail(ev); err != nil {
			return err
		}
	}
	if durable && hook != nil {
		hook(ev)
	}
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	return nil
}

func (r *recorder) Record(ev audit.Event) error { return r.add(ev, false) }
func (r *recorder) Commit(ev audit.Event) error { return r.add(ev, true) }

func (r *recorder) set(fail func(audit.Event) error, hook func(audit.Event)) {
	r.mu.Lock()
	r.failWhen, r.onCommit = fail, hook
	r.mu.Unlock()
}

func (r *recorder) find(pred func(audit.Event) bool) *audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.events) - 1; i >= 0; i-- {
		if pred(r.events[i]) {
			e := r.events[i]
			return &e
		}
	}
	return nil
}

const edgePolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ro", "ap", "fx"], "default_template": "ro"}},
  "templates": {
    "ro": {"rules": [{"id": "ro-t", "server": "t", "tools": ["echo", "slow", "big"]}]},
    "ap": {"rules": [{"id": "ap-t", "server": "t", "tools": ["echo"], "approval": true}]},
    "fx": {"rules": [{"id": "fx-t", "server": "t", "tools": ["echo"], "filters": ["redact-test"]}]}
  }
}`

func testBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "edge-backend", Version: "1"}, nil)
	type textArgs struct {
		Text string `json:"text"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(ctx context.Context, req *mcp.CallToolRequest, a textArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
	})
	type slowArgs struct {
		MS int `json:"ms"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "slow"}, func(ctx context.Context, req *mcp.CallToolRequest, a slowArgs) (*mcp.CallToolResult, any, error) {
		select {
		case <-time.After(time.Duration(a.MS) * time.Millisecond):
		case <-ctx.Done():
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "slow"}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "big"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 128<<10)}}}, nil, nil
	})
	return s
}

type harness struct {
	t       *testing.T
	cfg     *config.Config
	gw      *Gateway
	store   *session.Store
	decider *policy.Decider
	rec     *recorder
	caps    *pipeline.Capabilities
	srv     *httptest.Server
	reg     *backend.Registry
	evErr   error
	evMu    sync.Mutex
}

type harnessOpts struct {
	approver pipeline.Approver
	filters  *pipeline.Filters
	limits   string
	// backend, policy and screen replace the defaults (inspection_test.go).
	backend func() *mcp.Server
	policy  string
	screen  pipeline.ToolScreen
	// healthGate is passed as Deps.HealthGate (gate_test.go).
	healthGate func() []string
	// raw replaces the backend with a scripted stdio server
	// (southbound_test.go).
	raw func(ctx context.Context, in io.Reader, out io.Writer) error
	// manifests replaces the live tool list (icons_test.go).
	manifests pipeline.ManifestSource
	// toml is appended to the configuration (uds_test.go).
	toml string
	// evidence replaces the in-memory recorder as the Gateway's evidence
	// (crash_test.go: a real journal on a fault-injecting file layer).
	evidence    audit.Recorder
	evidenceErr func() error
}

// limitsTOML is the harness's [limits] body: the defaults below, with any
// key that extra sets taken from extra instead.
func limitsTOML(extra string) string {
	out := []string{}
	for _, d := range []string{`upstream_timeout = "2s"`, `client_deadline = "3s"`, `result_bytes = 65536`} {
		key := strings.TrimSpace(strings.SplitN(d, "=", 2)[0])
		if !strings.Contains(extra, key+" ") && !strings.Contains(extra, key+"=") {
			out = append(out, d)
		}
	}
	return strings.Join(append(out, extra), "\n")
}

func newHarness(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	h := &harness{t: t, rec: &recorder{}}
	h.srv = httptest.NewUnstartedServer(nil)
	addr := h.srv.Listener.Addr().String()
	toml := fmt.Sprintf(`
[listener]
address = %q
public_url = "https://%s"
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[limits]
%s
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[server]]
alias = "t"
command = "/inproc/t"
%s
`, addr, addr, limitsTOML(o.limits), o.toml)
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	h.cfg = cfg
	pol := edgePolicy
	if o.policy != "" {
		pol = o.policy
	}
	if o.backend == nil {
		o.backend = testBackend
	}
	snap, err := policy.Compile([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	h.caps = pipeline.NewCapabilities(time.Minute)
	launcher := pipeline.InProcessLauncher{Servers: map[string]func() *mcp.Server{"/inproc/t": o.backend}}
	if o.raw != nil {
		launcher = pipeline.InProcessLauncher{Raw: map[string]func(context.Context, io.Reader, io.Writer) error{"/inproc/t": o.raw}}
	}
	reg, err := backend.Start(context.Background(), cfg.Servers, backend.Options{
		Limits:   backend.Limits{PerPrincipal: 4, Total: 4, Queue: 4, UpstreamTimeout: cfg.Limits.UpstreamTimeout.Duration, ResultBytes: cfg.Limits.ResultBytes},
		Launcher: launcher, Capabilities: h.caps, Log: diag.Discard(), Manifests: o.manifests,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.reg = reg
	h.decider = policy.NewDecider(snap, cfg.Limits.PrincipalCallsPerMin)
	h.store = session.NewStore(cfg, h.decider.Snapshot)
	oauth := session.NewOAuth(cfg, h.store, h.rec, authguard.New(authguard.Config{}))
	prof, _ := profile.Resolve("auto", "in-process", false, profile.Host{OS: "darwin", Arch: "arm64"})
	var evidence audit.Recorder = h.rec
	evidenceErr := func() error { h.evMu.Lock(); defer h.evMu.Unlock(); return h.evErr }
	if o.evidence != nil {
		evidence, evidenceErr = o.evidence, o.evidenceErr
	}
	h.gw, err = New(Deps{Config: cfg, Store: h.store, OAuth: oauth, Decider: h.decider, Registry: reg, Evidence: evidence,
		EvidenceErr: evidenceErr, Log: diag.Discard(), Profile: prof,
		Approver: o.approver, Filters: o.filters, Capabilities: h.caps, ConsoleURL: "https://127.0.0.1:8444", Screen: o.screen,
		HealthGate: o.healthGate})
	if err != nil {
		t.Fatal(err)
	}
	h.srv.Config.Handler = h.gw.Handler()
	h.srv.StartTLS()
	t.Cleanup(func() {
		h.srv.Close()
		h.gw.Close()
		reg.Close()
	})
	return h
}

func (h *harness) session(template string) (*session.Session, string) {
	h.t.Helper()
	s, tok, err := h.store.Create(session.CreateParams{PrincipalID: "cc", ClientID: "c", Listener: "tls", Claims: session.Claims{Template: template}})
	if err != nil {
		h.t.Fatal(err)
	}
	return s, tok.Access
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

func (h *harness) client(token string) *mcp.ClientSession {
	h.t.Helper()
	hc := &http.Client{Transport: bearerRT{token, h.srv.Client().Transport}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "edge-test", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: h.srv.URL + "/mcp", HTTPClient: hc}, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { cs.Close() })
	return cs
}

func callErr(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (*jsonrpc.Error, map[string]any) {
	t.Helper()
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	var we *jsonrpc.Error
	if !errors.As(err, &we) {
		t.Fatalf("%s: expected JSON-RPC error, got %v", name, err)
	}
	var data map[string]any
	json.Unmarshal(we.Data, &data)
	return we, data
}

func TestIntentCommittedBeforeCapability(t *testing.T) {
	reqtest.Verifies(t, "FR-4.13")
	// SR-6.2-1's kill points with a fault-injecting file layer are in
	// TestIntentCrashConsistency (crash_test.go).
	reqtest.Partial(t, "SR-6.2-1")
	reqtest.Scenario(t, reqtest.Standalone, "AT-12") // journal flush fault before launch
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	cs := h.client(tok)
	outstanding := -1
	h.rec.set(nil, func(ev audit.Event) {
		if ev.Phase == audit.PhaseAuthorized {
			outstanding = h.caps.Outstanding()
		}
	})
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err != nil {
		t.Fatal(err)
	}
	if outstanding != 0 {
		t.Fatalf("a capability existed when the intent was committed (%d)", outstanding)
	}
	if h.caps.Outstanding() != 1 {
		t.Fatal("capability not issued after the intent")
	}
	// When the intent cannot be committed, no capability is issued and the
	// call is refused fail-closed.
	before := h.caps.Outstanding()
	h.rec.set(func(ev audit.Event) error {
		if ev.Phase == audit.PhaseAuthorized {
			return errors.New("disk full")
		}
		return nil
	}, nil)
	we, data := callErr(t, cs, "t_echo", map[string]any{"text": "y"})
	if we.Code != CodeGatewayFailClosed || data["reasonCode"] != ReasonJournalUnavailable {
		t.Fatalf("%+v %v", we, data)
	}
	if h.caps.Outstanding() != before {
		t.Fatal("capability issued without a committed intent")
	}
}

func TestAuditFailureFailsClosed(t *testing.T) {
	reqtest.Partial(t, "SR-6.1-1")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	cs := h.client(tok)
	// The requested event cannot be written: the call is refused.
	h.rec.set(func(ev audit.Event) error {
		if ev.Phase == audit.PhaseRequested {
			return errors.New("io error")
		}
		return nil
	}, nil)
	if we, data := callErr(t, cs, "t_echo", map[string]any{"text": "x"}); we.Code != CodeGatewayFailClosed || data["reasonCode"] != ReasonJournalUnavailable {
		t.Fatalf("%+v %v", we, data)
	}
	// The delivered event cannot be written: the result is withheld
	// (SR-6.3-1, tested on the wire in TestReleaseCommitFailureWithholds).
	h.rec.set(func(ev audit.Event) error {
		if ev.Phase == audit.PhaseDelivered {
			return errors.New("io error")
		}
		return nil
	}, nil)
	if we, data := callErr(t, cs, "t_echo", map[string]any{"text": "x"}); we.Code != CodeResponseWithheld || data["reasonCode"] != ReasonOutcomeUnrecorded || data["message"] != reasonMessages[ReasonOutcomeUnrecorded] {
		t.Fatalf("%+v %v", we, data)
	}
	// A sticky journal failure fails the whole endpoint closed.
	h.rec.set(nil, nil)
	h.evMu.Lock()
	h.evErr = errors.New("journal failed")
	h.evMu.Unlock()
	req, _ := http.NewRequest("POST", h.srv.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 503 || !strings.Contains(string(b), ReasonJournalUnavailable) {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	if hl := h.gw.Health(); hl.State != "fail-closed" {
		t.Fatalf("health %+v", hl)
	}
}

type fakeApprover struct {
	res pipeline.ApprovalResult
	err error
	got pipeline.ApprovalRequest
}

func (f *fakeApprover) Request(ctx context.Context, r pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	f.got = r
	return f.res, f.err
}

func TestApproverSeam(t *testing.T) {
	reqtest.Partial(t, "FR-1.50")
	ap := &fakeApprover{res: pipeline.ApprovalResult{Outcome: pipeline.Approved, ApprovalID: "a1", Approver: "ethan"}}
	h := newHarness(t, harnessOpts{approver: ap})
	_, tok := h.session("ap")
	cs := h.client(tok)
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(lt.Tools) != 1 || lt.Tools[0].Meta[MetaRequiresUserInteraction] != true || lt.Tools[0].Meta[MetaApprovalRequired] != true {
		t.Fatalf("%v %v", lt, err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "ok"}}); err != nil {
		t.Fatal(err)
	}
	if ap.got.Hold != h.cfg.Limits.ApprovalHold.Duration || ap.got.Call.PublicName != "t_echo" {
		t.Fatalf("%+v", ap.got)
	}
	if e := h.rec.find(func(e audit.Event) bool { return e.Class == "approval" && e.Outcome == "approved" }); e == nil {
		t.Fatal("approval not recorded")
	}
	ap.res = pipeline.ApprovalResult{Outcome: pipeline.Denied}
	if we, data := callErr(t, cs, "t_echo", map[string]any{"text": "no"}); we.Code != CodePolicyDenied || data["reasonCode"] != ReasonApprovalDenied {
		t.Fatalf("%+v %v", we, data)
	}
	ap.res, ap.err = pipeline.ApprovalResult{}, errors.New("approval service down")
	we, data := callErr(t, cs, "t_echo", map[string]any{"text": "later"})
	if we.Code != CodeApprovalRequired || data["reasonCode"] != ReasonApprovalNoSvc || !strings.HasPrefix(fmt.Sprint(data["consoleUrl"]), "https://127.0.0.1:8444/approvals") {
		t.Fatalf("%+v %v", we, data)
	}
}

type withholdFilter struct{}

func (withholdFilter) ID() string { return "redact-test" }
func (withholdFilter) FilterResponse(ctx context.Context, c *pipeline.Call, r *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	return pipeline.ResponseVerdict{Action: pipeline.Block, ReasonCode: "TEST_WITHHELD"}, nil
}

func TestFilterSeamAndProvenance(t *testing.T) {
	reqtest.Verifies(t, "FR-4.12", "SR-5.13-1")
	f := pipeline.NewFilters()
	if err := f.RegisterResponse(withholdFilter{}, pipeline.Registration{Order: 10}); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, harnessOpts{filters: f})
	_, tok := h.session("ro")
	res, err := h.client(tok).CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	prov := res.Meta["local.smcpgw/provenance"].(map[string]any)
	if fmt.Sprint(prov["filters"]) != "[schema-validate]" || prov["untrusted"] != true || prov["manifest"] != "live" || prov["serverRevision"] == "" || prov["toolRevision"] == "" {
		t.Fatalf("%v", prov)
	}
	// The fx template's rule obliges the optional response filter.
	_, tok = h.session("fx")
	we, data := callErr(t, h.client(tok), "t_echo", map[string]any{"text": "x"})
	if we.Code != CodeResponseWithheld || data["reasonCode"] != "TEST_WITHHELD" {
		t.Fatalf("%+v %v", we, data)
	}
}

// gatedBackend is testBackend whose "slow" tool reports on started when
// it begins and returns only when its context ends or release is closed,
// so tests synchronize on the backend instead of sleeping.
func gatedBackend(started chan<- struct{}, release <-chan struct{}) func() *mcp.Server {
	return func() *mcp.Server {
		s := testBackend()
		mcp.AddTool(s, &mcp.Tool{Name: "slow"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "slow"}}}, nil, nil
		})
		return s
	}
}

func TestSessionEndCancelsInFlightCall(t *testing.T) {
	reqtest.Partial(t, "FR-2.11")
	reqtest.Verifies(t, "SR-1.17-2")
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	h := newHarness(t, harnessOpts{backend: gatedBackend(started, release)})
	s, tok := h.session("ro")
	cs := h.client(tok)
	errc := make(chan error, 1)
	recv := func(what string) error {
		t.Helper()
		select {
		case err := <-errc:
			return err
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: call did not end", what)
			return nil
		}
	}
	wait := func(what string) {
		t.Helper()
		select {
		case <-started:
		case err := <-errc:
			t.Fatalf("%s: call ended before reaching the backend: %v", what, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: call never reached the backend", what)
		}
	}
	go func() {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_slow", Arguments: map[string]any{}})
		errc <- err
	}()
	// The backend is executing the call; it returns only when cancelled.
	wait("terminate")
	// Concurrent terminations: exactly one succeeds.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.store.Terminate(s.ID) {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d terminations succeeded", ok)
	}
	var we *jsonrpc.Error
	if err := recv("terminate"); !errors.As(err, &we) || we.Code != CodeSessionInvalid {
		t.Fatalf("got %v", err)
	}
	if e := h.rec.find(func(e audit.Event) bool { return e.ReasonCode == ReasonSessionEnded || e.Phase == audit.PhaseWithheld }); e == nil {
		t.Fatal("no terminal event for the cancelled call")
	}

	// Stop during backend execution: the result is withheld at release.
	_, tok2 := h.session("ro")
	cs2 := h.client(tok2)
	go func() {
		_, err := cs2.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_slow", Arguments: map[string]any{}})
		errc <- err
	}()
	wait("stop")
	if err := h.gw.Stop("test", "release recheck"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := recv("stop"); !errors.As(err, &we) || we.Code != CodeResponseWithheld {
		t.Fatalf("stopped release: %v", err)
	}
}

func TestStopResumeAudited(t *testing.T) {
	reqtest.Partial(t, "FR-4.14")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	cs := h.client(tok)
	if err := h.gw.Stop("operator-token", "drill"); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err == nil {
		t.Fatal("call ran while stopped")
	}
	// Resume is refused when it cannot be recorded.
	h.rec.set(func(ev audit.Event) error {
		if ev.ReasonCode == "EMERGENCY_RESUME" {
			return errors.New("io")
		}
		return nil
	}, nil)
	if err := h.gw.Resume("operator-token"); !errors.Is(err, ErrAuditUnavailable) || !h.gw.Stopped() {
		t.Fatalf("resume without evidence: %v", err)
	}
	h.rec.set(nil, nil)
	if err := h.gw.Resume("operator-token"); err != nil || h.gw.Stopped() {
		t.Fatal(err)
	}
	for _, r := range []string{ReasonEmergencyStop, "EMERGENCY_RESUME"} {
		if e := h.rec.find(func(e audit.Event) bool { return e.ReasonCode == r && e.Class == "admin" }); e == nil {
			t.Fatalf("%s not recorded", r)
		}
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyHotSwapRebuildsCatalog(t *testing.T) {
	reqtest.Verifies(t, "FR-3.10", "SR-5.4-1")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	cs := h.client(tok)
	lt, _ := cs.ListTools(context.Background(), nil)
	if len(lt.Tools) != 3 {
		t.Fatalf("%d tools", len(lt.Tools))
	}
	r2, err := policy.Compile([]byte(strings.Replace(strings.Replace(edgePolicy, `"r1"`, `"r2"`, 1), `["echo", "slow", "big"]`, `["echo"]`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := h.gw.ActivatePolicy("test", r2); !changed || err != nil {
		t.Fatalf("%v %v", changed, err)
	}
	// The SDK client caches tools/list for ttlMs (FR-1.13); a new client sees the
	// rebuilt catalog.
	cs = h.client(tok)
	lt, _ = cs.ListTools(context.Background(), nil)
	if len(lt.Tools) != 1 || lt.Tools[0].Name != "t_echo" {
		t.Fatalf("catalog not rebuilt: %v", lt.Tools)
	}
	if we, _ := callErr(t, cs, "t_slow", map[string]any{"ms": 1}); we.Message != "Unknown tool" {
		t.Fatalf("%+v", we)
	}
	// Same revision with different content is refused and changes nothing.
	bad, _ := policy.Compile([]byte(strings.Replace(edgePolicy, `"r1"`, `"r2"`, 1)))
	if _, err := h.gw.ActivatePolicy("test", bad); !errors.Is(err, policy.ErrRevisionReused) {
		t.Fatalf("got %v", err)
	}
	if h.decider.Snapshot().Digest != r2.Digest {
		t.Fatal("refused activation changed the snapshot")
	}
}

func TestNoSnapshotFailsClosed(t *testing.T) {
	reqtest.Verifies(t, "SR-1.2-1")
	reqtest.Partial(t, "FR-9.17")
	h := newHarness(t, harnessOpts{})
	s, tok := h.session("ro")
	h.decider.Activate(nil)
	req, _ := http.NewRequest("POST", h.srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 503 || !strings.Contains(string(b), fmt.Sprint(CodeGatewayFailClosed)) {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	// serverFor must not dereference a nil snapshot.
	hr := httptest.NewRequest("POST", "/mcp", nil)
	hr = hr.WithContext(context.WithValue(hr.Context(), ctxSession, s))
	if h.gw.serverFor(hr) == nil {
		t.Fatal("no server")
	}
}

func TestDispatchErrorsWriteTerminalEvents(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	s, _ := h.session("ro")
	cases := map[string]error{
		"capability": &backend.CapabilityError{Err: pipeline.ErrCapabilityUsed},
		"backend":    &backend.BackendError{Code: -32000},
		"queue":      backend.ErrQueueFull,
		"timeout":    backend.ErrTimeout,
		"too large":  backend.ErrTooLarge,
		"deadline":   context.DeadlineExceeded,
		"cancelled":  context.Canceled,
		"rpc":        &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "bad"},
		"other":      errors.New("pipe broke"),
	}
	terminal := map[audit.Phase]bool{audit.PhaseDenied: true, audit.PhaseFailed: true, audit.PhaseIndeterminate: true, audit.PhaseWithheld: true}
	for name, err := range cases {
		c := &callRun{g: h.gw, corr: "corr-" + name, base: audit.Event{CorrelationID: "corr-" + name}, dec: policy.Decision{ID: "d", PolicyRevision: "r1"}}
		if got := h.gw.mapDispatchError(c, s.ID, err); got == nil {
			t.Errorf("%s: no error", name)
		}
		e := h.rec.find(func(e audit.Event) bool { return e.CorrelationID == "corr-"+name })
		if e == nil || !terminal[e.Phase] {
			t.Errorf("%s: terminal event %+v", name, e)
		}
	}
}

func TestHealthReportsUnconfined(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	hl := h.gw.Health()
	if hl.State != "degraded" || hl.Profile != profile.Standalone || hl.ReleaseLabel != "not enforced" || !strings.Contains(strings.Join(hl.Causes, ","), "unconfined") {
		t.Fatalf("%+v", hl)
	}
	r, err := h.srv.Client().Get(h.srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	r.Body.Close()
	if body["state"] != "degraded" || body["release_label"] != "not enforced" || body["sessions"] != nil {
		t.Fatalf("%v", body)
	}
}
