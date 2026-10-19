package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The reasons backend: a raw newline-delimited JSON-RPC stdio server
// (SMCP_E2E_BACKEND=reasons) whose tools each misbehave in one way, so the
// test can drive the Gateway into every Appendix B outcome. It speaks the
// 2025-11-25 handshake the Gateway uses southbound.

// reasonTools lists the backend's tools; the schema of each is an object
// with the named string properties ("n" is an integer).
var reasonTools = map[string][]string{
	"echo": {"text"}, "read_file": {"path"}, "fetch": {"url"}, "count": {"n"}, "pick": {"choice"}, "pii_tool": {"text"},
	"leak": nil, "bidi": nil, "bad_result": nil, "garble": nil, "ask": nil, "crash": nil, "crash_read": nil,
	"hang": nil, "fail": nil, "big": nil, "slow": {"ms"}, "write": nil, "untrusted": nil, "approve_me": nil,
	"quota": nil, "rated": nil, "needs_missing": nil, "ferr_req": nil, "ferr_resp": nil, "ftime_req": nil,
	"ftime_resp": nil, "gated": nil, "gated_resp": nil, "denied": nil,
}

// reasonsSecret is registered as a secret fingerprint the way the Secret
// Broker registers a delivered value; the leak tool returns it.
const reasonsSecret = "reasons-e2e-registered-secret-0123456789"

func runReasonsBackend() {
	var mu sync.Mutex
	out := bufio.NewWriter(os.Stdout)
	write := func(v any) {
		b, _ := json.Marshal(v)
		mu.Lock()
		defer mu.Unlock()
		out.Write(append(b, '\n'))
		out.Flush()
	}
	writeRaw := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		out.WriteString(s)
		out.Flush()
	}
	text := func(s string) map[string]any {
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": s}}}
	}
	reply := func(id json.RawMessage, result any) {
		write(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
	var tools []any
	for name, props := range reasonTools {
		p := map[string]any{}
		for _, n := range props {
			typ := "string"
			if n == "n" || n == "ms" {
				typ = "integer"
			}
			p[n] = map[string]any{"type": typ}
		}
		tool := map[string]any{"name": name, "description": "reasons fixture " + name,
			"inputSchema": map[string]any{"type": "object", "properties": p}}
		if name == "bidi" { // its structured content breaks this schema
			tool["outputSchema"] = map[string]any{"type": "object", "properties": map[string]any{"n": map[string]any{"type": "integer"}}, "required": []any{"n"}}
		}
		tools = append(tools, tool)
	}
	call := func(id json.RawMessage, name string, args map[string]any) {
		switch name {
		case "leak":
			reply(id, text("value: "+reasonsSecret))
		case "bidi":
			reply(id, map[string]any{"content": []any{map[string]any{"type": "text", "text": "{}"}}, "structuredContent": map[string]any{"n": "not a number"}})
		case "bad_result":
			reply(id, map[string]any{"resultType": "bogus", "content": []any{}})
		case "garble":
			writeRaw("this line is not JSON\n")
		case "ask":
			reply(id, map[string]any{"resultType": "input_required", "requestState": "c3RhdGU", "inputRequests": map[string]any{
				"q": map[string]any{"method": "elicitation/create", "params": map[string]any{"message": "name?",
					"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}}}}}})
		case "crash", "crash_read":
			os.Exit(3)
		case "hang":
		case "fail":
			write(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32001, "message": "backend detail"}})
		case "big":
			reply(id, text(strings.Repeat("x", 128<<10)))
		case "slow":
			ms, _ := args["ms"].(float64)
			time.Sleep(time.Duration(ms) * time.Millisecond)
			reply(id, text("slow"))
		default:
			reply(id, text("ok:"+name))
		}
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || len(m.ID) == 0 || m.Method == "" {
			continue
		}
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(m.Params, &p)
			if p.ProtocolVersion == "" {
				p.ProtocolVersion = "2025-11-25"
			}
			reply(m.ID, map[string]any{"protocolVersion": p.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "e2e-reasons", "version": "1"}})
		case "ping":
			reply(m.ID, map[string]any{})
		case "tools/list":
			reply(m.ID, map[string]any{"tools": tools})
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			go call(m.ID, p.Name, p.Arguments)
		default:
			write(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		}
	}
	os.Exit(0)
}

// reasonsPolicy grants the reasons backend's tools under template main,
// with one rule per obligation the test needs; taint and taintap classify
// an untrusted read and a write; bound has more candidate rules for one
// server than the CP-12 bound of 256 allows.
func reasonsPolicy(revision string, profileTemplates ...string) string {
	if len(profileTemplates) == 0 {
		profileTemplates = []string{"main", "taint", "taintap", "bound"}
	}
	var bound []string
	for i := 0; i < 257; i++ {
		bound = append(bound, fmt.Sprintf(`{"id": "b-%03d", "server": "r", "tools": ["x%03d"]}`, i, i))
	}
	bound = append(bound, `{"id": "b-echo", "server": "r", "tools": ["echo"]}`)
	tmpl, _ := json.Marshal(profileTemplates)
	// The first revision, imported from the policy file at start, grants
	// the high-risk server hr without flagging its class; publication
	// refuses such a grant (SR-3.13-1), so later revisions leave it out.
	hr := ""
	if revision == "reasons-1" {
		hr = `,
      {"id": "m-hr", "server": "hr", "tools": ["echo"]}`
	}
	return fmt.Sprintf(`{
  "revision": %q,
  "framework_profiles": {"dev": {"templates": %s, "default_template": "main"}},
  "templates": {
    "main": {"rules": [
      {"id": "m-all", "server": "r", "tools": ["echo", "read_file", "fetch", "count", "leak", "bidi", "bad_result", "garble", "ask", "crash", "hang", "fail", "big", "slow"]},
      {"id": "m-read", "server": "r", "tools": ["crash_read"], "side_effect": "read"},
      {"id": "m-pick", "server": "r", "tools": ["pick"], "when": [{"op": "eq", "arg": "choice", "value": "a"}]},
      {"id": "m-pii", "server": "r", "tools": ["pii_tool"], "filters": ["pii-detect"]},
      {"id": "m-approve", "server": "r", "tools": ["approve_me"], "approval": true},
      {"id": "m-quota", "server": "r", "tools": ["quota"], "calls_per_session": 1},
      {"id": "m-rate", "server": "r", "tools": ["rated"], "calls_per_minute": 1},
      {"id": "m-missing", "server": "r", "tools": ["needs_missing"], "filters": ["no-such-filter"]},
      {"id": "m-ferr-req", "server": "r", "tools": ["ferr_req"], "filters": ["e2e-error-req"]},
      {"id": "m-ferr-resp", "server": "r", "tools": ["ferr_resp"], "filters": ["e2e-error-resp"]},
      {"id": "m-ftime-req", "server": "r", "tools": ["ftime_req"], "filters": ["e2e-slow-req"]},
      {"id": "m-ftime-resp", "server": "r", "tools": ["ftime_resp"], "filters": ["e2e-slow-resp"]},
      {"id": "m-gated", "server": "r", "tools": ["gated"], "filters": ["e2e-gate-req"]},
      {"id": "m-gated-resp", "server": "r", "tools": ["gated_resp"], "filters": ["e2e-gate-resp"]},
      {"id": "m-s2", "server": "s2", "tools": ["gated"], "filters": ["e2e-gate-req"]}%s
    ]},
    "taint": {"taint_action": "deny", "rules": [
      {"id": "t-u", "server": "r", "tools": ["untrusted"], "side_effect": "read", "source_trust": "untrusted"},
      {"id": "t-w", "server": "r", "tools": ["write"], "side_effect": "write"}
    ]},
    "taintap": {"taint_action": "approve", "rules": [
      {"id": "ta-u", "server": "r", "tools": ["untrusted"], "side_effect": "read", "source_trust": "untrusted"},
      {"id": "ta-w", "server": "r", "tools": ["write"], "side_effect": "write"}
    ]},
    "bound": {"rules": [%s]}
  }
}`, revision, tmpl, hr, strings.Join(bound, ",\n"))
}

// gateFilter blocks a call in its chain until release is closed, after
// signalling entered; it lets the test change state between the decision
// and launch (request side) or between dispatch and release (response
// side).
type gateFilter struct {
	id      string
	entered chan struct{}
	release chan struct{}
}

func newGate(id string) *gateFilter {
	return &gateFilter{id: id, entered: make(chan struct{}, 1), release: make(chan struct{})}
}

func (g *gateFilter) ID() string { return g.id }
func (g *gateFilter) wait(ctx context.Context) {
	g.entered <- struct{}{}
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}
func (g *gateFilter) FilterRequest(ctx context.Context, _ *pipeline.Call, _ json.RawMessage) (pipeline.RequestVerdict, error) {
	g.wait(ctx)
	return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
}
func (g *gateFilter) FilterResponse(ctx context.Context, _ *pipeline.Call, _ *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	g.wait(ctx)
	return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
}

// testFilter fails (err) or outlasts the CP-14 deadline (slow).
type testFilter struct {
	id   string
	slow bool
}

func (f testFilter) ID() string { return f.id }
func (f testFilter) run(ctx context.Context) error {
	if f.slow {
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		return nil
	}
	return errors.New("e2e filter failure")
}
func (f testFilter) FilterRequest(ctx context.Context, _ *pipeline.Call, _ json.RawMessage) (pipeline.RequestVerdict, error) {
	return pipeline.RequestVerdict{Action: pipeline.Pass}, f.run(ctx)
}
func (f testFilter) FilterResponse(ctx context.Context, _ *pipeline.Call, _ *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	return pipeline.ResponseVerdict{Action: pipeline.Pass}, f.run(ctx)
}

// confinedForTest is the subprocess launcher reporting itself as
// confining, so that the high-risk server hr starts on a development host
// and its calls reach the decision's SR-3.13-1 check. Nothing else in this
// test depends on confinement.
type confinedForTest struct{ pipeline.SubprocessLauncher }

func (confinedForTest) Name() string   { return "e2e-confined" }
func (confinedForTest) Confined() bool { return true }

// reasonGateway is a Gateway with the Approval Service, the console, the
// principal directory and the reasons backend under the aliases r, s2 and
// hr (hr declares a high-risk class).
type reasonGateway struct {
	*fixture
	svc      *approval.Service
	gate     *gateFilter
	gateResp *gateFilter
	failing  atomic.Value // []string: the health gate's causes
}

type reasonOpts struct {
	stateDir string // reuse a state directory (restart); "" for a new one
	limits   string
	lifetime string // CP-17 approval lifetime (default 5m)
	policy   string
}

func startReasons(t *testing.T, o reasonOpts) *reasonGateway {
	t.Helper()
	dir := t.TempDir()
	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = filepath.Join(dir, "state")
	}
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(dir, "roots")
	if err := os.MkdirAll(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	port, adminPort := freePort(t), freePort(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A pii rule-set version with a blocking data-class rule
	// (DATA_CLASS_IN_ARGUMENTS when pii-detect is named, SR-5.8-1).
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := filters.ExportEmbedded(rulesDir); err != nil {
		t.Fatal(err)
	}
	lib, err := filters.LoadDir(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	base, err := lib.Get(filters.RuleSetPII, "")
	if err != nil {
		t.Fatal(err)
	}
	pii := *base
	pii.Version = "2099.1.0"
	pii.Rules = append(append([]*filters.Rule{}, base.Rules...), &filters.Rule{ID: "e2e-project-code", Kind: "regex", Pattern: `\bPRJ-[0-9]{4}\b`,
		CaseSensitive: true, RequestAction: "block", ResponseAction: "redact"})
	if err := filters.AddVersion(rulesDir, &pii); err != nil {
		t.Fatal(err)
	}
	lifetime := o.lifetime
	if lifetime == "" {
		lifetime = "5m"
	}
	server := func(alias, extra string) string {
		return fmt.Sprintf("[[server]]\nalias = %q\ncommand = %q\nargs = [\"-test.run=NONE\"]\n%s[server.env]\nSMCP_E2E_BACKEND = \"reasons\"\n", alias, exe, extra)
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
[approvals]
lifetime = %q
keepalive = "100ms"
notify = "off"
[[approvals.account]]
username = "alice"
password_hash = %q
[policy]
file = %q
[filters]
deadline = "1s"
rules_dir = %q
rule_versions = { %s = "2099.1.0" }
[filters.size]
argument_bytes = 65536
argument_depth = 16
[filters.paths]
roots = [%q]
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
%s%s%s`, port, port, adminPort, stateDir, mustHash(t, "admin password 12"), mustHash(t, approverPassword), lifetime, mustHash(t, approverAccountPassword),
		filepath.Join(dir, "policy.json"), rulesDir, filters.RuleSetPII, roots, e2eLimits(o.limits), clientID,
		server("r", ""), server("s2", ""), server("hr", "risk_classes = [\"general-sql\"]\n"))
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := o.policy
	if pol == "" {
		pol = reasonsPolicy("reasons-1")
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rg := &reasonGateway{gate: newGate("e2e-gate-req"), gateResp: newGate("e2e-gate-resp")}
	rg.failing.Store([]string(nil))
	svc, err := approval.New(approval.Options{Config: cfg, Log: diag.Discard(), JanitorInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	rg.svc = svc
	extra := func(f *pipeline.Filters) error {
		for _, r := range []pipeline.RequestFilter{rg.gate, testFilter{id: "e2e-error-req"}, testFilter{id: "e2e-slow-req", slow: true}} {
			if err := f.RegisterRequest(r, pipeline.Registration{Order: 500}); err != nil {
				return err
			}
		}
		for _, r := range []pipeline.ResponseFilter{rg.gateResp, testFilter{id: "e2e-error-resp"}, testFilter{id: "e2e-slow-resp", slow: true}} {
			if err := f.RegisterResponse(r, pipeline.Registration{Order: 500}); err != nil {
				return err
			}
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), JanitorInterval: 200 * time.Millisecond, Approver: svc, Approvals: svc, Launcher: confinedForTest{},
		ExtraFilters: extra, HealthGate: func() []string { return rg.failing.Load().([]string) }})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	svc.Start(ctx, a.Evidence, a.Admin, a.Gateway)
	if _, err := consoleapi.Attach(a, diag.Discard()); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
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
	f.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if f.operator, err = keys.LoadAdminToken(stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.stop(); svc.Close() })
	f.withPrincipals()
	rg.fixture = f
	return rg
}

// appendixB parses SRS Appendix B Table B.2: each reason code with its
// Gateway or standard error codes and its data.message text.
func appendixB(t *testing.T) (codes map[string][]int64, messages map[string]string, order []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "srs_build", "appendix.md"))
	if err != nil {
		t.Fatal(err)
	}
	sec := string(raw)
	sec = sec[strings.Index(sec, "### B.2"):]
	sec = sec[:strings.Index(sec, "\n### B.3")] // Table B.2 only
	codes, messages = map[string][]int64{}, map[string]string{}
	row := regexp.MustCompile("^\\| `([A-Z_]+)` \\|")
	num := regexp.MustCompile("`(-3[12]\\d{3})`")
	for _, line := range strings.Split(sec, "\n") {
		m := row.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for _, c := range num.FindAllStringSubmatch(cells[1], -1) {
			var n int64
			fmt.Sscan(c[1], &n)
			codes[m[1]] = append(codes[m[1]], n)
		}
		messages[m[1]] = strings.TrimSpace(cells[len(cells)-1])
		order = append(order, m[1])
	}
	if len(order) < 50 {
		t.Fatalf("Appendix B Table B.2 has %d rows", len(order))
	}
	return codes, messages, order
}

// appendixB3 returns the reason codes of Appendix B Table B.3 (no request
// reaches them).
func appendixB3(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "srs_build", "appendix.md"))
	if err != nil {
		t.Fatal(err)
	}
	sec := string(raw)
	sec = sec[strings.Index(sec, "### B.3"):]
	sec = sec[:strings.Index(sec, "\n## ")]
	out := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([A-Z_]+)` \\|").FindAllStringSubmatch(sec, -1) {
		out[m[1]] = true
	}
	return out
}

// wireError is one Gateway error as the harness received it.
type wireError struct {
	code int64
	data map[string]any
}

// unreachable lists the Table B.2 reason codes that no request can
// produce, with the reason; it must name the codes of SRS Appendix B Table
// B.3. The test checks their messages through the error builder.
var unreachable = map[string]string{
	// Routes are server aliases, which are unique, and a public name
	// resolves to one server: the decision never sees two routes.
	"AMBIGUOUS_ROUTE": "routes are unique server aliases",
	// A tool is presented only while the registry resolves it to its
	// server; when the route goes, the server is suspended or its tool
	// list changed, and the catalog drops the name (the call is then an
	// unknown tool, -32602) or the decision sees the suspension first
	// (REVISION_NOT_ENABLED).
	"NO_ROUTE": "the catalog drops a tool whose route goes",
	// The catalog presents only granted tools that no deny rule covers
	// (FR-1.26), so a call to a denied tool is an unknown tool (-32602).
	"DENY_RULE": "denied tools are not presented",
	// Revoking a credential and suspending a principal terminate their
	// sessions under the Enforcement Coordinator's gate (SR-1.16-1), so
	// the session check refuses the next call first (SESSION_STATE).
	"CREDENTIAL_INVALID": "revocation ends the sessions first",
	"PRINCIPAL_DISABLED": "suspension ends the sessions first",
	// The capability is issued and consumed inside one call; only a
	// Gateway defect produces this.
	"CAPABILITY": "internal invariant",
	// tools/call arguments are decoded as a JSON object before the
	// inspection chain sees them; anything else is -32602 from the
	// protocol layer.
	"ARGUMENTS_INVALID": "arguments are always parsed JSON",
	// MCP cancellation: the harness that cancelled a call does not wait
	// for, and gets no response to, the cancelled request.
	"CANCELLED": "the cancelling harness gets no response",
}

// elsewhere lists the Table B.2 reason codes another test triggers with a
// data.message check, because they need a fixture this test does not have.
var elsewhere = map[string]string{
	// Needs a promoted baseline and synchronous scoring.
	"ANOMALY_WITHHELD": "TestSynchronousScoringBeforeDispatchAndRelease",
	// Needs a journal flush failure between the backend's response and the
	// delivered event, injected in the edge harness (SR-6.3-1).
	"OUTCOME_UNRECORDED": "internal/edge.TestAuditFailureFailsClosed, internal/edge.TestReleaseCommitFailureWithholds",
}

// TestEveryReasonCodeEndToEnd is FR-1.51's verification: every Appendix B
// error code and every Table B.2 reason code that a request can produce
// is triggered through the harness listener (or, for session creation,
// the token endpoint) of running Gateways, and each error carries the
// table's data.message with {approvalUrl} and {correlationId} filled in;
// -31002 carries an approvalUrl that opens the approval in G-13 (the
// console serves the page at that path and its G-13 view loads
// /api/v1/approvals/{id}). The codes no request can produce are listed in
// unreachable with the reason, and their messages are checked through the
// error builder.
func TestEveryReasonCodeEndToEnd(t *testing.T) {
	reqtest.Verifies(t, "FR-1.51")
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root (JOURNAL_UNAVAILABLE)")
	}
	codes, messages, order := appendixB(t)
	b3 := appendixB3(t)
	for reason := range unreachable {
		if !b3[reason] {
			t.Errorf("%s is treated as unreachable but is not in Table B.3", reason)
		}
	}
	for reason := range b3 {
		if _, ok := unreachable[reason]; !ok {
			t.Errorf("Table B.3 lists %s but this test does not treat it as unreachable", reason)
		}
	}
	got := map[string][]wireError{}
	record := func(reason string, w wireError) {
		t.Helper()
		if w.data["reasonCode"] != reason {
			t.Fatalf("%s: got code %d data %v", reason, w.code, w.data)
		}
		got[reason] = append(got[reason], w)
	}
	fromErr := func(reason string, err error) {
		t.Helper()
		var we *jsonrpc.Error
		if !errors.As(err, &we) {
			t.Fatalf("%s: not a JSON-RPC error: %v", reason, err)
		}
		var data map[string]any
		_ = json.Unmarshal(we.Data, &data)
		record(reason, wireError{we.Code, data})
	}
	fromBody := func(reason, body string) {
		t.Helper()
		var m struct {
			Error *struct {
				Code int64          `json:"code"`
				Data map[string]any `json:"data"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(body), &m) != nil || m.Error == nil {
			t.Fatalf("%s: body %s", reason, body)
		}
		record(reason, wireError{m.Error.Code, m.Error.Data})
	}

	rg := startReasons(t, reasonOpts{limits: `upstream_timeout = "2s"
client_deadline = "3s"
principal_calls_per_minute = 100000
principal_call_burst = 100000
sessions_per_principal = 32
listen_streams_per_session = 1
approval_hold = "0s"
tool_queue = 1
tool_concurrency_total = 1
tool_concurrency_per_principal = 1`})
	access, _, tokenBody := rg.oauthLogin("")
	sessionID, _ := tokenBody["session_id"].(string)
	cs := rg.mcpClient(access)
	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, lines := rg.openListenStream(ctx, access, `"L0"`)
		waitAck(t, ctx, lines)
		st, _, body := rg.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":"L1","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},%s}}`, modernMeta),
			modernHeaders(access, "subscriptions/listen"))
		if st != 200 {
			t.Fatalf("LISTEN_LIMIT: %d %s", st, body)
		}
		fromBody("LISTEN_LIMIT", body)
		cancel()
	}
	callAs := func(cs *mcp.ClientSession, reason, tool string, args map[string]any) {
		t.Helper()
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
		if err == nil {
			t.Fatalf("%s: %s succeeded: %+v", reason, tool, res)
		}
		fromErr(reason, err)
	}
	callR := func(reason, tool string, args map[string]any) { t.Helper(); callAs(cs, reason, tool, args) }
	ok := func(cs *mcp.ClientSession, tool string, args map[string]any) {
		t.Helper()
		if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args}); err != nil || res.IsError {
			t.Fatalf("%s: %v %+v", tool, err, res)
		}
	}
	ok(cs, "r_echo", map[string]any{"text": "hi"})

	// -31001 from the decision.
	callR("NO_PERMIT", "r_pick", map[string]any{"choice": "b"})
	callR("HIGH_RISK_UNFLAGGED", "hr_echo", map[string]any{"text": "x"})
	boundAccess, _, _ := rg.oauthLogin("smcp:template:bound")
	callAs(rg.mcpClient(boundAccess), "EVAL_BOUND", "r_echo", map[string]any{"text": "x"})
	taintAccess, _, _ := rg.oauthLogin("smcp:template:taint")
	tcs := rg.mcpClient(taintAccess)
	ok(tcs, "r_untrusted", nil)
	callAs(tcs, "TAINT_DENIED", "r_write", nil)

	// -31001 from request inspection (built-in filters and test filters).
	callR("ARGUMENTS_TOO_LARGE", "r_echo", map[string]any{"text": strings.Repeat("a", 70<<10)})
	deep := any("x")
	for i := 0; i < 40; i++ {
		deep = []any{deep}
	}
	callR("ARGUMENTS_TOO_DEEP", "r_echo", map[string]any{"text": "x", "extra": deep})
	callR("UNICODE_CONTROL", "r_echo", map[string]any{"text": "a\u202eb"})
	callR("SECRET_IN_ARGUMENTS", "r_echo", map[string]any{"text": "key=" + "AKIA" + "IOSFODNN7EXAMPLE"})
	callR("PATH_INVALID", "r_read_file", map[string]any{"path": "a%2f..%2fb"})
	callR("PATH_OUTSIDE_ROOTS", "r_read_file", map[string]any{"path": "/etc/passwd"})
	callR("URL_INVALID", "r_fetch", map[string]any{"url": "http://exa mple.com/"})
	callR("URL_NOT_ALLOWED", "r_fetch", map[string]any{"url": "ftp://example.com/x"})
	callR("URL_PRIVATE_ADDRESS", "r_fetch", map[string]any{"url": "http://127.0.0.1/x"})
	callR("DATA_CLASS_IN_ARGUMENTS", "r_pii_tool", map[string]any{"text": "see PRJ-1234"})
	callR("FILTER_UNAVAILABLE", "r_needs_missing", nil)
	callR("FILTER_ERROR", "r_ferr_req", nil)
	callR("FILTER_TIMEOUT", "r_ftime_req", nil)
	callR("SCHEMA_INVALID", "r_count", map[string]any{"n": "seven"})

	// -31002 and the approval outcomes.
	callR("APPROVAL_REQUIRED", "r_approve_me", nil)
	tapAccess, _, _ := rg.oauthLogin("smcp:template:taintap")
	tap := rg.mcpClient(tapAccess)
	ok(tap, "r_untrusted", nil)
	callAs(tap, "TAINT_APPROVAL", "r_write", nil)

	// -31003 from response inspection, validation and release.
	callR("FILTER_BLOCKED", "r_bidi", nil)
	rg.app.Inspector.Fingerprints().Register("e2e-secret@1", reasonsSecret)
	callR("SECRET_LEAK", "r_leak", nil)
	callR("RESULT_TOO_LARGE", "r_big", nil)
	callR("RESULT_INVALID", "r_bad_result", nil)
	callR("FILTER_ERROR", "r_ferr_resp", nil)
	callR("FILTER_TIMEOUT", "r_ftime_resp", nil)
	// RELEASE_REFUSED: the session is suspended while the result waits in
	// the response chain.
	{
		errc := make(chan error, 1)
		go func() {
			_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "r_gated_resp"})
			errc <- err
		}()
		<-rg.gateResp.entered
		if st, body := rg.admin("POST", "/api/v1/sessions/"+sessionID+"/suspend", rg.operator, map[string]any{}); st != 200 {
			t.Fatalf("suspend: %d %v", st, body)
		}
		close(rg.gateResp.release)
		fromErr("RELEASE_REFUSED", <-errc)
		if st, body := rg.admin("POST", "/api/v1/sessions/"+sessionID+"/resume", rg.operator, map[string]any{}); st != 200 {
			t.Fatalf("resume: %d %v", st, body)
		}
	}

	// -31004 from launch authorization and the fail-closed check.
	gated := func(reason, tool string, change, undo func()) {
		t.Helper()
		errc := make(chan error, 1)
		go func() {
			_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool})
			errc <- err
		}()
		select {
		case <-rg.gate.entered:
		case err := <-errc:
			t.Fatalf("%s: call ended before the gate: %v", reason, err)
		}
		change()
		select {
		case rg.gate.release <- struct{}{}:
			fromErr(reason, <-errc)
		case err := <-errc: // the change ended the call's filter early
			fromErr(reason, err)
		}
		if undo != nil {
			undo()
		}
	}
	gated("POLICY_REVISION_CHANGED", "r_gated", func() { rg.publish(reasonsPolicy("reasons-2")) }, nil)
	// The library suspends a revision through Registry.Suspend (drift,
	// revocation); the flag is set at once and the instance is torn down
	// after it, which can outlast the CP-14 deadline the gated call runs
	// under, so the teardown runs on its own goroutine.
	gated("REVISION_NOT_ENABLED", "s2_gated", func() {
		s2 := rg.app.Registry.Servers()["s2"]
		go rg.app.Registry.Suspend("s2", "e2e suspension")
		for !s2.Suspended() {
			time.Sleep(time.Millisecond)
		}
	}, nil)
	mcpPost := func(reason string, wantStatus int) {
		t.Helper()
		st, _, body := rg.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{%s}}`, modernMeta), modernHeaders(access, "tools/list"))
		if st != wantStatus {
			t.Fatalf("%s: status %d %s", reason, st, body)
		}
		fromBody(reason, body)
	}
	rg.failing.Store([]string{"e2e cause"})
	mcpPost("FAIL_CLOSED", 503)
	rg.failing.Store([]string(nil))
	if st, _ := rg.admin("POST", "/admin/v1/stop", rg.operator, map[string]any{"reason": "drill"}); st != 200 {
		t.Fatal("stop")
	}
	mcpPost("EMERGENCY_STOP", 503)
	if st, _ := rg.admin("POST", "/admin/v1/resume", rg.operator, map[string]any{}); st != 200 {
		t.Fatal("resume")
	}

	// -31005.
	ok(cs, "r_quota", nil)
	callR("QUOTA_EXHAUSTED", "r_quota", nil)
	// The rule's one call per minute bounds the principal and session
	// windows too, which already hold this test's calls.
	callR("RATE_LIMITED", "r_rated", nil)
	{
		errs := make(chan error, 3)
		for i := 0; i < 3; i++ {
			go func() {
				_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "r_slow", Arguments: map[string]any{"ms": 800}})
				errs <- err
			}()
		}
		for i := 0; i < 3; i++ {
			if err := <-errs; err != nil {
				fromErr("QUEUE_FULL", err)
			}
		}
		if len(got["QUEUE_FULL"]) == 0 {
			t.Fatal("QUEUE_FULL: no call was refused by the queue bound")
		}
	}

	// -31007, -31009, -31010: backend outcomes.
	// A garbled line, an exit and a timeout each replace the instance. The
	// next call waits for the replacement within its 2 s upstream timeout,
	// and a loaded host (CI's -race -coverpkg test binary is the backend)
	// can take longer to start it, which turned INSTANCE_FAILED into
	// UPSTREAM_TIMEOUT now and then; so each call after a replacement is
	// made once the replacement is serving.
	rsrv := rg.app.Registry.Servers()["r"]
	restarts := rsrv.Restarts()
	replaced := func(after string) {
		t.Helper()
		restarts++
		for deadline := time.Now().Add(60 * time.Second); rsrv.Restarts() < restarts; time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("the instance was not replaced after %s", after)
			}
		}
	}
	callR("BACKEND_ERROR", "r_fail", nil)
	callR("BACKEND_OUTPUT_INVALID", "r_garble", nil)
	replaced("BACKEND_OUTPUT_INVALID")
	callR("INSTANCE_FAILED", "r_crash", nil)
	replaced("INSTANCE_FAILED")
	callR("DISPATCH_FAILED", "r_crash_read", nil)
	replaced("DISPATCH_FAILED")
	callR("UPSTREAM_TIMEOUT", "r_hang", nil)
	replaced("UPSTREAM_TIMEOUT")
	callR("INPUT_REQUIRED_UNSUPPORTED", "r_ask", nil)

	// NO_TEMPLATE: the profile stops permitting the bound session's
	// template, which stays defined (so the session keeps its catalog).
	rg.publish(reasonsPolicy("reasons-3", "main", "taint", "taintap"))
	callAs(rg.mcpClient(boundAccess), "NO_TEMPLATE", "r_echo", map[string]any{"text": "x"})

	// -31006.
	{
		st, _, body := rg.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":8,"method":"tools/list","params":{%s}}`, modernMeta), modernHeaders("not-a-token", "tools/list"))
		if st != 401 {
			t.Fatalf("SESSION_INVALID: %d %s", st, body)
		}
		fromBody("SESSION_INVALID", body)
	}
	// SESSION_STATE: the session is suspended between the decision and
	// launch (a suspended session's token is SESSION_INVALID at the edge).
	suspend := func(on bool) {
		verb := "resume"
		if on {
			verb = "suspend"
		}
		if st, body := rg.admin("POST", "/api/v1/sessions/"+sessionID+"/"+verb, rg.operator, map[string]any{}); st != 200 {
			t.Fatalf("%s: %d %v", verb, st, body)
		}
	}
	gated("SESSION_STATE", "r_gated", func() { suspend(true) }, func() { suspend(false) })

	// -31001 and -31005 from session creation (token endpoint).
	tokenError := func(reason, scope string, wantStatus int) {
		t.Helper()
		st, body := rg.tokenRequest(scope)
		if st != wantStatus {
			t.Fatalf("%s: token %d %s", reason, st, body)
		}
		var m struct {
			SMCP map[string]any `json:"smcp_error"`
		}
		if json.Unmarshal(body, &m) != nil || m.SMCP == nil {
			t.Fatalf("%s: %s", reason, body)
		}
		code, _ := m.SMCP["code"].(float64)
		d := map[string]any{"reasonCode": m.SMCP["reasonCode"], "message": m.SMCP["message"]}
		record(reason, wireError{int64(code), d})
	}
	tokenError("TEMPLATE_NOT_PERMITTED", "smcp:template:bound", 400)

	// A second Gateway: CP-13 client deadline shorter than the upstream
	// timeout, one session per principal, then the journal outage.
	g2 := startReasons(t, reasonOpts{limits: `upstream_timeout = "5s"
client_deadline = "1s"
principal_calls_per_minute = 100000
principal_call_burst = 100000
sessions_per_principal = 1`})
	acc2, _, _ := g2.oauthLogin("")
	cs2 := g2.mcpClient(acc2)
	callAs(cs2, "CLIENT_DEADLINE", "r_hang", nil)
	{
		st, body := g2.tokenRequest("")
		if st != 429 {
			t.Fatalf("SESSION_LIMIT: %d %s", st, body)
		}
		var m struct {
			SMCP map[string]any `json:"smcp_error"`
		}
		_ = json.Unmarshal(body, &m)
		code, _ := m.SMCP["code"].(float64)
		record("SESSION_LIMIT", wireError{int64(code), map[string]any{"reasonCode": m.SMCP["reasonCode"], "message": m.SMCP["message"]}})
	}
	// APPROVAL_UNAVAILABLE: the Approval Service cannot store the request.
	store := filepath.Join(g2.stateDir, approval.StoreDir)
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store, 0o500); err != nil {
		t.Fatal(err)
	}
	callAs(cs2, "APPROVAL_UNAVAILABLE", "r_approve_me", nil)
	if err := os.Chmod(store, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(g2.stateDir, "journal")
	if err := os.Chmod(journal, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(journal, 0o700) })
	// The journal fails when it next opens a segment, after 1,000 events
	// (audit.Options.MaxEvents), so this takes about 170 calls. Under the
	// race detector on a loaded CI runner that took more than the 20 s this
	// loop used to allow; the bound only stops a journal that never fails.
	deadline := time.Now().Add(120 * time.Second)
	for {
		_, err := cs2.CallTool(context.Background(), &mcp.CallToolParams{Name: "r_echo", Arguments: map[string]any{"text": "j"}})
		var we *jsonrpc.Error
		if errors.As(err, &we) && strings.Contains(string(we.Data), edge.ReasonJournalUnavailable) {
			fromErr("JOURNAL_UNAVAILABLE", err)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("journal never became unavailable: %v", err)
		}
	}

	// A third Gateway for the held-approval outcomes (CP-45 hold longer
	// than the CP-17 lifetime): two identical held calls wait on one
	// approval and, once it is approved, one consumes it and the other gets
	// APPROVAL_CONSUMED; a held call is denied while held; a call held past
	// the approval's lifetime gets APPROVAL_EXPIRED.
	g3 := startReasons(t, reasonOpts{lifetime: "3s", limits: `approval_hold = "20s"
principal_calls_per_minute = 100000
principal_call_burst = 100000
tool_concurrency_total = 4
tool_concurrency_per_principal = 4`})
	acc3, _, _ := g3.oauthLogin("")
	cs3 := []*mcp.ClientSession{g3.mcpClient(acc3)}
	alice := approverTokenFor(t, g3.fixture)
	held := func(args map[string]any, n int, verb string) []error {
		t.Helper()
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			go func() {
				if i == 0 {
					_, err := cs3[0].CallTool(context.Background(), &mcp.CallToolParams{Name: "r_approve_me", Arguments: args})
					errs <- err
					return
				}
				// Another JSON-RPC ID in the same session (the binding
				// includes the session).
				errs <- g3.rawToolCall(acc3, fmt.Sprintf(`"held-%d"`, i), "r_approve_me", args)
			}()
		}
		var id string
		deadline := time.Now().Add(10 * time.Second)
		for id == "" {
			st, body := g3.admin("GET", "/api/v1/approvals?state=pending", g3.operator, nil)
			items, _ := body["approvals"].([]any)
			for _, it := range items {
				if m, _ := it.(map[string]any); m["state"] == "pending" {
					id = idOf(it)
				}
			}
			if id == "" && time.Now().After(deadline) {
				t.Fatalf("pending approvals: %d %v", st, body)
			}
			time.Sleep(20 * time.Millisecond)
		}
		// Every call holds the pending approval before the decision.
		time.Sleep(300 * time.Millisecond)
		if st, body := g3.admin("POST", "/api/v1/approvals/"+id+"/"+verb, alice, map[string]any{}); st != 200 {
			t.Fatalf("%s: %d %v", verb, st, body)
		}
		var failed []error
		for i := 0; i < n; i++ {
			if err := <-errs; err != nil {
				failed = append(failed, err)
			}
		}
		return failed
	}
	if failed := held(nil, 2, "approve"); len(failed) != 1 {
		t.Fatalf("APPROVAL_CONSUMED: %d calls failed: %v", len(failed), failed)
	} else {
		fromErr("APPROVAL_CONSUMED", failed[0])
	}
	if failed := held(map[string]any{"why": "deny"}, 1, "deny"); len(failed) != 1 {
		t.Fatalf("APPROVAL_DENIED: %v", failed)
	} else {
		fromErr("APPROVAL_DENIED", failed[0])
	}
	callAs(cs3[0], "APPROVAL_EXPIRED", "r_approve_me", map[string]any{"why": "expire"})

	// NO_SNAPSHOT: the third Gateway restarted after its active policy
	// revision was altered starts fail-closed (SR-1.1-2).
	g3dir := g3.stateDir
	g3.stop()
	tamperActiveRevision(t, g3dir)
	g4 := startReasons(t, reasonOpts{stateDir: g3dir})
	{
		st, _, body := g4.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{%s}}`, modernMeta), modernHeaders("any", "tools/list"))
		if st != 503 {
			t.Fatalf("NO_SNAPSHOT: %d %s", st, body)
		}
		fromBody("NO_SNAPSHOT", body)
	}

	// Every Table B.2 row: triggered with its code and message, or
	// unreachable with the builder's message equal to the table's.
	seenCodes := map[int64]bool{}
	for _, reason := range order {
		why, ok := unreachable[reason]
		if test, ok2 := elsewhere[reason]; ok2 {
			why, ok = "triggered in "+test, true
		}
		if ok {
			if len(got[reason]) > 0 {
				t.Errorf("%s is listed as not triggered here (%s) but was triggered", reason, why)
			}
			for _, code := range codes[reason] {
				data := map[string]any{"correlationId": "c-1"}
				if want := strings.ReplaceAll(messages[reason], "{correlationId}", "c-1"); edge.Message(code, reason, data) != want {
					t.Errorf("%s: builder message %q, want %q", reason, edge.Message(code, reason, data), want)
				}
			}
			continue
		}
		ws := got[reason]
		if len(ws) == 0 {
			t.Errorf("%s was not triggered", reason)
			continue
		}
		for _, code := range codes[reason] {
			found := false
			for _, w := range ws {
				found = found || w.code == code
			}
			if !found {
				t.Errorf("%s: code %d not seen (got %v)", reason, code, ws)
			}
		}
		for _, w := range ws {
			seenCodes[w.code] = true
			want := messages[reason]
			if strings.Contains(want, "{correlationId}") {
				corr, _ := w.data["correlationId"].(string)
				if corr == "" {
					t.Errorf("%s: no correlationId in %v", reason, w.data)
				}
				want = strings.ReplaceAll(want, "{correlationId}", corr)
			}
			if strings.Contains(want, "{approvalUrl}") {
				link, _ := w.data["approvalUrl"].(string)
				if link == "" {
					t.Errorf("%s: no approvalUrl in %v", reason, w.data)
				}
				want = strings.ReplaceAll(want, "{approvalUrl}", link)
			}
			if w.data["message"] != want {
				t.Errorf("%s (%d): data.message %q, want %q", reason, w.code, w.data["message"], want)
			}
		}
	}
	// Every Appendix B.1 Gateway code was produced by some request.
	for code := int64(-31001); code >= -31010; code-- {
		if !seenCodes[code] {
			t.Errorf("Gateway code %d never produced", code)
		}
	}
	// -31002: approvalUrl opens the approval in G-13.
	for _, reason := range []string{"APPROVAL_REQUIRED", "TAINT_APPROVAL"} {
		w := got[reason][0]
		link, _ := w.data["approvalUrl"].(string)
		id, _ := w.data["approvalId"].(string)
		u, err := url.Parse(link)
		if err != nil || id == "" || link != rg.cfg.AdminURL()+"/approvals/"+id {
			t.Fatalf("%s: approvalUrl %q approvalId %q", reason, link, id)
		}
		r, body := rg.get(u.String())
		if r.StatusCode != 200 || !strings.Contains(string(body), `<div id="root">`) {
			t.Fatalf("%s: console page %d", reason, r.StatusCode)
		}
		if st, rec := rg.admin("GET", "/api/v1/approvals/"+id, rg.operator, nil); st != 200 || rec["id"] != id {
			t.Fatalf("%s: G-13 record %d %v", reason, st, rec)
		}
	}
}

// rawToolCall posts one tools/call with the given JSON-RPC ID and returns
// its JSON-RPC error (nil for a result). A held call answers as an event
// stream whose last data line is the response.
func (f *fixture) rawToolCall(access, id, tool string, args map[string]any) error {
	f.t.Helper()
	a, _ := json.Marshal(args)
	if args == nil {
		a = []byte("{}")
	}
	hdr := modernHeaders(access, "tools/call")
	hdr["Mcp-Name"] = tool
	_, _, body := f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":%q,"arguments":%s,%s}}`, id, tool, a, modernMeta), hdr)
	last := body
	for _, line := range strings.Split(body, "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok {
			last = d
		}
	}
	var m struct {
		Error *jsonrpc.Error `json:"error"`
	}
	if err := json.Unmarshal([]byte(last), &m); err != nil {
		f.t.Fatalf("tools/call %s: %v: %s", tool, err, body)
	}
	if m.Error == nil {
		return nil
	}
	return m.Error
}

// approverTokenFor signs in the Approver account alice of a fixture.
func approverTokenFor(t *testing.T, f *fixture) string {
	t.Helper()
	st, body := f.admin("POST", "/api/v1/approvals/login", "", map[string]any{"username": "alice", "password": approverAccountPassword})
	tok, _ := body["token"].(string)
	if st != 200 || tok == "" {
		t.Fatalf("approver login: %d %v", st, body)
	}
	return tok
}

// tokenRequest runs the authorization-code flow and returns the token
// endpoint's status and body.
func (f *fixture) tokenRequest(scope string) (int, []byte) {
	f.t.Helper()
	r, b := f.oauthTokenResponse(scope, clientID, "approver", approverPassword, nil)
	return r.StatusCode, b
}

// tamperActiveRevision changes the signed policy control record so that
// its signature no longer verifies.
func tamperActiveRevision(t *testing.T, stateDir string) {
	t.Helper()
	p := filepath.Join(stateDir, policystore.ControlFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c["actor"] = "tampered"
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
