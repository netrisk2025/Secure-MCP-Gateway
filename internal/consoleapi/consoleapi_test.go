package consoleapi

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

type fakeCtl struct{}

func (fakeCtl) Health() edge.Health                                   { return edge.Health{State: "healthy", Causes: []string{}} }
func (fakeCtl) Stop(string, string) error                             { return nil }
func (fakeCtl) Resume(string) error                                   { return nil }
func (fakeCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

type fakeServers struct{ m map[string]*backend.Server }

func (f fakeServers) Servers() map[string]*backend.Server { return f.m }
func (fakeServers) Launcher() pipeline.Launcher           { return pipeline.SubprocessLauncher{} }

const testPolicy = `{"revision":"r7","framework_profiles":{"dev":{"templates":["ro","ap"],"default_template":"ro"}},
"templates":{"ro":{"rules":[{"id":"ro-fs","server":"fs","tools":["read","missing"]}]},
"ap":{"rules":[{"id":"ap-fs","server":"fs","tools":["write"],"approval":true,"filters":["size-limit"]}]}}}`

type fixture struct {
	t        *testing.T
	srv      *httptest.Server
	operator string
	store    *session.Store
	journal  *audit.Journal
	fan      *audit.Fanout
	console  *Console
	dir      string
}

func newFixture(t *testing.T, evidence audit.Recorder) *fixture {
	t.Helper()
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, dir: dir}
	f.srv = httptest.NewUnstartedServer(nil)
	toml := fmt.Sprintf(`[admin_listener]
address = %q
[state]
dir = %q
[policy]
file = %q
[admin]
username = "admin"
password_hash = "$argon2id$x"
[[approver]]
username = "sam"
password_hash = "$argon2id$x"
[[principal]]
id = "cc"
framework = "claude-code"
display_name = "Claude Code"
profile = "dev"
[[client]]
client_id = "c1"
principal = "cc"
redirect_uris = ["http://localhost:*/callback"]
[[server]]
alias = "fs"
command = "/usr/bin/true"
args = ["--root", "/tmp/x"]
env = { MODE = "ro" }
secret_env = { TOKEN = "fs-token" }
[[server]]
alias = "off"
command = "/usr/bin/false"
`, f.srv.Listener.Addr().String(), dir, filepath.Join(dir, "policy.json"))
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Policy.File, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := policy.Load(cfg.Policy.File)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.LoadEvidenceKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.journal, err = audit.Open(filepath.Join(dir, "journal"), key, audit.Options{MaxEvents: 3})
	if err != nil {
		t.Fatal(err)
	}
	f.fan = audit.NewFanout(f.journal, nil)
	t.Cleanup(func() { f.fan.Close(); f.journal.Close() })
	if evidence == nil {
		evidence = f.fan
	}
	admin, err := adminapi.New(adminapi.Options{Config: cfg, Controller: fakeCtl{}, Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	f.store = session.NewStore(cfg, func() *policy.Snapshot { return snap })
	servers := fakeServers{m: map[string]*backend.Server{"fs": {Alias: "fs", Revision: "live-abc", Era: "2026-07-28", ManifestSource: "live",
		Tools:          []*mcp.Tool{{Name: "read", Description: "Read a file", InputSchema: map[string]any{"type": "object"}}, {Name: "write"}},
		SuspendedTools: []pipeline.WithheldTool{{Name: "poisoned", ReasonCode: "METADATA_BLOCKED", Stage: "import", Findings: []pipeline.Finding{{Filter: "metadata-scan", RuleSet: "tool-metadata", Rule: "r1"}}}}}}}
	pub, err := keys.LoadEvidencePublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.console, err = Register(Deps{Admin: admin, Config: cfg, Sessions: f.store, Servers: servers, Snapshot: func() *policy.Snapshot { return snap },
		Evidence: evidence, Observe: f.fan, JournalDir: f.journal.Dir(), AnchorPath: f.journal.AnchorPath(), PublicKey: pub,
		Assets: fstest.MapFS{
			"index.html":         {Data: []byte("<!doctype html><title>console</title>")},
			"assets/index-1.js":  {Data: []byte("console.log(1)")},
			"assets/style-1.css": {Data: []byte("body{}")},
		}})
	if err != nil {
		t.Fatal(err)
	}
	f.operator, _ = keys.LoadAdminToken(dir)
	f.srv.Config.Handler = admin.Handler()
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) raw(method, path, token string, body any) *http.Response {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fixture) do(method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	r := f.raw(method, path, f.operator, body)
	defer r.Body.Close()
	var out map[string]any
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

func (f *fixture) record(evs ...audit.Event) {
	f.t.Helper()
	for _, e := range evs {
		if e.PolicyStatus == "" {
			e.PolicyStatus = "not_evaluated"
		}
		if e.Origin == "" {
			e.Origin = "E-08"
		}
		if err := f.fan.Commit(e); err != nil {
			f.t.Fatal(err)
		}
	}
}

func TestStaticConsoleCSPAndDeepLinks(t *testing.T) {
	// FR-8.26: assets come from the binary and the CSP allows no other
	// origin; the help text and fonts are part of the same bundle, which this
	// unit test does not inspect. FR-8.28: deep links return the page.
	reqtest.Partial(t, "FR-8.26", "FR-8.28", "SR-6.17-1")
	f := newFixture(t, nil)
	for _, p := range []string{"/", "/approvals/01a1-xyz", "/sessions/abc", "/audit/events/e1", "/library/smcp-ref-filesystem/0.0.0-dev+abc",
		"/library/pkg/1.2.0", "/policy/revisions/r1.1", "/audit/decisions/d1"} {
		r := f.raw("GET", p, "", nil)
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || !strings.Contains(string(b), "<title>console</title>") {
			t.Fatalf("%s: %d %s", p, r.StatusCode, b)
		}
		csp := r.Header.Get("Content-Security-Policy")
		if csp != ConsoleCSP || strings.Contains(csp, "unsafe") || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "img-src 'self'") {
			t.Fatalf("csp %q", csp)
		}
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("headers %v", r.Header)
		}
	}
	r := f.raw("GET", "/assets/index-1.js", "", nil)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Type"), "javascript") || !strings.Contains(r.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", r.StatusCode, r.Header)
	}
	for _, p := range []string{"/assets/missing.js", "/favicon.ico", "/assets/sub/missing.css"} {
		r = f.raw("GET", p, "", nil)
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatalf("missing build file %s: %d", p, r.StatusCode)
		}
	}
	// Unknown control API routes are JSON 404 for the console's
	// "not available in this build" state, never the page.
	for _, m := range []string{"GET", "POST"} {
		var body any
		if m == "POST" {
			body = map[string]any{}
		}
		r = f.raw(m, "/api/v1/policy", f.operator, body)
		var e struct {
			Error struct{ Code string } `json:"error"`
		}
		json.NewDecoder(r.Body).Decode(&e)
		r.Body.Close()
		if r.StatusCode != 404 || e.Error.Code != "route_not_found" {
			t.Fatalf("%s unknown route: %d %+v", m, r.StatusCode, e)
		}
	}
	r = f.raw("POST", "/", "", map[string]any{})
	r.Body.Close()
	if r.StatusCode != 405 {
		t.Fatalf("POST page: %d", r.StatusCode)
	}
	// Console API routes require the control API authentication.
	r = f.raw("GET", "/api/v1/sessions", "", nil)
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("unauthenticated: %d", r.StatusCode)
	}
	req, _ := http.NewRequest("GET", f.srv.URL+"/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+f.operator)
	req.Header.Set("Origin", "https://evil.example")
	r, _ = f.srv.Client().Do(req)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatalf("foreign origin: %d", r.StatusCode)
	}
}

func TestSessionsListInspectTerminate(t *testing.T) {
	// List, inspect and terminate; suspension is TestSessionSuspendAndResume
	// and principals and credentials are internal/principals.
	reqtest.Partial(t, "FR-8.19")
	f := newFixture(t, nil)
	s, _, err := f.store.Create(session.CreateParams{PrincipalID: "cc", ClientID: "c1", Claims: session.Claims{Template: "ro", Purpose: "review"}, ApprovedBy: "sam", Listener: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	code, out := f.do("GET", "/api/v1/sessions", nil)
	list, _ := out["sessions"].([]any)
	if code != 200 || len(list) != 1 || list[0].(map[string]any)["id"] != s.ID || list[0].(map[string]any)["approved_by"] != "sam" {
		t.Fatalf("list: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/sessions/"+s.ID, nil)
	if code != 200 || out["template"] != "ro" || out["purpose"] != "review" || out["state"] != "active" {
		t.Fatalf("get: %d %v", code, out)
	}
	if code, _ = f.do("GET", "/api/v1/sessions/nope", nil); code != 404 {
		t.Fatalf("unknown: %d", code)
	}
	if code, _ = f.do("POST", "/api/v1/sessions/"+s.ID+"/terminate", map[string]any{"bogus": 1}); code != 400 {
		t.Fatalf("bad body: %d", code)
	}
	code, out = f.do("POST", "/api/v1/sessions/"+s.ID+"/terminate", map[string]any{"reason": "operator test"})
	if code != 200 || out["state"] != session.StateTerminated {
		t.Fatalf("terminate: %d %v", code, out)
	}
	if f.store.IsActive(s.ID) {
		t.Fatal("session still active")
	}
	code, out = f.do("POST", "/api/v1/sessions/"+s.ID+"/terminate", map[string]any{})
	if code != 409 || out["state"] != session.StateTerminated {
		t.Fatalf("second terminate: %d %v", code, out)
	}
	evs, _ := audit.ReadEvents(f.journal.Dir())
	found := false
	for _, e := range evs {
		if e.ReasonCode == "SESSION_TERMINATED_BY_OPERATOR" && e.SessionID == s.ID {
			d := e.Detail.(map[string]any)
			found = d["actor"] == "operator-token" && d["reason"] == "operator test"
		}
	}
	if !found {
		t.Fatalf("terminate not journaled: %+v", evs)
	}
	code, out = f.do("GET", "/api/v1/sessions/principals", nil)
	ps, _ := out["principals"].([]any)
	as, _ := out["session_approvers"].([]any)
	cs, _ := out["clients"].([]any)
	if code != 200 || len(ps) != 1 || len(as) != 1 || len(cs) != 1 || as[0].(map[string]any)["username"] != "sam" {
		t.Fatalf("principals: %d %v", code, out)
	}
	if strings.Contains(fmt.Sprint(out), "argon2") {
		t.Fatal("password hash disclosed")
	}
}

func TestSessionSuspendAndResume(t *testing.T) {
	reqtest.Partial(t, "FR-8.19", "FR-2.8")
	f := newFixture(t, nil)
	s, tok, err := f.store.Create(session.CreateParams{PrincipalID: "cc", ClientID: "c1", Claims: session.Claims{Template: "ro"}, Listener: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do("POST", "/api/v1/sessions/"+s.ID+"/resume", map[string]any{}); code != 409 {
		t.Fatalf("resume of an active session: %d", code)
	}
	code, out := f.do("POST", "/api/v1/sessions/"+s.ID+"/suspend", map[string]any{"reason": "investigating"})
	if code != 200 || out["state"] != session.StateSuspended {
		t.Fatalf("suspend: %d %v", code, out)
	}
	if _, err := f.store.Authenticate(tok.Access, "tls"); err == nil {
		t.Fatal("suspended session authenticated")
	}
	// Still listed, with its state.
	code, out = f.do("GET", "/api/v1/sessions", nil)
	list, _ := out["sessions"].([]any)
	if code != 200 || len(list) != 1 || list[0].(map[string]any)["state"] != session.StateSuspended {
		t.Fatalf("list: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/sessions/"+s.ID+"/resume", map[string]any{"reason": "cleared"})
	if code != 200 || out["state"] != session.StateActive {
		t.Fatalf("resume: %d %v", code, out)
	}
	if _, err := f.store.Authenticate(tok.Access, "tls"); err != nil {
		t.Fatal("resumed session refused")
	}
	evs, _ := audit.ReadEvents(f.journal.Dir())
	seen := map[string]bool{}
	for _, e := range evs {
		if e.SessionID == s.ID {
			seen[e.ReasonCode] = true
		}
	}
	if !seen["SESSION_SUSPENDED_BY_OPERATOR"] || !seen["SESSION_RESUMED_BY_OPERATOR"] {
		t.Fatalf("suspend and resume not journaled: %v", seen)
	}
}

func TestTerminateRefusedWhenJournalFails(t *testing.T) {
	reqtest.Partial(t, "FR-8.19")
	mem := &audit.Memory{}
	f := newFixture(t, mem)
	s, _, err := f.store.Create(session.CreateParams{PrincipalID: "cc", Claims: session.Claims{Template: "ro"}})
	if err != nil {
		t.Fatal(err)
	}
	mem.Fail(fmt.Errorf("disk full"))
	code, out := f.do("POST", "/api/v1/sessions/"+s.ID+"/terminate", map[string]any{})
	if code != 503 || !f.store.IsActive(s.ID) {
		t.Fatalf("terminate without evidence: %d %v", code, out)
	}
}

func TestServersAndCatalog(t *testing.T) {
	// FR-8.18 also asks for attestations, drift, revocation and the
	// enable/suspend/retire/alias/trust-anchor actions of E-13/E-14.
	// SR-3.4-1 also asks for SBOM, mounts, egress and sandbox profile.
	reqtest.Partial(t, "FR-8.18", "SR-3.4-1")
	f := newFixture(t, nil)
	code, out := f.do("GET", "/api/v1/servers", nil)
	list, _ := out["servers"].([]any)
	if code != 200 || len(list) != 2 {
		t.Fatalf("servers: %d %v", code, out)
	}
	fs := list[0].(map[string]any)
	if fs["state"] != "running" || fs["revision"] != "live-abc" || fs["verified"] != false || fs["tool_count"] != float64(2) ||
		fmt.Sprint(fs["env_keys"]) != "[MODE]" || fmt.Sprint(fs["secret_slots"]) != "[TOKEN]" || fs["launcher"] != "subprocess" || fs["confined"] != false {
		t.Fatalf("fs: %v", fs)
	}
	if strings.Contains(fmt.Sprint(out), "fs-token") || strings.Contains(fmt.Sprint(out), "\"ro\"") {
		t.Fatalf("environment values disclosed: %v", out)
	}
	if list[1].(map[string]any)["state"] != "not_running" {
		t.Fatalf("off: %v", list[1])
	}
	// SR-5.9-2: the tools the registry holds as suspended are listed.
	if st, _ := fs["suspended_tools"].([]any); len(st) != 1 || st[0].(map[string]any)["name"] != "poisoned" || st[0].(map[string]any)["reason_code"] != "METADATA_BLOCKED" {
		t.Fatalf("suspended tools: %v", fs["suspended_tools"])
	}
	if st, _ := list[1].(map[string]any)["suspended_tools"].([]any); st == nil || len(st) != 0 {
		t.Fatalf("off: suspended tools %v", list[1])
	}
	code, out = f.do("GET", "/api/v1/servers/fs", nil)
	tools, _ := out["tools"].([]any)
	if code != 200 || len(tools) != 2 || tools[0].(map[string]any)["public_name"] != "fs_read" || tools[0].(map[string]any)["revision"] != "live-abc/read" {
		t.Fatalf("server: %d %v", code, out)
	}
	if code, _ = f.do("GET", "/api/v1/servers/zzz", nil); code != 404 {
		t.Fatalf("unknown server: %d", code)
	}
	code, out = f.do("GET", "/api/v1/catalog", nil)
	tpls, _ := out["templates"].([]any)
	if code != 200 || out["policy_revision"] != "r7" || len(tpls) != 2 {
		t.Fatalf("catalog: %d %v", code, out)
	}
	ap := tpls[0].(map[string]any)
	g := ap["tools"].([]any)[0].(map[string]any)
	if ap["name"] != "ap" || g["approval"] != true || g["public_name"] != "fs_write" || fmt.Sprint(g["filters"]) != "[size-limit]" || g["available"] != true {
		t.Fatalf("ap: %v", ap)
	}
	ro := tpls[1].(map[string]any)
	if fmt.Sprint(ro["default_for"]) != "[dev]" {
		t.Fatalf("ro: %v", ro)
	}
	for _, x := range ro["tools"].([]any) {
		m := x.(map[string]any)
		if m["tool"] == "missing" && m["available"] != false {
			t.Fatalf("missing tool offered: %v", m)
		}
	}
	if code, _ = f.do("GET", "/api/v1/catalog?template=nope", nil); code != 404 {
		t.Fatalf("unknown template: %d", code)
	}
	code, out = f.do("GET", "/api/v1/catalog?template=ro", nil)
	if code != 200 || len(out["templates"].([]any)) != 1 {
		t.Fatalf("filtered: %v", out)
	}
}

func TestAuditBrowserFiltersPagingAndDetail(t *testing.T) {
	// FR-8.22 also asks for navigation to rule revisions, route, server
	// revision and baseline snapshot and a bounded graph (E-25/E-26).
	reqtest.Partial(t, "FR-8.22")
	f := newFixture(t, nil)
	for i := range 5 {
		f.record(audit.Event{Class: "tool_call", Phase: audit.PhaseRequested, CorrelationID: fmt.Sprintf("c%d", i), SessionID: "s1"},
			audit.Event{Class: "tool_call", Phase: audit.PhaseDenied, CorrelationID: fmt.Sprintf("c%d", i), Outcome: "deny", ReasonCode: "NO_RULE", SessionID: "s1"})
	}
	code, out := f.do("GET", "/api/v1/audit/events?limit=3&class=tool_call", nil)
	evs, _ := out["events"].([]any)
	if code != 200 || len(evs) != 3 || out["next_before"] == "" {
		t.Fatalf("page 1: %d %v", code, out)
	}
	first := evs[0].(map[string]any)
	if first["correlation_id"] != "c4" || first["phase"] != "denied" {
		t.Fatalf("not newest first: %v", first)
	}
	seen := map[string]bool{}
	before := ""
	for range 10 {
		q := "/api/v1/audit/events?limit=3&class=tool_call"
		if before != "" {
			q += "&before=" + before
		}
		_, out = f.do("GET", q, nil)
		for _, e := range out["events"].([]any) {
			id := e.(map[string]any)["event_id"].(string)
			if seen[id] {
				t.Fatalf("duplicate %s", id)
			}
			seen[id] = true
		}
		before, _ = out["next_before"].(string)
		if before == "" {
			break
		}
	}
	if len(seen) != 10 {
		t.Fatalf("paging saw %d events", len(seen))
	}
	_, out = f.do("GET", "/api/v1/audit/events?reason_code=NO_RULE&correlation_id=c2", nil)
	if n := len(out["events"].([]any)); n != 1 {
		t.Fatalf("filter: %d", n)
	}
	_, out = f.do("GET", "/api/v1/audit/events?q=no_rule", nil)
	if n := len(out["events"].([]any)); n != 5 {
		t.Fatalf("text: %d", n)
	}
	_, out = f.do("GET", "/api/v1/audit/events?until=2000-01-01T00:00:00Z", nil)
	if n := len(out["events"].([]any)); n != 0 {
		t.Fatalf("until: %d", n)
	}
	for _, q := range []string{"limit=0", "limit=5000", "since=yesterday", "before=nope"} {
		if code, _ := f.do("GET", "/api/v1/audit/events?"+q, nil); code != 400 {
			t.Fatalf("%s: %d", q, code)
		}
	}
	code, out = f.do("GET", "/api/v1/audit/events/"+first["event_id"].(string), nil)
	rel, _ := out["related"].([]any)
	if code != 200 || len(rel) != 2 || rel[0].(map[string]any)["phase"] != "requested" {
		t.Fatalf("detail: %d %v", code, out)
	}
	if code, _ = f.do("GET", "/api/v1/audit/events/none", nil); code != 404 {
		t.Fatalf("unknown event: %d", code)
	}
}

func TestAuditExportNeutralisesFormulas(t *testing.T) {
	// SR-6.17-1: CSV cells beginning with =, +, - or @ are prefixed with an
	// apostrophe. Escaped rendering is the console's (React text nodes) and
	// is not checked here.
	reqtest.Partial(t, "SR-6.17-1")
	f := newFixture(t, nil)
	f.record(audit.Event{Class: "tool_call", ReasonCode: "=HYPERLINK(\"x\")", Outcome: "+1", CorrelationID: "-c", SessionID: "@s", Detail: map[string]any{"a": "b"}})
	r := f.raw("GET", "/api/v1/audit/export?format=csv&class=tool_call", f.operator, nil)
	defer r.Body.Close()
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/csv") || !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d %v", r.StatusCode, r.Header)
	}
	rows, err := csv.NewReader(r.Body).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("csv: %v %v", err, rows)
	}
	row := map[string]string{}
	for i, h := range rows[0] {
		row[h] = rows[1][i]
	}
	if row["reason_code"] != `'=HYPERLINK("x")` || row["outcome"] != "'+1" || row["correlation_id"] != "'-c" || row["session_id"] != "'@s" || row["detail"] != `{"a":"b"}` {
		t.Fatalf("row: %v", row)
	}
	r2 := f.raw("GET", "/api/v1/audit/export?format=jsonl", f.operator, nil)
	defer r2.Body.Close()
	sc := bufio.NewScanner(r2.Body)
	n := 0
	for sc.Scan() {
		var e audit.Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			t.Fatalf("line %q", sc.Text())
		}
		n++
	}
	if n < 2 {
		t.Fatalf("jsonl lines %d", n)
	}
	if code, _ := f.do("GET", "/api/v1/audit/export?format=xml", nil); code != 400 {
		t.Fatal("bad format accepted")
	}
	evs, _ := audit.ReadEvents(f.journal.Dir())
	exports := 0
	for _, e := range evs {
		if e.ReasonCode == "AUDIT_EXPORTED" {
			exports++
		}
	}
	if exports != 2 {
		t.Fatalf("exports journaled: %d", exports)
	}
}

func TestJournalVerification(t *testing.T) {
	// FR-7.5 is the verifier itself (internal/audit); this checks that the
	// console reports its result, including a failure.
	reqtest.Partial(t, "FR-7.5")
	f := newFixture(t, nil)
	_, out := f.do("GET", "/api/v1/audit/verify", nil)
	if out["status"] != "not_run" {
		t.Fatalf("initial: %v", out)
	}
	for i := range 7 {
		f.record(audit.Event{Class: "tool_call", CorrelationID: fmt.Sprint(i)})
	}
	code, out := f.do("POST", "/api/v1/audit/verify", map[string]any{})
	if code != 200 || out["status"] != "verified" || out["segments"].(float64) < 2 || out["checked_by"] != "operator-token" {
		t.Fatalf("verify: %d %v", code, out)
	}
	_, last := f.do("GET", "/api/v1/audit/verify", nil)
	if last["status"] != "verified" {
		t.Fatalf("last: %v", last)
	}
	seg := filepath.Join(f.journal.Dir(), "segment-000001.jsonl")
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg, bytes.Replace(b, []byte(`"correlation_id":"0"`), []byte(`"correlation_id":"9"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out = f.do("POST", "/api/v1/audit/verify", map[string]any{})
	if out["status"] != "failed" || !strings.Contains(out["error"].(string), "segment-000001") {
		t.Fatalf("tampered: %v", out)
	}
}

func TestEvidenceStream(t *testing.T) {
	// FR-8.23: state changes reach open views within 2 s. This checks the
	// evidence stream that drives the refresh; the browser side is in
	// console/e2e.
	reqtest.Partial(t, "FR-8.23")
	f := newFixture(t, nil)
	r := f.raw("GET", "/api/v1/audit/stream", f.operator, nil)
	defer r.Body.Close()
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %v", r.StatusCode, r.Header)
	}
	rd := bufio.NewReader(r.Body)
	if l, _ := rd.ReadString('\n'); !strings.HasPrefix(l, ": stream open") {
		t.Fatalf("first line %q", l)
	}
	start := time.Now()
	f.record(audit.Event{Class: "admin", Outcome: "stopped", ReasonCode: "EMERGENCY_STOP"})
	got := make(chan string, 1)
	go func() {
		for {
			l, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(l, "data: ") {
				got <- l
				return
			}
		}
	}()
	select {
	case l := <-got:
		if !strings.Contains(l, "EMERGENCY_STOP") || time.Since(start) > 2*time.Second {
			t.Fatalf("event %q after %v", l, time.Since(start))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event within 2 s")
	}
}
