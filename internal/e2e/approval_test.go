package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const approvalPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ap"], "default_template": "ap"}},
  "templates": {
    "ap": {"rules": [{"id": "ap-echo", "server": "t", "tools": ["echo"], "approval": true},
                     {"id": "ap-plain", "server": "t", "tools": ["dotted.name"]}]}
  }
}`

const approverAccountPassword = "alice password 12"

// approvalFixture is a running Gateway with the Approval Service, an
// evidence observer and a desktop notifier that hands each notification to
// a channel.
type approvalFixture struct {
	*fixture
	svc    *approval.Service
	notes  chan string
	mu     sync.Mutex
	events []audit.Event
}

// chanNotifier is an approval.Notifier that sends "title|body" to a
// channel, so tests wait for the notification instead of polling a file.
// A full channel drops the notification (tests that do not read it).
type chanNotifier chan string

func (c chanNotifier) Notify(_ context.Context, title, body string) error {
	select {
	case c <- title + "|" + body:
	default:
	}
	return nil
}

func (af *approvalFixture) observed() []audit.Event {
	af.mu.Lock()
	defer af.mu.Unlock()
	return append([]audit.Event(nil), af.events...)
}

func startApprovals(t *testing.T, hold, lifetime string) *approvalFixture {
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
[approvals]
keepalive = "100ms"
lifetime = %q
notify = "off"
[[approvals.account]]
username = "alice"
password_hash = %q
[policy]
file = %q
[limits]
approval_hold = %q
upstream_timeout = "2s"
client_deadline = "3s"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = %q
principal = "cc"
redirect_uris = ["http://localhost:*/callback"]
[[server]]
alias = "t"
command = %q
args = ["-test.run=NONE"]
[server.env]
SMCP_E2E_BACKEND = "1"
`, port, port, adminPort, stateDir, mustHash(t, "admin password 12"), mustHash(t, approverPassword), lifetime,
		mustHash(t, approverAccountPassword), filepath.Join(dir, "policy.json"), hold, clientID, exe)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(approvalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	af := &approvalFixture{notes: make(chan string, 16)}
	svc, err := approval.New(approval.Options{Config: cfg, Log: diag.Discard(), JanitorInterval: 50 * time.Millisecond, Notifier: chanNotifier(af.notes)})
	if err != nil {
		t.Fatal(err)
	}
	af.svc = svc
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), JanitorInterval: 200 * time.Millisecond, Approver: svc, Approvals: svc,
		Observers: map[string]audit.Observer{"test": audit.ObserverFunc(func(e audit.Event) { af.mu.Lock(); af.events = append(af.events, e); af.mu.Unlock() })}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	svc.Start(ctx, a.Evidence, a.Admin, a.Gateway)
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
	t.Cleanup(func() { f.stop(); svc.Close() })
	af.fixture = f
	return af
}

// pending waits for n pending approvals and returns them (newest first).
func (af *approvalFixture) pending(n int) []any {
	af.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, body := af.admin("GET", "/api/v1/approvals", af.operator, nil)
		items, _ := body["approvals"].([]any)
		if st == 200 && len(items) >= n {
			return items
		}
		if time.Now().After(deadline) {
			af.t.Fatalf("pending approvals: %d %v", st, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func idOf(v any) string { m, _ := v.(map[string]any); s, _ := m["id"].(string); return s }

// approverToken signs in the Approver account alice.
func (af *approvalFixture) approverToken() string {
	af.t.Helper()
	st, body := af.admin("POST", "/api/v1/approvals/login", "", map[string]any{"username": "alice", "password": approverAccountPassword})
	tok, _ := body["token"].(string)
	if st != 200 || tok == "" || body["role"] != "approver" {
		af.t.Fatalf("approver login: %d %v", st, body)
	}
	return tok
}

func TestApprovalHeldApprovedDeniedAndReplay(t *testing.T) {
	// FR-3.14: the G-13 console view is another element's (E-24 console).
	// FR-3.24: the CLI is tested in cmd/smcpctl. FR-1.51: the -31001 and
	// -31002 messages are checked here, every other code in the edge unit
	// test.
	reqtest.Verifies(t, "FR-3.20", "FR-3.21", "FR-3.16")
	reqtest.Partial(t, "FR-3.14", "FR-3.17", "FR-3.19", "FR-1.51", "SR-1.18-2")
	af := startApprovals(t, "20s", "5m")
	access, _, _ := af.oauthLogin("")
	var progress atomic.Int32
	thirdKeepAlive := make(chan struct{})
	hc := &http.Client{Transport: bearerRT{access, af.client.Transport}}
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e-harness", Version: "1"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(context.Context, *mcp.ProgressNotificationClientRequest) {
			if progress.Add(1) == 3 {
				close(thirdKeepAlive)
			}
		}})
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: af.cfg.ResourceURI(), HTTPClient: hc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Held call, approved through the control API by an Approver: the
	// original request returns the tool result.
	type out struct {
		res *mcp.CallToolResult
		err error
	}
	callAsync := func(text string) <-chan out {
		ch := make(chan out, 1)
		go func() {
			p := &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": text}}
			p.SetProgressToken("tok-" + text)
			r, err := cs.CallTool(context.Background(), p)
			ch <- out{r, err}
		}()
		return ch
	}
	ch := callAsync("hello")
	items := af.pending(1)
	id := idOf(items[0])
	// Several keep-alive intervals pass while the call is held.
	select {
	case <-thirdKeepAlive:
	case o := <-ch:
		t.Fatalf("held call answered before a decision: %+v", o)
	case <-time.After(20 * time.Second):
		t.Fatalf("%d progress keep-alives at a 100 ms interval", progress.Load())
	}
	select {
	case o := <-ch:
		t.Fatalf("held call answered before a decision: %+v", o)
	default:
	}
	// Notification (X-14), without argument values.
	select {
	case b := <-af.notes:
		if !strings.Contains(b, id) || !strings.Contains(b, "t_echo") || strings.Contains(b, "hello") {
			t.Fatalf("desktop notification %q", b)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no desktop notification")
	}
	alice := af.approverToken()
	st, rec := af.admin("GET", "/api/v1/approvals/"+id, alice, nil)
	if st != 200 || rec["public_name"] != "t_echo" || fmt.Sprint(rec["arguments"]) != "map[text:hello]" || rec["state"] != "pending" ||
		fmt.Sprint(rec["decisive_rules"]) != "[ap-echo]" || rec["approval_url"] != af.cfg.AdminURL()+"/approvals/"+id {
		t.Fatalf("%d %v", st, rec)
	}
	st, rec = af.admin("POST", "/api/v1/approvals/"+id+"/approve", alice, map[string]any{"comment": "ok"})
	if st != 200 || rec["decided_by"] != "approver:alice" || rec["state"] != "approved" {
		t.Fatalf("approve: %d %v", st, rec)
	}
	o := <-ch
	if o.err != nil || o.res.Content[0].(*mcp.TextContent).Text != "echo:hello" {
		t.Fatalf("held call result: %+v %v", o.res, o.err)
	}
	if _, rec = af.admin("GET", "/api/v1/approvals/"+id, alice, nil); rec["state"] != "consumed" {
		t.Fatalf("not consumed: %v", rec)
	}

	// Replay: the identical call does not reuse the consumed approval; it
	// is held for a new one, which is then denied.
	ch = callAsync("hello")
	var replayID string
	for _, it := range af.pending(1) {
		if idOf(it) != id {
			replayID = idOf(it)
		}
	}
	if replayID == "" {
		t.Fatal("replay did not create a new approval")
	}
	if st, _ := af.admin("POST", "/api/v1/approvals/"+replayID+"/deny", af.operator, map[string]any{}); st != 200 {
		t.Fatalf("deny: %d", st)
	}
	o = <-ch
	we, data := rpcErr(t, o.err)
	if we.Code != edge.CodePolicyDenied || data["reasonCode"] != "APPROVAL_DENIED" || data["message"] != "A person reviewing this call denied it." || data["approvalId"] != replayID ||
		we.Message != "approval denied: A person reviewing this call denied it." {
		t.Fatalf("denial: %+v %v", we, data)
	}
	corr := data["correlationId"]
	for _, e := range af.observed() {
		if e.CorrelationID == corr && e.Phase == audit.PhaseDispatched {
			t.Fatal("denied call was dispatched")
		}
	}
	// A decided approval cannot be decided again.
	if st, body := af.admin("POST", "/api/v1/approvals/"+replayID+"/approve", alice, map[string]any{}); st != 409 || body["state"] != "denied" {
		t.Fatalf("second decision: %d %v", st, body)
	}
	// Evidence for request, approve, deny and consume. Observers receive
	// committed events from a queue of their own, so the last ones may
	// still be on their way.
	outcomes := map[string]bool{}
	missing := func() string {
		clear(outcomes)
		for _, e := range af.observed() {
			if e.Class == "approval" && e.Origin == "E-07" {
				outcomes[e.Outcome] = true
			}
		}
		for _, want := range []string{"requested", "approved", "denied", "consumed"} {
			if !outcomes[want] {
				return want
			}
		}
		return ""
	}
	for deadline := time.Now().Add(10 * time.Second); missing() != ""; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no %s evidence: %v", missing(), outcomes)
		}
	}

	// FR-3.16: the creating session sees the state; another session gets
	// 404; no token gets 401.
	req, _ := http.NewRequest("GET", af.base+"/smcp/v1/approvals/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	r, body := af.do(req)
	if r.StatusCode != 200 || !strings.Contains(string(body), `"state":"consumed"`) {
		t.Fatalf("status query: %d %s", r.StatusCode, body)
	}
	other, _, _ := af.oauthLogin("")
	req.Header.Set("Authorization", "Bearer "+other)
	if r, _ := af.do(req); r.StatusCode != 404 {
		t.Fatalf("other session: %d", r.StatusCode)
	}
	req.Header.Del("Authorization")
	if r, _ := af.do(req); r.StatusCode != 401 {
		t.Fatalf("no token: %d", r.StatusCode)
	}
}

func TestApprovalRoles(t *testing.T) {
	// The CLI half of FR-3.24, with the Auditor refusal, is
	// cmd/smcpctl.TestApprovalsCLI; this covers the control API roles.
	reqtest.Partial(t, "FR-3.24")
	af := startApprovals(t, "0s", "5m")
	// A Session Approver account cannot sign in for tool-call approvals,
	// and neither can the administrator password.
	for _, cred := range [][2]string{{"approver", approverPassword}, {"admin", "admin password 12"}, {"alice", "wrong password 1"}} {
		if st, _ := af.admin("POST", "/api/v1/approvals/login", "", map[string]any{"username": cred[0], "password": cred[1]}); st != 401 {
			t.Fatalf("%s signed in as Approver: %d", cred[0], st)
		}
	}
	alice := af.approverToken()
	// The Approver role reaches the approval routes only.
	if st, _ := af.admin("GET", "/api/v1/approvals", alice, nil); st != 200 {
		t.Fatalf("approver list: %d", st)
	}
	// Every role may read health (Appendix C, "View health and status").
	if st, _ := af.admin("GET", "/admin/v1/health", alice, nil); st != 200 {
		t.Fatalf("approver health: %d", st)
	}
	for _, p := range [][2]string{{"POST", "/admin/v1/stop"}, {"POST", "/admin/v1/resume"}, {"POST", "/admin/v1/policy/reload"}} {
		var body any
		if p[0] == "POST" {
			body = map[string]any{}
		}
		if st, b := af.admin(p[0], p[1], alice, body); st != 403 {
			t.Fatalf("approver reached %s: %d %v", p[1], st, b)
		}
	}
	if af.app.Gateway.Stopped() {
		t.Fatal("approver stopped the Gateway")
	}
	// The administrator reaches the approval routes; a harness token does
	// not.
	if st, _ := af.admin("GET", "/api/v1/approvals?state=all", af.operator, nil); st != 200 {
		t.Fatal(st)
	}
	access, _, _ := af.oauthLogin("")
	if st, _ := af.admin("GET", "/api/v1/approvals", access, nil); st != 401 {
		t.Fatalf("harness token on the control API: %d", st)
	}
	if st, _ := af.admin("POST", "/api/v1/approvals/logout", alice, map[string]any{}); st != 204 {
		t.Fatal(st)
	}
	if st, _ := af.admin("GET", "/api/v1/approvals", alice, nil); st != 401 {
		t.Fatalf("token valid after logout: %d", st)
	}
	if st, _ := af.admin("GET", "/api/v1/approvals?state=bogus", af.operator, nil); st != 400 {
		t.Fatal(st)
	}
	if st, _ := af.admin("GET", "/api/v1/approvals/00000000-0000-0000-0000-000000000000", af.operator, nil); st != 404 {
		t.Fatal(st)
	}
	// The legacy /admin/v1/approvals list reports the running service.
	if st, body := af.admin("GET", "/admin/v1/approvals", af.operator, nil); st != 200 || body["service"] != "running" {
		t.Fatalf("%d %v", st, body)
	}
}

// sseCall posts a legacy-era tools/call and returns the response's content
// type and its lines with arrival times.
type sseLine struct {
	at   time.Time
	text string
}

func (af *approvalFixture) rawCall(access, text string) (string, []sseLine) {
	af.t.Helper()
	return af.rawCallMeta(access, text, "")
}

// rawCallMeta is rawCall with a params._meta object (JSON) when meta is not empty.
func (af *approvalFixture) rawCallMeta(access, text, meta string) (string, []sseLine) {
	af.t.Helper()
	m := ""
	if meta != "" {
		m = `,"_meta":` + meta
	}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"` + text + `"}` + m + `}}`
	req, _ := http.NewRequest("POST", af.cfg.ResourceURI(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	r, err := af.client.Do(req)
	if err != nil {
		af.t.Fatal(err)
	}
	defer r.Body.Close()
	var lines []sseLine
	sc := bufio.NewScanner(r.Body)
	for sc.Scan() {
		lines = append(lines, sseLine{time.Now(), sc.Text()})
	}
	return r.Header.Get("Content-Type"), lines
}

func TestApprovalHoldBoundSSEKeepAliveRetryAndExpiry(t *testing.T) {
	// FR-3.19: both keep-alive forms over a 1 s hold bound at the 100 ms
	// interval: SSE comment lines without a progress token (first) and
	// notifications/progress with one (at the end), each with no response
	// before the bound.
	reqtest.Verifies(t, "FR-3.22", "FR-3.15", "FR-3.19")
	reqtest.Partial(t, "FR-1.51")
	af := startApprovals(t, "1s", "3s")
	access, _, _ := af.oauthLogin("")

	// Without a progress token the held call is an event stream with SSE
	// comment keep-alives, ending at the hold bound with -31002.
	start := time.Now()
	ct, lines := af.rawCall(access, "sse")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type %q", ct)
	}
	var comments int
	var final string
	// Keep-alives stop at the bound: none follows the final -31002 event.
	// The order of lines in the stream is checked rather than wall-clock
	// time since the request, which under load includes request latency.
	for _, l := range lines {
		if strings.HasPrefix(l.text, ": keep-alive") {
			comments++
			if final != "" {
				t.Fatalf("keep-alive after the bound's final event, %v after the start", l.at.Sub(start))
			}
		}
		if strings.HasPrefix(l.text, "data: ") {
			final = l.text
		}
	}
	if comments < 5 || comments > 15 || time.Since(start) < time.Second {
		t.Fatalf("%d keep-alives over %v", comments, time.Since(start))
	}
	items := af.pending(1)
	id := idOf(items[0])
	url := af.cfg.AdminURL() + "/approvals/" + id
	for _, want := range []string{`"code":-31002`, `"reasonCode":"APPROVAL_REQUIRED"`, `"approvalId":"` + id + `"`, `"expiresAt":"`, `"approvalUrl":"` + url + `"`,
		`"message":"This call needs approval. Open ` + url + ` to approve it, then run the same request again."`,
		// error.message carries the same text, because Claude Code shows only error.message (FR-3.25).
		`"message":"approval required: This call needs approval. Open ` + url + ` to approve it, then run the same request again."`} {
		if !strings.Contains(final, want) {
			t.Fatalf("-31002 lacks %s: %s", want, final)
		}
	}
	// The approval stays pending after the bound; approve it, and the
	// identical retry consumes it. It is not held, so it answers in JSON.
	if st, _ := af.admin("POST", "/api/v1/approvals/"+id+"/approve", af.operator, map[string]any{}); st != 200 {
		t.Fatal(st)
	}
	ct, lines = af.rawCall(access, "sse")
	if !strings.HasPrefix(ct, "application/json") || len(lines) != 1 || !strings.Contains(lines[0].text, "echo:sse") {
		t.Fatalf("retry: %q %v", ct, lines)
	}
	if _, rec := af.admin("GET", "/api/v1/approvals/"+id, af.operator, nil); rec["state"] != "consumed" {
		t.Fatalf("%v", rec)
	}

	// CP-17 expiry: an approval left pending past its lifetime expires and
	// can no longer be approved; the retry asks for a new approval.
	af.rawCall(access, "late")
	var lateID string
	for _, it := range af.pending(1) {
		lateID = idOf(it)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, rec := af.admin("GET", "/api/v1/approvals/"+lateID, af.operator, nil)
		if rec["state"] == "expired" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not expired: %v", rec)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if st, body := af.admin("POST", "/api/v1/approvals/"+lateID+"/approve", af.operator, map[string]any{}); st != 409 || body["state"] != "expired" {
		t.Fatalf("expired approval approved: %d %v", st, body)
	}
	_, lines = af.rawCall(access, "late")
	newID := idOf(af.pending(1)[0])
	var all strings.Builder
	for _, l := range lines {
		all.WriteString(l.text + "\n")
	}
	if newID == lateID || !strings.Contains(all.String(), `"approvalId":"`+newID+`"`) {
		t.Fatalf("retry after expiry reused %s: %s", lateID, all.String())
	}
	// The observer's queue may still hold the event.
	expired := func() bool {
		for _, e := range af.observed() {
			if d, ok := e.Detail.(map[string]any); ok && e.Class == "approval" && e.Outcome == "expired" && d["approval_id"] == lateID {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(10 * time.Second); !expired(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no expiry evidence")
		}
	}

	// With a progress token the keep-alives are notifications/progress for
	// that token, and the only response is the -31002 at the bound.
	start = time.Now()
	ct, lines = af.rawCallMeta(access, "progress", `{"progressToken":"pt-19"}`)
	if !strings.HasPrefix(ct, "text/event-stream") || time.Since(start) < time.Second {
		t.Fatalf("content type %q after %v", ct, time.Since(start))
	}
	var progress, responses int
	final = ""
	for _, l := range lines {
		if !strings.HasPrefix(l.text, "data: ") {
			continue
		}
		switch {
		case strings.Contains(l.text, `"method":"notifications/progress"`):
			if !strings.Contains(l.text, `"progressToken":"pt-19"`) || final != "" {
				t.Fatalf("progress keep-alive %s (after the response: %v)", l.text, final != "")
			}
			progress++
		case strings.Contains(l.text, `"id":7`):
			responses++
			final = l.text
		}
	}
	if progress < 5 || progress > 15 || responses != 1 || !strings.Contains(final, `"code":-31002`) {
		t.Fatalf("%d progress keep-alives, %d responses, final %s", progress, responses, final)
	}
}
