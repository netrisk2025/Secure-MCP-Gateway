package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleauth"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// approvalGateway is a Gateway run in process with the Approval Service
// and the console sign-in service (consoleauth), as cmd/smcpd wires them.
type approvalGateway struct {
	cfgPath string
	cfg     *config.Config
	svc     *approval.Service
	alicePW string // password file of the Approver account alice
	audPW   string // password file of the Auditor console account aud

	mu     sync.Mutex
	events []audit.Event
}

func (g *approvalGateway) Observe(e audit.Event) {
	g.mu.Lock()
	g.events = append(g.events, e)
	g.mu.Unlock()
}

// approvalEvent waits for the E-07 evidence event of approval id with the
// given outcome and returns it.
func (g *approvalGateway) approvalEvent(t *testing.T, id, outcome string) audit.Event {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		g.mu.Lock()
		for _, e := range g.events {
			if e.Class == "approval" && e.Origin == "E-07" && e.Outcome == outcome && detail(e)["approval_id"] == id {
				g.mu.Unlock()
				return e
			}
		}
		g.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no %s evidence for approval %s", outcome, id)
		}
	}
}

// startApprovalGateway runs a Gateway in process with the Approval
// Service, the console sign-in service with an Auditor account, and an
// evidence observer.
func startApprovalGateway(t *testing.T) *approvalGateway {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	hash := func(pw string) string {
		h, err := keys.HashPassword(pw)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	pol := `{"revision":"r1","framework_profiles":{"dev":{"templates":["ro"],"default_template":"ro"}},"templates":{"ro":{"rules":[]}}}`
	writeFile(t, dir, "policy.json", pol)
	cfgPath := writeFile(t, dir, "smcp.toml", fmt.Sprintf(`
[listener]
address = "127.0.0.1:%s"
[admin_listener]
address = "127.0.0.1:%s"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[[approver]]
username = "sessionapprover"
password_hash = %q
[approvals]
notify = "off"
[[approvals.account]]
username = "alice"
password_hash = %q
[[console.account]]
username = "aud"
password_hash = %q
role = "auditor"
[policy]
file = "policy.json"
`, freePort(t), freePort(t), state, hash("admin password 12"), hash("session approver 1"), hash("alice password 12"), hash("auditor password 12")))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approval.New(approval.Options{Config: cfg, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), Approver: svc, Approvals: svc})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	svc.Start(ctx, a.Evidence, a.Admin, a.Gateway)
	consoleauth.New(consoleauth.Options{Config: cfg, Evidence: a.Evidence, Log: diag.Discard()}).Register(a.Admin)
	g := &approvalGateway{cfgPath: cfgPath, cfg: cfg, svc: svc}
	a.Evidence.AddObserver("approvals-cli-test", g, 0)
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done; a.Close(); svc.Close() })
	g.alicePW = writeFile(t, dir, "alice.pw", "alice password 12\n")
	g.audPW = writeFile(t, dir, "aud.pw", "auditor password 12\n")
	return g
}

func heldCall(svc *approval.Service, text string) <-chan pipeline.ApprovalResult {
	ch := make(chan pipeline.ApprovalResult, 1)
	// The hold outlasts the CLI steps that decide the approval, each of
	// which signs in (password hashing, slow under the race detector).
	go func() {
		c := pipeline.Call{CorrelationID: "corr-" + text, SessionID: "s1", PrincipalID: "cc", Server: "fs", Tool: "write", PublicName: "fs_write",
			ServerRevision: "sr1", ToolRevision: "tr1", PolicyRevision: "r1", DecisiveRules: []string{"rule-w"}}
		r, _ := svc.Request(context.Background(), pipeline.ApprovalRequest{Call: c, Arguments: json.RawMessage(`{"text":"` + text + `"}`), Hold: 2 * time.Minute})
		ch <- r
	}()
	return ch
}

func waitPending(t *testing.T, svc *approval.Service, n int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l := svc.List(approval.StatePending); len(l) >= n {
			return l[0].ID
		}
		if time.Now().After(deadline) {
			t.Fatal("no pending approval")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// TestApprovalsCLI is FR-3.24's verification: held calls are approved
// (as the Approver alice) and denied (as the Administrator, with the
// operator token) with the CLI; the evidence is printed before each
// decision takes effect, each decision is recorded with the approver's
// identity in the approval record and in the E-07 evidence event, and an
// Auditor account is refused by the CLI and, with its own console token,
// by the approval routes.
func TestApprovalsCLI(t *testing.T) {
	reqtest.Verifies(t, "FR-3.24")
	reqtest.Partial(t, "FR-3.18", "FR-3.23")
	gw := startApprovalGateway(t)
	cfgPath, svc, alicePW := gw.cfgPath, gw.svc, gw.alicePW
	cli := func(stdin string, args ...string) (string, error) {
		var out bytes.Buffer
		err := approvalsCmd(args, strings.NewReader(stdin), &out)
		return out.String(), err
	}

	// watch prints a new approval as it is requested.
	watchOut := &syncBuf{}
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- approvalsCmd([]string{"watch", "--config", cfgPath, "--user", "alice", "--password-file", alicePW, "--max-events", "1"}, strings.NewReader(""), watchOut)
	}()
	// Signing in hashes the password, which is slow under the race
	// detector on a loaded machine; the 2 s bound below starts once the
	// watch is running.
	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(watchOut.String(), "watching") {
		select {
		case err := <-watchDone:
			t.Fatalf("watch ended before it started: %v %s", err, watchOut.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("watch did not start: %s", watchOut.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	created := time.Now()
	ch := heldCall(svc, "one")
	id := waitPending(t, svc, 1)
	select {
	case err := <-watchDone:
		if err != nil || !strings.Contains(watchOut.String(), "requested "+id+" fs_write on fs") {
			t.Fatalf("watch: %v %s", err, watchOut.String())
		}
		if time.Since(created) > 2*time.Second {
			t.Fatal("watch notice later than 2 s")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("watch printed nothing: %s", watchOut.String())
	}

	// list (operator token) and show (Approver).
	out, err := cli("", "--config", cfgPath)
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "fs_write") || !strings.Contains(out, "pending") {
		t.Fatalf("list: %v %s", err, out)
	}
	out, err = cli("", "show", id, "--config", cfgPath, "--user", "alice", "--password-file", alicePW)
	for _, want := range []string{"fs_write", "sr1", "tr1", "rule-w", `"text": "one"`, "sha256:", "/approvals/" + id} {
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("show lacks %q: %v %s", want, err, out)
		}
	}
	// approve shows the evidence and asks; "n" changes nothing.
	out, err = cli("n\n", "approve", id, "--config", cfgPath, "--user", "alice", "--password-file", alicePW)
	if err == nil || !strings.Contains(out, `"text": "one"`) || !strings.Contains(out, "Approve this call? [y/N]") {
		t.Fatalf("unconfirmed approve: %v %s", err, out)
	}
	if r, _ := svc.Get(id); r.State != approval.StatePending {
		t.Fatalf("approved without confirmation: %+v", r)
	}
	out, err = cli("y\n", "approve", id, "--config", cfgPath, "--user", "alice", "--password-file", alicePW, "--comment", "checked")
	if err != nil || !strings.Contains(out, "approved "+id+" by approver:alice") {
		t.Fatalf("approve: %v %s", err, out)
	}
	if r := <-ch; r.Outcome != pipeline.Approved || r.Approver != "approver:alice" {
		t.Fatalf("held call: %+v", r)
	}
	if r, _ := svc.Get(id); r.State != approval.StateConsumed || r.DecidedBy != "approver:alice" || r.Comment != "checked" {
		t.Fatalf("%+v", r)
	}
	if e := gw.approvalEvent(t, id, "approved"); detail(e)["approver"] != "approver:alice" || detail(e)["comment"] != "checked" {
		t.Fatalf("approve evidence: %+v", e)
	}

	// deny with --yes, as the administrator (operator token).
	ch = heldCall(svc, "two")
	id2 := waitPending(t, svc, 1)
	out, err = cli("", "deny", id2, "--yes", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "denied "+id2+" by operator-token") || !strings.Contains(out, `"text": "two"`) {
		t.Fatalf("deny: %v %s", err, out)
	}
	if r := <-ch; r.Outcome != pipeline.Denied {
		t.Fatalf("%+v", r)
	}
	if r, _ := svc.Get(id2); r.State != approval.StateDenied || r.DecidedBy != "operator-token" {
		t.Fatalf("denied record: %+v", r)
	}
	if e := gw.approvalEvent(t, id2, "denied"); detail(e)["approver"] != "operator-token" {
		t.Fatalf("deny evidence: %+v", e)
	}
	// Deciding again fails; list --state all --json shows both.
	if out, err := cli("", "approve", id2, "--yes", "--config", cfgPath); err == nil || !strings.Contains(out, "denied") {
		t.Fatalf("second decision: %v %s", err, out)
	}
	out, err = cli("", "list", "--state", "all", "--json", "--config", cfgPath)
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, id2) {
		t.Fatalf("list all: %v %s", err, out)
	}

	// An Auditor account is refused: the CLI cannot sign in with it, and
	// the Auditor's own console token is refused by every approval route
	// the CLI uses, so a held call cannot be decided with it. (Every
	// subcommand signs in the same way; two attempts stay under the
	// sign-in lockout that the Session Approver attempt below adds to.)
	ch = heldCall(svc, "three")
	id3 := waitPending(t, svc, 1)
	for _, sub := range [][]string{{"approve", id3, "--yes"}, {"deny", id3, "--yes"}} {
		args := append(append([]string{}, sub...), "--config", cfgPath, "--user", "aud", "--password-file", gw.audPW)
		if out, err := cli("", args...); err == nil || !strings.Contains(out+err.Error(), "sign-in failed") {
			t.Fatalf("auditor %s: %v %s", sub[0], err, out)
		}
	}
	audTok := consoleToken(t, gw.cfg, "aud", "auditor password 12", "auditor")
	for _, r := range [][2]string{{"GET", "/api/v1/approvals"}, {"GET", "/api/v1/approvals/" + id3}, {"GET", "/api/v1/approvals/watch"},
		{"POST", "/api/v1/approvals/" + id3 + "/approve"}, {"POST", "/api/v1/approvals/" + id3 + "/deny"}} {
		if st, body := rawAdmin(t, gw.cfg, audTok, r[0], r[1]); st != http.StatusForbidden || !strings.Contains(body, "role_refused") {
			t.Fatalf("auditor %s %s: %d %s", r[0], r[1], st, body)
		}
	}
	if r, _ := svc.Get(id3); r.State != approval.StatePending {
		t.Fatalf("auditor decided the call: %+v", r)
	}
	if _, err := cli("", "deny", id3, "--yes", "--config", cfgPath); err != nil {
		t.Fatal(err)
	}
	<-ch

	// A Session Approver account and a wrong password are refused.
	spw := writeFile(t, t.TempDir(), "s.pw", "session approver 1")
	if out, err := cli("", "list", "--config", cfgPath, "--user", "sessionapprover", "--password-file", spw); err == nil || !strings.Contains(out+err.Error(), "sign-in failed") {
		t.Fatalf("session approver signed in: %v %s", err, out)
	}
	if _, err := cli("", "show", "--config", cfgPath); err == nil {
		t.Fatal("show without an ID")
	}
	if _, err := cli("", "bogus", "--config", cfgPath); err == nil {
		t.Fatal("unknown subcommand")
	}
	if out, err := cli("", "help"); err != nil || !strings.Contains(out, "approve <id>") {
		t.Fatalf("%v %s", err, out)
	}
	_ = os.Remove(spw)
}

// consoleToken signs in a console account (internal/consoleauth) and
// returns its bearer token.
func consoleToken(t *testing.T, cfg *config.Config, user, password, role string) string {
	t.Helper()
	c, err := newAdminClient(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	res, st, err := c.do("POST", "/api/v1/console/login", map[string]any{"username": user, "password": password, "role": role})
	tok, _ := res["token"].(string)
	if err != nil || st != http.StatusOK || tok == "" || res["role"] != role {
		t.Fatalf("console login %s: %d %v %v", user, st, res, err)
	}
	return tok
}

// rawAdmin sends one control API request with token and returns the status
// and the start of the body (a stream is not read to its end).
func rawAdmin(t *testing.T, cfg *config.Config, token, method, path string) (int, string) {
	t.Helper()
	c, err := newAdminClient(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req, _ := http.NewRequest(method, c.base+path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(raw)
}

// detail returns an evidence event's detail map.
func detail(e audit.Event) map[string]any { d, _ := e.Detail.(map[string]any); return d }
