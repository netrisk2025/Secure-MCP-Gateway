package e2e

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/principals"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// cp16 is the CP-16 revocation propagation bound.
const cp16 = 2 * time.Second

// withPrincipals attaches the principal directory and its control API
// routes to a running fixture, as cmd/smcpd does.
func (f *fixture) withPrincipals() {
	f.t.Helper()
	d, err := principals.Open(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.cfg.SetDirectory(d)
	(&principals.Service{Dir: d, Sessions: f.app.Store, Snapshot: f.app.Decider.Snapshot, Evidence: f.app.Evidence, Log: diag.Discard(),
		Gate: f.app.Gateway.Serialize}).Register(f.app.Admin)
}

// issueClient creates a public OAuth client credential for a principal
// through the control API.
func (f *fixture) issueClient(principal string) string {
	f.t.Helper()
	code, out := f.admin("POST", "/api/v1/principals/"+principal+"/credentials", f.operator,
		map[string]any{"redirect_uris": []string{"http://localhost:51234/callback"}, "confidential": false})
	id, _ := out["client_id"].(string)
	if code != 201 || id == "" {
		f.t.Fatalf("issue credential for %s: %d %v", principal, code, out)
	}
	return id
}

// loadGen keeps calling t_echo from several goroutines until stopped.
type loadGen struct {
	stop chan struct{}
	wg   sync.WaitGroup
	ok   atomic.Int64
}

func startLoad(clients ...*mcp.ClientSession) *loadGen {
	g := &loadGen{stop: make(chan struct{})}
	for _, cs := range clients {
		for i := 0; i < 2; i++ {
			g.wg.Add(1)
			go func(cs *mcp.ClientSession) {
				defer g.wg.Done()
				for {
					select {
					case <-g.stop:
						return
					default:
					}
					if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "load"}}); err == nil && !res.IsError {
						g.ok.Add(1)
					}
				}
			}(cs)
		}
	}
	return g
}

func (g *loadGen) end() { close(g.stop); g.wg.Wait() }

// closeIdle drops the client's idle connections. Under load the HTTP client
// can dial connections it never uses; the server counts such a connection
// as active for its first five seconds, which would hold up the fixture's
// graceful shutdown.
func (f *fixture) closeIdle() {
	if tr, ok := f.client.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// authorizedAfter returns the launch authorizations (committed decision
// intents) recorded for the session later than t.
func (f *fixture) authorizedAfter(sessionID string, t time.Time) []audit.Event {
	f.t.Helper()
	evs, err := audit.ReadEvents(filepath.Join(f.stateDir, "journal"))
	if err != nil {
		f.t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range evs {
		if e.Class != "decision" || e.Phase != audit.PhaseAuthorized || e.SessionID != sessionID {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.Time)
		if err == nil && at.After(t) {
			out = append(out, e)
		}
	}
	return out
}

// TestRevocationUnderLoad: while sessions of two principals call tools
// continuously, revoking one principal's credential stops launch
// authorizations for its session within CP-16 and leaves the other
// principal's session working (SR-2.2-1); suspending a principal and
// terminating a session do the same (SR-2.4-1).
func TestRevocationUnderLoad(t *testing.T) {
	reqtest.Verifies(t, "SR-2.4-1", "SR-2.2-1")
	f := start(t, "tool_concurrency_total = 4\ntool_concurrency_per_principal = 2\ntool_queue = 8\nprincipal_calls_per_minute = 100000")
	f.withPrincipals()
	if _, err := consoleapi.Attach(f.app, diag.Discard()); err != nil { // session termination route
		t.Fatal(err)
	}
	if code, out := f.admin("POST", "/api/v1/principals", f.operator, map[string]any{"id": "second", "framework": "codex", "display_name": "Second", "profile": "dev"}); code != 201 {
		t.Fatalf("create principal: %d %v", code, out)
	}
	ccClient, secondClient := f.issueClient("cc"), f.issueClient("second")
	accA, _, bodyA := f.oauthLoginClient("", ccClient)
	accB, _, bodyB := f.oauthLoginClient("", secondClient)
	accC, _, bodyC := f.oauthLoginClient("", ccClient)
	sessA, sessB, sessC := bodyA["session_id"].(string), bodyB["session_id"].(string), bodyC["session_id"].(string)
	csA, csB, csC := f.mcpClient(accA), f.mcpClient(accB), f.mcpClient(accC)

	// 1. Revoke the second principal's credential under load.
	load := startLoad(csA, csB, csC)
	time.Sleep(300 * time.Millisecond)
	revokedAt := time.Now()
	if code, out := f.admin("POST", "/api/v1/credentials/"+secondClient+"/revoke", f.operator, map[string]any{"reason": "test"}); code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	before := load.ok.Load()
	time.Sleep(cp16 + 500*time.Millisecond)
	if late := f.authorizedAfter(sessB, revokedAt.Add(cp16)); len(late) != 0 {
		t.Fatalf("revoked credential: %d launch authorizations after CP-16", len(late))
	}
	if len(f.authorizedAfter(sessA, revokedAt.Add(cp16))) == 0 || load.ok.Load() == before {
		t.Fatal("the other principal's session stopped working after the revocation")
	}

	// 2. Terminate one session of cc under load; its other session works.
	terminatedAt := time.Now()
	if code, out := f.admin("POST", "/api/v1/sessions/"+sessC+"/terminate", f.operator, map[string]any{}); code != 200 {
		t.Fatalf("terminate: %d %v", code, out)
	}
	time.Sleep(cp16 + 500*time.Millisecond)
	if late := f.authorizedAfter(sessC, terminatedAt.Add(cp16)); len(late) != 0 {
		t.Fatalf("terminated session: %d launch authorizations after CP-16", len(late))
	}
	if len(f.authorizedAfter(sessA, terminatedAt.Add(cp16))) == 0 {
		t.Fatal("the principal's other session stopped working")
	}

	// 3. Suspend the principal under load.
	suspendedAt := time.Now()
	if code, out := f.admin("POST", "/api/v1/principals/cc/suspend", f.operator, map[string]any{"reason": "test"}); code != 200 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	time.Sleep(cp16 + 500*time.Millisecond)
	load.end()
	f.closeIdle()
	if late := f.authorizedAfter(sessA, suspendedAt.Add(cp16)); len(late) != 0 {
		t.Fatalf("suspended principal: %d launch authorizations after CP-16", len(late))
	}
}

// TestPolicyRollbackKeepsRevocations: rolling the policy back to a revision
// published before a credential revocation, a principal suspension and a
// server suspension leaves all three in effect: they live outside the
// policy document (SR-7.9-1; the application rollback is AT-19).
func TestPolicyRollbackKeepsRevocations(t *testing.T) {
	reqtest.Partial(t, "SR-7.9-1")
	f := start(t, "")
	f.withPrincipals()
	if code, out := f.admin("POST", "/api/v1/principals", f.operator, map[string]any{"id": "second", "framework": "codex", "profile": "dev"}); code != 201 {
		t.Fatalf("create principal: %d %v", code, out)
	}
	revoked := f.issueClient("cc")
	acc, _, _ := f.oauthLoginClient("", revoked)
	cs := f.mcpClient(acc)
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err != nil {
		t.Fatal(err)
	}
	// r2 is published after r1; the revocations happen under r2.
	f.publish(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1))
	if code, _ := f.admin("POST", "/api/v1/credentials/"+revoked+"/revoke", f.operator, map[string]any{"reason": "test"}); code != 200 {
		t.Fatal("revoke failed")
	}
	if code, _ := f.admin("POST", "/api/v1/principals/second/suspend", f.operator, map[string]any{"reason": "test"}); code != 200 {
		t.Fatal("suspend principal failed")
	}
	if !f.app.Registry.Suspend("t", "test suspension") {
		t.Fatal("suspend server failed")
	}
	if st, rb := f.admin("POST", "/api/v1/policy/rollback", f.operator, map[string]any{"to": "r1", "revision": "r3"}); st != 201 {
		t.Fatalf("rollback: %d %v", st, rb)
	}
	if f.cfg.FindClient(revoked) != nil {
		t.Fatal("the revoked credential is back after the rollback")
	}
	if p := f.cfg.FindPrincipal("second"); p != nil && (p.Enabled == nil || *p.Enabled) {
		t.Fatal("the suspended principal is enabled after the rollback")
	}
	if f.app.Registry.Resolve("t_echo") != nil || f.app.Registry.Servers()["t"] != nil {
		t.Fatal("the suspended server is back after the rollback")
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err == nil {
		t.Fatal("the session of the revoked credential still calls tools")
	}
}

// TestStopUnderLoad: no launch authorization is issued later than one
// second after an emergency stop while calls arrive continuously
// (FR-11.10).
func TestStopUnderLoad(t *testing.T) {
	reqtest.Verifies(t, "FR-11.10")
	f := start(t, "tool_concurrency_total = 4\ntool_concurrency_per_principal = 4\ntool_queue = 8\nprincipal_calls_per_minute = 100000")
	acc, _, body := f.oauthLogin("")
	sess := body["session_id"].(string)
	cs1, cs2 := f.mcpClient(acc), f.mcpClient(acc)
	load := startLoad(cs1, cs2)
	time.Sleep(500 * time.Millisecond)
	if load.ok.Load() == 0 {
		t.Fatal("no call succeeded before the stop")
	}
	stoppedAt := time.Now()
	if code, out := f.admin("POST", "/admin/v1/stop", f.operator, map[string]any{"reason": "test"}); code != 200 {
		t.Fatalf("stop: %d %v", code, out)
	}
	time.Sleep(1500 * time.Millisecond)
	load.end()
	f.closeIdle()
	if late := f.authorizedAfter(sess, stoppedAt.Add(time.Second)); len(late) != 0 {
		t.Fatalf("%d launch authorizations more than 1 s after the stop", len(late))
	}
}
