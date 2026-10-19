package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestJournalUnwritableDuringTraffic is SR-1.2-2's test with the real
// Evidence Journal, together with edge.TestIntentCommitFailureJournalUnavailable
// (an injected flush failure of the decision intent):
//
//   - the graph mirror's database stops answering during traffic, first
//     hung and then failing, and dispatch continues;
//   - the journal directory is made unwritable during traffic; once the
//     journal cannot append (the next segment cannot be created), every
//     call is refused with -31004 and JOURNAL_UNAVAILABLE, the backend
//     receives no call after that, and every call the backend did receive
//     has its decision intent in the journal.
func TestJournalUnwritableDuringTraffic(t *testing.T) {
	reqtest.Verifies(t, "SR-1.2-2")
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	log := filepath.Join(t.TempDir(), "calls.log")
	f := startWith(t, "principal_calls_per_minute = 100000", fmt.Sprintf("SMCP_E2E_CALL_LOG = %q\n", log))
	fake := graph.NewFake()
	mirror, err := graph.New(graph.Options{Config: f.cfg, Log: diag.Discard(), Backend: fake})
	if err != nil {
		t.Fatal(err)
	}
	f.app.Evidence.AddObserver("graph", mirror, 0)
	mirror.Start(context.Background(), f.app.Evidence)
	t.Cleanup(func() { fake.Unblock(); mirror.Close() })

	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	n := 0
	call := func() (*jsonrpc.Error, error) {
		n++
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": fmt.Sprint("call-", n)}})
		var we *jsonrpc.Error
		if errors.As(err, &we) {
			return we, nil
		}
		if err == nil && res.IsError {
			return nil, fmt.Errorf("tool error %+v", res.Content)
		}
		return nil, err
	}
	mustServe := func(what string) {
		t.Helper()
		t0 := time.Now()
		if we, err := call(); we != nil || err != nil {
			t.Fatalf("%s: %v %v", what, we, err)
		}
		if d := time.Since(t0); d > 2*time.Second {
			t.Fatalf("%s took %v", what, d)
		}
	}
	for range 3 {
		mustServe("call with the graph database up")
	}
	fake.Block() // the database stops answering
	for range 3 {
		mustServe("call with the graph database hung")
	}
	fake.Unblock()
	fake.Fail(graph.ErrUnavailable) // and then refuses connections
	for range 3 {
		mustServe("call with the graph database down")
	}

	// The journal directory becomes unwritable during traffic.
	jdir := filepath.Join(f.stateDir, "journal")
	if err := os.Chmod(jdir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(jdir, 0o700) })
	var refused *jsonrpc.Error
	for i := 0; i < 1000 && refused == nil; i++ {
		we, err := call()
		if err != nil {
			t.Fatalf("call %d: %v", n, err)
		}
		refused = we
	}
	if refused == nil {
		t.Fatal("the journal kept appending in an unwritable directory")
	}
	if refused.Code != edge.CodeGatewayFailClosed && refused.Code != edge.CodeResponseWithheld || !strings.Contains(string(refused.Data), "JOURNAL_UNAVAILABLE") {
		t.Fatalf("first refusal: %d %s %s", refused.Code, refused.Message, refused.Data)
	}
	received := func() []string {
		raw, _ := os.ReadFile(log)
		return strings.Fields(string(raw))
	}
	before := len(received())
	// The endpoint now fails closed: the SDK client sees the refusal as a
	// transport error, a raw request shows its code and reason.
	for range 3 {
		if we, err := call(); err == nil && we == nil {
			t.Fatal("a call was served after the journal failed")
		}
	}
	status, _, body := f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"raw"},%s}}`, modernMeta),
		modernHeaders(access, "tools/call"))
	if status != 503 || !strings.Contains(body, fmt.Sprint(edge.CodeGatewayFailClosed)) || !strings.Contains(body, "JOURNAL_UNAVAILABLE") {
		t.Fatalf("raw call after the journal failed: %d %s", status, body)
	}
	if after := len(received()); after != before {
		t.Fatalf("the backend received %d calls after the journal failed", after-before)
	}

	// Every call the backend received has its decision intent in the
	// journal, ahead of its dispatch.
	if err := os.Chmod(jdir, 0o700); err != nil {
		t.Fatal(err)
	}
	evs, err := audit.ReadEvents(jdir)
	if err != nil {
		t.Fatal(err)
	}
	authorized, dispatched := map[string]bool{}, 0
	for _, e := range evs {
		switch {
		case e.Phase == audit.PhaseAuthorized:
			authorized[e.CorrelationID] = true
		case e.Phase == audit.PhaseDispatched:
			if !authorized[e.CorrelationID] {
				t.Fatalf("dispatch %s without an earlier decision intent", e.CorrelationID)
			}
			dispatched++
		}
	}
	if got := len(received()); got > len(authorized) || dispatched < got-1 {
		// The call that hit the failure may have been dispatched with its
		// intent committed and its dispatched or completed event lost.
		t.Fatalf("backend received %d calls; journal has %d intents and %d dispatches", got, len(authorized), dispatched)
	}
}
