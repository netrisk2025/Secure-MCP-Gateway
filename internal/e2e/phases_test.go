package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestCallPhasesForEachOutcome is FR-7.2: calls driven to each terminal
// outcome record the expected sequence of call phases in the journal:
// delivered, denied (refused before dispatch: the tool needs an approval
// and no approver is attached), filtered (a request filter blocked
// the arguments), failed (the backend answered with an error), withheld
// (the result exceeded the 64 KiB result bound) and indeterminate (the backend did
// not answer within the upstream timeout, so it may have acted). Together
// the sequences use every phase: requested, denied, authorized, dispatched,
// completed, failed, indeterminate, filtered, delivered and withheld.
func TestCallPhasesForEachOutcome(t *testing.T) {
	reqtest.Verifies(t, "FR-7.2")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	type outcome struct {
		name, tool string
		args       map[string]any
		want       string
	}
	cases := []outcome{
		{"delivered", "t_echo", map[string]any{"text": "hi"}, "requested,authorized,dispatched,completed,delivered"},
		{"denied", "t_write", map[string]any{}, "requested,denied"},
		{"filtered", "t_echo", map[string]any{"text": "key=" + "AKIA" + "IOSFODNN7EXAMPLE"}, "requested,filtered"},
		{"failed", "t_rpcerror", map[string]any{}, "requested,authorized,dispatched,failed"},
		{"withheld", "t_big", map[string]any{"kib": 128}, "requested,authorized,dispatched,withheld"},
		{"indeterminate", "t_slow", map[string]any{}, "requested,authorized,dispatched,indeterminate"},
	}
	for _, c := range cases {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
		if c.name == "delivered" {
			if err != nil || res.IsError {
				t.Fatalf("delivered call: %v %+v", err, res)
			}
		} else if err == nil && (res == nil || !res.IsError) {
			t.Fatalf("%s: call succeeded", c.name)
		}
	}
	// The journal holds each call's events in order; group them by
	// correlation ID and match each sequence to its tool.
	deadline := time.Now().Add(5 * time.Second)
	var evs []audit.Event
	for {
		var err error
		evs, err = audit.ReadEvents(filepath.Join(f.stateDir, "journal"))
		if err == nil && countPhase(evs, audit.PhaseIndeterminate) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("journal: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	byCorr := map[string][]string{}
	toolOf := map[string]string{}
	var order []string
	for _, e := range evs {
		if e.CorrelationID == "" || e.Phase == "" {
			continue
		}
		if _, seen := byCorr[e.CorrelationID]; !seen {
			order = append(order, e.CorrelationID)
		}
		if e.Class == "call" && e.Phase == audit.PhaseRequested {
			if d, ok := e.Detail.(map[string]any); ok {
				toolOf[e.CorrelationID], _ = d["public_name"].(string)
			}
		}
		byCorr[e.CorrelationID] = append(byCorr[e.CorrelationID], string(e.Phase))
	}
	seen := map[string]bool{}
	for i, c := range cases {
		if i >= len(order) {
			t.Fatalf("only %d calls in the journal", len(order))
		}
		corr := order[i]
		if toolOf[corr] != c.tool {
			t.Fatalf("%s: journal call %d is %s", c.name, i, toolOf[corr])
		}
		got := strings.Join(byCorr[corr], ",")
		if got != c.want {
			t.Errorf("%s: phases %s, want %s", c.name, got, c.want)
		}
		for _, p := range byCorr[corr] {
			seen[p] = true
		}
	}
	for _, p := range []string{"requested", "denied", "authorized", "dispatched", "completed", "failed", "indeterminate", "filtered", "delivered", "withheld"} {
		if !seen[p] {
			t.Errorf("phase %s never recorded", p)
		}
	}
}

func countPhase(evs []audit.Event, p audit.Phase) int {
	n := 0
	for _, e := range evs {
		if e.Phase == p {
			n++
		}
	}
	return n
}
