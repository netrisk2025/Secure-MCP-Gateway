package edge

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSessionRebindsOnActivation: a revision activated while a session is
// open governs that session's next request: the next decision records the
// new revision ID, and the session's catalog follows the new grants
// (FR-2.12).
func TestSessionRebindsOnActivation(t *testing.T) {
	reqtest.Verifies(t, "FR-2.12")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	cs := h.client(tok)
	call := func(name string) *audit.Event {
		t.Helper()
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"text": "x"}}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return h.rec.find(func(e audit.Event) bool { return e.Class == "decision" && e.Phase == audit.PhaseAuthorized })
	}
	if e := call("t_echo"); e == nil || e.PolicyRevision != "r1" {
		t.Fatalf("before activation: %+v", e)
	}
	next := strings.Replace(strings.Replace(edgePolicy, `"r1"`, `"r2"`, 1), `"tools": ["echo", "slow", "big"]`, `"tools": ["echo", "big"]`, 1)
	snap, err := policy.Compile([]byte(next))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.gw.ActivatePolicy("test", snap); err != nil {
		t.Fatal(err)
	}
	if e := call("t_echo"); e == nil || e.PolicyRevision != "r2" {
		t.Fatalf("first request after activation: %+v", e)
	}
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range lt.Tools {
		if tl.Name == "t_slow" {
			t.Fatal("the session kept a tool the new revision removed")
		}
	}
}
