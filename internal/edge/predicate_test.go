package edge

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const predicatePolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["p"], "default_template": "p"}},
  "templates": {"p": {"rules": [{"id": "say", "server": "t", "tools": ["echo"], "when": [{"arg": "text", "op": "in", "value": ["hello", "hi"]}]}]}}
}`

// TestPredicatesThroughGateway: the Gateway passes the call's arguments,
// route and prerequisites to the decision: a call whose argument satisfies
// the rule's predicate runs, one that does not is denied with NO_PERMIT and
// the failed predicate in its decision record (SR-1.7-1, SR-1.7-2, gateway
// part).
func TestPredicatesThroughGateway(t *testing.T) {
	reqtest.Partial(t, "SR-1.7-1", "SR-1.7-2")
	h := newHarness(t, harnessOpts{policy: predicatePolicy})
	_, tok := h.session("p")
	cs := h.client(tok)
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "hello"}}); err != nil || res.IsError {
		t.Fatalf("permitted argument: %v %v", res, err)
	}
	we, data := callErr(t, cs, "t_echo", map[string]any{"text": "rm -rf"})
	if we.Code != CodePolicyDenied || data["reasonCode"] != "NO_PERMIT" {
		t.Fatalf("%d %v", we.Code, data)
	}
	e := h.rec.find(func(e audit.Event) bool { return e.Class == "decision" && e.Phase == audit.PhaseDenied })
	if d, _ := e.Detail.(map[string]any); e == nil || d["failed_predicate"] != "in on text" {
		t.Fatalf("decision record %+v", e)
	}
}
