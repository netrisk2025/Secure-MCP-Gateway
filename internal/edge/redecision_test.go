package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// redactDestination is a request filter that, while on, replaces the
// destination "dest:evil" in the text argument (an action-defining
// argument) with a redaction marker.
type redactDestination struct{ on atomic.Bool }

func (*redactDestination) ID() string { return "redact-destination" }
func (f *redactDestination) FilterRequest(_ context.Context, _ *pipeline.Call, args json.RawMessage) (pipeline.RequestVerdict, error) {
	if !f.on.Load() || !strings.Contains(string(args), "dest:evil") {
		return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
	}
	return pipeline.RequestVerdict{Action: pipeline.Transform, Arguments: json.RawMessage(strings.ReplaceAll(string(args), "dest:evil", "dest:[REDACTED]")),
		ReasonCode: "DESTINATION_REDACTED"}, nil
}

// digestApprover approves a call only when a person approved its exact
// arguments before, as the Approval Service binds an approval to the
// canonical argument digest (SR-1.18-2).
type digestApprover struct {
	mu       sync.Mutex
	approved map[string]bool
	last     pipeline.ApprovalRequest
}

func argDigest(args json.RawMessage) string {
	c, _ := policy.Canonical(args)
	s := sha256.Sum256(c)
	return hex.EncodeToString(s[:])
}

func (a *digestApprover) Request(_ context.Context, r pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = r
	if a.approved[argDigest(r.Arguments)] {
		return pipeline.ApprovalResult{Outcome: pipeline.Approved, ApprovalID: "ap-" + argDigest(r.Arguments)[:8], Approver: "person"}, nil
	}
	return pipeline.ApprovalResult{Outcome: pipeline.Pending, ReasonCode: pipeline.ReasonApprovalRequired}, nil
}

func (a *digestApprover) approveLast() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.approved[argDigest(a.last.Arguments)] = true
}

func redecisionHarness(t *testing.T, ap pipeline.Approver) (*harness, *redactDestination) {
	t.Helper()
	rf := &redactDestination{}
	f := pipeline.NewFilters()
	if err := f.RegisterRequest(rf, pipeline.Registration{Order: 10, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	return newHarness(t, harnessOpts{filters: f, approver: ap, limits: "principal_calls_per_minute = 1000"}), rf
}

func authorizedDecision(t *testing.T, h *harness, res *mcp.CallToolResult) *audit.Event {
	t.Helper()
	raw, _ := json.Marshal(res.Meta["local.smcpgw/provenance"])
	var prov struct {
		DecisionID string `json:"decisionId"`
	}
	_ = json.Unmarshal(raw, &prov)
	e := h.rec.find(func(e audit.Event) bool {
		return e.Class == "decision" && e.Phase == audit.PhaseAuthorized && e.DecisionID == prov.DecisionID
	})
	if e == nil {
		t.Fatalf("no authorized decision event for %s", prov.DecisionID)
	}
	return e
}

// TestRedecisionAfterTransformation: when a request filter transforms the
// arguments, the call gets a second decision before launch; the authorized
// decision record names the first decision, and the launch is bound to the
// second. An untransformed call has one decision (SR-5.12-1).
func TestRedecisionAfterTransformation(t *testing.T) {
	reqtest.Verifies(t, "SR-5.12-1")
	h, rf := redecisionHarness(t, nil)
	rf.on.Store(true)
	_, tok := h.session("ro")
	cs := h.client(tok)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "send to dest:evil"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content[0].(*mcp.TextContent).Text; got != "echo:send to dest:[REDACTED]" {
		t.Fatalf("backend saw %q", got)
	}
	e := authorizedDecision(t, h, res)
	d, _ := e.Detail.(map[string]any)
	first, _ := d["superseded_decision_id"].(string)
	if first == "" || first == e.DecisionID || d["redecision_reason"] != "arguments_transformed" {
		t.Fatalf("decision record %+v", d)
	}
	rules, _ := d["decisive_rules"].([]string)
	if len(rules) != 1 || rules[0] != "r1/ro/ro-t" {
		t.Fatalf("decisive rule revisions %v", d["decisive_rules"])
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "send to bob"}})
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := authorizedDecision(t, h, res).Detail.(map[string]any); d["superseded_decision_id"] != nil {
		t.Fatalf("untransformed call decided twice: %+v", d)
	}
}

// TestNewToolsDenied: grants name tools of a server by exact name, so the
// tools a newly enabled revision adds ("slow" and "big" next to the
// granted "echo") are absent from the catalog and refused until a
// published grant names them (SR-3.10-1).
func TestNewToolsDenied(t *testing.T) {
	reqtest.Verifies(t, "SR-3.10-1")
	h := newHarness(t, harnessOpts{policy: onePolicy})
	_, tok := h.session("one")
	cs := h.client(tok)
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(lt.Tools) != 1 || lt.Tools[0].Name != "t_echo" {
		t.Fatalf("catalog %v %v", lt, err)
	}
	for _, name := range []string{"t_slow", "t_big"} {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{}}); err == nil {
			t.Fatalf("%s ran without a grant", name)
		}
		if h.rec.find(func(e audit.Event) bool {
			return e.Phase == audit.PhaseDispatched && strings.HasSuffix(e.ToolRevision, "/"+strings.TrimPrefix(name, "t_"))
		}) != nil {
			t.Fatalf("%s was dispatched", name)
		}
	}
	// Publishing a grant for one of them makes it available.
	next := strings.Replace(strings.Replace(onePolicy, `"r1"`, `"r2"`, 1), `"tools": ["echo"]`, `"tools": ["echo", "slow"]`, 1)
	snap, err := policy.Compile([]byte(next))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.gw.ActivatePolicy("test", snap); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_slow", Arguments: map[string]any{"ms": 1}}); err != nil {
		t.Fatalf("granted tool: %v", err)
	}
}

// TestApprovalAfterTransformation: an approval granted for a call's
// arguments does not cover the same call once a request filter changes its
// destination; a new approval bound to the transformed arguments is
// required, and once approved those arguments run (SR-1.18-3).
func TestApprovalAfterTransformation(t *testing.T) {
	reqtest.Verifies(t, "SR-1.18-3")
	ap := &digestApprover{approved: map[string]bool{}}
	h, rf := redecisionHarness(t, ap)
	_, tok := h.session("ap")
	cs := h.client(tok)
	args := map[string]any{"text": "send to dest:evil"}
	// The person approves the call as sent.
	if we, data := callErr(t, cs, "t_echo", args); we.Code != CodeApprovalRequired {
		t.Fatalf("%d %v", we.Code, data)
	}
	ap.approveLast()
	// A redaction rule now changes the destination: the earlier approval
	// does not apply, and the request names the transformed arguments and
	// the second decision.
	rf.on.Store(true)
	we, data := callErr(t, cs, "t_echo", args)
	if we.Code != CodeApprovalRequired || data["reasonCode"] != pipeline.ReasonApprovalRequired {
		t.Fatalf("transformed call ran on the old approval: %d %v", we.Code, data)
	}
	if !strings.Contains(string(ap.last.Arguments), "dest:[REDACTED]") {
		t.Fatalf("approval requested for %s", ap.last.Arguments)
	}
	ev := h.rec.find(func(e audit.Event) bool { return e.Class == "approval" && e.CorrelationID == data["correlationId"] })
	if d, _ := ev.Detail.(map[string]any); ev == nil || d["superseded_decision_id"] == nil || ap.last.Call.DecisionID != ev.DecisionID {
		t.Fatalf("approval request not bound to the second decision: %+v", ev)
	}
	// Approving the transformed arguments lets the call run.
	ap.approveLast()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: args})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != "echo:send to dest:[REDACTED]" {
		t.Fatalf("%v %v", res, err)
	}
}
