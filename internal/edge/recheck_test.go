package edge

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// stateDirectory is a run-time directory whose principal suspension and
// credential revocation a test flips.
type stateDirectory struct {
	suspended, revoked atomic.Bool
}

func (*stateDirectory) Principal(string) (config.Principal, bool) { return config.Principal{}, false }
func (*stateDirectory) Client(string) (config.Client, bool)       { return config.Client{}, false }
func (d *stateDirectory) Suspended(id string) bool                { return id == "cc" && d.suspended.Load() }
func (d *stateDirectory) CredentialRevoked(id string) bool        { return id == "c" && d.revoked.Load() }

// betweenFilter runs act once, inside request inspection: after the
// decision permitted the call and before launch authorization.
type betweenFilter struct{ act atomic.Pointer[func()] }

func (*betweenFilter) ID() string { return "between-decision-and-launch" }

func (f *betweenFilter) FilterRequest(context.Context, *pipeline.Call, json.RawMessage) (pipeline.RequestVerdict, error) {
	if a := f.act.Swap(nil); a != nil {
		(*a)()
	}
	return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
}

// TestPreLaunchRecheck is SR-1.17-1's test: a new policy revision, a
// suspended session, a revoked credential, a suspended principal or a
// suspended server revision, each brought about after the decision
// permitted a call but before launch authorization, refuses the launch
// under the gate: no decision intent is committed and nothing is
// dispatched.
func TestPreLaunchRecheck(t *testing.T) {
	reqtest.Verifies(t, "SR-1.17-1")
	bf := &betweenFilter{}
	f := pipeline.NewFilters()
	if err := f.RegisterRequest(bf, pipeline.Registration{Order: 10, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, harnessOpts{filters: f, limits: "principal_calls_per_minute = 1000"})
	dir := &stateDirectory{}
	h.cfg.SetDirectory(dir) // before the first request
	sess, tok := h.session("ro")
	cs := h.client(tok)
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "before"}}); err != nil {
		t.Fatal(err)
	}
	r2, err := policy.Compile([]byte(strings.Replace(edgePolicy, `"r1"`, `"r2"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, reason string
		code         int64
		act, undo    func()
	}{
		{"policy revision changed", ReasonRevisionChanged, CodeGatewayFailClosed, func() {
			if _, err := h.gw.ActivatePolicy("test", r2); err != nil {
				t.Error(err)
			}
		}, func() {}},
		{"session suspended", ReasonSessionState, CodeSessionInvalid, func() { h.store.Suspend(sess.ID) }, func() { h.store.Resume(sess.ID) }},
		{"credential revoked", policy.ReasonCredentialInvalid, CodePolicyDenied, func() { dir.revoked.Store(true) }, func() { dir.revoked.Store(false) }},
		{"principal suspended", policy.ReasonPrincipalDisabled, CodePolicyDenied, func() { dir.suspended.Store(true) }, func() { dir.suspended.Store(false) }},
		{"server revision suspended", policy.ReasonRevisionNotEnabled, CodePolicyDenied, func() { h.reg.Suspend("t", "test suspension") }, func() {}},
	} {
		act := c.act
		bf.act.Store(&act)
		we, data := callErr(t, cs, "t_echo", map[string]any{"text": c.name})
		if we.Code != c.code || data["reasonCode"] != c.reason {
			t.Fatalf("%s: %d %v", c.name, we.Code, data)
		}
		corr, _ := data["correlationId"].(string)
		for _, e := range h.rec.all() {
			if e.CorrelationID == corr && (e.Phase == audit.PhaseAuthorized || e.Phase == audit.PhaseDispatched) {
				t.Fatalf("%s: %s event for the refused call", c.name, e.Phase)
			}
		}
		denied := h.rec.find(func(e audit.Event) bool {
			return e.CorrelationID == corr && e.Phase == audit.PhaseDenied && e.Origin == "E-12" && e.ReasonCode == c.reason
		})
		if denied == nil {
			t.Fatalf("%s: no E-12 denial", c.name)
		}
		c.undo()
	}
}

// TestRevocationSerializedWithLaunch is SR-1.16-1 for revocation: a
// revocation run through Gateway.Serialize waits for a launch
// authorization in progress, and a launch authorization that starts after
// it sees the revocation. TestEmergencyStopSerializedWithLaunch covers
// emergency stop and policy activation against launch and release
// authorization through the same gate.
func TestRevocationSerializedWithLaunch(t *testing.T) {
	reqtest.Verifies(t, "SR-1.16-1")
	h := newHarness(t, harnessOpts{})
	dir := &stateDirectory{}
	h.cfg.SetDirectory(dir)
	_, tok := h.session("ro")
	cs := h.client(tok)

	entered, release := holdLaunch(h)
	errc := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "first"}})
		errc <- err
	}()
	<-entered
	revoked := make(chan struct{})
	go func() {
		h.gw.Serialize(func() { dir.revoked.Store(true) })
		close(revoked)
	}()
	select {
	case <-revoked:
		t.Fatal("revocation completed while a launch authorization held the gate")
	case <-time.After(200 * time.Millisecond):
	}
	if dir.revoked.Load() {
		t.Fatal("credential state changed inside a launch authorization")
	}
	close(release)
	<-revoked
	if err := <-errc; err != nil {
		t.Fatalf("call authorized before the revocation: %v", err)
	}
	// After the revocation every launch is refused.
	we, data := callErr(t, cs, "t_echo", map[string]any{"text": "after"})
	if we.Code != CodePolicyDenied || (data["reasonCode"] != policy.ReasonCredentialInvalid && data["reasonCode"] != policy.ReasonPrincipalDisabled) {
		t.Fatalf("call after the revocation: %d %v", we.Code, data)
	}
}
