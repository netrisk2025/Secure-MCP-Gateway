package edge

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// all returns a copy of the recorded events in order.
func (r *recorder) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

func indexOf(evs []audit.Event, pred func(audit.Event) bool) int {
	for i, e := range evs {
		if pred(e) {
			return i
		}
	}
	return -1
}

// holdLaunch makes the next launch authorization block inside the gate
// (while its decision intent is being committed) until release is closed.
func holdLaunch(h *harness) (entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.rec.set(nil, func(ev audit.Event) {
		if ev.Phase == audit.PhaseAuthorized {
			once.Do(func() { close(entered); <-release })
		}
	})
	return entered, release
}

// TestEmergencyStopSerializedWithLaunch is SR-7.6-1: an emergency stop
// waits for a launch authorization in progress, and no launch
// authorization follows the stop.
//
// It also covers SR-1.16-1 for emergency stop and policy activation: both
// are serialized with launch and release authorization through the one
// gate (revocation: TestRevocationSerializedWithLaunch).
func TestEmergencyStopSerializedWithLaunch(t *testing.T) {
	reqtest.Verifies(t, "SR-7.6-1", "SR-1.16-1")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	cs := h.client(tok)

	entered, release := holdLaunch(h)
	errc := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "first"}})
		errc <- err
	}()
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- h.gw.Stop("test", "race") }()
	select {
	case err := <-stopped:
		t.Fatalf("stop completed while a launch authorization held the gate: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if h.gw.Stopped() {
		t.Fatal("stop state changed inside a launch authorization")
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	// The first call was authorized before the stop; its release comes
	// after it and is withheld.
	var we *jsonrpc.Error
	if err := <-errc; !errors.As(err, &we) || we.Code != CodeResponseWithheld {
		t.Fatalf("call authorized before the stop: %v", err)
	}
	// Calls after the stop are refused and never authorized.
	for i := 0; i < 3; i++ {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "after"}}); err == nil {
			t.Fatal("call ran after the stop")
		}
	}
	evs := h.rec.all()
	stopAt := indexOf(evs, func(e audit.Event) bool { return e.Class == "admin" && e.ReasonCode == ReasonEmergencyStop })
	authAt := indexOf(evs, func(e audit.Event) bool { return e.Phase == audit.PhaseAuthorized })
	if stopAt < 0 || authAt < 0 || authAt > stopAt {
		t.Fatalf("authorized at %d, stop at %d", authAt, stopAt)
	}
	for _, e := range evs[stopAt:] {
		if e.Phase == audit.PhaseAuthorized {
			t.Fatalf("launch authorized after the stop: %+v", e)
		}
	}

	// Policy activation waits for a launch authorization in the same way.
	if err := h.gw.Resume("test"); err != nil {
		t.Fatal(err)
	}
	entered, release = holdLaunch(h)
	go func() {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "second"}})
		errc <- err
	}()
	<-entered
	r2, err := policy.Compile([]byte(strings.Replace(edgePolicy, `"r1"`, `"r2"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	activated := make(chan error, 1)
	go func() { _, err := h.gw.ActivatePolicy("test", r2); activated <- err }()
	select {
	case err := <-activated:
		t.Fatalf("activation completed while a launch authorization held the gate: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if h.decider.Snapshot().Revision != "r1" {
		t.Fatal("revision changed inside a launch authorization")
	}
	close(release)
	if err := <-activated; err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("call authorized under r1: %v", err)
	}
	evs = h.rec.all()
	actAt := indexOf(evs, func(e audit.Event) bool { return e.ReasonCode == "POLICY_ACTIVATED" })
	var lastR1 int
	for i, e := range evs {
		if e.Phase == audit.PhaseAuthorized && e.PolicyRevision == "r1" {
			lastR1 = i
		}
	}
	if actAt < 0 || lastR1 > actAt {
		t.Fatalf("r1 launch authorized at %d after activation at %d", lastR1, actAt)
	}
}

// TestUnevaluatedEventsCarryStatus is SR-6.19-1: an authentication failure
// and an outage denial are recorded without policy evaluation, each with a
// stable system-control reason and policy_status not_evaluated or
// unavailable.
func TestUnevaluatedEventsCarryStatus(t *testing.T) {
	reqtest.Verifies(t, "SR-6.19-1")
	var outage atomic.Bool
	h := newHarness(t, harnessOpts{healthGate: func() []string {
		if outage.Load() {
			return []string{"test_outage"}
		}
		return nil
	}})
	_, tok := h.session("ro")

	// Authentication failure.
	status, _, body := h.post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, map[string]string{"Authorization": "Bearer not-a-token"})
	if status != 401 || !strings.Contains(body, "-31006") {
		t.Fatalf("bad token: %d %s", status, body)
	}
	ev := h.rec.find(func(e audit.Event) bool { return e.Class == "auth_failure" })
	if ev == nil || ev.PolicyStatus != "not_evaluated" || ev.ReasonCode != "SESSION_INVALID" || ev.DecisionID != "" || ev.CorrelationID == "" {
		t.Fatalf("auth failure event: %+v", ev)
	}

	// Outage denial: the health gate trips after the request is accepted
	// and before the decision.
	h.rec.set(func(e audit.Event) error {
		if e.Phase == audit.PhaseRequested {
			outage.Store(true)
		}
		return nil
	}, nil)
	cs := h.client(tok)
	we, data := callErr(t, cs, "t_echo", map[string]any{"text": "x"})
	if we.Code != CodeGatewayFailClosed || data["reasonCode"] != ReasonFailClosed {
		t.Fatalf("outage: %+v %v", we, data)
	}
	ev = h.rec.find(func(e audit.Event) bool { return e.Class == "call" && e.Phase == audit.PhaseDenied })
	if ev == nil || ev.PolicyStatus != "unavailable" || ev.ReasonCode != ReasonFailClosed || ev.DecisionID != "" {
		t.Fatalf("outage denial event: %+v", ev)
	}
	if d := h.rec.find(func(e audit.Event) bool { return e.Class == "decision" }); d != nil {
		t.Fatalf("a decision was recorded during the outage: %+v", d)
	}
}
