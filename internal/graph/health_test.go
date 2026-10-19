package graph

import (
	"errors"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestMirrorHealthCheck: an enabled mirror that cannot reach the database
// makes the Gateway degraded (never fail-closed); a disabled or ready
// mirror reports nothing.
func TestMirrorHealthCheck(t *testing.T) {
	reqtest.Partial(t, "FR-7.12")
	disabled, err := New(Options{Config: newConfig(t, t.TempDir()), Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	if c := disabled.HealthCheck()(time.Now()); len(c) != 0 {
		t.Fatalf("disabled mirror: %v", c)
	}
	m, err := New(Options{Config: newConfig(t, t.TempDir()), Log: diag.Discard(), Backend: NewFake()})
	if err != nil {
		t.Fatal(err)
	}
	check := m.HealthCheck()
	for _, tc := range []struct {
		state string
		cause bool
	}{{StateConnecting, false}, {StateReady, false}, {StateUnavailable, true}, {StateRefused, true}} {
		m.setState(tc.state, errors.New("connection refused"))
		c := check(time.Now())
		if got := len(c) == 1 && c[0].Name == health.CauseGraphUnavailable && !c[0].Critical; got != tc.cause {
			t.Fatalf("%s: %+v", tc.state, c)
		}
	}
	mon := health.New(health.Options{Log: diag.Discard()})
	mon.Register("graph", check)
	mon.Evaluate()
	if mon.State() != health.Degraded || len(mon.Gate()) != 0 {
		t.Fatalf("state %s gate %v", mon.State(), mon.Gate())
	}
}

// TestIdleMirrorDetectsUnreachableDatabase: with no traffic, a ready
// mirror notices a failing database through its reachability probe within
// a second, keeps reporting it while it retries, and is ready again once
// the database answers (FR-7.11 graph reachability).
func TestIdleMirrorDetectsUnreachableDatabase(t *testing.T) {
	reqtest.Partial(t, "FR-7.11")
	f := NewFake()
	e := newEnv(t, f, 1000, nil, nil)
	waitReady(t, e.mirror)
	check := e.mirror.HealthCheck()
	f.Fail(ErrUnavailable)
	start := time.Now()
	for len(check(time.Now())) == 0 {
		if time.Since(start) > 2*ProbeInterval+time.Second {
			t.Fatalf("unreachable database not reported after %v: %+v", time.Since(start), e.mirror.Status(t.Context(), false))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Retries keep the cause: sample it across a few backoff periods.
	for range 30 {
		if len(check(time.Now())) == 0 {
			t.Fatalf("cause lapsed while retrying: %+v", e.mirror.Status(t.Context(), false))
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.Fail(nil)
	waitReady(t, e.mirror)
	if c := check(time.Now()); len(c) != 0 {
		t.Fatalf("ready mirror still reports %v", c)
	}
}
