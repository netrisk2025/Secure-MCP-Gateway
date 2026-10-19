package graph

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
)

// testEnv is a journal plus a mirror over a backend.
type testEnv struct {
	t       *testing.T
	dir     string
	cfg     *config.Config
	journal *audit.Journal
	fanout  *audit.Fanout
	mirror  *Mirror
}

func newConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	return &config.Config{State: config.State{Dir: dir}, Graph: config.Graph{
		CatchUpInterval: config.Duration{Duration: time.Hour}, MemoryInterval: config.Duration{Duration: time.Hour},
		RetentionInterval: config.Duration{Duration: 24 * time.Hour}}}
}

// newEnv opens a journal with segments of segEvents events and starts a
// mirror on b, registered as an observer of the journal's fanout.
func newEnv(t *testing.T, b Backend, segEvents int, mod func(*config.Config), now func() time.Time) *testEnv {
	t.Helper()
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, err := audit.Open(filepath.Join(dir, "journal"), key, audit.Options{MaxEvents: segEvents, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cfg := newConfig(t, dir)
	if mod != nil {
		mod(cfg)
	}
	e := &testEnv{t: t, dir: dir, cfg: cfg, journal: j, fanout: audit.NewFanout(j, diag.Discard())}
	e.mirror = e.startMirror(b, now)
	e.fanout.AddObserver("graph", e.mirror, 0)
	t.Cleanup(func() {
		e.fanout.Close()
		e.mirror.Close()
		_ = j.Close()
	})
	return e
}

func (e *testEnv) startMirror(b Backend, now func() time.Time) *Mirror {
	e.t.Helper()
	m, err := New(Options{Config: e.cfg, Log: diag.Discard(), Backend: b, Now: now, JournalDir: filepath.Join(e.dir, "journal")})
	if err != nil {
		e.t.Fatal(err)
	}
	m.Start(context.Background(), e.fanout)
	return m
}

// waitReady waits until the mirror is ready.
func waitReady(t *testing.T, m *Mirror) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := m.DAS(); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("mirror not ready: %+v", m.Status(context.Background(), false))
}

func syncMirror(t *testing.T, m *Mirror) {
	t.Helper()
	waitReady(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
}

// callEvents returns the evidence of one permitted tool call.
func callEvents(n int, session, principal string) []audit.Event {
	corr, dec := fmt.Sprintf("corr-%d", n), fmt.Sprintf("dec-%d", n)
	base := audit.Event{CorrelationID: corr, SessionID: session, PrincipalID: principal, ServerRevision: "live-abc",
		ToolRevision: "live-abc/echo", PolicyStatus: "evaluated"}
	ev := func(class string, phase audit.Phase, origin, outcome string, withDecision bool) audit.Event {
		e := base
		e.Class, e.Phase, e.Origin, e.Outcome = class, phase, origin, outcome
		if withDecision {
			e.DecisionID, e.PolicyRevision = dec, "r1"
		}
		return e
	}
	decision := ev("decision", audit.PhaseAuthorized, "E-12", "permit", true)
	// The decision record as the edge writes it (SR-6.4-1).
	decision.Detail = map[string]any{"considered_rules": []any{"r1/dev/allow-echo", "r1/dev/deny-write"},
		"applicable_rules": []any{"r1/dev/allow-echo"}, "decisive_rules": []any{"r1/dev/allow-echo"},
		"obligations": map[string]any{"audit_profile": "audit_profile@file"}}
	return []audit.Event{
		ev("call", audit.PhaseRequested, "E-02", "", false),
		decision,
		ev("call", audit.PhaseDispatched, "E-10", "", true),
		ev("call", audit.PhaseCompleted, "E-10", "ok", true),
		ev("call", audit.PhaseDelivered, "E-12", "ok", true),
	}
}

func deniedEvents(n int, session, principal string) []audit.Event {
	corr, dec := fmt.Sprintf("dcorr-%d", n), fmt.Sprintf("ddec-%d", n)
	base := audit.Event{CorrelationID: corr, SessionID: session, PrincipalID: principal, ServerRevision: "live-abc", ToolRevision: "live-abc/write"}
	a, b := base, base
	a.Class, a.Phase, a.Origin, a.PolicyStatus = "call", audit.PhaseRequested, "E-02", "not_evaluated"
	b.Class, b.Phase, b.Origin, b.Outcome, b.ReasonCode, b.PolicyStatus, b.DecisionID, b.PolicyRevision = "decision", audit.PhaseDenied, "E-06", "deny", "NO_MATCHING_RULE", "evaluated", dec, "r1"
	return []audit.Event{a, b}
}

func (e *testEnv) commit(evs ...audit.Event) {
	e.t.Helper()
	for _, ev := range evs {
		if err := e.fanout.Commit(ev); err != nil {
			e.t.Fatal(err)
		}
	}
}

// workload commits a gateway start, a session, n calls and one denial.
func (e *testEnv) workload(n int) {
	e.t.Helper()
	e.commit(audit.Event{Class: "gateway", Origin: "E-23", Outcome: "started", PolicyRevision: "r1"})
	e.commit(audit.Event{Class: "session", Origin: "E-04", SessionID: "s1", PrincipalID: "cc", Outcome: "active", ReasonCode: "SIGN_IN", PolicyRevision: "r1"})
	for i := 0; i < n; i++ {
		e.commit(callEvents(i, "s1", "cc")...)
	}
	e.commit(deniedEvents(0, "s1", "cc")...)
}

func journalIDs(t *testing.T, dir string) []string {
	t.Helper()
	evs, err := audit.ReadEvents(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(evs))
	for i, ev := range evs {
		ids[i] = ev.EventID
	}
	return ids
}
