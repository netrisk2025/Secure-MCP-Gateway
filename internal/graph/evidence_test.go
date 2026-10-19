package graph

import (
	"context"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// failedEvents returns the evidence of a permitted call whose backend
// failed after dispatch.
func failedEvents(n int, session, principal string) []audit.Event {
	evs := callEvents(n+5000, session, principal)[:3] // requested, authorized, dispatched
	f := evs[2]
	f.Phase, f.Outcome, f.ReasonCode = audit.PhaseFailed, "failed", "DISPATCH_FAILED"
	return append(evs, f)
}

// TestDecisionLinkForEveryEvaluatedEvent: every event that carries a
// decision is linked to it with FOR_DECISION, for a permitted and
// delivered call as for a denied call that never reached a backend
// (SR-6.20-1).
func TestDecisionLinkForEveryEvaluatedEvent(t *testing.T) {
	reqtest.Verifies(t, "SR-6.20-1")
	f := NewFake()
	e := newEnv(t, f, 1000, nil, nil)
	e.workload(2) // two permitted calls and one denial
	e.commit(deniedEvents(1, "s1", "cc")...)
	syncMirror(t, e.mirror)
	evs, err := audit.ReadEvents(e.dir + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	linked, denied := 0, 0
	for _, ev := range evs {
		if ev.DecisionID == "" {
			continue
		}
		if !f.HasRel("AuditEvent", ev.EventID, "FOR_DECISION", "Decision", ev.DecisionID) {
			t.Errorf("%s %s event %s has no FOR_DECISION link to %s", ev.Class, ev.Phase, ev.EventID, ev.DecisionID)
		}
		linked++
		if ev.Phase == audit.PhaseDenied {
			denied++
		}
	}
	if linked < 10 || denied != 2 {
		t.Fatalf("linked %d events, %d denials", linked, denied)
	}
	// The denied calls were never dispatched, and their decisions exist.
	for _, id := range []string{"ddec-0", "ddec-1"} {
		if d := f.Node("Decision", id); d["outcome"] != "deny" {
			t.Fatalf("decision %s: %v", id, d)
		}
	}
}

// TestOutageBackfillKeepsPolicyStatus: while the graph database is down,
// permits, denials and failures are all recorded in the Evidence Journal;
// after recovery the mirror holds every one of them with the policy status
// it was recorded with (SR-6.13-1).
func TestOutageBackfillKeepsPolicyStatus(t *testing.T) {
	reqtest.Verifies(t, "SR-6.13-1")
	f := NewFake()
	e := newEnv(t, f, 200, nil, nil)
	waitReady(t, e.mirror)
	f.Fail(ErrUnavailable) // the database stops
	for i := 0; i < 3; i++ {
		e.commit(callEvents(i, "s1", "cc")...)
		e.commit(deniedEvents(i, "s1", "cc")...)
		e.commit(failedEvents(i, "s1", "cc")...)
	}
	e.commit(audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: "SESSION_INVALID", PolicyStatus: "not_evaluated"})
	e.commit(audit.Event{Class: "call", Phase: audit.PhaseDenied, Origin: "E-12", CorrelationID: "fc-1", Outcome: "deny", ReasonCode: "FAIL_CLOSED", PolicyStatus: "unavailable"})
	deadline := time.Now().Add(5 * time.Second)
	for e.mirror.Status(context.Background(), false).State == StateReady && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st := e.mirror.Status(context.Background(), false); st.State == StateReady {
		t.Fatalf("mirror ready during the outage: %+v", st)
	}
	during, err := audit.ReadEvents(e.dir + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	if len(during) != 3*(5+2+4)+2 {
		t.Fatalf("journal holds %d events during the outage", len(during))
	}
	statuses := map[string]bool{}
	for _, ev := range during {
		statuses[ev.PolicyStatus] = true
	}
	if !statuses["evaluated"] || !statuses["not_evaluated"] || !statuses["unavailable"] {
		t.Fatalf("policy statuses recorded: %v", statuses)
	}
	f.Fail(nil) // the database is back
	syncMirror(t, e.mirror)
	for _, ev := range during {
		n := f.Node("AuditEvent", ev.EventID)
		if n == nil {
			t.Fatalf("event %s (%s %s) missing from the mirror", ev.EventID, ev.Class, ev.Phase)
		}
		if n["policyStatus"] != ev.PolicyStatus {
			t.Fatalf("event %s: mirror policy status %v, journal %q", ev.EventID, n["policyStatus"], ev.PolicyStatus)
		}
	}
}
