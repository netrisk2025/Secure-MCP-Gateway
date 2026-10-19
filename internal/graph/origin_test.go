package graph

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestOriginLabelsAndObservedBackend: every mirrored event carries its
// origin label (gateway, backend, broker or admin), and a backend is linked
// as observed (OBSERVED_FROM) only by events of a call the Gateway
// dispatched to it: a call denied before dispatch has no such link
// (SR-6.5-1).
func TestOriginLabelsAndObservedBackend(t *testing.T) {
	reqtest.Verifies(t, "SR-6.5-1")
	f := NewFake()
	e := newEnv(t, f, 1000, nil, nil)
	e.commit(callEvents(0, "s1", "cc")...)
	e.commit(deniedEvents(0, "s1", "cc")...)
	e.commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: "signed_in", ReasonCode: "ADMIN_SIGNIN"})
	e.commit(audit.Event{Class: "egress", Origin: "E-18", Outcome: "deny", ReasonCode: "EGRESS_NO_GRANT", ServerRevision: "live-abc"})
	e.commit(audit.Event{Class: "server_asserted", Origin: "E-15", Outcome: "stderr", ServerRevision: "live-abc"})
	syncMirror(t, e.mirror)
	evs, err := audit.ReadEvents(e.dir + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"call": audit.OriginGateway, "decision": audit.OriginGateway, "admin": audit.OriginAdmin,
		"egress": audit.OriginBroker, "server_asserted": audit.OriginBackend}
	for _, ev := range evs {
		n := f.Node("AuditEvent", ev.EventID)
		if n == nil {
			t.Fatalf("event %s not mirrored", ev.EventID)
		}
		if n["originLabel"] != want[ev.Class] {
			t.Errorf("%s %s event labelled %v, want %s", ev.Class, ev.Phase, n["originLabel"], want[ev.Class])
		}
		observed := f.HasRel("AuditEvent", ev.EventID, "OBSERVED_FROM", "ServerRevision", "live-abc")
		switch {
		case ev.CorrelationID == "dcorr-0" && observed:
			t.Errorf("denied call: %s %s event links the backend as observed", ev.Class, ev.Phase)
		case ev.CorrelationID == "corr-0" && ev.Phase == audit.PhaseRequested && observed:
			t.Error("the requested event of a call links the backend before dispatch")
		case ev.CorrelationID == "corr-0" && (ev.Phase == audit.PhaseDispatched || ev.Phase == audit.PhaseCompleted || ev.Phase == audit.PhaseDelivered) && !observed:
			t.Errorf("%s event of a dispatched call does not link the backend", ev.Phase)
		case ev.Class == "server_asserted" && !observed:
			t.Error("server-asserted evidence does not link its backend")
		}
	}
	// The denied call's decision still targets the server revision.
	if !f.HasRel("Decision", "ddec-0", "TARGETED", "ServerRevision", "live-abc") {
		t.Fatal("the denied decision lost its target")
	}
}
