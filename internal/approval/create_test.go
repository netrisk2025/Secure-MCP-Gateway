package approval

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestApprovalRequestCreation is FR-3.14: a call whose decision carries
// the approval obligation, with no matching unconsumed approval, creates a
// pending approval record bound to the call (SR-1.18-2 binding fields),
// listed by the pending list that the console's Approvals view (G-13) and
// `smcpctl approvals list` read (GET /api/v1/approvals), notifies approvers
// through the desktop notifier, and holds the call instead of answering
// it while the approval is pending.
func TestApprovalRequestCreation(t *testing.T) {
	reqtest.Verifies(t, "FR-3.14")
	f := newFixture(t, nil)
	var keepalives atomic.Int32
	c := call("s1", "c1")
	ch := f.request(c, args(`{"path":"/tmp/x"}`), 5*time.Second, func(string) { keepalives.Add(1) })
	p := f.waitPending(t, 1)
	rec, ok := f.svc.Get(p.ID)
	if !ok || rec.State != StatePending || rec.SessionID != c.SessionID || rec.PrincipalID != c.PrincipalID || rec.Server != c.Server ||
		rec.Tool != c.Tool || rec.PublicName != c.PublicName || rec.ServerRevision != c.ServerRevision || rec.ToolRevision != c.ToolRevision ||
		rec.PolicyRevision != c.PolicyRevision || rec.ArgumentsDigest == "" || rec.CorrelationID != c.CorrelationID {
		t.Fatalf("pending record %+v", rec)
	}
	listed := false
	for _, s := range f.svc.List(StatePending) {
		listed = listed || s.ID == p.ID
	}
	if !listed {
		t.Fatal("pending approval not in the pending list")
	}
	// Held, not answered, while pending.
	time.Sleep(100 * time.Millisecond)
	select {
	case r := <-ch:
		t.Fatalf("held call answered while pending: %+v", r)
	default:
	}
	if keepalives.Load() == 0 {
		t.Fatal("no keep-alive while held")
	}
	// The approver was notified.
	deadline := time.Now().Add(2 * time.Second)
	for len(f.notes.all()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := f.notes.all(); len(n) != 1 {
		t.Fatalf("desktop notifications %v", n)
	}
	// Approving releases the held call.
	if err := f.svc.Decide(context.Background(), p.ID, true, "admin:admin", ""); err != nil {
		t.Fatal(err)
	}
	if r := <-ch; r.err != nil || r.res.Outcome != pipeline.Approved {
		t.Fatalf("%+v", r)
	}
}
