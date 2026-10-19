package approval

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestBindingRefusesEveryMismatch is SR-1.18-2: an approved approval is
// consumed only by a retry that matches its session, principal, server,
// tool and route with their revisions, canonical argument digest and
// policy revision; a retry with a changed argument, from another session,
// after a revision change or after expiry is refused (a new pending
// approval, not the approved one); the identical retry consumes it once;
// and no lifetime longer than CP-17 is accepted.
func TestBindingRefusesEveryMismatch(t *testing.T) {
	reqtest.Verifies(t, "SR-1.18-2")
	for _, lt := range []time.Duration{MaxLifetime + time.Second, -time.Second} {
		cfg := &config.Config{State: config.State{Dir: t.TempDir()}}
		cfg.Approvals.Lifetime.Duration = lt
		if _, err := New(Options{Config: cfg}); err == nil || !strings.Contains(err.Error(), "CP-17") {
			t.Fatalf("lifetime %s accepted: %v", lt, err)
		}
	}
	c := &clock{t: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)}
	f := newFixture(t, func(_ *config.Config, o *Options) { o.Now = c.now })
	a := args(`{"path":"/a","mode":"w"}`)
	approved := func(corr string) string {
		t.Helper()
		r := <-f.request(call("s1", corr), a, 0, nil)
		if r.res.Outcome != pipeline.Pending || !r.res.ExpiresAt.Equal(c.now().Add(DefaultLifetime)) {
			t.Fatalf("%+v", r)
		}
		if err := f.svc.Decide(context.Background(), r.res.ApprovalID, true, "admin:admin", ""); err != nil {
			t.Fatal(err)
		}
		return r.res.ApprovalID
	}
	id := approved("c0")
	mismatch := map[string]func(*pipeline.Call){
		"another session":         func(x *pipeline.Call) { x.SessionID = "s2" },
		"another principal":       func(x *pipeline.Call) { x.PrincipalID = "other" },
		"another server":          func(x *pipeline.Call) { x.Server = "fs2" },
		"another tool":            func(x *pipeline.Call) { x.Tool = "delete_file" },
		"another route":           func(x *pipeline.Call) { x.PublicName = "fs2_write_file" },
		"server revision changed": func(x *pipeline.Call) { x.ServerRevision = "sr2" },
		"tool revision changed":   func(x *pipeline.Call) { x.ToolRevision = "tr2" },
		"policy revision changed": func(x *pipeline.Call) { x.PolicyRevision = "r2" },
	}
	for name, mut := range mismatch {
		x := call("s1", "m-"+name)
		mut(&x)
		if r := <-f.request(x, a, 0, nil); r.err != nil || r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
			t.Errorf("%s: %+v", name, r)
		}
	}
	for _, changed := range []string{`{"path":"/b","mode":"w"}`, `{"path":"/a","mode":"w","extra":1}`, `{"path":"/a"}`} {
		if r := <-f.request(call("s1", "m-args"), args(changed), 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
			t.Errorf("changed argument %s: %+v", changed, r)
		}
	}
	if rec, _ := f.svc.Get(id); rec.State != StateApproved {
		t.Fatalf("a mismatched retry touched the approval: %+v", rec)
	}
	// The identical retry (canonically equal arguments) consumes it, once.
	if r := <-f.request(call("s1", "c1"), args(`{"mode":"w", "path":"/a"}`), 0, nil); r.res.Outcome != pipeline.Approved || r.res.ApprovalID != id {
		t.Fatalf("identical retry: %+v", r)
	}
	if r := <-f.request(call("s1", "c2"), a, 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
		t.Fatalf("second use: %+v", r)
	}
	// After expiry the approved approval is refused.
	id2 := approved("c3")
	c.add(DefaultLifetime + time.Second)
	if r := <-f.request(call("s1", "c4"), a, 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id2 {
		t.Fatalf("expired approval consumed: %+v", r)
	}
	f.svc.Expire()
	if rec, _ := f.svc.Get(id2); rec.State != StateExpired || rec.ConsumedAt != nil {
		t.Fatalf("%+v", rec)
	}
}

// TestDecisionRecordsApproverTimeAndComment is FR-3.17: approve and deny
// decisions are stored with the approver identity, the decision time and
// the optional comment, and each produces an audit event carrying the same
// three fields. The console's Approvals view (G-13) posts to
// /api/v1/approvals/{id}/approve and /deny, whose handler passes the
// authenticated actor and the comment to the same decide step
// (internal/e2e TestApprovalHeldApprovedDeniedAndReplay drives those
// routes over HTTP).
func TestDecisionRecordsApproverTimeAndComment(t *testing.T) {
	reqtest.Verifies(t, "FR-3.17")
	c := &clock{t: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)}
	f := newFixture(t, func(_ *config.Config, o *Options) { o.Now = c.now })
	r1 := <-f.request(call("s1", "c1"), args(`{"n":1}`), 0, nil)
	r2 := <-f.request(call("s1", "c2"), args(`{"n":2}`), 0, nil)
	c.add(30 * time.Second)
	decidedAt := c.now()
	if err := f.svc.Decide(context.Background(), r1.res.ApprovalID, true, "approver:alice", "ok for the demo"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Decide(context.Background(), r2.res.ApprovalID, false, "admin:bob", ""); err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct {
		id, state, by, comment, outcome string
	}{
		{r1.res.ApprovalID, StateApproved, "approver:alice", "ok for the demo", "approved"},
		{r2.res.ApprovalID, StateDenied, "admin:bob", "", "denied"},
	} {
		rec, _ := f.svc.Get(w.id)
		if rec.State != w.state || rec.DecidedBy != w.by || rec.Comment != w.comment || rec.DecidedAt == nil || !rec.DecidedAt.Equal(decidedAt) {
			t.Errorf("stored %s: %+v", w.id, rec)
		}
		found := false
		for _, e := range f.mem.Events() {
			d, _ := e.Detail.(map[string]any)
			if e.Class != "approval" || d["approval_id"] != w.id || e.Outcome != w.outcome {
				continue
			}
			found = true
			if d["approver"] != w.by || d["decided_at"] != decidedAt.UTC().Format(time.RFC3339Nano) {
				t.Errorf("event for %s: %v", w.id, d)
			}
			if got, _ := d["comment"].(string); got != w.comment {
				t.Errorf("event comment for %s: %v", w.id, d)
			}
		}
		if !found {
			t.Errorf("no %s event for %s", w.outcome, w.id)
		}
	}
}
