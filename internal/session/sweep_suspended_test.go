package session

import (
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSweepKeepsSuspendedSessions: a suspended session has no end time, and
// the sweep must not take it for one that ended long ago. It stays
// readable and resumable until it expires (FR-2.8).
func TestSweepKeepsSuspendedSessions(t *testing.T) {
	reqtest.Partial(t, "FR-2.8")
	s := newStore(t)
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	sess, tok, err := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Suspend(sess.ID) {
		t.Fatal("suspend failed")
	}
	now = now.Add(time.Second)
	s.Sweep()
	if got := s.Get(sess.ID); got == nil || got.State != StateSuspended {
		t.Fatalf("suspended session after a sweep: %+v", got)
	}
	if !s.Resume(sess.ID) {
		t.Fatal("resume after a sweep failed")
	}
	if _, err := s.Authenticate(tok.Access, "tls"); err != nil {
		t.Fatalf("resumed session: %v", err)
	}
}
