package session

import (
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSuspendAndResume checks the suspended state of FR-2.8: a suspended
// session's tokens are refused and it is not active, it keeps its place in
// the principal's session count, it resumes with the same tokens, and it
// still expires and can be terminated.
func TestSuspendAndResume(t *testing.T) {
	reqtest.Partial(t, "FR-2.8", "FR-8.19")
	s := newStore(t)
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	sess, tok, err := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Resume(sess.ID) {
		t.Fatal("resumed an active session")
	}
	if !s.Suspend(sess.ID) || s.Suspend(sess.ID) {
		t.Fatal("suspend: want true once")
	}
	if got := s.Get(sess.ID); got.State != StateSuspended {
		t.Fatalf("state %s", got.State)
	}
	if _, err := s.Authenticate(tok.Access, "tls"); err != ErrSessionInvalid {
		t.Fatal("suspended session's access token accepted")
	}
	if _, _, err := s.Refresh(tok.Refresh, "cid"); err != ErrSessionInvalid {
		t.Fatal("suspended session refreshed")
	}
	if s.IsActive(sess.ID) || len(s.Active()) != 0 || len(s.List()) != 1 {
		t.Fatalf("active %v, listed %d", s.IsActive(sess.ID), len(s.List()))
	}
	// Still counts toward sessions_per_principal (2).
	if _, _, err := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"}); err != ErrTooManySessions {
		t.Fatalf("limit with a suspended session: %v", err)
	}
	if !s.Resume(sess.ID) {
		t.Fatal("resume")
	}
	if _, err := s.Authenticate(tok.Access, "tls"); err != nil {
		t.Fatalf("resumed session refused: %v", err)
	}
	// A suspended session expires at its idle deadline and cannot resume.
	s.Suspend(sess.ID)
	now = now.Add(31 * time.Minute)
	if s.Resume(sess.ID) {
		t.Fatal("expired session resumed")
	}
	if got := s.Get(sess.ID); got.State != StateExpired || got.EndReason != EndIdle {
		t.Fatalf("state %s %s", got.State, got.EndReason)
	}
	// A suspended session can be terminated.
	b, _, err := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	s.Suspend(b.ID)
	if !s.Terminate(b.ID) || s.Get(b.ID).State != StateTerminated {
		t.Fatal("terminate a suspended session")
	}
}
