package session

import (
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const cfgTOML = `
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[limits]
sessions_per_principal = 2
session_idle_timeout = "30m"
session_max_lifetime = "8h"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[principal]]
id = "off"
framework = "codex"
profile = "dev"
enabled = false
[[client]]
client_id = "cid"
principal = "cc"
redirect_uris = ["http://localhost/cb"]
`

const pol = `{"revision":"r1","framework_profiles":{"dev":{"templates":["ro","rw"],"default_template":"ro"}},
"templates":{"ro":{"rules":[{"id":"a","server":"fs","tools":["read_file"]}]},"rw":{"rules":[{"id":"b","server":"fs","tools":["write_file"]}]}}}`

func newStore(t *testing.T) *Store {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgTOML))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := policy.Compile([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(cfg, func() *policy.Snapshot { return snap })
}

func TestScopes(t *testing.T) {
	reqtest.Verifies(t, "FR-2.21")
	c, err := ParseScopes([]string{"smcp:template:rw", "smcp:purpose:tests", "smcp:project:/w", "smcp:user:ethan", "openid"})
	if err != nil || c.Template != "rw" || c.Purpose != "tests" || c.Project != "/w" || c.EndUser != "ethan" {
		t.Fatalf("%v %+v", err, c)
	}
	if _, err := ParseScopes([]string{"smcp:admin"}); err == nil {
		t.Fatal("unknown smcp scope accepted")
	}
}

func TestCreateSelectsTemplateAndLimits(t *testing.T) {
	// The store-level part of FR-2.3, FR-2.6 and FR-2.10; the create paths
	// and their Gateway errors are in create_test.go, FR-2.4 in
	// TestSessionContextKey and FR-2.7 in internal/e2e.
	reqtest.Verifies(t, "FR-2.8")
	reqtest.Partial(t, "FR-2.3", "FR-2.6", "FR-2.10")
	s := newStore(t)
	sess, tok, err := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls", Claims: Claims{Purpose: "p", Project: "/x"}})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Template != "ro" || sess.PolicyRevision != "r1" || sess.State != StateActive || sess.Purpose != "p" || sess.Project != "/x" || tok.Access == "" || tok.Refresh == "" {
		t.Fatalf("%+v %+v", sess, tok)
	}
	if _, _, err := s.Create(CreateParams{PrincipalID: "cc", Listener: "tls", Claims: Claims{Template: "nope"}}); err != ErrNoTemplate {
		t.Fatalf("got %v", err)
	}
	if _, _, err := s.Create(CreateParams{PrincipalID: "off", Listener: "tls"}); err != ErrUnknownPrincipal {
		t.Fatalf("got %v", err)
	}
	if _, _, err := s.Create(CreateParams{PrincipalID: "cc", Listener: "tls", Claims: Claims{Template: "rw"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(CreateParams{PrincipalID: "cc", Listener: "tls"}); err != ErrTooManySessions {
		t.Fatalf("got %v", err)
	}
	// Ending a session frees its slot.
	if !s.Terminate(sess.ID) {
		t.Fatal("terminate")
	}
	if _, _, err := s.Create(CreateParams{PrincipalID: "cc", Listener: "tls"}); err != nil {
		t.Fatalf("slot not freed: %v", err)
	}
	// Returned sessions are copies: writing to one changes nothing.
	sess.State = StateActive
	if s.Get(sess.ID).State != StateTerminated {
		t.Fatal("caller mutated the table")
	}
}

func TestAuthenticateAndLifetimes(t *testing.T) {
	// FR-2.5 is verified by internal/edge.TestTokenPresentation.
	reqtest.Verifies(t, "FR-2.9", "FR-2.22", "SR-2.1-2")
	reqtest.Partial(t, "FR-2.5", "SR-2.3-1")
	s := newStore(t)
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	sess, tok, _ := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	if sess.accessHash == tok.Access || len(sess.accessHash) != 64 {
		t.Fatal("token stored in clear or not as SHA-256")
	}
	if _, err := s.Authenticate(tok.Access, "tls"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(tok.Access, "uds"); err != ErrSessionInvalid {
		t.Fatal("token accepted on another listener")
	}
	if _, err := s.Authenticate("bogus", "tls"); err != ErrSessionInvalid {
		t.Fatal("bogus token accepted")
	}
	// Idle timeout.
	now = now.Add(31 * time.Minute)
	if _, err := s.Authenticate(tok.Access, "tls"); err != ErrSessionInvalid {
		t.Fatal("idle session accepted")
	}
	if got := s.Get(sess.ID); got.State != StateExpired || got.EndReason != EndIdle {
		t.Fatalf("state %s %s", got.State, got.EndReason)
	}
	// Refresh extends idle but not max lifetime, and rotates both tokens.
	now = time.Now()
	sess2, tok2, _ := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	for i := 0; i < 20; i++ {
		now = now.Add(25 * time.Minute)
		_, nt, err := s.Refresh(tok2.Refresh, "cid")
		if err != nil {
			if now.Sub(sess2.CreatedAt) > 8*time.Hour {
				return // expired by max lifetime, as required
			}
			t.Fatalf("refresh %d: %v", i, err)
		}
		if nt.Refresh == tok2.Refresh {
			t.Fatal("refresh token not rotated")
		}
		if _, err := s.Authenticate(tok2.Access, "tls"); err == nil {
			t.Fatal("old access token still valid after refresh")
		}
		tok2 = nt
	}
	t.Fatal("session outlived the maximum lifetime")
}

func TestRefreshReuseRevokesFamily(t *testing.T) {
	reqtest.Verifies(t, "FR-2.22")
	s := newStore(t)
	sess, tok, _ := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	// Another client cannot use the refresh token, and the attempt does not rotate it.
	if _, _, err := s.Refresh(tok.Refresh, "other"); err != ErrSessionInvalid {
		t.Fatalf("other client: %v", err)
	}
	_, t2, err := s.Refresh(tok.Refresh, "cid")
	if err != nil {
		t.Fatal(err)
	}
	// The old refresh token is replayed: the whole session is revoked.
	if _, _, err := s.Refresh(tok.Refresh, "cid"); err != ErrRefreshReuse {
		t.Fatalf("reuse: %v", err)
	}
	if got := s.Get(sess.ID); got.State != StateTerminated || got.EndReason != EndRefreshReuse {
		t.Fatalf("%s %s", got.State, got.EndReason)
	}
	if _, _, err := s.Refresh(t2.Refresh, "cid"); err != ErrSessionInvalid {
		t.Fatalf("current refresh token survived revocation: %v", err)
	}
	if _, err := s.Authenticate(t2.Access, "tls"); err != ErrSessionInvalid {
		t.Fatal("access token survived revocation")
	}
}

func TestSweepPrunesEndedSessions(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	var ended sync.WaitGroup
	ended.Add(2)
	s.OnEnd(func(Session) { ended.Done() })
	a, ta, _ := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
	s.Refresh(ta.Refresh, "cid")
	s.Terminate(a.ID)
	now = now.Add(31 * time.Minute) // the second idles out
	s.Sweep()
	ended.Wait()
	// The terminated session ended 31 minutes ago and is gone; the idle one
	// ended now and stays readable.
	if s.Len() != 1 || len(s.Active()) != 0 {
		t.Fatalf("len %d active %d", s.Len(), len(s.Active()))
	}
	now = now.Add(EndedRetention + time.Minute)
	s.Sweep()
	if s.Len() != 0 || len(s.usedRefresh) != 0 {
		t.Fatalf("ended sessions not pruned: %d %d", s.Len(), len(s.usedRefresh))
	}
}

// TestConcurrentAccess runs readers against writers; with -race it catches
// any field read outside the lock.
func TestConcurrentAccess(t *testing.T) {
	s := newStore(t)
	s.OnEnd(func(e Session) { _ = e.State })
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				sess, tok, err := s.Create(CreateParams{PrincipalID: "cc", ClientID: "cid", Listener: "tls"})
				if err != nil {
					continue
				}
				var inner sync.WaitGroup
				inner.Add(3)
				go func() { defer inner.Done(); s.Terminate(sess.ID) }()
				go func() {
					defer inner.Done()
					if e, err := s.Authenticate(tok.Access, "tls"); err == nil {
						_ = e.State + e.IdleDeadline.String()
					}
				}()
				go func() {
					defer inner.Done()
					if e := s.Get(sess.ID); e != nil {
						_ = e.State
					}
					for _, e := range s.Active() {
						_ = e.IdleDeadline
					}
				}()
				inner.Wait()
				s.Terminate(sess.ID)
			}
		}()
	}
	wg.Wait()
}
