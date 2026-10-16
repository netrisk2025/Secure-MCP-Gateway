package session

import (
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
	reqtest.Verifies(t, "FR-2.3", "FR-2.4", "FR-2.6", "FR-2.7", "FR-2.10", "FR-2.8")
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
}

func TestAuthenticateAndLifetimes(t *testing.T) {
	reqtest.Verifies(t, "FR-2.5", "FR-2.9", "FR-2.22", "SR-2.1-2", "SR-2.3-1")
	s := newStore(t)
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	sess, tok, _ := s.Create(CreateParams{PrincipalID: "cc", Listener: "tls"})
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
	if s.Get(sess.ID).State != StateExpired {
		t.Fatal("state not expired")
	}
	// Refresh extends idle but not max lifetime.
	now = time.Now()
	sess2, tok2, _ := s.Create(CreateParams{PrincipalID: "cc", Listener: "tls"})
	for i := 0; i < 20; i++ {
		now = now.Add(25 * time.Minute)
		_, nt, err := s.Refresh(tok2.Refresh)
		if err != nil {
			if now.Sub(sess2.CreatedAt) > 8*time.Hour {
				return // expired by max lifetime, as required
			}
			t.Fatalf("refresh %d: %v", i, err)
		}
		if _, err := s.Authenticate(tok2.Access, "tls"); err == nil {
			t.Fatal("old access token still valid after refresh")
		}
		tok2 = nt
	}
	t.Fatal("session outlived the maximum lifetime")
}
