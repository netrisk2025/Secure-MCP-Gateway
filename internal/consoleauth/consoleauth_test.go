package consoleauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type nopCtl struct{}

func (nopCtl) Health() edge.Health                                   { return edge.Health{} }
func (nopCtl) Stop(string, string) error                             { return nil }
func (nopCtl) Resume(string) error                                   { return nil }
func (nopCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

type fixture struct {
	srv *adminapi.Server
	rec *audit.Memory
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	hash, err := keys.HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	toml := "[admin_listener]\naddress = \"127.0.0.1:8444\"\n[state]\ndir = \"" + dir + "\"\n[admin]\nusername = \"admin\"\npassword_hash = \"" + hash + "\"\n" +
		"[[approver]]\nusername = \"sam\"\npassword_hash = \"" + hash + "\"\n"
	for _, a := range [][2]string{{"olga", "operator"}, {"pat", "policy_author"}, {"aud", "auditor"}, {"rita", "researcher"}} {
		toml += "[[console.account]]\nusername = \"" + a[0] + "\"\npassword_hash = \"" + hash + "\"\nrole = \"" + a[1] + "\"\n"
	}
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{rec: &audit.Memory{}, now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	f.srv, err = adminapi.New(adminapi.Options{Config: cfg, Controller: nopCtl{}, Evidence: f.rec})
	if err != nil {
		t.Fatal(err)
	}
	New(Options{Config: cfg, Evidence: f.rec, Now: func() time.Time { return f.now }}).Register(f.srv)
	f.srv.Handle("POST /api/v1/sessions/{id}/terminate", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	f.srv.Handle("GET /api/v1/clients", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return f
}

func (f *fixture) do(method, path, tok, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:8444"
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *fixture) login(t *testing.T, user, role string) string {
	t.Helper()
	body := `{"username":"` + user + `","password":"correct horse battery"`
	if role != "" {
		body += `,"role":"` + role + `"`
	}
	code, out := f.do("POST", "/api/v1/console/login", "", body+"}")
	if code != 200 {
		t.Fatalf("login %s: %d %v", user, code, out)
	}
	return out["token"].(string)
}

func TestConsoleAccounts(t *testing.T) {
	// The accounts exist for every Appendix C role; the full matrix is
	// exercised in adminapi.TestAppendixCMatrix.
	reqtest.Partial(t, "FR-8.2")
	f := newFixture(t)
	for user, role := range map[string]string{"olga": "operator", "pat": "policy_author", "aud": "auditor", "rita": "researcher"} {
		tok := f.login(t, user, "")
		code, me := f.do("GET", "/api/v1/console/session", tok, "")
		if code != 200 || me["role"] != role || me["actor"] != role+":"+user {
			t.Fatalf("%s session: %d %v", user, code, me)
		}
		if len(me["routes"].([]any)) == 0 {
			t.Fatalf("no routes listed")
		}
	}
	// An Operator may terminate a session; an Auditor may not.
	if code, _ := f.do("POST", "/api/v1/sessions/s1/terminate", f.login(t, "olga", ""), "{}"); code != 204 {
		t.Fatalf("operator terminate: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/sessions/s1/terminate", f.login(t, "aud", ""), "{}"); code != 403 {
		t.Fatalf("auditor terminate: %d", code)
	}
	// Session Approvers ([[approver]]) sign in with their role and reach
	// the client registrations, not the sessions.
	sa := f.login(t, "sam", "session_approver")
	if code, _ := f.do("GET", "/api/v1/clients", sa, ""); code != 204 {
		t.Fatalf("session approver clients: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/sessions/s1/terminate", sa, "{}"); code != 403 {
		t.Fatalf("session approver terminate: %d", code)
	}
	// A Session Approver is not a console account and vice versa.
	if code, _ := f.do("POST", "/api/v1/console/login", "", `{"username":"sam","password":"correct horse battery"}`); code != 401 {
		t.Fatalf("session approver without role: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/console/login", "", `{"username":"olga","password":"correct horse battery","role":"auditor"}`); code != 401 {
		t.Fatalf("wrong role: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/console/login", "", `{"username":"olga","password":"wrong"}`); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/console/login", "", `{"username":"olga","password":"x","role":"administrator"}`); code != 400 {
		t.Fatalf("administrator role: %d", code)
	}
	// Logout ends the token; expiry too.
	tok := f.login(t, "pat", "")
	if code, _ := f.do("POST", "/api/v1/console/logout", tok, "{}"); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/console/session", tok, ""); code != 401 {
		t.Fatalf("after logout: %d", code)
	}
	tok = f.login(t, "pat", "")
	f.now = f.now.Add(SessionTTL)
	if code, _ := f.do("GET", "/api/v1/console/session", tok, ""); code != 401 {
		t.Fatalf("after expiry: %d", code)
	}
	ok, failed := 0, 0
	for _, e := range f.rec.Events() {
		switch e.ReasonCode {
		case "CONSOLE_SIGNIN":
			ok++
		case "CONSOLE_SIGNIN_FAILED":
			failed++
		}
	}
	if ok == 0 || failed < 3 {
		t.Fatalf("evidence: %d sign-ins, %d failures", ok, failed)
	}
}
