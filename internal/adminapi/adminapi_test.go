package adminapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type fakeCtl struct {
	mu      sync.Mutex
	stopped bool
	actors  []string
	snap    *policy.Snapshot
}

func (f *fakeCtl) Health() edge.Health {
	return edge.Health{State: "degraded", Causes: []string{"unconfined"}}
}
func (f *fakeCtl) Stop(actor, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped, f.actors = true, append(f.actors, "stop:"+actor)
	return nil
}
func (f *fakeCtl) Resume(actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped, f.actors = false, append(f.actors, "resume:"+actor)
	return nil
}
func (f *fakeCtl) ActivatePolicy(actor string, s *policy.Snapshot) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snap != nil && f.snap.Revision == s.Revision {
		if f.snap.Digest != s.Digest {
			return false, policy.ErrRevisionReused
		}
		return false, nil
	}
	f.snap = s
	return true, nil
}

type fixture struct {
	t        *testing.T
	srv      *httptest.Server
	cfg      *config.Config
	ctl      *fakeCtl
	rec      *audit.Memory
	operator string
	server   *Server
	now      time.Time
}

const pol = `{"revision":"%s","framework_profiles":{"dev":{"templates":["ro"],"default_template":"ro"}},"templates":{"ro":{"rules":[%s]}}}`

func newFixture(t *testing.T, adminTOML string) *fixture {
	t.Helper()
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, ctl: &fakeCtl{}, rec: &audit.Memory{}, now: time.Now()}
	f.srv = httptest.NewUnstartedServer(nil)
	toml := fmt.Sprintf("[admin_listener]\naddress = %q\n[state]\ndir = %q\n[policy]\nfile = %q\n[admin]\nusername = \"admin\"\n%s\n",
		f.srv.Listener.Addr().String(), dir, filepath.Join(dir, "policy.json"), adminTOML)
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = cfg
	os.WriteFile(cfg.Policy.File, []byte(fmt.Sprintf(pol, "r1", "")), 0o600)
	s, err := New(Options{Config: cfg, Controller: f.ctl, Evidence: f.rec,
		Guard: authguard.New(authguard.Config{MaxFailures: 3, PerSourcePerMinute: 1000}), Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	f.server = s
	f.operator, _ = keys.LoadAdminToken(dir)
	f.srv.Config.Handler = s.Handler()
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) do(method, path, token string, body any, hdr map[string]string) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	r, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]any
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

func TestControlAPIAuthenticationAndCSRF(t *testing.T) {
	// The bearer-token half; browser sessions are browser_test.go.
	reqtest.Partial(t, "SR-2.5-1")
	hash, _ := keys.HashPassword("admin password 12")
	f := newFixture(t, fmt.Sprintf("password_hash = %q", hash))
	if st, _ := f.do("GET", "/admin/v1/health", "", nil, nil); st != 401 {
		t.Fatalf("unauthenticated: %d", st)
	}
	if st, _ := f.do("GET", "/admin/v1/health", "some-harness-session-token", nil, nil); st != 401 {
		t.Fatalf("foreign token: %d", st)
	}
	if e := f.rec.Events(); len(e) == 0 || e[len(e)-1].ReasonCode != "ADMIN_AUTH_FAILED" {
		t.Fatal("authentication failure not recorded")
	}
	if st, body := f.do("GET", "/admin/v1/health", f.operator, nil, nil); st != 200 || body["state"] != "degraded" {
		t.Fatalf("%d %v", st, body)
	}
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"foreign origin", map[string]string{"Origin": "https://evil.example"}, 403},
		{"cross-site fetch", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"wrong host", map[string]string{"Host": "evil.example"}, 421},
	}
	for _, c := range cases {
		if st, _ := f.do("POST", "/admin/v1/stop", f.operator, map[string]any{}, c.hdr); st != c.want {
			t.Errorf("%s: %d", c.name, st)
		}
	}
	// A form post (what a cross-site page can send without preflight) is refused.
	req, _ := http.NewRequest("POST", f.srv.URL+"/admin/v1/stop", strings.NewReader("reason=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+f.operator)
	r, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 415 {
		t.Fatalf("form post: %d", r.StatusCode)
	}
	if f.ctl.stopped {
		t.Fatal("a refused request stopped the Gateway")
	}
	if r.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("framing allowed")
	}
}

func TestStopResumeAndLogin(t *testing.T) {
	reqtest.Verifies(t, "FR-4.14")
	hash, _ := keys.HashPassword("admin password 12")
	f := newFixture(t, fmt.Sprintf("password_hash = %q", hash))
	if st, _ := f.do("POST", "/admin/v1/stop", f.operator, map[string]any{"reason": "drill"}, nil); st != 200 || !f.ctl.stopped {
		t.Fatalf("stop: %d", st)
	}
	// A non-administrator cannot resume.
	if st, _ := f.do("POST", "/admin/v1/resume", "not-an-admin", map[string]any{}, nil); st != 401 || !f.ctl.stopped {
		t.Fatalf("non-admin resume: %d", st)
	}
	// Administrator session via password sign-in.
	st, body := f.do("POST", "/admin/v1/login", "", map[string]any{"username": "admin", "password": "admin password 12"}, nil)
	if st != 200 {
		t.Fatalf("login: %d %v", st, body)
	}
	tok := body["token"].(string)
	if st, _ := f.do("POST", "/admin/v1/resume", tok, map[string]any{}, nil); st != 200 || f.ctl.stopped {
		t.Fatalf("admin resume: %d", st)
	}
	if strings.Join(f.ctl.actors, ",") != "stop:operator-token,resume:admin:admin" {
		t.Fatalf("actors %v", f.ctl.actors)
	}
	// Session tokens expire and log out.
	f.now = f.now.Add(SessionTTL + time.Second)
	if st, _ := f.do("GET", "/admin/v1/health", tok, nil, nil); st != 401 {
		t.Fatalf("expired admin session accepted: %d", st)
	}
	// Repeated wrong passwords lock the account.
	for i := 0; i < 3; i++ {
		f.do("POST", "/admin/v1/login", "", map[string]any{"username": "admin", "password": "wrong"}, nil)
	}
	if st, _ := f.do("POST", "/admin/v1/login", "", map[string]any{"username": "admin", "password": "admin password 12"}, nil); st != 429 {
		t.Fatalf("lockout: %d", st)
	}
	// Approvals placeholder.
	if st, body := f.do("GET", "/admin/v1/approvals", f.operator, nil, nil); st != 200 || body["service"] != "none" {
		t.Fatalf("%d %v", st, body)
	}
	if st, _ := f.do("POST", "/admin/v1/approvals/x", f.operator, map[string]any{"decision": "approve"}, nil); st != 501 {
		t.Fatalf("approve without service: %d", st)
	}
}

func TestPolicyReload(t *testing.T) {
	reqtest.Verifies(t, "FR-3.10")
	hash, _ := keys.HashPassword("admin password 12")
	f := newFixture(t, fmt.Sprintf("password_hash = %q", hash))
	if st, body := f.do("POST", "/admin/v1/policy/reload", f.operator, map[string]any{}, nil); st != 200 || body["revision"] != "r1" || body["changed"] != true {
		t.Fatalf("%d %v", st, body)
	}
	os.WriteFile(f.cfg.Policy.File, []byte(`{"revision":`), 0o600)
	if st, _ := f.do("POST", "/admin/v1/policy/reload", f.operator, map[string]any{}, nil); st != 422 {
		t.Fatalf("invalid policy: %d", st)
	}
	os.WriteFile(f.cfg.Policy.File, []byte(fmt.Sprintf(pol, "r1", `{"id":"a","server":"x","tools":["t"]}`)), 0o600)
	if st, _ := f.do("POST", "/admin/v1/policy/reload", f.operator, map[string]any{}, nil); st != 409 {
		t.Fatalf("revision reuse: %d", st)
	}
	if f.ctl.snap.Revision != "r1" || f.ctl.snap.Digest == "" {
		t.Fatal("snapshot changed")
	}
}

func TestBootstrapTokenRedeemedOnce(t *testing.T) {
	token := "bootstrap-token-0123456789-abcdefghijklmnop"
	sum := sha256.Sum256([]byte(token))
	f := newFixture(t, fmt.Sprintf("bootstrap_token_sha256 = %q\nbootstrap_token_expires = %q", hex.EncodeToString(sum[:]), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)))
	// No password yet: sign-in fails.
	if st, _ := f.do("POST", "/admin/v1/login", "", map[string]any{"username": "admin", "password": "new admin password"}, nil); st != 401 {
		t.Fatalf("login before bootstrap: %d", st)
	}
	if st, _ := f.do("POST", "/admin/v1/bootstrap", "", map[string]any{"token": "wrong", "password": "new admin password"}, nil); st != 401 {
		t.Fatalf("wrong token: %d", st)
	}
	if st, _ := f.do("POST", "/admin/v1/bootstrap", "", map[string]any{"token": token, "password": "short"}, nil); st != 400 {
		t.Fatalf("weak password: %d", st)
	}
	if st, body := f.do("POST", "/admin/v1/bootstrap", "", map[string]any{"token": token, "password": "new admin password"}, nil); st != 204 {
		t.Fatalf("redeem: %d %v", st, body)
	}
	if st, _ := f.do("POST", "/admin/v1/bootstrap", "", map[string]any{"token": token, "password": "another password!"}, nil); st != 409 {
		t.Fatalf("second redeem: %d", st)
	}
	if st, _ := f.do("POST", "/admin/v1/login", "", map[string]any{"username": "admin", "password": "new admin password"}, nil); st != 200 {
		t.Fatalf("login after bootstrap: %d", st)
	}
	st, err := os.Stat(filepath.Join(f.cfg.State.Dir, AdminPasswordFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("password file: %v", err)
	}
}

func TestBootstrapTokenExpires(t *testing.T) {
	token := "bootstrap-token-0123456789-abcdefghijklmnop"
	sum := sha256.Sum256([]byte(token))
	f := newFixture(t, fmt.Sprintf("bootstrap_token_sha256 = %q\nbootstrap_token_expires = %q", hex.EncodeToString(sum[:]), time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)))
	if st, _ := f.do("POST", "/admin/v1/bootstrap", "", map[string]any{"token": token, "password": "new admin password"}, nil); st != 410 {
		t.Fatalf("expired token: %d", st)
	}
}
