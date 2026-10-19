package principals

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

func TestApproverDirectory(t *testing.T) {
	reqtest.Partial(t, "FR-2.23")
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Approvers = []config.Approver{{Username: "file-approver", PasswordHash: "$argon2id$x"}}
	d, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDirectory(d)
	adminHash, err := keys.HashPassword("administrator pw 1")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ user, pw string }{
		{"Bad Name", "long enough pw 1"},
		{"desk", "short"},
		{"desk", strings.Repeat("p", MaxApproverPassword+1)},
		{"desk", "administrator pw 1"}, // the Administrator's password
		{"admin", "long enough pw 1"},  // the Administrator's username
		{"file-approver", "long enough pw 1"},
	} {
		if _, err := d.AddApprover(c.user, c.pw, adminHash, "admin:admin"); err == nil {
			t.Errorf("accepted %q", c.user)
		}
	}
	v, err := d.AddApprover("desk", "desk approver pw 1", adminHash, "admin:admin")
	if err != nil || v.Source != "console" || v.CreatedBy != "admin:admin" {
		t.Fatalf("add: %v %+v", err, v)
	}
	if _, err := d.AddApprover("desk", "another pw 12345", adminHash, "admin:admin"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	a := cfg.FindApprover("desk")
	if a == nil || !keys.VerifyPassword(a.PasswordHash, "desk approver pw 1") {
		t.Fatalf("FindApprover: %+v", a)
	}
	if got := cfg.SessionApprovers(); len(got) != 2 || got[0].Username != "file-approver" || got[1].Username != "desk" {
		t.Fatalf("SessionApprovers: %+v", got)
	}
	raw, _ := os.ReadFile(filepath.Join(cfg.State.Dir, File))
	if strings.Contains(string(raw), "desk approver pw 1") {
		t.Fatal("password stored in clear")
	}
	d2, err := Open(cfg)
	if err != nil || len(d2.Approvers()) != 1 {
		t.Fatalf("not persisted: %v", err)
	}
	if l := d.ListApprovers(); len(l) != 2 || l[0].Username != "desk" || l[1].Source != "file" {
		t.Fatalf("list: %+v", l)
	}
	if err := d.RemoveApprover("file-approver"); !errors.Is(err, ErrFromFile) {
		t.Fatalf("remove file approver: %v", err)
	}
	if err := d.RemoveApprover("ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove unknown: %v", err)
	}
	if err := d.RemoveApprover("desk"); err != nil || cfg.FindApprover("desk") != nil {
		t.Fatalf("remove: %v", err)
	}
}

// TestApproverRoutes creates and removes a Session Approver through the
// control API: Administrator only, evidence before the change, no password
// or hash in any response, and the account's console sessions end on
// removal.
func TestApproverRoutes(t *testing.T) {
	reqtest.Partial(t, "FR-2.23")
	srv := httptest.NewUnstartedServer(nil)
	cfg := testConfig(t, srv.Listener.Addr().String())
	adminHash, _ := keys.HashPassword("administrator pw 1")
	snap, err := policy.Load(cfg.Policy.File)
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	admin, err := adminapi.New(adminapi.Options{Config: cfg, Controller: fakeCtl{}, Evidence: mem})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDirectory(d)
	var ended []string
	(&Service{Dir: d, Sessions: session.NewStore(cfg, func() *policy.Snapshot { return snap }), Snapshot: func() *policy.Snapshot { return snap }, Evidence: mem,
		AdminHash: func() string { return adminHash }, EndSessions: func(a string) int { ended = append(ended, a); return 1 }}).Register(admin)
	srv.Config.Handler = admin.Handler()
	srv.StartTLS()
	defer srv.Close()
	op, _ := keys.LoadAdminToken(cfg.State.Dir)
	do := func(method, path string, body any) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+op)
		r, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if code, out := do("POST", "/api/v1/approvers", map[string]any{"username": "desk", "password": "administrator pw 1"}); code != 400 {
		t.Fatalf("admin password: %d %s", code, out)
	}
	if n := len(mem.Events()); n != 0 {
		t.Fatalf("refused request recorded %d events", n)
	}
	if code, out := do("POST", "/api/v1/approvers", map[string]any{"username": "desk", "password": "desk approver pw 1"}); code != 201 || strings.Contains(out, "argon2") || strings.Contains(out, "desk approver pw 1") {
		t.Fatalf("create: %d %s", code, out)
	}
	if code, out := do("GET", "/api/v1/approvers", nil); code != 200 || !strings.Contains(out, `"desk"`) || strings.Contains(out, "argon2") {
		t.Fatalf("list: %d %s", code, out)
	}
	if code, out := do("POST", "/api/v1/approvers/desk/remove", map[string]any{"reason": "left"}); code != 200 || !strings.Contains(out, `"ended_console_sessions":1`) {
		t.Fatalf("remove: %d %s", code, out)
	}
	if len(ended) != 1 || ended[0] != "session_approver:desk" {
		t.Fatalf("console sessions ended: %v", ended)
	}
	if code, _ := do("POST", "/api/v1/approvers/desk/remove", map[string]any{}); code != 404 {
		t.Fatalf("second remove: %d", code)
	}
	var codes []string
	for _, e := range mem.Events() {
		codes = append(codes, e.ReasonCode)
		if strings.Contains(jsonOf(e), "desk approver pw 1") {
			t.Fatal("password in evidence")
		}
	}
	if strings.Join(codes, ",") != "SESSION_APPROVER_CREATED,SESSION_APPROVER_REMOVED" {
		t.Fatalf("evidence: %v", codes)
	}
	// Administrator only: no other role is in the matrix for these routes.
	for _, p := range []string{"GET /api/v1/approvers", "POST /api/v1/approvers", "POST /api/v1/approvers/{username}/remove"} {
		if r := adminapi.RolesFor(p); len(r) != 0 {
			t.Errorf("%s admits %v", p, r)
		}
	}
	mem.Fail(errors.New("disk full"))
	if code, _ := do("POST", "/api/v1/approvers", map[string]any{"username": "other", "password": "other approver pw"}); code != 503 || cfg.FindApprover("other") != nil {
		t.Fatalf("create without evidence: %d", code)
	}
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
