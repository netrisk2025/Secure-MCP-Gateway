package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type tokenAuth map[string][2]string

func (a tokenAuth) Authenticate(tok string) (string, string, bool) {
	v, ok := a[tok]
	return v[0], v[1], ok
}

func TestRoleSeam(t *testing.T) {
	// FR-8.2 asks for every Appendix C role; this covers the role check
	// for Administrator, Approver and an unknown role.
	reqtest.Partial(t, "FR-8.2")
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("[admin_listener]\naddress = \"127.0.0.1:8444\"\n[state]\ndir = \"" + dir + "\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	rec := &audit.Memory{}
	s, err := New(Options{Config: cfg, Controller: &fakeCtl{}, Evidence: rec})
	if err != nil {
		t.Fatal(err)
	}
	operator, _ := keys.LoadAdminToken(dir)
	s.AddAuthenticator(tokenAuth{"ap-tok": {"approver:alice", RoleApprover}, "aud-tok": {"auditor:bob", "auditor"}})
	var seen []string
	s.HandleRoles("GET /api/v1/test", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, ActorOf(r)+"/"+RoleOf(r))
		w.WriteHeader(http.StatusNoContent)
	}, RoleApprover)
	s.HandlePublic("GET /api/v1/test/public", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	do := func(method, path, tok string) int {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Host = "127.0.0.1:8444"
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w.Code
	}
	if c := do("GET", "/api/v1/test", operator); c != 204 {
		t.Fatalf("administrator: %d", c)
	}
	if c := do("GET", "/api/v1/test", "ap-tok"); c != 204 {
		t.Fatalf("approver: %d", c)
	}
	if c := do("GET", "/api/v1/test", "aud-tok"); c != 403 {
		t.Fatalf("other role: %d", c)
	}
	if c := do("GET", "/api/v1/test", "nope"); c != 401 {
		t.Fatalf("unknown token: %d", c)
	}
	// Handle routes stay Administrator-only.
	if c := do("POST", "/admin/v1/stop", "ap-tok"); c != 403 {
		t.Fatalf("approver on stop: %d", c)
	}
	if c := do("GET", "/admin/v1/health", operator); c != 200 {
		t.Fatalf("administrator on health: %d", c)
	}
	if c := do("GET", "/api/v1/test/public", ""); c != 204 {
		t.Fatalf("public: %d", c)
	}
	if strings.Join(seen, ",") != "operator-token/administrator,approver:alice/approver" {
		t.Fatalf("%v", seen)
	}
	refused := 0
	for _, e := range rec.Events() {
		if e.ReasonCode == "ADMIN_ROLE_REFUSED" {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("%d role refusals recorded", refused)
	}
}
