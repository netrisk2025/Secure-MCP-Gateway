package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// A long-lived response (an event stream) can tell when the token that
// opened it was signed out: StillAuthenticated re-resolves the token.
func TestStillAuthenticated(t *testing.T) {
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("[admin_listener]\naddress = \"127.0.0.1:8444\"\n[state]\ndir = \"" + dir + "\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Config: cfg, Controller: &fakeCtl{}, Evidence: &audit.Memory{}})
	if err != nil {
		t.Fatal(err)
	}
	operator, _ := keys.LoadAdminToken(dir)
	accounts := tokenAuth{"aud-tok": {"auditor:bob", RoleAuditor}}
	s.AddAuthenticator(accounts)
	var check func() bool
	s.HandleRoles("GET /api/v1/stream-test", func(w http.ResponseWriter, r *http.Request) {
		check = func() bool { return StillAuthenticated(r) }
		w.WriteHeader(http.StatusNoContent)
	}, RoleAuditor)
	open := func(tok string) {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/stream-test", nil)
		req.Host = "127.0.0.1:8444"
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("open: %d", w.Code)
		}
	}
	open("aud-tok")
	if !check() {
		t.Fatal("live token reported as not authenticated")
	}
	delete(accounts, "aud-tok") // signed out
	if check() {
		t.Fatal("signed-out token still reported as authenticated")
	}
	open(operator)
	if !check() {
		t.Fatal("operator token reported as not authenticated")
	}
	if StillAuthenticated(httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("unauthenticated request reported as authenticated")
	}
}
