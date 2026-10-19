package adminapi

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// matrixServer registers a stub handler on every matrix route that New
// did not register, and a token per role.
func matrixServer(t *testing.T) (*Server, map[string]string) {
	t.Helper()
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
	registered := map[string]bool{}
	for _, r := range s.Routes() {
		registered[r.Pattern] = true
	}
	stub := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	// Administrator-only routes of other elements that the rows exercise.
	adminOnly := []string{"POST /api/v1/packages/{id}/{rev}/enable", "POST /api/v1/packages/{id}/{rev}/retire", "POST /api/v1/remote/enable",
		"POST /api/v1/secrets", "POST /api/v1/secrets/{name}/rotate", "DELETE /api/v1/secrets/{name}"}
	for _, p := range append(MatrixPatterns(), adminOnly...) {
		if !registered[p] {
			s.Handle(p, stub)
		}
	}
	operator, _ := keys.LoadAdminToken(dir)
	toks := map[string]string{RoleAdministrator: operator}
	auth := tokenAuth{}
	for _, role := range Roles[1:] {
		toks[role] = role + "-token"
		auth[role+"-token"] = [2]string{role + ":someone", role}
	}
	s.AddAuthenticator(auth)
	return s, toks
}

func call(s *Server, tok, method, path, body string) int {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:8444"
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code
}

// TestAppendixCMatrix exercises one control API operation per Appendix C
// row as every role and compares the outcome with the matrix. Rows whose
// operations do not exist yet (principal and credential management,
// Session Approver account creation, S3 payload grants, purge, memory
// budgets) are not covered, and the Researcher's pseudonymized view of S2
// fields is approximated by refusing the raw record route, so the claim is
// partial.
func TestAppendixCMatrix(t *testing.T) {
	reqtest.Partial(t, "FR-8.2")
	s, toks := matrixServer(t)
	const (
		A = RoleAdministrator
		O = RoleOperator
		P = RolePolicyAuthor
		V = RoleApprover
		S = RoleSessionApprover
		U = RoleAuditor
		R = RoleResearcher
	)
	all := []string{A, O, P, V, S, U, R}
	rows := []struct {
		row, method, path, body string
		allowed                 []string
	}{
		{"emergency stop", "POST", "/admin/v1/stop", `{"reason":"x"}`, []string{A, O}},
		{"resume", "POST", "/admin/v1/resume", `{}`, []string{A}},
		{"view health", "GET", "/admin/v1/health", "", all},
		{"view health status", "GET", "/api/v1/health/status", "", all},
		{"simulate policy draft", "POST", "/api/v1/policy/simulate", `{}`, []string{A, P}},
		{"edit (validate) policy draft", "POST", "/api/v1/policy/validate", `{}`, []string{A, P}},
		{"publish policy", "POST", "/api/v1/policy/revisions", `{}`, []string{A, P}},
		{"roll back policy", "POST", "/api/v1/policy/rollback", `{}`, []string{A, P}},
		{"create research campaign", "POST", "/api/v1/research/campaigns", `{}`, []string{A, P, R}},
		{"submit research campaign", "POST", "/api/v1/research/campaigns/c1/submit", `{}`, []string{A, P, R}},
		{"approve research campaign", "POST", "/api/v1/research/campaigns/c1/approve", `{}`, []string{A, P}},
		{"approve dynamic client registration", "POST", "/api/v1/clients/c1/approve", `{}`, []string{A, S}},
		{"enable server", "POST", "/api/v1/packages/p/1/enable", `{}`, []string{A}},
		{"suspend server", "POST", "/api/v1/packages/p/1/disable", `{}`, []string{A, O}},
		{"retire server", "POST", "/api/v1/packages/p/1/retire", `{}`, []string{A}},
		{"enable Remote Access Profile", "POST", "/api/v1/remote/enable", `{}`, []string{A}},
		{"terminate session", "POST", "/api/v1/sessions/s1/terminate", `{}`, []string{A, O}},
		{"secret create", "POST", "/api/v1/secrets", `{}`, []string{A}},
		{"secret rotate", "POST", "/api/v1/secrets/n/rotate", `{}`, []string{A}},
		{"secret revoke", "DELETE", "/api/v1/secrets/n", "", []string{A}},
		{"audit query", "GET", "/api/v1/audit/events", "", []string{A, O, P, U}},
		{"audit export", "GET", "/api/v1/audit/export", "", []string{A, O, P, U}},
		{"observation analytics", "GET", "/api/v1/observations/aggregate", "", []string{A, O, P, U, R}},
		{"observation S2 fields (raw records)", "GET", "/api/v1/observations", "", []string{A, O, P, U}},
		{"baseline promotion", "POST", "/api/v1/baselines/b1/promote", `{}`, []string{A, P}},
		{"backups", "POST", "/api/v1/backup", `{}`, []string{A, O}},
		{"key rotation", "POST", "/api/v1/keys/rotate", `{}`, []string{A, O}},
		{"dataset export of a campaign", "POST", "/api/v1/research/exports", `{"campaign_id":"c1"}`, []string{A, R}},
		{"dataset export without a campaign", "POST", "/api/v1/research/exports", `{"format":"csv"}`, []string{A}},
	}
	for _, row := range rows {
		for _, role := range all {
			got := call(s, toks[role], row.method, row.path, row.body)
			want := http.StatusForbidden
			if slices.Contains(row.allowed, role) {
				want = http.StatusNoContent
				if row.path == "/admin/v1/stop" || row.path == "/admin/v1/resume" || row.path == "/admin/v1/health" {
					want = http.StatusOK
				}
			}
			if got != want {
				t.Errorf("%s (%s %s) as %s: got %d, want %d", row.row, row.method, row.path, role, got, want)
			}
		}
	}
}

// TestRoutesRecordRoles checks the route table the console and the OpenAPI
// document read.
func TestRoutesRecordRoles(t *testing.T) {
	reqtest.Partial(t, "FR-8.2")
	s, _ := matrixServer(t)
	var stop, login *RouteInfo
	for _, r := range s.Routes() {
		switch r.Pattern {
		case "POST /admin/v1/stop":
			stop = &r
		case "POST /admin/v1/login":
			login = &r
		}
	}
	if stop == nil || !slices.Equal(stop.Roles, []string{RoleAdministrator, RoleOperator}) {
		t.Fatalf("stop: %+v", stop)
	}
	if login == nil || !login.Public || login.Roles != nil {
		t.Fatalf("login: %+v", login)
	}
	if len(MatrixPatterns()) < 50 {
		t.Fatalf("matrix too small: %d", len(MatrixPatterns()))
	}
}
