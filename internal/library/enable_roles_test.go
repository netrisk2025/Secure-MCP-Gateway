package library

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// roleTokens authenticates "role-<role>" as an actor of that role, as the
// console's account sessions do.
type roleTokens struct{}

func (roleTokens) Authenticate(tok string) (string, string, bool) {
	role, ok := strings.CutPrefix(tok, "role-")
	if !ok {
		return "", "", false
	}
	return role + ":tester", role, true
}

// TestEnableOnlyByAdministrator is SR-3.9-1: a revision moves from
// verified-disabled to enabled only on an authenticated Administrator
// action. Import and the library scan leave it verified-disabled;
// enablement through the control API by each non-Administrator role of
// Appendix C (Operator, Policy Author, Approver, Session Approver,
// Auditor, Researcher), by an unauthenticated caller and by an unknown
// token is refused and changes nothing; the Administrator (operator token
// and an administrator account) enables it.
func TestEnableOnlyByAdministrator(t *testing.T) {
	reqtest.Verifies(t, "SR-3.9-1")
	r := newRuntime(t, fixtureDesc)
	if _, err := r.lib.Import(r.pkg(pkgtest.Spec{ID: "role-pkg", Revision: "1.0.0", Alias: "rp"}), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	r.lib.Scan("scan")
	state := func() string {
		rev, ok := r.lib.Get("role-pkg", "1.0.0")
		if !ok {
			t.Fatal("revision missing")
		}
		return rev.State
	}
	if s := state(); s != StateVerifiedDisabled {
		t.Fatalf("after import and scan: %s", s)
	}
	r.start(t, []config.Server{{Alias: "fx", Package: "fx-id"}})
	f := newAPI(t, r)
	f.api.AddAuthenticator(roleTokens{})
	const path = "/api/v1/packages/role-pkg/1.0.0/enable"
	for _, role := range adminapi.Roles {
		if role == adminapi.RoleAdministrator {
			continue
		}
		if st, out := f.do("POST", path, "role-"+role, map[string]any{}); st != http.StatusForbidden {
			t.Errorf("%s: %d %v", role, st, out)
		}
	}
	for _, tok := range []string{"", "not-a-token"} {
		if st, _ := f.do("POST", path, tok, map[string]any{}); st != http.StatusUnauthorized {
			t.Errorf("token %q: %d", tok, st)
		}
	}
	if s := state(); s != StateVerifiedDisabled {
		t.Fatalf("enabled by a refused caller: %s", s)
	}
	// An administrator account enables it.
	if st, out := f.do("POST", path, "role-"+adminapi.RoleAdministrator, map[string]any{}); st != http.StatusOK {
		t.Fatalf("administrator account: %d %v", st, out)
	}
	if s := state(); s != StateEnabled {
		t.Fatalf("after the Administrator: %s", s)
	}
	// And the operator token (the Administrator's own credential) too.
	if st, out := f.do("POST", "/api/v1/packages/role-pkg/1.0.0/disable", f.token, map[string]any{}); st != http.StatusOK {
		t.Fatalf("disable: %d %v", st, out)
	}
	if st, out := f.do("POST", path, f.token, map[string]any{}); st != http.StatusOK || state() != StateEnabled {
		t.Fatalf("operator token: %d %v", st, out)
	}
}
