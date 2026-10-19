package adminapi

import (
	"net/http"
	"slices"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAuditRoutesByRole is SR-6.16-1: every audit query and export route
// of the control API (journal browser, export, verification, evidence
// stream and the graph investigation queries) is authorized by the
// caller's Appendix C role: Administrator, Operator, Policy Author and
// Auditor may query and export; Approver, Session Approver and Researcher
// are refused.
func TestAuditRoutesByRole(t *testing.T) {
	reqtest.Verifies(t, "SR-6.16-1")
	s, toks := matrixServer(t)
	allowed := []string{RoleAdministrator, RoleOperator, RolePolicyAuthor, RoleAuditor}
	routes := []struct{ method, path string }{
		{"GET", "/api/v1/audit/events"},
		{"GET", "/api/v1/audit/events/e1"},
		{"GET", "/api/v1/audit/export"},
		{"GET", "/api/v1/audit/verify"},
		{"POST", "/api/v1/audit/verify"},
		{"GET", "/api/v1/audit/stream"},
		{"GET", "/api/v1/graph/status"},
		{"GET", "/api/v1/graph/neighborhood"},
		{"GET", "/api/v1/graph/events/e1/path"},
		{"GET", "/api/v1/graph/queries"},
		{"GET", "/api/v1/graph/queries/q"},
	}
	for _, r := range routes {
		for _, role := range Roles {
			body := ""
			if r.method == http.MethodPost {
				body = `{}`
			}
			got := call(s, toks[role], r.method, r.path, body)
			want := http.StatusForbidden
			if slices.Contains(allowed, role) {
				want = http.StatusNoContent
			}
			if got != want {
				t.Errorf("%s %s as %s: %d, want %d", r.method, r.path, role, got, want)
			}
		}
	}
	// Unauthenticated callers are refused before any role check.
	for _, r := range routes {
		if got := call(s, "", r.method, r.path, ""); got != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: %d", r.method, r.path, got)
		}
	}
}

// TestResearcherExclusions is SR-2-2 in part: the Researcher role is
// refused policy publication, approval decisions, secret operations,
// dynamic-client decisions and raw observation records (S2 fields), and
// may export a dataset only for a named campaign.
//
// Partial: this matrix server stubs the routes; the refusal of every
// excluded operation by the real elements, credential operations and S3
// payload access included, is internal/acceptance.TestResearcherRoleLimits.
func TestResearcherExclusions(t *testing.T) {
	reqtest.Partial(t, "SR-2-2")
	s, toks := matrixServer(t)
	stub := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	// Approval decisions are registered by internal/approval for Approvers.
	s.HandleRoles("POST /api/v1/approvals/{id}/approve", stub, RoleApprover)
	s.HandleRoles("POST /api/v1/approvals/{id}/deny", stub, RoleApprover)
	researcher := toks[RoleResearcher]
	for _, r := range []struct{ method, path, body string }{
		{"POST", "/api/v1/policy/revisions", `{}`},
		{"POST", "/api/v1/policy/rollback", `{}`},
		{"POST", "/admin/v1/policy/reload", `{}`},
		{"POST", "/api/v1/approvals/a1/approve", `{}`},
		{"POST", "/api/v1/approvals/a1/deny", `{}`},
		{"POST", "/api/v1/secrets", `{}`},
		{"POST", "/api/v1/secrets/n/rotate", `{}`},
		{"DELETE", "/api/v1/secrets/n", ""},
		{"GET", "/api/v1/secrets", ""},
		{"POST", "/api/v1/clients/c1/approve", `{}`},
		{"POST", "/api/v1/clients/c1/deny", `{}`},
		{"GET", "/api/v1/observations", ""},
		{"POST", "/api/v1/research/campaigns/c1/approve", `{}`},
		{"POST", "/api/v1/research/exports", `{"format":"csv"}`},
	} {
		if got := call(s, researcher, r.method, r.path, r.body); got != http.StatusForbidden {
			t.Errorf("researcher %s %s: %d, want 403", r.method, r.path, got)
		}
	}
	if got := call(s, researcher, "POST", "/api/v1/research/exports", `{"campaign_id":"c1"}`); got != http.StatusNoContent {
		t.Errorf("researcher export of a campaign: %d", got)
	}
	if got := call(s, toks[RoleApprover], "POST", "/api/v1/approvals/a1/approve", `{}`); got != http.StatusNoContent {
		t.Errorf("approver decision: %d", got)
	}
}
