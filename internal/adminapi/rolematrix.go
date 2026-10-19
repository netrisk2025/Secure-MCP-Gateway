package adminapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// The remaining application roles of SRS Appendix C (FR-8.2). Their
// accounts are configured in [[console.account]] (Operator, Policy Author,
// Auditor, Researcher) and [[approver]] (Session Approver) and signed in by
// internal/consoleauth; Approvers are E-07's [[approvals.account]].
const (
	RoleOperator        = "operator"
	RolePolicyAuthor    = "policy_author"
	RoleAuditor         = "auditor"
	RoleResearcher      = "researcher"
	RoleSessionApprover = "session_approver"
)

// Roles lists every Appendix C role in the matrix's column order.
var Roles = []string{RoleAdministrator, RoleOperator, RolePolicyAuthor, RoleApprover, RoleSessionApprover, RoleAuditor, RoleResearcher}

var (
	everyRole  = []string{RoleOperator, RolePolicyAuthor, RoleApprover, RoleSessionApprover, RoleAuditor, RoleResearcher}
	analytics  = []string{RoleOperator, RolePolicyAuthor, RoleAuditor, RoleResearcher}
	auditQuery = []string{RoleOperator, RolePolicyAuthor, RoleAuditor}
	opsRead    = []string{RoleOperator, RoleAuditor}
	operator   = []string{RoleOperator}
	author     = []string{RolePolicyAuthor}
)

// routeRoles is the Appendix C matrix expressed per control API route: the
// roles besides the Administrator that may use the route. The Administrator
// may use every route. A route missing here is Administrator-only (or, for
// HandleRoles routes, admits the roles its element names).
//
// Mapping of the matrix rows:
//   - Emergency stop / resume: Operator may stop, not resume.
//   - View health and status: every role.
//   - Edit, simulate, publish, roll back policy: Policy Author. Policy
//     reads are also open to Operators and Auditors, who need the rules
//     behind a decision.
//   - Approve research campaign: Policy Author; Researchers create, submit
//     and stop their own campaigns (refined below).
//   - Approve dynamic client registrations: Session Approver.
//   - Enable / suspend / retire servers: Operator may suspend only.
//   - Principals, credentials, sessions: Operator may suspend and
//     terminate sessions (not resume them).
//   - Secret create / rotate / revoke: Administrator only; metadata reads
//     are open to Operators and Auditors.
//   - Audit query and redacted export: Operator, Policy Author, Auditor.
//   - Observation analytics (S0/S1): Operator, Policy Author, Auditor,
//     Researcher. Raw observation records carry S2 fields, which the
//     Researcher may see only pseudonymized, so that route excludes the
//     Researcher.
//   - Baseline promotion / rollback: Policy Author.
//   - Memory budgets, backups, key rotation: Operator.
//   - Dataset export: Researcher, for approved campaigns (refined below).
var routeRoles = map[string][]string{
	// adminapi
	"GET /admin/v1/health":         everyRole,
	"POST /admin/v1/stop":          operator,
	"POST /admin/v1/policy/reload": author,

	// policyadmin (E-05)
	"GET /api/v1/policy":                            {RoleOperator, RolePolicyAuthor, RoleAuditor},
	"GET /api/v1/policy/revisions":                  {RoleOperator, RolePolicyAuthor, RoleAuditor},
	"GET /api/v1/policy/revisions/{id}":             {RoleOperator, RolePolicyAuthor, RoleAuditor},
	"GET /api/v1/policy/revisions/{id}/permissions": {RoleOperator, RolePolicyAuthor, RoleAuditor},
	"POST /api/v1/policy/revisions":                 author,
	"POST /api/v1/policy/validate":                  author,
	"POST /api/v1/policy/diff":                      author,
	"POST /api/v1/policy/simulate":                  author,
	"POST /api/v1/policy/rollback":                  author,

	// filters (E-09, E-11): the G-02 filter test workbench
	"GET /api/v1/filters":       {RoleOperator, RolePolicyAuthor, RoleAuditor},
	"POST /api/v1/filters/scan": author,

	// egress (E-18)
	"GET /api/v1/egress":             opsRead,
	"GET /api/v1/egress/grants":      opsRead,
	"GET /api/v1/egress/connections": opsRead,

	// secrets (E-19, E-20): metadata only
	"GET /api/v1/secrets":               opsRead,
	"GET /api/v1/secrets/{name}":        opsRead,
	"GET /api/v1/secrets/{name}/impact": opsRead,

	// graph (E-25, E-26, E-28)
	"GET /api/v1/graph/status":           auditQuery,
	"POST /api/v1/graph/rebuild":         operator,
	"GET /api/v1/graph/neighborhood":     auditQuery,
	"GET /api/v1/graph/events/{id}/path": auditQuery,
	"GET /api/v1/graph/queries":          auditQuery,
	"GET /api/v1/graph/queries/{name}":   auditQuery,

	// sandbox (E-15, E-17)
	"GET /api/v1/runtime":                      opsRead,
	"GET /api/v1/runtime/instances":            opsRead,
	"GET /api/v1/runtime/instances/{id}":       opsRead,
	"POST /api/v1/runtime/instances/{id}/kill": operator,
	"GET /api/v1/runtime/doctor":               opsRead,

	// consoleapi (E-24)
	"GET /api/v1/sessions":                 opsRead,
	"GET /api/v1/sessions/principals":      opsRead,
	"GET /api/v1/sessions/{id}":            opsRead,
	"POST /api/v1/sessions/{id}/terminate": operator,
	"POST /api/v1/sessions/{id}/suspend":   operator,
	// Resuming a session is the Administrator's: the Operator may suspend
	// and terminate sessions only (Appendix C).
	"GET /api/v1/principals":                 opsRead,
	"GET /api/v1/servers":                    auditQuery,
	"GET /api/v1/servers/{alias}":            auditQuery,
	"GET /api/v1/catalog":                    auditQuery,
	"GET /api/v1/audit/events":               auditQuery,
	"GET /api/v1/audit/events/{id}":          auditQuery,
	"GET /api/v1/decisions/{id}/explanation": auditQuery,
	"GET /api/v1/audit/export":               auditQuery,
	"GET /api/v1/audit/verify":               auditQuery,
	"POST /api/v1/audit/verify":              auditQuery,
	"GET /api/v1/audit/stream":               auditQuery,
	"GET /api/v1/console/session":            everyRole,
	"POST /api/v1/console/logout":            everyRole,
	"GET /api/v1/openapi.json":               everyRole,

	// analytics (SS-10, E-27)
	"GET /api/v1/observations/status":                analytics,
	"GET /api/v1/observations/parameters":            analytics,
	"GET /api/v1/observations":                       auditQuery,
	"GET /api/v1/observations/aggregate":             analytics,
	"GET /api/v1/observations/metrics":               analytics,
	"GET /api/v1/observations/cost":                  analytics,
	"GET /api/v1/observations/objects":               analytics,
	"GET /api/v1/observations/objects/{kind}":        analytics,
	"POST /api/v1/observations/audit-profile":        author,
	"POST /api/v1/observations/observation-policy":   author,
	"POST /api/v1/observations/anomaly-response":     author,
	"POST /api/v1/observations/memory-budget":        operator,
	"GET /api/v1/baselines":                          analytics,
	"POST /api/v1/baselines/snapshots":               author,
	"POST /api/v1/baselines/flags":                   author,
	"GET /api/v1/baselines/{id}":                     analytics,
	"GET /api/v1/baselines/{id}/drift":               analytics,
	"POST /api/v1/baselines/{id}/promote":            author,
	"GET /api/v1/anomalies":                          analytics,
	"GET /api/v1/research/campaigns":                 {RolePolicyAuthor, RoleAuditor, RoleResearcher},
	"POST /api/v1/research/campaigns":                {RolePolicyAuthor, RoleResearcher},
	"GET /api/v1/research/campaigns/{id}":            {RolePolicyAuthor, RoleAuditor, RoleResearcher},
	"POST /api/v1/research/campaigns/{id}/{action}":  {RolePolicyAuthor, RoleResearcher},
	"GET /api/v1/research/exports":                   {RoleResearcher},
	"POST /api/v1/research/exports":                  {RoleResearcher},
	"GET /api/v1/research/exports/{id}":              {RoleResearcher},
	"GET /api/v1/research/exports/{id}/files/{name}": {RoleResearcher},

	// remote (FR-16)
	"GET /api/v1/remote":                {RoleOperator, RoleSessionApprover},
	"GET /api/v1/clients":               {RoleSessionApprover},
	"GET /api/v1/clients/{id}":          {RoleSessionApprover},
	"POST /api/v1/clients/{id}/approve": {RoleSessionApprover},
	"POST /api/v1/clients/{id}/deny":    {RoleSessionApprover},

	// ops (E-21, E-22, E-23)
	"GET /api/v1/health/status": everyRole,
	// POST /api/v1/health/ack is the Administrator's: leaving fail-closed
	// after an integrity cause needs an administrator acknowledgment
	// (FR-7.13), as resuming after a stop does.
	"GET /api/v1/keys":         operator,
	"POST /api/v1/keys/rotate": operator,
	"GET /api/v1/backup":       operator,
	"POST /api/v1/backup":      operator,

	// library (E-13, E-14)
	"GET /api/v1/packages":                            opsRead,
	"GET /api/v1/packages/receipts":                   opsRead,
	"POST /api/v1/packages/scan":                      operator,
	"GET /api/v1/packages/{id}/{rev}":                 opsRead,
	"POST /api/v1/packages/{id}/{rev}/disable":        operator,
	"POST /api/v1/packages/{id}/{rev}/classification": operator,
}

// refine narrows a route's roles by the request: it returns false when the
// role, although listed for the route, may not perform this request.
var refine = map[string]func(role string, r *http.Request) bool{
	// Researchers draft, submit and stop campaigns; approving, rejecting
	// and expiring them is the Policy Author's (Appendix C).
	"POST /api/v1/research/campaigns/{id}/{action}": func(role string, r *http.Request) bool {
		if role != RoleResearcher {
			return true
		}
		a := r.PathValue("action")
		return a == "submit" || a == "stop"
	},
	// Researchers export datasets of approved campaigns only.
	"POST /api/v1/research/exports": func(role string, r *http.Request) bool {
		if role != RoleResearcher {
			return true
		}
		raw, err := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		if err != nil {
			return false
		}
		var body struct {
			CampaignID string `json:"campaign_id"`
		}
		return json.Unmarshal(raw, &body) == nil && body.CampaignID != ""
	},
}

// RolesFor returns the roles besides the Administrator that the matrix
// admits to a route pattern.
func RolesFor(pattern string) []string { return slices.Clone(routeRoles[pattern]) }

// RouteInfo describes one registered control API route.
type RouteInfo struct {
	Pattern string   `json:"pattern"`
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Public  bool     `json:"public,omitempty"`
	Roles   []string `json:"roles"` // including administrator; empty when public
	// Refined is true when some listed role may use only part of the route.
	Refined bool `json:"refined,omitempty"`
}

// DescribeRoute returns the RouteInfo that registering pattern records:
// public for HandlePublic, otherwise Handle (extra empty) or HandleRoles
// with the extra roles, merged with the matrix. tools/openapi uses it to
// describe the routes found in the sources without starting the Gateway.
func DescribeRoute(pattern string, extra []string, public bool) RouteInfo {
	if public {
		return routeInfo(pattern, nil, true)
	}
	return routeInfo(pattern, mergeRoles(pattern, extra), false)
}

func routeInfo(pattern string, roles []string, public bool) RouteInfo {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		method, path = "", pattern
	}
	ri := RouteInfo{Pattern: pattern, Method: method, Path: path, Public: public}
	if !public {
		ri.Roles = append([]string{RoleAdministrator}, roles...)
		_, ri.Refined = refine[pattern]
	}
	return ri
}

func (s *Server) record(pattern string, roles []string, public bool) {
	ri := routeInfo(pattern, roles, public)
	s.mu.Lock()
	s.routes = append(s.routes, ri)
	s.mu.Unlock()
}

// Routes returns every route registered on the control API, sorted by path
// and method.
func (s *Server) Routes() []RouteInfo {
	s.mu.Lock()
	out := slices.Clone(s.routes)
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// mergeRoles adds the matrix roles of pattern to the roles an element named.
func mergeRoles(pattern string, roles []string) []string {
	out := slices.Clone(roles)
	for _, r := range routeRoles[pattern] {
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// MatrixPatterns returns the route patterns the matrix names, sorted.
func MatrixPatterns() []string {
	out := make([]string, 0, len(routeRoles))
	for p := range routeRoles {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
