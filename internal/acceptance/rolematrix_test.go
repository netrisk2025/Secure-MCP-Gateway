package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Roles of SRS Appendix C, by the letters the matrix below uses.
var matrixRoles = []struct{ letter, role string }{
	{"A", "administrator"}, {"O", "operator"}, {"P", "policy_author"}, {"V", "approver"},
	{"S", "session_approver"}, {"U", "auditor"}, {"R", "researcher"},
}

// matrixProbe is one request of a control API operation and the roles
// (letters of matrixRoles) Appendix C admits to it.
type matrixProbe struct {
	path, body string // empty path: the pattern with every {param} filled in
	allowed    string
}

// matrixOp is the Appendix C row a control API operation belongs to and
// its probes. Each row name is the matrix's; the note under the matrix
// says which row read routes and operations the matrix does not name
// follow.
type matrixOp struct {
	row    string
	probes []matrixProbe
}

func op(row, allowed string) matrixOp {
	return matrixOp{row: row, probes: []matrixProbe{{allowed: allowed}}}
}

const (
	rowStop      = "Emergency stop / resume"
	rowHealth    = "View health and status"
	rowOwn       = "Own sign-in (each role ends its own session)"
	rowDraft     = "Edit, simulate policy drafts"
	rowPublish   = "Publish / roll back policy"
	rowCampaign  = "Approve research campaign; Researcher campaigns"
	rowApprovals = "Decide tool-call approvals"
	rowClients   = "Approve dynamic client registrations (Remote Access)"
	rowServers   = "Enable / suspend / retire servers; aliases"
	rowTrust     = "Enroll trust anchors"
	rowRemote    = "Enable or disable the Remote Access Profile"
	rowPrincipal = "Principals, credentials, sessions"
	rowSAccounts = "Create Session Approver accounts"
	rowSecrets   = "Secret create / rotate / revoke"
	rowAudit     = "Audit query and redacted export"
	rowAnalytics = "Observation analytics (S0/S1)"
	rowS2        = "Observation S2 fields"
	rowBaseline  = "Baseline promotion / rollback"
	rowOps       = "Memory budgets, backups, key rotation"
	rowExport    = "Dataset export"
	rowPurge     = "Purge"
	rowInventory = "Operational inventory reads (note under the matrix)"
	rowAdminOnly = "Not named in the matrix: Administrator only"
)

// appendixC maps every control API operation to its Appendix C row and the
// roles that row admits. It is written from the SRS appendix, not from the
// route table of internal/adminapi, so that a route whose roles drift from
// the matrix fails here.
var appendixC = map[string]matrixOp{
	"POST /admin/v1/stop":   op(rowStop, "AO"),
	"POST /admin/v1/resume": op(rowStop, "A"),

	"GET /admin/v1/health":          op(rowHealth, "AOPVSUR"),
	"GET /api/v1/health/status":     op(rowHealth, "AOPVSUR"),
	"GET /api/v1/openapi.json":      op(rowHealth, "AOPVSUR"),
	"GET /api/v1/console/session":   op(rowOwn, "AOPVSUR"),
	"POST /api/v1/console/logout":   op(rowOwn, "AOPVSUR"),
	"POST /admin/v1/logout":         op(rowOwn, "A"),
	"POST /api/v1/approvals/logout": op(rowOwn, "AV"),

	"POST /api/v1/policy/validate": op(rowDraft, "AP"),
	"POST /api/v1/policy/diff":     op(rowDraft, "AP"),
	"POST /api/v1/policy/simulate": op(rowDraft, "AP"),
	"POST /api/v1/filters/scan":    op(rowDraft, "AP"),

	"POST /api/v1/policy/revisions":                op(rowPublish, "AP"),
	"POST /api/v1/policy/rollback":                 op(rowPublish, "AP"),
	"POST /admin/v1/policy/reload":                 op(rowPublish, "AP"),
	"POST /api/v1/observations/audit-profile":      op(rowPublish, "AP"),
	"POST /api/v1/observations/observation-policy": op(rowPublish, "AP"),
	"POST /api/v1/observations/anomaly-response":   op(rowPublish, "AP"),

	"POST /api/v1/research/campaigns": op(rowCampaign, "APR"),
	"POST /api/v1/research/campaigns/{id}/{action}": {row: rowCampaign, probes: []matrixProbe{
		{path: "/api/v1/research/campaigns/fr82/approve", allowed: "AP"},
		{path: "/api/v1/research/campaigns/fr82/reject", allowed: "AP"},
		{path: "/api/v1/research/campaigns/fr82/expire", allowed: "AP"},
		{path: "/api/v1/research/campaigns/fr82/submit", allowed: "APR"},
		{path: "/api/v1/research/campaigns/fr82/stop", allowed: "APR"},
	}},
	"GET /api/v1/research/campaigns":      op(rowCampaign, "APUR"),
	"GET /api/v1/research/campaigns/{id}": op(rowCampaign, "APUR"),

	"GET /api/v1/approvals":               op(rowApprovals, "AV"),
	"GET /api/v1/approvals/watch":         op(rowApprovals, "AV"),
	"GET /api/v1/approvals/{id}":          op(rowApprovals, "AV"),
	"POST /api/v1/approvals/{id}/approve": op(rowApprovals, "AV"),
	"POST /api/v1/approvals/{id}/deny":    op(rowApprovals, "AV"),
	"GET /admin/v1/approvals":             op(rowApprovals, "A"),
	"POST /admin/v1/approvals/{id}":       op(rowApprovals, "A"),

	"GET /api/v1/clients":               op(rowClients, "AS"),
	"GET /api/v1/clients/{id}":          op(rowClients, "AS"),
	"POST /api/v1/clients/{id}/approve": op(rowClients, "AS"),
	"POST /api/v1/clients/{id}/deny":    op(rowClients, "AS"),
	"GET /api/v1/remote":                op(rowClients, "AOS"),

	"POST /api/v1/packages/{id}/{rev}/enable":         op(rowServers, "A"),
	"POST /api/v1/packages/{id}/{rev}/retire":         op(rowServers, "A"),
	"POST /api/v1/packages/{id}/{rev}/disable":        op(rowServers, "AO"),
	"POST /api/v1/packages/{id}/{rev}/classification": op(rowServers, "AO"),
	"POST /api/v1/packages/scan":                      op(rowServers, "AO"),
	"POST /api/v1/runtime/instances/{id}/kill":        op(rowServers, "AO"),

	"POST /api/v1/packages/trust":          op(rowTrust, "A"),
	"DELETE /api/v1/packages/trust/{name}": op(rowTrust, "A"),

	"POST /api/v1/remote/enable":  op(rowRemote, "A"),
	"POST /api/v1/remote/disable": op(rowRemote, "A"),

	"POST /api/v1/principals":                     op(rowPrincipal, "A"),
	"POST /api/v1/principals/{id}/credentials":    op(rowPrincipal, "A"),
	"POST /api/v1/principals/{id}/enable":         op(rowPrincipal, "A"),
	"POST /api/v1/principals/{id}/suspend":        op(rowPrincipal, "A"),
	"POST /api/v1/credentials/{client_id}/revoke": op(rowPrincipal, "A"),
	"POST /api/v1/clients/{id}/revoke":            op(rowPrincipal, "A"),
	"POST /api/v1/sessions/{id}/terminate":        op(rowPrincipal, "AO"),
	"POST /api/v1/sessions/{id}/suspend":          op(rowPrincipal, "AO"),
	"POST /api/v1/sessions/{id}/resume":           op(rowPrincipal, "A"),

	"GET /api/v1/approvers":                    op(rowSAccounts, "A"),
	"POST /api/v1/approvers":                   op(rowSAccounts, "A"),
	"POST /api/v1/approvers/{username}/remove": op(rowSAccounts, "A"),

	"POST /api/v1/secrets":               op(rowSecrets, "A"),
	"POST /api/v1/secrets/{name}/rotate": op(rowSecrets, "A"),
	"DELETE /api/v1/secrets/{name}":      op(rowSecrets, "A"),
	"POST /api/v1/secrets/{name}/resume": op(rowSecrets, "A"),
	// The Secret Use Policy binds secrets to servers: a secret operation.
	"GET /api/v1/secret-use-policy":           op(rowSecrets, "A"),
	"POST /api/v1/secret-use-policy/validate": op(rowSecrets, "A"),
	"POST /api/v1/secret-use-policy":          op(rowSecrets, "A"),
	"POST /api/v1/secret-use-policy/rollback": op(rowSecrets, "A"),
	"POST /api/v1/secrets/reload":             op(rowSecrets, "A"),

	"GET /api/v1/audit/events":                      op(rowAudit, "AOPU"),
	"GET /api/v1/audit/events/{id}":                 op(rowAudit, "AOPU"),
	"GET /api/v1/audit/export":                      op(rowAudit, "AOPU"),
	"GET /api/v1/audit/stream":                      op(rowAudit, "AOPU"),
	"GET /api/v1/audit/verify":                      op(rowAudit, "AOPU"),
	"POST /api/v1/audit/verify":                     op(rowAudit, "AOPU"),
	"GET /api/v1/decisions/{id}/explanation":        op(rowAudit, "AOPU"),
	"GET /api/v1/policy":                            op(rowAudit, "AOPU"),
	"GET /api/v1/policy/revisions":                  op(rowAudit, "AOPU"),
	"GET /api/v1/policy/revisions/{id}":             op(rowAudit, "AOPU"),
	"GET /api/v1/policy/revisions/{id}/permissions": op(rowAudit, "AOPU"),
	"GET /api/v1/filters":                           op(rowAudit, "AOPU"),
	"GET /api/v1/servers":                           op(rowAudit, "AOPU"),
	"GET /api/v1/servers/{alias}":                   op(rowAudit, "AOPU"),
	"GET /api/v1/catalog":                           op(rowAudit, "AOPU"),
	"GET /api/v1/graph/status":                      op(rowAudit, "AOPU"),
	"GET /api/v1/graph/neighborhood":                op(rowAudit, "AOPU"),
	"GET /api/v1/graph/events/{id}/path":            op(rowAudit, "AOPU"),
	"GET /api/v1/graph/queries":                     op(rowAudit, "AOPU"),
	"GET /api/v1/graph/queries/{name}":              op(rowAudit, "AOPU"),

	"GET /api/v1/observations/status":         op(rowAnalytics, "AOPUR"),
	"GET /api/v1/observations/parameters":     op(rowAnalytics, "AOPUR"),
	"GET /api/v1/observations/aggregate":      op(rowAnalytics, "AOPUR"),
	"GET /api/v1/observations/metrics":        op(rowAnalytics, "AOPUR"),
	"GET /api/v1/observations/cost":           op(rowAnalytics, "AOPUR"),
	"GET /api/v1/observations/objects":        op(rowAnalytics, "AOPUR"),
	"GET /api/v1/observations/objects/{kind}": op(rowAnalytics, "AOPUR"),
	"GET /api/v1/baselines":                   op(rowAnalytics, "AOPUR"),
	"GET /api/v1/baselines/{id}":              op(rowAnalytics, "AOPUR"),
	"GET /api/v1/baselines/{id}/drift":        op(rowAnalytics, "AOPUR"),
	"GET /api/v1/anomalies":                   op(rowAnalytics, "AOPUR"),

	// The Operator reaches the records with their S2 fields removed;
	// the test below checks the fields.
	"GET /api/v1/observations": op(rowS2, "AOPU"),

	"POST /api/v1/baselines/snapshots":    op(rowBaseline, "AP"),
	"POST /api/v1/baselines/flags":        op(rowBaseline, "AP"),
	"POST /api/v1/baselines/{id}/promote": op(rowBaseline, "AP"),

	"GET /api/v1/backup":                      op(rowOps, "AO"),
	"POST /api/v1/backup":                     op(rowOps, "AO"),
	"GET /api/v1/keys":                        op(rowOps, "AO"),
	"POST /api/v1/keys/rotate":                op(rowOps, "AO"),
	"POST /api/v1/observations/memory-budget": op(rowOps, "AO"),
	"POST /api/v1/graph/rebuild":              op(rowOps, "AO"),

	"GET /api/v1/egress":                 op(rowInventory, "AOU"),
	"GET /api/v1/egress/grants":          op(rowInventory, "AOU"),
	"GET /api/v1/egress/connections":     op(rowInventory, "AOU"),
	"GET /api/v1/secrets":                op(rowInventory, "AOU"),
	"GET /api/v1/secrets/{name}":         op(rowInventory, "AOU"),
	"GET /api/v1/secrets/{name}/impact":  op(rowInventory, "AOU"),
	"GET /api/v1/runtime":                op(rowInventory, "AOU"),
	"GET /api/v1/runtime/doctor":         op(rowInventory, "AOU"),
	"GET /api/v1/runtime/instances":      op(rowInventory, "AOU"),
	"GET /api/v1/runtime/instances/{id}": op(rowInventory, "AOU"),
	"GET /api/v1/sessions":               op(rowInventory, "AOU"),
	"GET /api/v1/sessions/principals":    op(rowInventory, "AOU"),
	"GET /api/v1/sessions/{id}":          op(rowInventory, "AOU"),
	"GET /api/v1/principals":             op(rowInventory, "AOU"),
	"GET /api/v1/packages":               op(rowInventory, "AOU"),
	"GET /api/v1/packages/receipts":      op(rowInventory, "AOU"),
	"GET /api/v1/packages/{id}/{rev}":    op(rowInventory, "AOU"),

	"GET /api/v1/research/exports":                   op(rowExport, "AR"),
	"GET /api/v1/research/exports/{id}":              op(rowExport, "AR"),
	"GET /api/v1/research/exports/{id}/files/{name}": op(rowExport, "AR"),
	"POST /api/v1/research/exports": {row: rowExport, probes: []matrixProbe{
		{body: `{"campaign_id":"fr82"}`, allowed: "AR"}, // Researchers: approved campaigns only
		{body: `{"format":"csv"}`, allowed: "A"},
	}},

	"POST /api/v1/observations/purge": op(rowPurge, "A"),

	"POST /api/v1/health/ack":    op(rowAdminOnly, "A"), // with resume: leaving fail-closed (FR-7.13)
	"POST /api/v1/config/reload": op(rowAdminOnly, "A"),
}

// publicOps are the sign-in routes, which take no bearer token.
var publicOps = []string{"POST /admin/v1/bootstrap", "POST /admin/v1/login", "POST /admin/v1/session/logout",
	"POST /api/v1/approvals/login", "POST /api/v1/console/login"}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// TestRoleMatrixEveryOperation is FR-8.2's verification against the real
// smcpd: it signs in one account of each of the seven roles, reads every
// control API operation from the served OpenAPI document, and performs
// every operation as every role. An operation is admitted when the answer
// is anything but the role refusal (403 role_refused); the handler may
// still refuse the request for its content (400, 404, 409), which is not
// a role decision. The admitted roles must equal the Appendix C row of
// the operation (appendixC above). Beyond the routes it checks the two
// matrix cells that are not a route decision: the Operator receives
// observation records without their S2 fields, and only the Session
// Approver can complete a harness sign-in (the Administrator, Approver
// and console accounts are refused on the OAuth page). Payload (S3)
// access has no control API operation: release 1.0 stores no payloads
// (SR-6.6-1), S3 fields leave the Gateway only in a campaign export with
// a raw-export grant (SR-6-2), and the Researcher's view of S2 fields is
// the pseudonymized dataset export (FR-10.33).
func TestRoleMatrixEveryOperation(t *testing.T) {
	needBinaries(t)
	priv := t.TempDir()
	const rolePassword = "acceptance role password 1"
	pw := writeFile(t, priv, "role.pw", rolePassword+"\n", 0o600)
	hashOut, err := (&gateway{t: t}).ctlRaw("hash-password", "--password-file", pw)
	if err != nil {
		t.Fatalf("hash-password: %v %s", err, hashOut)
	}
	hash := strings.TrimSpace(hashOut[strings.LastIndex(hashOut, "$argon2id"):])
	users := map[string]string{"operator": "olga", "policy_author": "pat", "auditor": "aud", "researcher": "rita"}
	var extra strings.Builder
	for _, r := range []string{"operator", "policy_author", "auditor", "researcher"} {
		fmt.Fprintf(&extra, "\n[[console.account]]\nusername = %q\npassword_hash = %q\nrole = %q\n", users[r], hash, r)
	}
	fmt.Fprintf(&extra, "\n[[approvals.account]]\nusername = \"alice\"\npassword_hash = %q\n", hash)
	// The vault registers the secret routes.
	vp := writeFile(t, priv, "vault-pass", "vault passphrase "+randomString(12)+"\n", 0o600)
	fmt.Fprintf(&extra, "\n[secrets]\nkey_source = \"passphrase\"\npassphrase_file = %q\nuse_policy_file = \"secret-use.json\"\n", vp)
	g := newGateway(t, options{extra: extra.String()})
	writeFile(t, g.dir, "secret-use.json", `{"revision": "u0"}`, 0o600)
	g.mustCtl("secrets", "init")
	if err := os.WriteFile(filepath.Join(g.sandbox, "matrix.txt"), []byte("matrix-marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.start()
	reqtest.Verifies(t, "FR-8.2")

	login := func(role string) string {
		t.Helper()
		var path string
		var body map[string]any
		switch role {
		case "administrator":
			path, body = "/admin/v1/login", map[string]any{"username": "admin", "password": adminPassword}
		case "approver":
			path, body = "/api/v1/approvals/login", map[string]any{"username": "alice", "password": rolePassword}
		case "session_approver":
			path, body = "/api/v1/console/login", map[string]any{"username": "approver", "password": approverPassword, "role": role}
		default:
			path, body = "/api/v1/console/login", map[string]any{"username": users[role], "password": rolePassword, "role": role}
		}
		st, out := g.apiAs("", "POST", path, body)
		tok, _ := out["token"].(string)
		if st != http.StatusOK || tok == "" {
			t.Fatalf("sign-in as %s: %d %v", role, st, out)
		}
		return tok
	}
	toks := map[string]string{}
	for _, r := range matrixRoles {
		toks[r.letter] = login(r.role)
	}

	// Observation S2 fields: an Observation Policy that adds the S2
	// parameters path_prefixes and argument_value_hashes to the selection
	// in force, records of two calls, read as each role that may read
	// records. The Operator's rows carry none of the S2 fields that the
	// Administrator's rows carry.
	st, params := g.apiAs(toks["A"], "GET", "/api/v1/observations/parameters", nil)
	if st != http.StatusOK {
		t.Fatalf("parameters: %d %v", st, params)
	}
	s2 := map[string]bool{}
	sel := []any{"path_prefixes", "argument_value_hashes"}
	list, _ := params["parameters"].([]any)
	for _, p := range list {
		m, _ := p.(map[string]any)
		if m["sensitivity"] == "S2" {
			s2[fmt.Sprint(m["name"])] = true
		}
		if m["selected"] == true {
			sel = append(sel, m["name"])
		}
	}
	if !s2["path_prefixes"] || !s2["argument_value_hashes"] {
		t.Fatalf("S2 parameters of the catalog: %v", s2)
	}
	if st, out := g.apiAs(toks["A"], "POST", "/api/v1/observations/observation-policy",
		map[string]any{"body": map[string]any{"policy_id": "fr82", "parameters": sel, "sampling_rate": 1}, "reason": "FR-8.2 S2 fields"}); st != http.StatusCreated || out["apply_error"] != nil {
		t.Fatalf("observation policy: %d %v", st, out)
	}
	cs := g.session(g.token(""))
	g.mustCall(cs, "ref_echo", map[string]any{"text": "matrix"}, "matrix")
	g.mustCall(cs, "ref_read_file", map[string]any{"path": "matrix.txt"}, "matrix-marker")
	s2Fields := func(letter string) []string {
		_, out := g.apiAs(toks[letter], "GET", "/api/v1/observations?limit=100", nil)
		rows, _ := out["rows"].([]any)
		seen := map[string]bool{}
		for _, r := range rows {
			for k := range r.(map[string]any) {
				if s2[k] {
					seen[k] = true
				}
			}
		}
		var names []string
		for k := range seen {
			names = append(names, k)
		}
		sort.Strings(names)
		return names
	}
	var adminS2 []string
	for deadline := time.Now().Add(30 * time.Second); len(adminS2) == 0; time.Sleep(200 * time.Millisecond) {
		if adminS2 = s2Fields("A"); len(adminS2) == 0 && time.Now().After(deadline) {
			t.Fatal("no observation record with an S2 field")
		}
	}
	for _, l := range []string{"P", "U"} {
		if got := s2Fields(l); !slices.Equal(got, adminS2) {
			t.Errorf("S2 fields for %s: %v, want %v", l, got, adminS2)
		}
	}
	if got := s2Fields("O"); len(got) != 0 {
		t.Errorf("the Operator receives S2 fields %v", got)
	}

	// Every operation the running Gateway serves.
	st, doc := g.apiAs(toks["A"], "GET", "/api/v1/openapi.json", nil)
	if st != http.StatusOK {
		t.Fatalf("openapi: %d", st)
	}
	paths, _ := doc["paths"].(map[string]any)
	var served []string
	public := map[string]bool{}
	for p, item := range paths {
		for m, o := range item.(map[string]any) {
			pattern := strings.ToUpper(m) + " " + p
			served = append(served, pattern)
			if om, _ := o.(map[string]any); om["x-smcp-public"] == true {
				public[pattern] = true
			}
		}
	}
	sort.Strings(served)
	if len(served) < 100 {
		t.Fatalf("the OpenAPI document lists %d operations", len(served))
	}
	var gotPublic []string
	for p := range public {
		gotPublic = append(gotPublic, p)
	}
	sort.Strings(gotPublic)
	if !slices.Equal(gotPublic, publicOps) {
		t.Errorf("public operations %v, want %v", gotPublic, publicOps)
	}
	for _, p := range served {
		if _, ok := appendixC[p]; !ok && !public[p] {
			t.Errorf("operation %s has no Appendix C row in this test", p)
		}
	}
	for p := range appendixC {
		if !slices.Contains(served, p) {
			t.Errorf("operation %s of the matrix is not served", p)
		}
	}

	hc := g.httpClient()
	do := func(tok, method, path, body string) (int, string) {
		t.Helper()
		var rd io.Reader
		if method != http.MethodGet && method != http.MethodDelete {
			rd = bytes.NewReader([]byte(body))
		}
		req, _ := http.NewRequest(method, g.adminURL+path, rd)
		if rd != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			return resp.StatusCode, "" // a stream: the status is the decision
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return resp.StatusCode, e.Error.Code
	}
	// Sign-out routes end the session they are called with; they run
	// last, and an admitted role signs in again afterwards.
	ordered := slices.Clone(served)
	sort.SliceStable(ordered, func(i, j int) bool {
		return !strings.HasSuffix(ordered[i], "/logout") && strings.HasSuffix(ordered[j], "/logout")
	})
	rows := map[string]int{}
	probes := 0
	for _, pattern := range ordered {
		if public[pattern] {
			continue
		}
		o := appendixC[pattern]
		rows[o.row]++
		method, route, _ := strings.Cut(pattern, " ")
		for _, pr := range o.probes {
			path := pr.path
			if path == "" {
				path = pathParam.ReplaceAllString(route, "fr82")
			}
			body := pr.body
			if body == "" {
				body = "{}"
			}
			for _, r := range matrixRoles {
				code, errCode := do(toks[r.letter], method, path, body)
				probes++
				if code == http.StatusUnauthorized {
					t.Fatalf("%s %s as %s: 401 (token no longer valid)", method, path, r.role)
				}
				if errCode == "route_not_found" {
					t.Errorf("%s %s as %s: the route is not registered on this Gateway", method, path, r.role)
					continue
				}
				admitted := !(code == http.StatusForbidden && errCode == "role_refused")
				if want := strings.Contains(pr.allowed, r.letter); admitted != want {
					t.Errorf("%s %s (%s) as %s: admitted %v (status %d %s), Appendix C admits %v", method, path, o.row, r.role, admitted, code, errCode, want)
				}
				if admitted && strings.HasSuffix(pattern, "/logout") {
					toks[r.letter] = login(r.role)
				}
			}
		}
	}
	t.Logf("%d operations in %d Appendix C rows, %d requests", len(served)-len(public), len(rows), probes)

	// Approve harness sign-in (OAuth authorization): only the Session
	// Approver. Its sign-in succeeded above (g.token); the Administrator,
	// the Approver and console accounts are refused on the sign-in page.
	for _, cred := range [][2]string{{"admin", adminPassword}, {"alice", rolePassword}, {"olga", rolePassword}, {"rita", rolePassword}} {
		if _, err := g.signInAtAs(g.publicURL, clientID, "http://127.0.0.1:51234/callback", "", cred[0], cred[1]); err == nil {
			t.Errorf("%s completed a harness sign-in", cred[0])
		}
	}
}
