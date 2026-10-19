package analytics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSensitivityByRole: observation records returned to the console carry
// S2 fields only for the Administrator, Policy Author and Auditor, and S3
// fields for nobody; aggregates over or grouped by a field the role may
// not see are refused, and a Researcher's aggregates stay within S0 and S1
// (SR-6-3, Appendix C). The route matrix keeps raw records from the
// Researcher altogether (TestRoleMatrix in internal/adminapi).
func TestSensitivityByRole(t *testing.T) {
	reqtest.Verifies(t, "SR-6-3")
	s, _ := jsonlService(t, nil)
	for _, n := range []string{"request_bytes", "destination_hostnames", "raw_arguments"} {
		if _, ok := s.Catalog.Lookup(n); !ok {
			t.Fatalf("catalog lacks %s", n)
		}
	}
	if got := []string{s.sensitivity("request_bytes"), s.sensitivity("destination_hostnames"), s.sensitivity("raw_arguments")}; got[0] != "S0" || got[1] != "S2" || got[2] != "S3" {
		t.Fatalf("sensitivities %v", got)
	}
	if err := s.Store.Append("records", []obsstore.Row{{"ts": time.Now().UTC(), "correlation_id": "c-1", "request_bytes": 12,
		"destination_hostnames": `["api.example.com"]`, "raw_arguments": `{"q":"secret"}`}}); err != nil {
		t.Fatal(err)
	}
	s.Sync()
	get := func(role, path string, h http.HandlerFunc) (int, map[string]any) {
		req := httptest.NewRequest("GET", path, nil)
		req = req.WithContext(adminapi.WithRole(req.Context(), "test:"+role, role))
		w := httptest.NewRecorder()
		h(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	for role, seesS2 := range map[string]bool{adminapi.RoleAdministrator: true, adminapi.RolePolicyAuthor: true, adminapi.RoleAuditor: true,
		adminapi.RoleOperator: false} {
		code, out := get(role, "/api/v1/observations?from=1h", s.listRecords)
		rows, _ := out["rows"].([]any)
		if code != http.StatusOK || len(rows) != 1 {
			t.Fatalf("%s: %d %v", role, code, out)
		}
		row := rows[0].(map[string]any)
		if _, ok := row["request_bytes"]; !ok || row["correlation_id"] != "c-1" {
			t.Fatalf("%s lost S0 data: %v", role, row)
		}
		if _, ok := row["destination_hostnames"]; ok != seesS2 {
			t.Fatalf("%s: S2 field present %v, want %v", role, ok, seesS2)
		}
		if _, ok := row["raw_arguments"]; ok {
			t.Fatalf("%s sees S3 data: %v", role, row)
		}
	}
	for _, tc := range []struct {
		role, query string
		want        int
	}{
		{adminapi.RoleOperator, "feature=destination_hostnames", http.StatusForbidden},
		{adminapi.RoleOperator, "feature=request_bytes&group_by=destination_hostnames", http.StatusForbidden},
		{adminapi.RoleResearcher, "feature=destination_hostnames", http.StatusForbidden},
		{adminapi.RoleAuditor, "feature=raw_arguments", http.StatusForbidden},
		{adminapi.RoleAdministrator, "feature=raw_arguments", http.StatusForbidden},
	} {
		code, out := get(tc.role, "/api/v1/observations/aggregate?from=1h&"+tc.query, s.aggregate)
		if code != tc.want {
			t.Fatalf("%s %s: %d %v", tc.role, tc.query, code, out)
		}
		if e, _ := out["error"].(map[string]any); e["code"] != "sensitivity_refused" {
			t.Fatalf("%s %s: %v", tc.role, tc.query, out)
		}
	}
	for _, role := range []string{adminapi.RoleResearcher, adminapi.RoleOperator, adminapi.RoleAuditor} {
		if code, out := get(role, "/api/v1/observations/aggregate?from=1h&feature=request_bytes", s.aggregate); code == http.StatusForbidden {
			t.Fatalf("%s refused an S0 aggregate: %v", role, out)
		}
	}
	if code, out := get(adminapi.RoleAuditor, "/api/v1/observations/aggregate?from=1h&feature=request_bytes&group_by=destination_hostnames", s.aggregate); code == http.StatusForbidden {
		t.Fatalf("auditor refused an S2 grouping: %v", out)
	}
}
