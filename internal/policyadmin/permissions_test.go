package policyadmin

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestEffectivePermissionReport: the report for a template lists every
// tool the revision permits after deny rules, with each grant's
// obligations and argument constraints, as computed by hand for the
// fixture (FR-3.6).
func TestEffectivePermissionReport(t *testing.T) {
	reqtest.Verifies(t, "FR-3.6")
	s, err := policy.Compile([]byte(`{"revision": "e1",
  "framework_profiles": {"dev": {"templates": ["work"], "default_template": "work"}},
  "templates": {"work": {"rules": [
    {"id": "fs-read", "server": "fs", "tools": ["read_file", "list_directory", "delete_file"],
     "when": [{"arg": "path", "op": "path_within", "value": ["/data"]}]},
    {"id": "web", "server": "fetch", "tools": ["fetch"], "approval": false, "calls_per_minute": 10,
     "when": [{"arg": "url", "op": "url_in", "value": ["https://docs.example.com"]}, {"op": "approval", "value": "required"}]},
    {"id": "no-delete", "effect": "deny", "server": "fs", "tools": ["delete_file"]}
  ]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := Permissions(s, "work")
	raw, _ := json.Marshal(got)
	want := []struct {
		server, tool, rule string
		approval           bool
		rate               int
		constraints        string
	}{
		{"fetch", "fetch", "web", true, 10, `[{"op":"url_in","arg":"url","value":["https://docs.example.com"]},{"op":"approval","value":"required"}]`},
		{"fs", "list_directory", "fs-read", false, 0, `[{"op":"path_within","arg":"path","value":["/data"]}]`},
		{"fs", "read_file", "fs-read", false, 0, `[{"op":"path_within","arg":"path","value":["/data"]}]`},
	}
	if len(got) != len(want) {
		t.Fatalf("report %s", raw)
	}
	for i, w := range want {
		p := got[i]
		c, _ := json.Marshal(p.Constraints)
		if p.Server != w.server || p.Tool != w.tool || p.Rule != w.rule || p.Approval != w.approval || p.CallsPerMinute != w.rate || string(c) != w.constraints {
			t.Fatalf("entry %d: %+v constraints %s", i, p, c)
		}
	}
	if strings.Contains(string(raw), "delete_file") {
		t.Fatal("a denied tool is in the report")
	}
}

// TestHighRiskRefusedAtPublication: publication refuses a revision that
// grants a server of a high-risk class without the template and profile
// flags (SR-3.13-1, publication part).
func TestHighRiskRefusedAtPublication(t *testing.T) {
	reqtest.Partial(t, "SR-3.13-1")
	f := newFixture(t)
	f.svc.o.ServerRiskClasses = func() map[string][]string { return map[string][]string{"fs": {"code-execution"}} }
	_, err := f.svc.Publish(rev("r2"), PublishOptions{Actor: "test"})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "high-risk") {
		t.Fatalf("publication: %v", err)
	}
}
