package secrets

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policyadmin"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestBindingInPermissionReport is FR-6.5: a secret is bound to a server
// only through a Secret Use Policy that names the declared slot, the
// permitted tools, the destination, the delivery mode, the purpose, the
// rate, the time window and the approval requirement; once the policy is
// published, the binding appears with those fields in the effective
// permission report of a template that grants the server, and a binding of
// a server the template does not grant does not.
func TestBindingInPermissionReport(t *testing.T) {
	reqtest.Verifies(t, "FR-6.5")
	slots := `"slots": [
  {"server": "u", "name": "api", "modes": ["S1"], "header": "Authorization", "header_template": "Bearer {secret}", "destination": "api.example.com"},
  {"server": "u", "name": "percall", "modes": ["S2"], "file_env": "PC_FILE"}
]`
	use, err := CompileUsePolicy([]byte(`{"revision": "s1", `+slots+`, "policies": [
	  {"id": "u-api", "secret": "api-key", "server": "u", "slot": "api", "mode": "S1", "tools": ["*"], "purpose": "call the API"},
	  {"id": "u-call", "secret": "sign-key", "server": "u", "slot": "percall", "mode": "S2", "tools": ["fetch"], "purpose": "sign requests",
	   "calls_per_minute": 30, "hours": {"start": "08:00", "end": "18:00"}, "approval": true},
	  {"id": "t-env", "secret": "env-secret", "server": "t", "slot": "API_TOKEN", "mode": "S4", "tools": ["*"], "purpose": "legacy",
	   "s4_waiver": {"approved_by": "admin:alice", "reason": "reads only the environment"}}]}`), policyServers)
	if err != nil {
		t.Fatal(err)
	}
	// An undeclared slot cannot be bound at all.
	if _, err := CompileUsePolicy([]byte(`{"revision": "s2", `+slotsJSON+`, "policies": [
	  {"id": "x", "secret": "s", "server": "u", "slot": "undeclared", "mode": "S3", "tools": ["*"], "purpose": "p"}]}`), policyServers); err == nil {
		t.Fatal("binding of an undeclared slot accepted")
	}
	snap, err := policy.Compile([]byte(`{"revision": "p1",
	  "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
	  "templates": {"ro": {"rules": [{"id": "ro-u", "server": "u", "tools": ["fetch"]}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	rep := policyadmin.PermissionReport(snap, "ro", use.BindingsFor)
	raw, _ := json.Marshal(rep)
	var out struct {
		Permissions    []map[string]any `json:"permissions"`
		SecretBindings []map[string]any `json:"secret_bindings"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Permissions) != 1 || len(out.SecretBindings) != 2 {
		t.Fatalf("report %s", raw)
	}
	byID := map[string]map[string]any{}
	for _, b := range out.SecretBindings {
		byID[b["id"].(string)] = b
	}
	api, call := byID["u-api"], byID["u-call"]
	for k, want := range map[string]any{"secret": "api-key", "server": "u", "slot": "api", "mode": "S1", "destination": "api.example.com", "purpose": "call the API"} {
		if api[k] != want {
			t.Errorf("S1 binding %s = %v, want %v", k, api[k], want)
		}
	}
	for k, want := range map[string]any{"secret": "sign-key", "server": "u", "slot": "percall", "mode": "S2", "purpose": "sign requests",
		"calls_per_minute": 30.0, "approval": true} {
		if call[k] != want {
			t.Errorf("S2 binding %s = %v, want %v", k, call[k], want)
		}
	}
	if tools, _ := call["tools"].([]any); len(tools) != 1 || tools[0] != "fetch" {
		t.Errorf("tools %v", call["tools"])
	}
	if h, _ := call["hours"].(map[string]any); h["start"] != "08:00" || h["end"] != "18:00" {
		t.Errorf("time window %v", call["hours"])
	}
	if strings.Contains(string(raw), "t-env") {
		t.Fatalf("binding of an ungranted server in the report: %s", raw)
	}
}
