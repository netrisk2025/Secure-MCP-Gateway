package secrets

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var policyServers = []config.Server{
	{Alias: "t", Command: "/inproc/t", SecretEnv: map[string]string{"API_TOKEN": "env-secret"}},
	{Alias: "u", Command: "/inproc/u"},
}

const slotsJSON = `"slots": [
  {"server": "u", "name": "multi", "modes": ["S1", "S3", "S4"], "env": "MULTI", "file_env": "MULTI_FILE", "header": "Authorization", "header_template": "Bearer {secret}", "destination": "api.example.com"},
  {"server": "u", "name": "envonly", "modes": ["S4"], "env": "ENV_ONLY"}
]`

func compile(policies string) error {
	_, err := CompileUsePolicy([]byte(`{"revision": "s1", `+slotsJSON+`, "policies": [`+policies+`]}`), policyServers)
	return err
}

func TestUsePolicyS4Waiver(t *testing.T) {
	// FR-6.9: S4 is accepted only with a waiver and only for a slot that
	// declares no other mode (slots are declared in the policy document).
	reqtest.Verifies(t, "FR-6.9")
	waiver := `"s4_waiver": {"approved_by": "admin:alice", "reason": "legacy server reads only the environment"}`
	cases := []struct {
		name, policy, want string
	}{
		{"waiver, no alternative", `{"id": "a", "secret": "s", "server": "u", "slot": "envonly", "mode": "S4", "tools": ["*"], "purpose": "p", ` + waiver + `}`, ""},
		{"no waiver", `{"id": "a", "secret": "s", "server": "u", "slot": "envonly", "mode": "S4", "tools": ["*"], "purpose": "p"}`, "s4_waiver"},
		{"waiver but another mode exists", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S4", "tools": ["*"], "purpose": "p", ` + waiver + `}`, "supports"},
		{"secret_env slot with waiver", `{"id": "a", "secret": "env-secret", "server": "t", "slot": "API_TOKEN", "mode": "S4", "tools": ["*"], "purpose": "p", ` + waiver + `}`, ""},
		{"secret_env names another secret", `{"id": "a", "secret": "other", "server": "t", "slot": "API_TOKEN", "mode": "S4", "tools": ["*"], "purpose": "p", ` + waiver + `}`, "secret_env names"},
		{"waiver on S3", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S3", "tools": ["*"], "purpose": "p", ` + waiver + `}`, "only valid with mode S4"},
	}
	for _, c := range cases {
		err := compile(c.policy)
		if c.want == "" && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestUsePolicyValidation(t *testing.T) {
	reqtest.Partial(t, "FR-6.5")
	cases := []struct {
		name, policy, want string
	}{
		{"undeclared slot", `{"id": "a", "secret": "s", "server": "u", "slot": "nope", "mode": "S3", "tools": ["*"], "purpose": "p"}`, "declares no slot"},
		{"unknown server", `{"id": "a", "secret": "s", "server": "zz", "slot": "multi", "mode": "S3", "tools": ["*"], "purpose": "p"}`, "unknown server"},
		{"mode not supported", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S2", "tools": ["x"], "purpose": "p"}`, "supports"},
		{"launch mode with tool list", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S3", "tools": ["x"], "purpose": "p"}`, "instance lifetime"},
		{"launch mode with approval", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S3", "tools": ["*"], "purpose": "p", "approval": true}`, "S2 only"},
		{"S1 other destination", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S1", "tools": ["*"], "purpose": "p", "destination": "evil.example"}`, "differs"},
		{"missing purpose", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S3", "tools": ["*"]}`, "schema"},
		{"bad hours", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S3", "tools": ["*"], "purpose": "p", "hours": {"start": "25:00", "end": "01:00"}}`, "schema"},
		{"two bindings of a slot", `{"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S3", "tools": ["*"], "purpose": "p"},
		                            {"id": "b", "secret": "s", "server": "u", "slot": "multi", "mode": "S1", "tools": ["*"], "purpose": "p"}`, "already bound"},
	}
	for _, c := range cases {
		err := compile(c.policy)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	u, err := CompileUsePolicy([]byte(`{"revision": "s1", `+slotsJSON+`, "policies": [
	  {"id": "a", "secret": "s", "server": "u", "slot": "multi", "mode": "S1", "tools": ["*"], "purpose": "p"}]}`), policyServers)
	if err != nil {
		t.Fatal(err)
	}
	if b := u.Bindings(); len(b) != 1 || b[0].Destination != "api.example.com" {
		t.Fatalf("S1 destination from the slot: %+v", u.bindings[0])
	}
	if len(u.Slots()) != 3 { // two declared plus the secret_env slot of t
		t.Fatalf("slots: %+v", u.Slots())
	}
	if _, err := CompileUsePolicy([]byte(`{"revision": "s1", "slots": [{"server": "u", "name": "x", "modes": ["S2"]}]}`), policyServers); err == nil {
		t.Fatal("S2 slot without file_env accepted")
	}
}
