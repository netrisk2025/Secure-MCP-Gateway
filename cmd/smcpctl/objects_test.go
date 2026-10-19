package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestPolicyObjectTypes is FR-3.1's test against a running smcpd: one object
// of each release 1.0 policy object type is created, validated (an invalid
// one is refused) and published or activated, and each is then read back
// under its identifier from the element that evaluates it:
//
//   - Framework Profile and Session Allow Policy Template: a policy document
//     published through the Policy Store; the grants computed from it name
//     the new template under the new profile.
//   - Secret Use Policy: a use-policy file reloaded into the Secret Broker;
//     the impact of the bound secret names the policy.
//   - Audit Profile, Observation Policy, Anomaly Response Policy: published
//     observation objects; the effective observation settings carry their
//     values.
//   - Research Campaign: created, submitted and approved in the Research
//     Dataset Service.
func TestPolicyObjectTypes(t *testing.T) {
	reqtest.Verifies(t, "FR-3.1")
	dir, cfgPath := bootstrapped(t)
	priv := t.TempDir()
	pp := writeFile(t, priv, "vault-pass", "vault passphrase for tests\n")
	usePath := filepath.Join(dir, "secret-use.json")
	if err := os.WriteFile(usePath, []byte(`{"revision": "u1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n[secrets]\nkey_source = \"passphrase\"\npassphrase_file = " + quote(pp) + "\nuse_policy_file = \"secret-use.json\"\n")
	f.Close()
	mustCtl(t, "secrets", "init", "--config", cfgPath)
	d := startDaemon(t, cfgPath)
	defer stopDaemon(t, d)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	api := func(method, path string, body any) (map[string]any, int) {
		t.Helper()
		out, code, err := c.do(method, path, body)
		if err != nil && code == 0 {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return out, code
	}

	// Framework Profile and Session Allow Policy Template.
	pol, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(pol, &doc); err != nil {
		t.Fatal(err)
	}
	parent := fmt.Sprint(doc["revision"]) // the bootstrap revision is the active one
	doc["revision"] = "objects-r2"
	doc["templates"].(map[string]any)["objects-tpl"] = map[string]any{"rules": []any{map[string]any{"id": "objects-echo", "server": "ref", "tools": []any{"echo"}}}}
	doc["framework_profiles"].(map[string]any)["objects-profile"] = map[string]any{"templates": []any{"objects-tpl"}, "default_template": "objects-tpl"}
	bad := map[string]any{"revision": "objects-bad", "framework_profiles": map[string]any{"p": map[string]any{"templates": []any{"missing"}, "default_template": "missing"}}, "templates": map[string]any{}}
	if _, code := api("POST", "/api/v1/policy/validate", map[string]any{"document": bad}); code < 400 {
		t.Fatalf("invalid policy document accepted: %d", code)
	}
	if out, code := api("POST", "/api/v1/policy/validate", map[string]any{"document": doc}); code != 200 {
		t.Fatalf("validate: %d %v", code, out)
	}
	if out, code := api("POST", "/api/v1/policy/revisions", map[string]any{"document": doc, "parent": parent}); code != 201 && code != 200 {
		t.Fatalf("publish: %d %v", code, out)
	}
	perms, code := api("GET", "/api/v1/policy/revisions/objects-r2/permissions?template=objects-tpl", nil)
	if code != 200 || !strings.Contains(jsonText(perms), "objects-echo") || !strings.Contains(jsonText(perms), "echo") {
		t.Fatalf("grants of the published template: %d %v", code, perms)
	}
	rev, code := api("GET", "/api/v1/policy/revisions/objects-r2", nil)
	if code != 200 || !strings.Contains(jsonText(rev), `"objects-profile":{`) {
		t.Fatalf("stored revision lacks the profile: %d %v", code, rev)
	}

	// Secret Use Policy.
	value := "objects-secret-value-0123456789"
	if out, err := ctl(t, value+"\n", "secrets", "set", "objects-key", "--type", "api_key", "--config", cfgPath); err != nil {
		t.Fatalf("secret: %v %s", err, out)
	}
	os.WriteFile(usePath, []byte(`{"revision": "u2", "slots": [{"server": "ref", "name": "token", "modes": ["S9"]}]}`), 0o600)
	if out, err := ctl(t, "", "secrets", "reload", "--config", cfgPath); err == nil {
		t.Fatalf("invalid Secret Use Policy activated: %s", out)
	}
	os.WriteFile(usePath, []byte(`{"revision": "u2",
	  "slots": [{"server": "ref", "name": "token", "modes": ["S3"], "file_env": "REF_TOKEN_FILE"}],
	  "policies": [{"id": "objects-use", "secret": "objects-key", "server": "ref", "slot": "token", "mode": "S3", "tools": ["*"], "purpose": "FR-3.1 test"}]}`), 0o600)
	if out := mustCtl(t, "secrets", "reload", "--config", cfgPath); !strings.Contains(out, `"revision": "u2"`) {
		t.Fatalf("reload: %s", out)
	}
	if out := mustCtl(t, "secrets", "impact", "objects-key", "--config", cfgPath); !strings.Contains(out, `"use_policy": "objects-use"`) {
		t.Fatalf("impact: %s", out)
	}

	// Audit Profile, Observation Policy and Anomaly Response Policy.
	if _, code := api("POST", "/api/v1/observations/audit-profile", map[string]any{"body": map[string]any{"retention": "1h"}}); code != 422 {
		t.Fatalf("invalid audit profile: %d", code)
	}
	for _, o := range []struct {
		path string
		body map[string]any
	}{
		{"audit-profile", map[string]any{"retention": "1440h", "escalation_parameters": []string{}}},
		{"observation-policy", map[string]any{"policy_id": "objects-obs", "parameters": []string{"request_bytes"}, "sampling_rate": 0.5, "contexts": []string{"principal"}, "bands": []float64{2, 3, 4}}},
		{"anomaly-response", map[string]any{"scoring": "sync", "require_approval_band": "abnormal", "withhold_band": "critical"}},
	} {
		if out, code := api("POST", "/api/v1/observations/"+o.path, map[string]any{"body": o.body, "reason": "FR-3.1 test"}); code != 201 {
			t.Fatalf("publish %s: %d %v", o.path, code, out)
		}
	}
	st, code := api("GET", "/api/v1/observations/objects", nil)
	eff, _ := st["effective"].(map[string]any)
	if code != 200 || eff == nil || eff["policy_id"] != "objects-obs" || eff["retention"] != "1440h0m0s" || eff["withhold_band"] != "critical" || eff["require_approval_band"] != "abnormal" {
		t.Fatalf("observation objects: %d %v", code, st)
	}
	for _, o := range st["objects"].([]any) {
		m := o.(map[string]any)
		if m["kind"] != "memory_budget" && m["active"] == nil {
			t.Errorf("%v has no active revision: %v", m["kind"], m)
		}
	}

	// Research Campaign.
	spec := filepath.Join(dir, "campaign.json")
	os.WriteFile(spec, []byte(`{"name":"bad","parameters":["no_such_parameter"]}`), 0o600)
	if out, err := ctl(t, "", "observe", "campaign", "create", "--file", spec, "--config", cfgPath); err == nil {
		t.Fatalf("invalid campaign accepted: %s", out)
	}
	os.WriteFile(spec, []byte(fmt.Sprintf(`{"name":"objects","parameters":["P-024"],"start":%q,"end":%q,"quota_bytes":100000}`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))), 0o600)
	var cp map[string]any
	if err := json.Unmarshal([]byte(mustCtl(t, "observe", "campaign", "create", "--file", spec, "--config", cfgPath)), &cp); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprint(cp["id"])
	mustCtl(t, "observe", "campaign", "submit", id, "--config", cfgPath)
	mustCtl(t, "observe", "campaign", "approve", id, "--config", cfgPath)
	if out := mustCtl(t, "observe", "campaign", "show", id, "--config", cfgPath); !strings.Contains(out, "approved") {
		t.Fatalf("campaign: %s", out)
	}
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
