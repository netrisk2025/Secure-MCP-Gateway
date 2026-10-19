package acceptance

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// at02Policy permits echo only for two argument values, permits list_files
// and read_file but denies read_file with a deny rule, and grants nothing
// for time_now.
const at02Policy = `{
  "revision": "at02-r2",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [
      {"id": "echo-bounded", "server": "ref", "tools": ["echo"], "when": [{"op": "in", "arg": "text", "value": ["allowed", "also allowed"]}]},
      {"id": "files", "server": "ref", "tools": ["list_files", "read_file"]},
      {"id": "no-read", "effect": "deny", "server": "ref", "tools": ["read_file"]}
    ]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// at02Revoked removes the echo grant.
const at02Revoked = `{
  "revision": "at02-r3",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [{"id": "files", "server": "ref", "tools": ["list_files"]}]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// TestAT02ExactAuthorization is acceptance scenario AT-02: default deny,
// deny precedence over a permit, argument bounds (policy predicates and
// the manifest inputSchema) and calls of tools the session was never shown,
// all against the real smcpd with policies published through the signed
// Policy Store. A grant removed while the session is open stops the next
// call without a new tools/list.
//
// The requirements are verified in full by the policy and edge unit tests;
// this end-to-end run claims them as partial.
func TestAT02ExactAuthorization(t *testing.T) {
	g := newGateway(t, options{})
	if err := os.WriteFile(filepath.Join(g.sandbox, "notes.txt"), []byte("at02 notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.start()
	g.scenario("AT-02")
	reqtest.Partial(t, "SR-1.3-1", "SR-1.4-1", "SR-1.8-1", "SR-5.5-1")

	pol := writeFile(t, t.TempDir(), "at02.json", at02Policy, 0o644)
	g.mustCtl("policy", "publish", pol)
	cs := g.session(g.token(""))

	// The catalog shows the permitted tools only; read_file is covered by
	// a deny rule and time_now by no permit.
	lt, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range lt.Tools {
		names = append(names, tl.Name)
	}
	if slices.Contains(names, "ref_time_now") || slices.Contains(names, "ref_read_file") || !slices.Contains(names, "ref_echo") {
		t.Fatalf("catalog %v", names)
	}

	// Deny precedence in the effective permissions: read_file has a permit
	// and a deny; only list_files and the bounded echo are granted.
	code, perms := g.api("GET", "/api/v1/policy/revisions/at02-r2/permissions?template=read-only", nil)
	var granted []string
	list, _ := perms["permissions"].([]any)
	for _, p := range list {
		m, _ := p.(map[string]any)
		granted = append(granted, m["tool"].(string))
	}
	slices.Sort(granted)
	if code != 200 || !slices.Equal(granted, []string{"echo", "list_files"}) {
		t.Fatalf("permissions %d %v", code, perms)
	}
	g.mustCall(cs, "ref_echo", map[string]any{"text": "allowed"}, "allowed")
	refused := func(name string, args map[string]any) {
		t.Helper()
		text, isErr, err := call(cs, name, args)
		if err == nil && !isErr {
			t.Fatalf("%s %v was not refused: %q", name, args, text)
		}
	}
	// Calls by name of tools the session was never shown are refused
	// without reaching the server: time_now (no permit) and read_file
	// (permit and deny).
	refused("ref_time_now", map[string]any{})
	refused("ref_read_file", map[string]any{"path": "notes.txt"})
	// Argument bounds: a predicate that does not hold (wrong value, wrong
	// type) is NO_PERMIT; arguments outside the inputSchema are
	// SCHEMA_INVALID.
	refused("ref_echo", map[string]any{"text": "not in the list"})
	refused("ref_echo", map[string]any{"text": 42})
	refused("ref_list_files", map[string]any{"path": ".", "x": true})
	refused("ref_list_files", map[string]any{"path": 7})

	// Removing the grant applies to the open session at once.
	pol = writeFile(t, t.TempDir(), "at02-r3.json", at02Revoked, 0o644)
	g.mustCtl("policy", "publish", pol)
	refused("ref_echo", map[string]any{"text": "allowed"})

	if out := g.mustCtl("policy", "history"); !strings.Contains(out, "at02-r3") {
		t.Fatalf("policy history: %s", out)
	}
	g.stop()
	reasons := map[string]int{}
	for _, e := range g.events() {
		if e.str("phase") == "denied" || e.str("phase") == "filtered" {
			reasons[e.str("reason_code")]++
		}
	}
	for code, n := range map[string]int{"NO_PERMIT": 2, "SCHEMA_INVALID": 2} {
		if reasons[code] < n {
			t.Errorf("reason %s seen %d times, want at least %d (all: %v)", code, reasons[code], n, reasons)
		}
	}
	// No refused call reached the server: one echo call was dispatched.
	if d := dispatchedCorrelations(g.events()); len(d) != 1 {
		t.Fatalf("%d calls dispatched, want 1", len(d))
	}
}
