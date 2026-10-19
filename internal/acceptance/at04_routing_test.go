package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const at04Policy = `{
  "revision": "at04-r2",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [
      {"id": "ref-read", "server": "ref", "tools": ["read_file"]},
      {"id": "ref2-read", "server": "ref2", "tools": ["read_file"]}
    ]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// at04Overlap has two permit rules of one template for ref read_file.
const at04Overlap = `{
  "revision": "at04-r3",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [
      {"id": "first-read", "server": "ref", "tools": ["read_file"]},
      {"id": "second-read", "server": "ref", "tools": ["read_file", "echo"], "approval": true}
    ]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// TestAT04RoutingAndOverlap is acceptance scenario AT-04 against the real
// smcpd: two instances of the same signed package under different aliases
// each get exactly one route (a call reaches the instance whose public name
// it used, and the decision records that route); a tool with no permitted
// route is refused; and a revision with two overlapping permits is rejected
// at publication with both rule IDs named, leaving the active revision in
// force.
//
// Partial: SR-1.11-1 has no way to make two routes eligible (routes are
// server aliases, which are unique), so the two-route case is covered by
// the policy unit tests only.
func TestAT04RoutingAndOverlap(t *testing.T) {
	g := newGateway(t, options{})
	second := t.TempDir()
	if err := os.WriteFile(filepath.Join(g.sandbox, "which.txt"), []byte("instance-ref\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "which.txt"), []byte("instance-ref2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(g.cfg)
	sum := regexp.MustCompile(`package_sha256 = "([0-9a-f]+)"`).FindSubmatch(raw)
	if sum == nil {
		t.Fatal("no package_sha256 in the bootstrap configuration")
	}
	g.appendConfig(fmt.Sprintf("\n[[server]]\nalias = \"ref2\"\npackage = \"smcp-ref-filesystem\"\npackage_sha256 = %q\nslots = { root = %q }\n", sum[1], second))
	if requestedProfile() == reqtest.Enforced {
		for _, d := range []string{filepath.Dir(second), second} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		g.appendConfig(fmt.Sprintf("\n[[runtime.server]]\nalias = \"ref2\"\n[[runtime.server.mount]]\nsource = %q\n", second))
	}
	g.start()
	g.scenario("AT-04")
	reqtest.Partial(t, "SR-1.9-1", "SR-1.11-1")

	g.mustCtl("policy", "publish", writeFile(t, t.TempDir(), "at04.json", at04Policy, 0o644))
	cs := g.session(g.token(""))
	g.mustCall(cs, "ref_read_file", map[string]any{"path": "which.txt"}, "instance-ref\n")
	g.mustCall(cs, "ref2_read_file", map[string]any{"path": "which.txt"}, "instance-ref2")
	if _, isErr, err := call(cs, "ref2_echo", map[string]any{"text": "x"}); err == nil && !isErr {
		t.Fatal("ref2_echo has no permitted route but was answered")
	}

	// Overlapping permits are rejected at publication, naming both rules.
	bad := writeFile(t, t.TempDir(), "overlap.json", at04Overlap, 0o644)
	out, err := g.ctl("policy", "publish", bad)
	if err == nil || !strings.Contains(out, "first-read") || !strings.Contains(out, "second-read") {
		t.Fatalf("overlapping permits: err %v\n%s", err, out)
	}
	if out, err := g.ctl("policy", "validate", bad); err == nil {
		t.Fatalf("policy validate accepted overlapping permits:\n%s", out)
	}
	if out := g.mustCtl("policy", "show"); !strings.Contains(out, "at04-r2") {
		t.Fatalf("active revision after the refused publication: %s", out)
	}
	g.mustCall(cs, "ref2_read_file", map[string]any{"path": "which.txt"}, "instance-ref2")
	g.stop()

	// Each permitted call has one route, the server of its public name.
	routes := map[string]string{}
	servers := map[string]string{}
	for _, e := range g.events() {
		c := e.str("correlation_id")
		if e.str("class") == "call" && e.str("phase") == "requested" {
			servers[c], _ = e.detail()["server"].(string)
		}
		if e.str("class") == "decision" && e.str("phase") == "authorized" {
			routes[c] = fmt.Sprint(e.detail()["route"])
		}
	}
	if len(routes) != 3 {
		t.Fatalf("%d authorized decisions, want 3: %v", len(routes), routes)
	}
	for c, r := range routes {
		if servers[c] == "" || !strings.Contains(r, servers[c]) || (servers[c] == "ref" && strings.Contains(r, "ref2")) {
			t.Fatalf("call to %s decided with route %q", servers[c], r)
		}
	}
}
