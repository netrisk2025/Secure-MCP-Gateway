package acceptance

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const at14Policy = `{
  "revision": "at14-r2",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [
      {"id": "ref", "server": "ref", "tools": ["echo"]},
      {"id": "hang", "server": "hang", "tools": ["hang", "echo"]}
    ]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// TestAT14RetryAndCrash is acceptance scenario AT-14 against the real
// smcpd with the HF-19 hostile fixture (a server that accepts a call and
// never answers), whose tools have no side-effect annotation and are
// therefore not known to be safe to repeat:
//
//   - the call ends at the upstream deadline with -31009, is recorded as
//     indeterminate and is dispatched exactly once (SR-7.2-1);
//   - smcpd killed while such a call is in flight restarts without
//     dispatching it again; the journal verifies.
//
// SR-7.1-1 (no side effects inside retryable database transactions) is an
// Inspection requirement, verified by its record in
// docs/verification/inspections.md; this scenario shows the Gateway-side
// consequence: no replay of a possibly executed call.
func TestAT14RetryAndCrash(t *testing.T) {
	extra := fmt.Sprintf("\n[[server]]\nalias = \"hang\"\ncommand = %q\nargs = [\"-fixture\", \"HF-19\"]\n", filepath.Join(binDir, "smcp-hostile"))
	if requestedProfile() == reqtest.Enforced {
		extra += "\n[[runtime.server]]\nalias = \"hang\"\n"
	}
	g := newGateway(t, options{limits: `upstream_timeout = "2s"`, extra: extra})
	g.writePolicy(at14Policy)
	g.start()
	g.scenario("AT-14")
	reqtest.Partial(t, "SR-7.2-1")

	cs := g.session(g.token(""))
	g.mustCall(cs, "hang_echo", map[string]any{"text": "alive"}, "alive")
	start := time.Now()
	_, _, err := call(cs, "hang_hang", map[string]any{"text": "lost"})
	if err == nil || !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "indeterminate") && !strings.Contains(err.Error(), "upstream") {
		t.Fatalf("never-answering call: %v", err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("the call took %s", d)
	}

	// Crash while a call is in flight.
	inflight := make(chan error, 1)
	go func() {
		_, _, err := call(cs, "hang_hang", map[string]any{"text": "crash"})
		inflight <- err
	}()
	time.Sleep(700 * time.Millisecond)
	g.kill()
	<-inflight
	g.start()
	time.Sleep(3 * time.Second) // longer than the upstream timeout
	g.stop()
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}

	dispatches := map[string]int{}
	tool := map[string]string{}
	outcome := map[string]string{}
	for _, e := range g.events() {
		c := e.str("correlation_id")
		if e.str("class") != "call" || c == "" {
			continue
		}
		switch e.str("phase") {
		case "requested":
			tool[c], _ = e.detail()["tool"].(string)
		case "dispatched":
			dispatches[c]++
		case "indeterminate", "failed", "completed":
			outcome[c] = e.str("phase") + "/" + e.str("reason_code")
		}
	}
	hangs := 0
	for c, name := range tool {
		if name != "hang" {
			continue
		}
		hangs++
		if dispatches[c] != 1 {
			t.Fatalf("hang call %s dispatched %d times", c, dispatches[c])
		}
	}
	if hangs != 2 {
		t.Fatalf("%d hang calls in the journal, want 2", hangs)
	}
	found := false
	for c, o := range outcome {
		if tool[c] == "hang" && strings.HasPrefix(o, "indeterminate") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no indeterminate outcome for the timed-out call: %v", outcome)
	}
}
