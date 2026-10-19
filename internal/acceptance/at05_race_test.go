package acceptance

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func at05Policy(rev string) string {
	return fmt.Sprintf(`{
  "revision": %q,
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [{"id": "echo", "server": "ref", "tools": ["echo"]}]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`, rev)
}

// TestAT05PublicationAndRevocationRace is acceptance scenario AT-05
// against the real smcpd. Eight callers keep calling while three policy
// revisions are published and then the callers' principal is suspended:
//
//   - every launch authorization in the journal carries the revision that
//     was active at its position in the journal, so each launch is ordered
//     entirely before or after each activation (SR-1.16-1);
//   - activation happens through the signed store and each revision is in
//     the history (SR-1.15-1 in part: no crash injection here);
//   - no launch is authorized for the suspended principal later than
//     CP-16 (2 s) after the suspension was recorded (SR-2.4-1).
func TestAT05PublicationAndRevocationRace(t *testing.T) {
	// The CP-11 per-principal rate is not under test here.
	g := newGateway(t, options{limits: "principal_calls_per_minute = 1000000"})
	g.start()
	g.scenario("AT-05")
	reqtest.Partial(t, "SR-1.15-1", "SR-1.16-1", "SR-2.4-1")

	var stop atomic.Bool
	var ok, refused atomic.Int64
	var wg sync.WaitGroup
	for i := range 8 {
		cs := g.session(g.freshToken())
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !stop.Load(); n++ {
				_, isErr, err := call(cs, "ref_echo", map[string]any{"text": fmt.Sprintf("caller %d call %d", i, n)})
				if err == nil && !isErr {
					ok.Add(1)
				} else {
					refused.Add(1)
					time.Sleep(20 * time.Millisecond)
				}
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	for _, rev := range []string{"at05-a", "at05-b", "at05-c"} {
		g.mustCtl("policy", "publish", writeFile(t, t.TempDir(), rev+".json", at05Policy(rev), 0o644))
		time.Sleep(300 * time.Millisecond)
	}
	before := ok.Load()
	// Revoke the principal of every caller.
	if code, out := g.api("POST", "/api/v1/principals/claude-code-local/suspend", map[string]any{"reason": "AT-05"}); code >= 300 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	time.Sleep(3 * time.Second)
	stop.Store(true)
	wg.Wait()
	if before < 20 {
		t.Fatalf("only %d calls succeeded before the termination", before)
	}
	hist := g.mustCtl("policy", "history")
	g.stop()

	for _, rev := range []string{"at05-a", "at05-b", "at05-c"} {
		if !strings.Contains(hist, rev) {
			t.Fatalf("history lacks %s:\n%s", rev, hist)
		}
	}
	active := ""
	activations := 0
	var terminated time.Time
	launches, late := 0, 0
	byRev := map[string]int{}
	for _, e := range g.events() {
		switch {
		case e.str("class") == "admin" && (e.str("reason_code") == "POLICY_ACTIVATED" || e.str("reason_code") == "POLICY_IMPORTED"):
			if r := e.str("policy_revision"); r != "" {
				active = r
			}
			activations++
		case e.str("reason_code") == "PRINCIPAL_SUSPENDED" && terminated.IsZero():
			terminated = parseTime(t, e.str("time"))
		case e.str("class") == "decision" && e.str("phase") == "authorized":
			launches++
			byRev[e.str("policy_revision")]++
			if e.str("policy_revision") != active {
				t.Fatalf("launch authorized under %s while %s was active", e.str("policy_revision"), active)
			}
			if !terminated.IsZero() && e.str("principal_id") == "claude-code-local" && parseTime(t, e.str("time")).Sub(terminated) > 2*time.Second {
				late++
			}
		}
	}
	// Launches happened under each published revision, so each activation
	// raced live traffic.
	for _, rev := range []string{"at05-a", "at05-b", "at05-c"} {
		if byRev[rev] == 0 {
			t.Fatalf("no launch under %s: %v", rev, byRev)
		}
	}
	if activations < 4 || launches < 20 || terminated.IsZero() {
		t.Fatalf("activations %d, launches %d, termination recorded %v", activations, launches, !terminated.IsZero())
	}
	if late > 0 {
		t.Fatalf("%d launches for the suspended principal more than CP-16 after the suspension", late)
	}
	t.Logf("%d calls released, %d refused, launches by revision %v, %d activations", ok.Load(), refused.Load(), byRev, activations)
}

func parseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("event time %q: %v", s, err)
	}
	return tm
}
