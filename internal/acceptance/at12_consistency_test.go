package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const at12Policy = `{
  "revision": "at12-r1",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [{"id": "echo", "server": "ref", "tools": ["echo"]}]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// TestAT12AuditConsistency is acceptance scenario AT-12 against the real
// binaries and a real Neo4j graph mirror, in the profile the run asks for
// (the CI job acceptance-enforced runs it in the Enforced profile):
//
//   - mirror replay and duplicate IDs: smcpd is killed in the middle of a
//     burst of calls and restarted; the mirror catches up from its
//     checkpoint, applying events it already holds again, and then holds
//     every journal event exactly once (SR-6.10-1, mirror half);
//   - journal flush fault: with the reference server running, the file
//     size limit of the smcpd process is lowered so that a journal append
//     fails (EFBIG, a real write error of the journal file). The call whose
//     record cannot be written is refused or its result withheld (-31003)
//     and none of its content reaches the client (SR-6.3-1); the next call
//     fails closed. After a restart without the limit, smcpd journal verify
//     passes, every dispatched call has its authorized (intent) record
//     before the dispatch, every delivered result has its completed record
//     (SR-6.2-1), and the mirror again holds every event exactly once.
//
// Partial claims: SR-6.2-1 asks for kills before, during and after the
// append and the flush with a fault-injecting file layer, SR-6.3-1 for a
// fault exactly after the backend responded (the unit tests of
// internal/edge inject both); SR-6.10-1 also covers the evidence exporter.
// SR-6.11-1 (export lag stop) is verified by its own tests and not
// exercised here. Linux only: the fault uses prlimit(2).
func TestAT12AuditConsistency(t *testing.T) {
	gopts := graphOptions(t)
	if runtime.GOOS != "linux" {
		t.Skip("the journal flush fault lowers RLIMIT_FSIZE of the running smcpd with prlimit(2), which needs Linux")
	}
	g := newGateway(t, options{extra: gopts})
	g.writePolicy(at12Policy)
	g.start()
	g.graphReset()
	g.scenario("AT-12")
	reqtest.Partial(t, "SR-6.2-1", "SR-6.3-1", "SR-6.10-1")

	cs := g.session(g.token(""))
	for i := range 5 {
		g.mustCall(cs, "ref_echo", map[string]any{"text": fmt.Sprintf("before %d", i)}, "before")
	}
	g.mirroredAll()

	// Mirror replay: a crash in the middle of a burst of calls.
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				if _, _, err := call(cs, "ref_echo", map[string]any{"text": fmt.Sprintf("burst %d %d", w, i)}); err != nil {
					return
				}
			}
		}()
	}
	waitEvents(g, 40)
	g.kill()
	wg.Wait()
	g.start()
	n := g.mirroredAll()
	t.Logf("after the crash and replay the mirror holds all %d journal events once", n)

	// Journal flush fault.
	cs = g.session(g.token(""))
	g.mustCall(cs, "ref_echo", map[string]any{"text": "warm"}, "warm") // the instance is running
	seg := openSegment(t, g)
	st, err := os.Stat(seg)
	if err != nil {
		t.Fatal(err)
	}
	limit := uint64(st.Size()) + 1500
	if err := limitFileSize(g.cmd.Process.Pid, limit); err != nil {
		t.Fatal(err)
	}
	t.Logf("RLIMIT_FSIZE of smcpd set to %d bytes (%s is %d bytes)", limit, filepath.Base(seg), st.Size())
	var faultErr error
	released := []string{}
	for i := range 20 {
		marker := fmt.Sprintf("flush-fault-%d", i)
		text, isErr, err := call(cs, "ref_echo", map[string]any{"text": marker})
		if err != nil || isErr {
			if strings.Contains(text, marker) {
				t.Fatalf("a refused call carried its content: %q", text)
			}
			faultErr = fmt.Errorf("call %d: err %v, tool error %v, text %q", i, err, isErr, text)
			break
		}
		released = append(released, text)
	}
	if faultErr == nil {
		t.Fatalf("20 calls succeeded with a file size limit of %d bytes; journal segment now %d bytes\n%s", limit, fileSize(seg), g.logs.String())
	}
	// The refusal names the journal: "launch refused" (no launch without
	// its intent record; reason JOURNAL_UNAVAILABLE, which the client
	// error text does not carry, so the Gateway's log must show the failed
	// journal write), "response withheld: evidence unavailable" (-31003)
	// or fail-closed (-31004).
	msg := faultErr.Error()
	logged := func() bool {
		// The log line may follow the response by a moment.
		for range 50 {
			if strings.Contains(g.logs.String(), "evidence journal failed") {
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("health after the fault: %v", g.health())
		return false
	}
	journal := strings.Contains(msg, "evidence unavailable") || strings.Contains(msg, "fail-closed") ||
		strings.Contains(msg, "launch refused") && logged()
	if !journal {
		t.Fatalf("the call after the journal fault failed for another reason: %v\n%s", faultErr, g.logs.String())
	}
	t.Logf("%d calls released before the fault; %v", len(released), faultErr)
	if text, isErr, err := call(cs, "ref_echo", map[string]any{"text": "after the fault"}); err == nil && !isErr {
		t.Fatalf("a call succeeded after the journal fault: %q", text)
	}
	g.kill()

	g.start()
	g.mirroredAll()
	g.stop()
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatalf("journal verify after the fault:\n%s", out)
	}
	phases := map[string][]string{}
	var order []string
	for _, e := range g.events() {
		c := e.str("correlation_id")
		if c == "" {
			continue
		}
		if phases[c] == nil {
			order = append(order, c)
		}
		phases[c] = append(phases[c], e.str("phase"))
	}
	sort.Strings(order)
	for _, c := range order {
		ps := phases[c]
		idx := func(p string) int {
			for i, x := range ps {
				if x == p {
					return i
				}
			}
			return -1
		}
		if d := idx("dispatched"); d >= 0 && (idx("authorized") < 0 || idx("authorized") > d) {
			t.Fatalf("call %s was dispatched without an authorized record before it: %v", c, ps)
		}
		if d := idx("delivered"); d >= 0 && (idx("completed") < 0 || idx("completed") > d) {
			t.Fatalf("call %s was delivered without a completed record before it: %v", c, ps)
		}
	}
}

// waitEvents waits up to ten seconds until the journal holds at least n
// events of class call.
func waitEvents(g *gateway, n int) {
	g.t.Helper()
	for range 200 {
		calls := 0
		for _, e := range g.events() {
			if e.str("class") == "call" {
				calls++
			}
		}
		if calls >= n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// openSegment returns the journal segment with the highest sequence number.
func openSegment(t *testing.T, g *gateway) string {
	t.Helper()
	segs, _ := filepath.Glob(filepath.Join(g.state, "journal", "segment-*.jsonl"))
	if len(segs) == 0 {
		t.Fatal("no journal segment")
	}
	sort.Strings(segs)
	return segs[len(segs)-1]
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return st.Size()
}
