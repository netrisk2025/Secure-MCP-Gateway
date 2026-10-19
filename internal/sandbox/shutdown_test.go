package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestShutdownSequenceAtDefaultTimings is FR-5.27 at the real intervals:
// stopping an instance whose server ignores EOF and SIGTERM closes its
// stdin first, sends SIGTERM 5 seconds later and SIGKILL 5 seconds after
// that. The times are those the fixture recorded when its stdin reached
// EOF and when Podman was asked for each signal.
func TestShutdownSequenceAtDefaultTimings(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 10 seconds")
	}
	reqtest.Verifies(t, "FR-5.27")
	h := newHarness(t, testRuntime(), func(o *Options) { o.TerminateAfter = 0 }) // the default
	if h.l.o.TerminateAfter != 5*time.Second {
		t.Fatalf("default wait %v", h.l.o.TerminateAfter)
	}
	eofFile := filepath.Join(t.TempDir(), "eof")
	spec := h.spec("stub")
	spec.Env["SMCP_FAKE_SERVER"] = "ignore-eof"
	spec.Env["SMCP_FAKE_EOF_FILE"] = eofFile
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	name := h.l.Instances()[0].Container
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(eofFile)
	if err != nil {
		t.Fatalf("the server never saw EOF on stdin: %v", err)
	}
	eof := time.Unix(0, int64(atoi(string(b))))
	signals := map[string]time.Time{}
	for _, line := range strings.Split(strings.TrimSpace(h.kills(name)), "\n") {
		sig, at, ok := strings.Cut(line, " ")
		n, err := strconv.ParseInt(at, 10, 64)
		if !ok || err != nil {
			t.Fatalf("kill record %q", line)
		}
		if _, seen := signals[sig]; !seen {
			signals[sig] = time.Unix(0, n)
		}
	}
	term, kill := signals["TERM"], signals["KILL"]
	if term.IsZero() || kill.IsZero() {
		t.Fatalf("signals %v", h.kills(name))
	}
	// stdin is closed at once; each wait is 5 s. A fake podman invocation
	// starts the test binary, which adds a little to each step.
	const slack = 3 * time.Second
	for _, c := range []struct {
		what     string
		from, to time.Time
		min, max time.Duration
	}{
		{"stdin close", start, eof, 0, time.Second},
		{"EOF to SIGTERM", eof, term, 5 * time.Second, 5*time.Second + slack},
		{"SIGTERM to SIGKILL", term, kill, 5 * time.Second, 5*time.Second + slack},
	} {
		if d := c.to.Sub(c.from); d < c.min-50*time.Millisecond || d > c.max {
			t.Errorf("%s took %v, want %v to %v", c.what, d, c.min, c.max)
		}
	}
}
