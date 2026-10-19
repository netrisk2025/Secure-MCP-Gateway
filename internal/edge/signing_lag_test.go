package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSigningLagStopsLaunch is SR-6.11-1's test: every event of the
// Gateway is appended to a real Evidence Journal whose signer is stalled
// (no segment closes), and the Health & Safety Monitor evaluates the
// journal check as smcpd registers it. Launch authorization goes on while
// the unsigned events are within the CP-27 stop thresholds, and is refused
// with FAIL_CLOSED once more than 1,000 events are unsigned, and again
// once the oldest unsigned event is older than 60 s; signing the backlog
// (a sealed segment) and the recovery interval restore service.
func TestSigningLagStopsLaunch(t *testing.T) {
	reqtest.Verifies(t, "SR-6.11-1")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, err := audit.Open(filepath.Join(t.TempDir(), "journal"), key, audit.Options{MaxEvents: 1 << 20, MaxAge: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	var mu sync.Mutex
	offset := time.Duration(0)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return time.Now().Add(offset) }
	advance := func(d time.Duration) { mu.Lock(); offset += d; mu.Unlock() }
	mon := health.New(health.Options{Now: now, Log: diag.Discard()})
	mon.Register("journal", health.Journal(j))
	h := newHarness(t, harnessOpts{healthGate: mon.Gate, limits: "principal_calls_per_minute = 1000000"})
	h.rec.set(func(ev audit.Event) error { return j.Record(ev) }, nil)
	_, tok := h.session("ro")
	cs := h.client(tok)
	served := func() bool {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}})
		return err == nil
	}
	gated := func() bool { return strings.Contains(strings.Join(mon.Gate(), ","), health.CauseSigningLag) }
	authorized := func() int {
		n := 0
		for _, e := range h.rec.all() {
			if e.Phase == audit.PhaseAuthorized {
				n++
			}
		}
		return n
	}

	// Count threshold.
	for {
		mon.Evaluate()
		n, _ := j.Unsigned()
		if n > health.SigningLagCount {
			break
		}
		if gated() {
			t.Fatalf("stopped at %d unsigned events, within the threshold", n)
		}
		if !served() {
			t.Fatalf("call refused at %d unsigned events", n)
		}
	}
	if !gated() {
		t.Fatal("no signing_lag cause above 1,000 unsigned events")
	}
	before := authorized()
	if served() || authorized() != before {
		t.Fatal("a launch was authorized above the count threshold")
	}

	// The backlog is signed; after the recovery interval service resumes.
	if err := j.Seal(); err != nil {
		t.Fatal(err)
	}
	mon.Evaluate()
	advance(health.DefaultRecovery + time.Second)
	mon.Evaluate()
	if gated() || !served() {
		t.Fatalf("not restored after the backlog was signed: %v", mon.Gate())
	}

	// Age threshold: a few unsigned events that grow old.
	advance(health.SigningLagStop - health.DefaultRecovery - 10*time.Second) // the clock already moved past the recovery interval
	mon.Evaluate()
	if gated() || !served() {
		t.Fatal("stopped before the oldest unsigned event was 60 s old")
	}
	advance(15 * time.Second)
	mon.Evaluate()
	if !gated() {
		t.Fatal("no signing_lag cause with an unsigned event older than 60 s")
	}
	before = authorized()
	if served() || authorized() != before {
		t.Fatal("a launch was authorized above the age threshold")
	}
}
