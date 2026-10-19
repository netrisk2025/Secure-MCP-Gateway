package backend

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// ringProc is a Process whose stderr is a Ring the test writes.
type ringProc struct {
	pipeline.Process
	ring *pipeline.Ring
}

func (p ringProc) StderrSince(off uint64) (string, uint64, uint64) { return p.ring.Since(off) }

// TestAsserterBoundsRedactsAndBatches: server-asserted text has the
// delivered secret values redacted and is cut to MaxAssertedText; stderr
// is read incrementally, with overwritten bytes counted; at most
// maxAssertionsPerInterval assertions are delivered per interval and the
// rest are counted (SR-6.18-1).
func TestAsserterBoundsRedactsAndBatches(t *testing.T) {
	reqtest.Partial(t, "SR-6.18-1")
	ring := &pipeline.Ring{Max: 64}
	var mu sync.Mutex
	var got []Assertion
	a := newAsserter("s", "s#1", ringProc{ring: ring}, map[string]string{"TOKEN": "hunter2-secret"}, func(x Assertion) {
		mu.Lock()
		got = append(got, x)
		mu.Unlock()
	})
	a.add(Assertion{Kind: AssertError, Code: -32000, Text: "failed with hunter2-secret"})
	a.notification("notifications/message", []byte(`{"data":"`+strings.Repeat("x", MaxAssertedText)+`"}`))
	_, _ = ring.Write([]byte(strings.Repeat("a", 100) + "tail"))
	a.run("rev-1", time.Hour) // only the explicit flushes below deliver
	a.flush()
	mu.Lock()
	if len(got) != 3 {
		t.Fatalf("delivered %d: %+v", len(got), got)
	}
	if got[0].Text != "failed with [REDACTED]" || got[0].Instance != "s#1" || got[0].ServerRevision != "rev-1" || got[0].Server != "s" {
		t.Fatalf("error assertion %+v", got[0])
	}
	if len(got[1].Text) != MaxAssertedText || got[1].Truncated != uint64(len(`{"data":""}`)) {
		t.Fatalf("notification not bounded: %d bytes, truncated %d", len(got[1].Text), got[1].Truncated)
	}
	if got[2].Kind != AssertStderr || !strings.HasSuffix(got[2].Text, "tail") || len(got[2].Text) != 64 || got[2].Skipped != 40 {
		t.Fatalf("stderr assertion %+v", got[2])
	}
	got = nil
	mu.Unlock()

	_, _ = ring.Write([]byte("next"))
	for i := 0; i < maxAssertionsPerInterval+5; i++ {
		a.add(Assertion{Kind: AssertNotification, Method: "m"})
	}
	a.stop() // final flush
	a.stop()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != maxAssertionsPerInterval || got[len(got)-1].Dropped != 6 {
		t.Fatalf("delivered %d, last dropped %d", len(got), got[len(got)-1].Dropped)
	}
}
