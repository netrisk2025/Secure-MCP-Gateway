package pipeline

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestRingKeepsTheMostRecentBytes: the stderr ring keeps at most Max bytes,
// the most recent, and 10 MiB written in 32 KiB chunks (how os/exec copies
// stderr) does not cost a copy of the bound per write.
func TestRingKeepsTheMostRecentBytes(t *testing.T) {
	r := &Ring{Max: 1 << 20}
	chunk := strings.Repeat("x", 32<<10-8)
	start := time.Now()
	for i := 0; i < 320; i++ {
		fmt.Fprintf(r, "%07d|%s", i, chunk)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("10 MiB took %s", d)
	}
	tail := r.Tail()
	if len(tail) != 1<<20 || !strings.HasSuffix(tail, chunk) || !strings.Contains(tail, "0000319|") || strings.Contains(tail, "0000280|") {
		t.Fatalf("tail is %d bytes", len(tail))
	}
	r.mu.Lock()
	held := len(r.buf)
	r.mu.Unlock()
	if held > r.Max+r.Max/4 {
		t.Fatalf("ring holds %d bytes", held)
	}
	// A single write larger than the bound keeps its end.
	big := strings.Repeat("a", 1<<20) + "END"
	_, _ = r.Write([]byte(big))
	if tail := r.Tail(); len(tail) != 1<<20 || !strings.HasSuffix(tail, "END") {
		t.Fatalf("after a large write: %d bytes", len(tail))
	}
}
