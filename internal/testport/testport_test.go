package testport

import (
	"net"
	"strconv"
	"testing"
)

// TestFreeDistinctBindable: ports are distinct, bindable, and below the
// default ephemeral ranges.
func TestFreeDistinctBindable(t *testing.T) {
	seen := map[int]bool{}
	for range 50 {
		p := Free(t)
		if seen[p] {
			t.Fatalf("port %d returned twice", p)
		}
		seen[p] = true
		if p < low || p >= high {
			t.Fatalf("port %d outside [%d, %d)", p, low, high)
		}
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			t.Fatalf("port %d not bindable: %v", p, err)
		}
		_ = l.Close()
	}
}
