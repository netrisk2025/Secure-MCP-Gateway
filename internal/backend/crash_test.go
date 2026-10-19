package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestCrashRestartAndSuspension is FR-5.12 for the dispatcher: an instance
// that exits unexpectedly fails its in-flight call (ErrInstanceFailed,
// which the edge records as failed, or indeterminate for a tool that may
// have acted) and is replaced, so the next call is served by a new
// instance; the third unexpected exit within five minutes suspends the
// server revision: its tools leave the catalog and a fourth call is
// refused without reaching any instance.
func TestCrashRestartAndSuspension(t *testing.T) {
	reqtest.Verifies(t, "FR-5.12")
	rs := &rawServer{call: func(func(string), json.RawMessage, string, json.RawMessage) bool {
		return false // the process exits without answering
	}}
	r, caps, l := startRaw(t, rs, 5*time.Second, nil)
	ref := r.Resolve("r_act")
	for i := 1; i <= CrashLimit; i++ {
		if _, err := r.Call(context.Background(), dispatch(caps, ref, fmt.Sprintf("c%d", i), `{}`)); !errors.Is(err, ErrInstanceFailed) {
			t.Fatalf("crash %d: %v", i, err)
		}
		if i < CrashLimit {
			// Replaced: the next call goes to a new instance.
			deadline := time.Now().Add(5 * time.Second)
			for l.launches.Load() < int32(i+1) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if l.launches.Load() != int32(i+1) {
				t.Fatalf("after crash %d: %d launches", i, l.launches.Load())
			}
		}
	}
	if r.Resolve("r_act") != nil || r.Servers()["r"] != nil {
		t.Fatal("server still presented after three unexpected exits")
	}
	launches, calls := l.launches.Load(), rs.calls.Load()
	if _, err := r.Call(context.Background(), dispatch(caps, ref, "c4", `{}`)); !errors.Is(err, ErrSuspended) {
		t.Fatalf("fourth call: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if l.launches.Load() != launches || rs.calls.Load() != calls {
		t.Fatalf("the suspended revision was launched or called again: launches %d->%d calls %d->%d", launches, l.launches.Load(), calls, rs.calls.Load())
	}
}
