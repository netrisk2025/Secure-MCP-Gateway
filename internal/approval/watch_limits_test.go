package approval

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Concurrent watch streams are bounded, and a stream whose request is no
// longer authenticated ends at the next notice instead of delivering it.
func TestWatchStreamLimitAndRevalidation(t *testing.T) {
	f := newFixture(t, nil)
	f.svc.streams.Store(maxWatchStreams)
	w := httptest.NewRecorder()
	f.svc.watch(w, httptest.NewRequest("GET", "/api/v1/approvals/watch", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stream beyond the limit: %d", w.Code)
	}
	if got := f.svc.streams.Load(); got != maxWatchStreams {
		t.Fatalf("refused stream changed the count to %d", got)
	}
	f.svc.streams.Store(0)

	// The request carries no authenticated actor, as after sign-out: the
	// snapshot goes out, the next notice ends the stream.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w = httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		f.svc.watch(w, httptest.NewRequest("GET", "/api/v1/approvals/watch", nil).WithContext(ctx))
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.svc.mu.Lock()
		n := len(f.svc.watchers)
		f.svc.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watch stream did not subscribe")
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.svc.mu.Lock()
	for ch := range f.svc.watchers {
		ch <- Notice{}
	}
	f.svc.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("stream kept running after its token stopped resolving")
	}
	if body := w.Body.String(); !strings.Contains(body, "event: snapshot") || strings.Contains(body, "event: approval") {
		t.Fatalf("stream body %q", body)
	}
	if got := f.svc.streams.Load(); got != 0 {
		t.Fatalf("stream count %d after the stream ended", got)
	}
}
