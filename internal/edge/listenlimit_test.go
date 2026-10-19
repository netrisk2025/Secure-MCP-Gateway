package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// FR-1.38: a session holds at most CP-20 listen_streams_per_session listen
// streams; one more is refused with -31005 (LISTEN_LIMIT) carrying the
// request ID. Another session is unaffected, and closing a stream frees its
// slot.
func TestListenStreamsBoundedPerSession(t *testing.T) {
	reqtest.Verifies(t, "FR-1.38")
	h := newHarness(t, harnessOpts{})
	limit := h.gw.cfg.Limits.ListenStreamsPerSess
	if limit != 2 {
		t.Fatalf("CP-20 default %d", limit)
	}
	_, tok := h.session("ro")
	// The first stream on a context this test cancels.
	ctx, closeFirst := context.WithCancel(context.Background())
	t.Cleanup(closeFirst)
	first := fmt.Sprintf(`{"jsonrpc":"2.0","id":"first","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{%s}}}`, wireMeta)
	req, _ := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/mcp", strings.NewReader(first))
	for k, v := range wireHeaders(tok, "subscriptions/listen") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := h.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("first listen: %v %v", resp, err)
	}
	for i := 1; i < limit; i++ {
		next(t, openListen(t, h, tok, fmt.Sprintf("sub-%d", i), `{"toolsListChanged":true}`), 5*time.Second)
	}
	waitUntil(t, func() bool { return h.gw.ListenStreams() == limit })
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"over","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{%s}}}`, wireMeta)
	st, _, raw := h.post(body, wireHeaders(tok, "subscriptions/listen"))
	if st != http.StatusOK || !strings.Contains(raw, ReasonListenLimit) || !strings.Contains(raw, "-31005") || !strings.Contains(raw, `"id":"over"`) {
		t.Fatalf("listen over the limit: %d %s", st, raw)
	}
	_, other := h.session("ro")
	next(t, openListen(t, h, other, "sub-other", `{"toolsListChanged":true}`), 5*time.Second)
	// Closing a stream frees its slot.
	closeFirst()
	resp.Body.Close()
	waitUntil(t, func() bool { return h.gw.ListenStreams() == limit })
	next(t, openListen(t, h, tok, "sub-again", `{"toolsListChanged":true}`), 5*time.Second)
}

// The tracker refuses a listen stream once all sessions together hold the
// total bound, even when the session itself is under its own bound, and
// admits one again when a stream ends.
func TestListenStreamsBoundedInTotal(t *testing.T) {
	tr := newTracker()
	var dones []func()
	for i := range 3 {
		done, ok := tr.addLimited(fmt.Sprintf("s%d", i), kindListen, 2, 3, func(error) {})
		if !ok {
			t.Fatalf("stream %d refused under the total bound", i)
		}
		dones = append(dones, done)
	}
	if _, ok := tr.addLimited("s9", kindListen, 2, 3, func(error) {}); ok {
		t.Fatal("stream admitted over the total bound")
	}
	if done, ok := tr.addLimited("s9", kindRequest, 2, 0, func(error) {}); !ok {
		t.Fatal("a request counted against the listen bound")
	} else {
		done()
	}
	dones[0]()
	if _, ok := tr.addLimited("s9", kindListen, 2, 3, func(error) {}); !ok {
		t.Fatal("stream refused after one ended")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A listen stream whose reader stops taking data loses the stream when a
// write cannot complete within listenWriteTimeout, instead of holding the
// writer blocked; the stream's context is cancelled.
func TestListenWriterSlowReader(t *testing.T) {
	old := listenWriteTimeout
	listenWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { listenWriteTimeout = old })
	result := make(chan error, 1)
	cancelled := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The writer cancels the stream with errListenStalled. The server
		// may cancel the request context first when the connection breaks,
		// so the cause passed to cancel is checked, not the context's.
		var once sync.Once
		cancel := func(cause error) {
			if errors.Is(cause, errListenStalled) {
				once.Do(func() { close(cancelled) })
			}
		}
		lw := newDeadlineWriter(w, cancel)
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := []byte("data: " + strings.Repeat("x", 64<<10) + "\n\n")
		for range 2000 { // far more than the socket buffers hold
			if _, err := lw.Write(chunk); err != nil {
				result <- err
				return
			}
			lw.Flush()
		}
		result <- nil
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// A client that sends the request and never reads the response.
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // test server
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("writes to a reader that never reads all completed")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("write to a stalled reader still blocked")
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("stream context not cancelled after the failed write")
	}
}
