package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// boundsListener serves h's Gateway through serveTLS, the harness
// listener's own server, with bounds b on an ephemeral port.
type boundsListener struct {
	t    *testing.T
	h    *harness
	addr string
	tc   *tls.Config
	ln   *connLimitListener
}

func serveBounds(t *testing.T, h *harness, b listenerBounds) *boundsListener {
	t.Helper()
	h.gw.bounds = b
	h.gw.unauth = newWorkLimit(b.Unauthenticated)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// serveTLS adds its own connection limit; the test builds the limited
	// listener itself so it can read its counters, and lifts the inner one.
	cl := newConnLimitListener(ln, b.Connections)
	b2 := b
	b2.Connections = 1 << 30
	go func() { done <- serveTLS(ctx, cl, h.gw.Handler(), h.srv.TLS, diag.Discard(), true, b2) }()
	t.Cleanup(func() { cancel(); <-done })
	tc := h.srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tc.ServerName = "127.0.0.1"
	return &boundsListener{t: t, h: h, addr: ln.Addr().String(), tc: tc, ln: cl}
}

func (l *boundsListener) dial() *tls.Conn {
	l.t.Helper()
	c, err := tls.Dial("tcp", l.addr, l.tc)
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { c.Close() })
	return c
}

// head is a POST request head for the MCP endpoint with the given body
// length; extra is added verbatim.
func (l *boundsListener) head(tok string, length int, extra string) string {
	return fmt.Sprintf("POST /mcp HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"+
		"Authorization: Bearer %s\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\nContent-Length: %d\r\n%s\r\n",
		l.h.cfg.Listener.Address, tok, length, extra)
}

// readResponse reads one HTTP response, or returns the error that ended the
// connection.
func readResponse(c net.Conn, timeout time.Duration) (*http.Response, string, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	r, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, "", err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r, string(b), nil
}

const boundsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{` + wireMeta + `}}}`

// TestPreParseBounds is SR-7.11-1 on the harness listener's own server
// (serveTLS with the header-error listener, as Gateway.Serve runs it), with
// the bounds shortened so the test runs in seconds:
//
//   - CP-06: an oversized header block is refused with 431, and a header
//     block that never finishes is cut off at the header deadline;
//   - CP-07: an oversized body is refused with 413, and a body that stops
//     arriving is cut off at the body deadline;
//   - CP-09 unauthenticated work: while the limit's worth of requests are
//     still sending their bodies, another request is refused with 429 and
//     -31005 before its body is read (its body is not JSON and it carries
//     no valid token, so any parsing or authentication would have answered
//     400 or 401); the slots come back when those requests end;
//   - CP-09 connections: connections beyond the limit are closed at
//     accept, and a slot freed by a closed connection is reused.
//
// None of the refused requests reaches authentication or the call
// pipeline: the journal holds no auth_failure or call event.
// TestDefaultBoundsAreAppendixA checks the production values.
func TestPreParseBounds(t *testing.T) {
	reqtest.Verifies(t, "SR-7.11-1")
	h := newHarness(t, harnessOpts{limits: "request_body_bytes = 4096"})
	_, tok := h.session("ro")
	noPipeline := func(step string) {
		t.Helper()
		if ev := h.rec.find(func(e audit.Event) bool { return e.Class == "call" || e.Class == "auth_failure" }); ev != nil {
			t.Fatalf("%s: a refused request reached authentication or the pipeline: %+v", step, ev)
		}
	}

	t.Run("header and body", func(t *testing.T) {
		l := serveBounds(t, h, listenerBounds{HeaderBytes: 4 << 10, HeaderTimeout: 300 * time.Millisecond, BodyTimeout: 600 * time.Millisecond, Connections: 64, Unauthenticated: 8})

		// A well-formed request is served.
		c := l.dial()
		if _, err := io.WriteString(c, l.head(tok, len(boundsList), "")+boundsList); err != nil {
			t.Fatal(err)
		}
		if r, body, err := readResponse(c, 5*time.Second); err != nil || r.StatusCode != 200 || !strings.Contains(body, "t_echo") {
			t.Fatalf("baseline request: %v %v %s", r, err, body)
		}

		// CP-06 size.
		c = l.dial()
		_, _ = io.WriteString(c, l.head(tok, len(boundsList), "X-Pad: "+strings.Repeat("p", 8<<10)+"\r\n")+boundsList)
		if r, _, err := readResponse(c, 5*time.Second); err != nil || r.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("oversized header: %v %v", r, err)
		}

		// CP-06 deadline: half a header block, then nothing.
		c = l.dial()
		_, _ = io.WriteString(c, "POST /mcp HTTP/1.1\r\nHost: "+h.cfg.Listener.Address+"\r\n")
		start := time.Now()
		if r, _, err := readResponse(c, 5*time.Second); err == nil && r.StatusCode < 400 {
			t.Fatalf("slow header was served: %d", r.StatusCode)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("slow header held the connection for %v", d)
		}

		// CP-07 size.
		big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("b", 8<<10) + `"}}`
		c = l.dial()
		_, _ = io.WriteString(c, l.head(tok, len(big), "")+big)
		if r, _, err := readResponse(c, 5*time.Second); err != nil || r.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body: %v %v", r, err)
		}

		// CP-07 deadline: a body that stops after ten bytes.
		c = l.dial()
		_, _ = io.WriteString(c, l.head("not-a-token", len(boundsList), "")+boundsList[:10])
		start = time.Now()
		r, _, err := readResponse(c, 5*time.Second)
		if err == nil && r.StatusCode < 400 {
			t.Fatalf("slow body was served: %d", r.StatusCode)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("slow body held the connection for %v", d)
		}
		noPipeline("header and body")
	})

	t.Run("unauthenticated work", func(t *testing.T) {
		l := serveBounds(t, h, listenerBounds{HeaderBytes: 16 << 10, HeaderTimeout: 5 * time.Second, BodyTimeout: 1500 * time.Millisecond, Connections: 64, Unauthenticated: 2})
		// Two requests hold both slots by sending their bodies slowly.
		var slow []*tls.Conn
		for range 2 {
			c := l.dial()
			_, _ = io.WriteString(c, l.head("not-a-token", len(boundsList), "")+boundsList[:5])
			slow = append(slow, c)
		}
		deadline := time.Now().Add(2 * time.Second)
		for len(h.gw.unauth) < 2 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if len(h.gw.unauth) != 2 {
			t.Fatalf("slow bodies hold %d slots, want 2", len(h.gw.unauth))
		}
		c := l.dial()
		junk := "not json at all"
		_, _ = io.WriteString(c, l.head("not-a-token", len(junk), "")+junk)
		r, body, err := readResponse(c, 1*time.Second)
		if err != nil {
			t.Fatalf("third request: %v", err)
		}
		reply := wantError(t, "unauthenticated work", r.StatusCode, body, http.StatusTooManyRequests, CodeRateLimited)
		if !strings.Contains(body, `"reasonCode":"QUEUE_FULL"`) || !strings.Contains(body, `"limit":2`) {
			t.Fatalf("unauthenticated-work refusal: %+v %s", reply, body)
		}
		noPipeline("unauthenticated work")
		// The slow requests end at the body deadline and give their slots back.
		for _, c := range slow {
			_, _, _ = readResponse(c, 5*time.Second)
		}
		deadline = time.Now().Add(3 * time.Second)
		for len(h.gw.unauth) > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := len(h.gw.unauth); n != 0 {
			t.Fatalf("%d unauthenticated-work slots not released", n)
		}
		c = l.dial()
		_, _ = io.WriteString(c, l.head(tok, len(boundsList), "")+boundsList)
		if r, _, err := readResponse(c, 5*time.Second); err != nil || r.StatusCode != 200 {
			t.Fatalf("request after the slots were released: %v %v", r, err)
		}
	})

	t.Run("connections", func(t *testing.T) {
		l := serveBounds(t, h, listenerBounds{HeaderBytes: 16 << 10, HeaderTimeout: 5 * time.Second, BodyTimeout: 5 * time.Second, Connections: 3, Unauthenticated: 8})
		var held []net.Conn
		for range 3 {
			c, err := net.Dial("tcp", l.addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			held = append(held, c)
		}
		deadline := time.Now().Add(2 * time.Second)
		for l.ln.open.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		// A flood beyond the limit is closed at accept: the TLS handshake fails.
		for i := range 5 {
			c, err := net.Dial("tcp", l.addr)
			if err != nil {
				continue // refused by the kernel is also a refusal
			}
			tc := tls.Client(c, l.tc)
			_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
			err = tc.Handshake()
			c.Close()
			if err == nil {
				t.Fatalf("connection %d beyond the limit completed a handshake", i+4)
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("connection %d beyond the limit was left waiting instead of closed", i+4)
			}
		}
		if l.ln.refused.Load() < 5 {
			t.Fatalf("refused %d connections, want 5", l.ln.refused.Load())
		}
		// Closing one held connection frees a slot for a served request.
		held[0].Close()
		deadline = time.Now().Add(2 * time.Second)
		for l.ln.open.Load() >= 3 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		c := l.dial()
		_, _ = io.WriteString(c, l.head(tok, len(boundsList), "")+boundsList)
		if r, _, err := readResponse(c, 5*time.Second); err != nil || r.StatusCode != 200 {
			t.Fatalf("request after a slot was freed: %v %v", r, err)
		}
	})
}

// TestDefaultBoundsAreAppendixA: the production bounds are the CP-06,
// CP-07 and CP-09 values of SRS Appendix A, and New gives them to every
// Gateway.
func TestDefaultBoundsAreAppendixA(t *testing.T) {
	reqtest.Partial(t, "SR-7.11-1")
	want := listenerBounds{HeaderBytes: 16 << 10, HeaderTimeout: 5 * time.Second, BodyTimeout: 15 * time.Second, Connections: 128, Unauthenticated: 32}
	if defaultBounds != want {
		t.Fatalf("defaults %+v, want %+v", defaultBounds, want)
	}
	h := newHarness(t, harnessOpts{})
	if h.gw.bounds != want || cap(h.gw.unauth) != 32 {
		t.Fatalf("gateway bounds %+v, %d slots", h.gw.bounds, cap(h.gw.unauth))
	}
}
