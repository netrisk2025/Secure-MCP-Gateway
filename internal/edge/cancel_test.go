package edge

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestStreamCloseCancelsWithinOneSecond is FR-1.41: a tools/call with a
// progress token is answered as an event stream; once the backend's first
// progress notification has arrived on it, the harness closes the
// connection, and notifications/cancelled for the call reaches the backend
// within 1 second. (Closing before the stream starts is
// TestNorthboundCancellationPropagated.)
func TestStreamCloseCancelsWithinOneSecond(t *testing.T) {
	reqtest.Verifies(t, "FR-1.41")
	ids := make(chan json.RawMessage, 1)
	sc := &scripted{call: func(w func(string), id json.RawMessage, _ string) bool {
		// One progress notification (the registry's first southbound
		// token) starts the harness's event stream; the call then never
		// answers.
		w(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"smcp-1","progress":1,"message":"working"}}`)
		ids <- id
		return true
	}}
	h := newScriptedHarness(t, sc, "")
	_, tok := h.session("rw")
	// A raw TLS connection, so that closing it is exactly the harness
	// closing the stream (no client transport in between).
	tc := h.srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := tls.Dial("tcp", h.srv.Listener.Addr().String(), tc)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"t_w","arguments":{},"_meta":{"progressToken":"p8",%s}}}`, wireMeta)
	req, err := http.NewRequest("POST", h.srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range wireHeaders(tok, "tools/call") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Mcp-Name", "t_w")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("not an event stream: %s", resp.Header.Get("Content-Type"))
	}
	var id json.RawMessage
	select {
	case id = <-ids:
	case <-time.After(5 * time.Second):
		t.Fatal("the call was not dispatched")
	}
	// The relayed progress shows the stream is open and the call in
	// flight.
	br := bufio.NewReader(resp.Body)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended before the progress event: %v", err)
		}
		if strings.HasPrefix(line, "data:") {
			if !strings.Contains(line, "notifications/progress") {
				t.Fatalf("first event %q", line)
			}
			break
		}
	}
	closed := time.Now()
	conn.Close()
	for time.Since(closed) < 3*time.Second {
		for _, l := range sc.received() {
			var m struct {
				Method string `json:"method"`
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
				} `json:"params"`
			}
			if json.Unmarshal([]byte(l), &m) == nil && m.Method == "notifications/cancelled" && string(m.Params.RequestID) == string(id) {
				if d := time.Since(closed); d > time.Second {
					t.Fatalf("southbound cancellation after %s", d)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no southbound notifications/cancelled for %s within 3 s", id)
}
