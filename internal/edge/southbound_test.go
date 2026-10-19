package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// southPolicy grants the scripted server's tools: "w" is a write-class
// tool and "rd" a read-class one.
const southPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["rw"], "default_template": "rw"}},
  "templates": {
    "rw": {"rules": [
      {"id": "w", "server": "t", "tools": ["w"], "side_effect": "write"},
      {"id": "rd", "server": "t", "tools": ["rd"], "side_effect": "read"}
    ]}
  }
}`

// scripted is a stdio MCP server that writes raw JSON-RPC lines, for
// behavior an SDK server never produces. call answers tools/call; it
// returns false to make the process exit.
type scripted struct {
	call  func(w func(string), id json.RawMessage, name string) bool
	calls atomic.Int32
	mu    sync.Mutex
	lines []string
}

func (sc *scripted) received() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return append([]string(nil), sc.lines...)
}

func (sc *scripted) serve(ctx context.Context, in io.Reader, out io.Writer) error {
	var wmu sync.Mutex
	w := func(s string) {
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = io.WriteString(out, s+"\n")
	}
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 1<<16), 1<<22)
	for scan.Scan() {
		sc.mu.Lock()
		sc.lines = append(sc.lines, scan.Text())
		sc.mu.Unlock()
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if json.Unmarshal(scan.Bytes(), &m) != nil {
			continue
		}
		switch m.Method {
		case "initialize":
			w(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"scripted","version":"1"}}}`, m.ID))
		case "tools/list":
			w(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"w","inputSchema":{"type":"object"}},{"name":"rd","inputSchema":{"type":"object"}}]}}`, m.ID))
		case "ping":
			w(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{}}`, m.ID))
		case "tools/call":
			sc.calls.Add(1)
			if !sc.call(w, m.ID, m.Params.Name) {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return scan.Err()
}

func newScriptedHarness(t *testing.T, sc *scripted, limits string) *harness {
	t.Helper()
	return newHarness(t, harnessOpts{raw: sc.serve, policy: southPolicy, limits: limits})
}

// expectRefusal calls a tool and checks the error code, reason code and
// the terminal evidence event.
func expectRefusal(t *testing.T, h *harness, cs *mcp.ClientSession, tool string, code int64, reason string, phase audit.Phase) {
	t.Helper()
	we, data := callErr(t, cs, tool, map[string]any{})
	if we.Code != code || data["reasonCode"] != reason {
		t.Fatalf("%s: %d %v", tool, we.Code, data)
	}
	corr, _ := data["correlationId"].(string)
	e := h.rec.find(func(e audit.Event) bool { return e.CorrelationID == corr && e.Phase == phase })
	if e == nil || e.ReasonCode != reason {
		t.Fatalf("%s: no %s event with %s", tool, phase, reason)
	}
	if h.rec.find(func(e audit.Event) bool { return e.CorrelationID == corr && e.Phase == audit.PhaseDelivered }) != nil {
		t.Fatalf("%s: a result was delivered", tool)
	}
}

// TestBackendProtocolFailures: a non-JSON stdout line fails the call with
// -31007 and the instance is terminated (FR-5.14); a malformed
// CallToolResult is withheld with -31003, a response with another request
// ID is never delivered (the call ends at the upstream timeout), and a
// message without the JSON-RPC envelope fails the call; each leaves
// evidence and releases nothing (SR-5.20-1).
func TestBackendProtocolFailures(t *testing.T) {
	reqtest.Verifies(t, "FR-5.14", "SR-5.20-1")
	var kind atomic.Value
	sc := &scripted{call: func(w func(string), id json.RawMessage, _ string) bool {
		switch kind.Load().(string) {
		case "log":
			w("listening on stdio")
		case "result":
			w(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"content":"not an array"}}`)
		case "id":
			w(`{"jsonrpc":"2.0","id":424242,"result":{"content":[{"type":"text","text":"stray"}]}}`)
		case "envelope":
			w(`{"id":` + string(id) + `,"result":{"content":[]}}`)
		}
		return true
	}}
	h := newScriptedHarness(t, sc, "")
	_, tok := h.session("rw")
	cs := h.client(tok)

	kind.Store("log")
	expectRefusal(t, h, cs, "t_rd", CodeBackendError, "BACKEND_OUTPUT_INVALID", audit.PhaseFailed)
	deadline := time.Now().Add(5 * time.Second)
	for h.reg.Servers()["t"].Restarts() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.reg.Servers()["t"].Restarts() != 1 {
		t.Fatal("the instance that wrote an invalid line was not replaced")
	}

	kind.Store("result")
	expectRefusal(t, h, cs, "t_rd", CodeResponseWithheld, "RESULT_INVALID", audit.PhaseWithheld)
	kind.Store("id")
	expectRefusal(t, h, cs, "t_rd", CodeIndeterminate, "UPSTREAM_TIMEOUT", audit.PhaseIndeterminate)
	kind.Store("envelope")
	expectRefusal(t, h, cs, "t_rd", CodeBackendError, "BACKEND_OUTPUT_INVALID", audit.PhaseFailed)
}

// TestInstanceFailureIndeterminate: when the instance exits after a
// write-class call was dispatched, the outcome is recorded as
// indeterminate with -31009 and the call is not sent again; a read-class
// call that loses its instance fails with -31007 (SR-7.2-1).
func TestInstanceFailureIndeterminate(t *testing.T) {
	reqtest.Verifies(t, "SR-7.2-1")
	sc := &scripted{call: func(func(string), json.RawMessage, string) bool { return false }}
	h := newScriptedHarness(t, sc, "")
	_, tok := h.session("rw")
	cs := h.client(tok)
	expectRefusal(t, h, cs, "t_w", CodeIndeterminate, "INSTANCE_FAILED", audit.PhaseIndeterminate)
	time.Sleep(200 * time.Millisecond) // a retry, if any, would reach the replacement by now
	if n := sc.calls.Load(); n != 1 {
		t.Fatalf("the write call reached instances %d times", n)
	}
	expectRefusal(t, h, cs, "t_rd", CodeBackendError, "DISPATCH_FAILED", audit.PhaseFailed)
}

// TestClientDeadline: a call that outlives the CP-13 client deadline ends
// with -31008 at the deadline, before the longer upstream timeout, and the
// backend call is cancelled southbound (FR-1.43).
func TestClientDeadline(t *testing.T) {
	reqtest.Verifies(t, "FR-1.43")
	ids := make(chan json.RawMessage, 1)
	sc := &scripted{call: func(_ func(string), id json.RawMessage, _ string) bool {
		ids <- id
		return true // never answers
	}}
	h := newScriptedHarness(t, sc, "upstream_timeout = \"10s\"\nclient_deadline = \"500ms\"")
	_, tok := h.session("rw")
	cs := h.client(tok)
	start := time.Now()
	we, data := callErr(t, cs, "t_rd", map[string]any{})
	elapsed := time.Since(start)
	if we.Code != CodeTimeout || data["reasonCode"] != "CLIENT_DEADLINE" || elapsed < 450*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("%d %v after %s", we.Code, data, elapsed)
	}
	id := <-ids
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range sc.received() {
			var m struct {
				Method string `json:"method"`
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
				} `json:"params"`
			}
			if json.Unmarshal([]byte(l), &m) == nil && m.Method == "notifications/cancelled" && string(m.Params.RequestID) == string(id) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no southbound notifications/cancelled for %s", id)
}

// TestNorthboundCancellationPropagated: closing the response stream of an
// in-flight write-class call (the 2026-07-28 cancellation signal) sends
// notifications/cancelled for it southbound and records the call as
// indeterminate, not as undone (SR-7.12-1).
func TestNorthboundCancellationPropagated(t *testing.T) {
	reqtest.Verifies(t, "SR-7.12-1")
	ids := make(chan json.RawMessage, 1)
	sc := &scripted{call: func(_ func(string), id json.RawMessage, _ string) bool {
		ids <- id
		return true // never answers
	}}
	h := newScriptedHarness(t, sc, "")
	_, tok := h.session("rw")
	ctx, cancel := context.WithCancel(context.Background())
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"t_w","arguments":{},"_meta":{%s}}}`, wireMeta)
	req, err := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range wireHeaders(tok, "tools/call") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Mcp-Name", "t_w")
	errc := make(chan error, 1)
	go func() {
		r, err := h.srv.Client().Do(req)
		if err == nil {
			_, err = io.ReadAll(r.Body)
			r.Body.Close()
		}
		errc <- err
	}()
	var id json.RawMessage
	select {
	case id = <-ids:
	case <-time.After(5 * time.Second):
		t.Fatal("the call was not dispatched")
	}
	cancel()
	<-errc
	deadline := time.Now().Add(5 * time.Second)
	cancelled := false
	for !cancelled && time.Now().Before(deadline) {
		for _, l := range sc.received() {
			var m struct {
				Method string `json:"method"`
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
				} `json:"params"`
			}
			if json.Unmarshal([]byte(l), &m) == nil && m.Method == "notifications/cancelled" && string(m.Params.RequestID) == string(id) {
				cancelled = true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cancelled {
		t.Fatalf("no southbound notifications/cancelled for %s", id)
	}
	var e *audit.Event
	for time.Now().Before(deadline) {
		if e = h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseIndeterminate }); e != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e == nil || e.ReasonCode != "CANCELLED" {
		t.Fatalf("cancellation event %+v", e)
	}
	if h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseDelivered }) != nil {
		t.Fatal("a result was delivered")
	}
}
