package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// listenMessage is one JSON-RPC message from a listen stream.
type listenMessage struct {
	Method string `json:"method"`
	Params struct {
		Meta          map[string]any  `json:"_meta"`
		Notifications map[string]bool `json:"notifications"`
	} `json:"params"`
}

// openListen opens a subscriptions/listen stream with request ID id and
// returns its messages in order.
func openListen(t *testing.T, h *harness, tok, id, notifications string) <-chan listenMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/mcp", strings.NewReader(
		fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"subscriptions/listen","params":{"notifications":%s,"_meta":{%s}}}`, id, notifications, wireMeta)))
	for k, v := range wireHeaders(tok, "subscriptions/listen") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("listen: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	out := make(chan listenMessage, 16)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var m listenMessage
			if json.Unmarshal([]byte(data), &m) == nil {
				out <- m
			}
		}
	}()
	return out
}

func next(t *testing.T, msgs <-chan listenMessage, within time.Duration) listenMessage {
	t.Helper()
	select {
	case m, ok := <-msgs:
		if !ok {
			t.Fatal("listen stream closed")
		}
		return m
	case <-time.After(within):
		t.Fatalf("no listen message within %s", within)
	}
	return listenMessage{}
}

// TestListenAcknowledgementAndListChanged is FR-1.33 and FR-1.34: the
// first message of a listen stream is notifications/subscriptions/
// acknowledged carrying the listen request ID as subscriptionId, and only
// toolsListChanged is acknowledged even when other types are requested.
//
// It also verifies FR-1.35 for both causes of a catalog change: after a
// policy activation removes a granted tool, and after the server providing
// the remaining tool is suspended, notifications/tools/list_changed tagged
// with the subscription ID arrives within 2 seconds, and tools/list then
// shows the changed catalog.
func TestListenAcknowledgementAndListChanged(t *testing.T) {
	reqtest.Verifies(t, "FR-1.33", "FR-1.34", "FR-1.35")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	msgs := openListen(t, h, tok, "sub-7", `{"toolsListChanged":true,"resourcesListChanged":true,"promptsListChanged":true}`)
	ack := next(t, msgs, 5*time.Second)
	if ack.Method != "notifications/subscriptions/acknowledged" || ack.Params.Meta["io.modelcontextprotocol/subscriptionId"] != "sub-7" {
		t.Fatalf("first message: %+v", ack)
	}
	if len(ack.Params.Notifications) != 1 || !ack.Params.Notifications["toolsListChanged"] {
		t.Fatalf("acknowledged notification types: %v", ack.Params.Notifications)
	}
	r2, err := policy.Compile([]byte(strings.Replace(strings.Replace(edgePolicy, `"r1"`, `"r2"`, 1), `["echo", "slow", "big"]`, `["echo"]`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if changed, err := h.gw.ActivatePolicy("test", r2); !changed || err != nil {
		t.Fatalf("%v %v", changed, err)
	}
	m := next(t, msgs, 2*time.Second)
	if m.Method != "notifications/tools/list_changed" || m.Params.Meta["io.modelcontextprotocol/subscriptionId"] != "sub-7" {
		t.Fatalf("after activation: %+v", m)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("list_changed after %s", d)
	}

	// A server suspension (SR-3.8-1) changes the catalog without a new
	// revision.
	list := fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta)
	if _, _, body := h.post(list, wireHeaders(tok, "tools/list")); !strings.Contains(body, `"t_echo"`) {
		t.Fatalf("catalog before suspension: %s", body)
	}
	start = time.Now()
	if !h.reg.Suspend("t", "test suspension") {
		t.Fatal("suspend refused")
	}
	m = next(t, msgs, 2*time.Second)
	if m.Method != "notifications/tools/list_changed" || m.Params.Meta["io.modelcontextprotocol/subscriptionId"] != "sub-7" {
		t.Fatalf("after suspension: %+v", m)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("list_changed after %s", d)
	}
	if _, _, body := h.post(list, wireHeaders(tok, "tools/list")); strings.Contains(body, `"t_echo"`) {
		t.Fatalf("catalog after suspension still lists the server's tool: %s", body)
	}
}
