package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Northbound protocol conformance over raw HTTP (FR-1.4 to FR-1.38): the
// edge's message mediation in front of the MCP SDK (internal/edge/mediate.go).

// TestNorthboundProtocolConformance runs the single-fixture protocol
// checks below as subtests of one Gateway, to keep the package's run time
// within the race detector's budget.
func TestNorthboundProtocolConformance(t *testing.T) {
	// The subtests make more calls than the default CP-11 rate allows.
	f := start(t, "principal_calls_per_minute = 100000\nprincipal_call_burst = 100000")
	for _, c := range []struct {
		name string
		run  func(*testing.T, *fixture)
	}{
		{"SingleMessageBodies", testSingleMessageBodies},
		{"NotificationsAccepted", testNotificationsAccepted},
		{"ResponseContentTypeAndStreams", testResponseContentTypeAndStreams},
		{"LegacySessionHeadersIgnored", testLegacySessionHeadersIgnoredOnTheWire},
		{"EveryResponseEchoesID", testEveryResponseEchoesID},
		{"DuplicateInFlightID", testDuplicateInFlightID},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := *f
			g.t = t
			c.run(t, &g)
		})
	}
}

// rawReply is one JSON-RPC response as sent on the wire.
type rawReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  map[string]any  `json:"result"`
	Error   *struct {
		Code    json.Number     `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func decodeRaw(t *testing.T, body string) rawReply {
	t.Helper()
	var r rawReply
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("response is not a JSON-RPC object: %v: %q", err, body)
	}
	return r
}

// postRaw sends body as is, with headers; a nil value removes the header
// the fixture would set (Content-Type, Accept).
func (f *fixture) postRaw(body []byte, hdr map[string]*string) (*http.Response, string) {
	f.t.Helper()
	req, _ := http.NewRequest("POST", f.cfg.ResourceURI(), strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range hdr {
		if v == nil {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, *v)
		}
	}
	r, b := f.do(req)
	return r, string(b)
}

func hdrs(m map[string]string) map[string]*string {
	out := map[string]*string{}
	for k, v := range m {
		out[k] = &v
	}
	return out
}

func wantRPCError(t *testing.T, name string, status int, body string, wantStatus int, wantCode int64, wantID string) {
	t.Helper()
	r := decodeRaw(t, body)
	if status != wantStatus || r.Error == nil || r.JSONRPC != "2.0" {
		t.Fatalf("%s: %d %s", name, status, body)
	}
	if c, err := r.Error.Code.Int64(); err != nil || c != wantCode {
		t.Fatalf("%s: code %s, want %d: %s", name, r.Error.Code, wantCode, body)
	}
	if string(r.ID) != wantID {
		t.Fatalf("%s: id %s, want %s", name, r.ID, wantID)
	}
}

// testSingleMessageBodies is FR-1.4 and FR-1.22: a batch, a response
// object and scalars are refused with 400 and -32600; invalid UTF-8 and
// truncated JSON with 400 and -32700. None of them reaches the pipeline.
func testSingleMessageBodies(t *testing.T, f *fixture) {
	reqtest.Verifies(t, "FR-1.4", "FR-1.22")
	access, _, _ := f.oauthLogin("")
	hdr := hdrs(modernHeaders(access, "tools/list"))
	list := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{%s}}`, modernMeta)
	for _, c := range []struct {
		name, body string
		id         string
	}{
		{"batch", "[" + list + "]", "null"},
		{"batch of one notification", `[{"jsonrpc":"2.0","method":"notifications/cancelled"}]`, "null"},
		{"response object", `{"jsonrpc":"2.0","id":7,"result":{}}`, "7"},
		{"error response object", `{"jsonrpc":"2.0","id":"r","error":{"code":-32000,"message":"x"}}`, `"r"`},
		{"number", `42`, "null"},
		{"string", `"tools/list"`, "null"},
		{"null", `null`, "null"},
		{"missing jsonrpc", fmt.Sprintf(`{"id":3,"method":"tools/list","params":{%s}}`, modernMeta), "3"},
		{"object id", `{"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}`, "null"},
	} {
		r, body := f.postRaw([]byte(c.body), hdr)
		wantRPCError(t, c.name, r.StatusCode, body, 400, -32600, c.id)
	}
	invalidUTF8 := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"` + "\xff\xfe" + `"}}}`)
	for _, c := range []struct {
		name string
		body []byte
	}{
		{"invalid UTF-8", invalidUTF8},
		{"truncated", []byte(list[:len(list)-5])},
		{"empty", nil},
	} {
		callHdr := hdrs(modernHeaders(access, "tools/call"))
		r, body := f.postRaw(c.body, callHdr)
		wantRPCError(t, c.name, r.StatusCode, body, 400, -32700, "null")
	}
	if n := f.app.Gateway.InFlight(); n != 0 {
		t.Fatalf("%d calls in flight", n)
	}
	// The well-formed request is accepted.
	if r, body := f.postRaw([]byte(list), hdr); r.StatusCode != 200 || decodeRaw(t, body).Error != nil {
		t.Fatalf("tools/list: %d %s", r.StatusCode, body)
	}
}

// testNotificationsAccepted is FR-1.5: notifications/cancelled and an
// unknown notification get 202 with an empty body and change nothing.
func testNotificationsAccepted(t *testing.T, f *fixture) {
	reqtest.Verifies(t, "FR-1.5")
	access, _, _ := f.oauthLogin("")
	list := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{%s}}`, modernMeta)
	_, before := f.postRaw([]byte(list), hdrs(modernHeaders(access, "tools/list")))
	for _, n := range []string{
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"x"}}`,
		`{"jsonrpc":"2.0","method":"notifications/smcp-unknown","params":{"x":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/unknown/no-params"}`,
	} {
		for _, h := range []map[string]string{modernHeaders(access, "notifications/cancelled"), {"Authorization": "Bearer " + access}} {
			r, body := f.postRaw([]byte(n), hdrs(h))
			if r.StatusCode != 202 || body != "" {
				t.Fatalf("%s: %d %q", n, r.StatusCode, body)
			}
		}
	}
	_, after := f.postRaw([]byte(list), hdrs(modernHeaders(access, "tools/list")))
	if before != after {
		t.Fatalf("tools/list changed after notifications:\n%s\n%s", before, after)
	}
	if f.app.Gateway.InFlight() != 0 || f.app.Gateway.ListenStreams() != 0 {
		t.Fatal("a notification left activity behind")
	}
}

// sseEvents reads an event stream to its end and returns each event's
// data, in order.
func sseEvents(t *testing.T, body io.Reader) []string {
	t.Helper()
	var out []string
	sc := bufio.NewScanner(body)
	for sc.Scan() {
		if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			out = append(out, d)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// testResponseContentTypeAndStreams is FR-1.6 and FR-1.7: tools/call
// without a progress token is answered with application/json; with one, as
// an event stream with X-Accel-Buffering: no that carries only the
// request's progress notifications and ends after the response;
// subscriptions/listen is an event stream with the same header.
func testResponseContentTypeAndStreams(t *testing.T, f *fixture) {
	reqtest.Verifies(t, "FR-1.6", "FR-1.7")
	access, _, _ := f.oauthLogin("")
	callHdr := modernHeaders(access, "tools/call")
	callHdr["Mcp-Name"] = "t_echo"

	r, body := f.postRaw([]byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"j"},%s}}`, modernMeta)), hdrs(callHdr))
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || !strings.Contains(body, "echo:j") {
		t.Fatalf("plain call: %d %s %s", r.StatusCode, r.Header.Get("Content-Type"), body)
	}

	meta := `"_meta":{"progressToken":"pt-9","io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
	req, _ := http.NewRequest("POST", f.cfg.ResourceURI(), strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":"c2","method":"tools/call","params":{"name":"t_echo","arguments":{"text":"s"},%s}}`, meta)))
	for k, v := range callHdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("progress call: %d %v", resp.StatusCode, resp.Header)
	}
	events := sseEvents(t, resp.Body) // returns only once the stream is closed
	if len(events) < 2 {
		t.Fatalf("expected progress and a response, got %q", events)
	}
	for i, e := range events {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				ProgressToken any `json:"progressToken"`
			} `json:"params"`
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal([]byte(e), &m); err != nil {
			t.Fatal(err)
		}
		last := i == len(events)-1
		switch {
		case last && string(m.ID) == `"c2"` && m.Result != nil && strings.Contains(e, "echo:s"):
		case !last && m.Method == "notifications/progress" && m.Params.ProgressToken == "pt-9":
		default:
			t.Fatalf("event %d does not belong to the request, or the stream continued after the response: %s", i, e)
		}
	}

	// subscriptions/listen.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ = http.NewRequestWithContext(ctx, "POST", f.cfg.ResourceURI(), strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":"L","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},%s}}`, modernMeta)))
	for k, v := range modernHeaders(access, "subscriptions/listen") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	lresp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer lresp.Body.Close()
	if lresp.StatusCode != 200 || !strings.HasPrefix(lresp.Header.Get("Content-Type"), "text/event-stream") || lresp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("listen: %d %v", lresp.StatusCode, lresp.Header)
	}
}

// testLegacySessionHeadersIgnoredOnTheWire is FR-1.16: on 2026-07-28
// requests Mcp-Session-Id and Last-Event-ID change nothing, and responses
// carry neither header.
func testLegacySessionHeadersIgnoredOnTheWire(t *testing.T, f *fixture) {
	reqtest.Verifies(t, "FR-1.16")
	access, _, _ := f.oauthLogin("")
	for _, m := range []struct{ method, body, want string }{
		{"server/discover", fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{%s}}`, modernMeta), `"supportedVersions"`},
		{"tools/list", fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{%s}}`, modernMeta), `"t_echo"`},
		{"tools/call", fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"h"},%s}}`, modernMeta), "echo:h"},
	} {
		plain := modernHeaders(access, m.method)
		if m.method == "tools/call" {
			plain["Mcp-Name"] = "t_echo"
		}
		legacy := map[string]string{"Mcp-Session-Id": "no-such-session", "Last-Event-ID": "stream-1_4"}
		for k, v := range plain {
			legacy[k] = v
		}
		s1, _, b1 := f.post(m.body, plain)
		s2, h2, b2 := f.post(m.body, legacy)
		if s1 != 200 || s2 != 200 || !strings.Contains(b2, m.want) || decodeRaw(t, b2).Error != nil {
			t.Fatalf("%s: %d %s / %d %s", m.method, s1, b1, s2, b2)
		}
		if h2.Get("Mcp-Session-Id") != "" || h2.Get("Last-Event-ID") != "" {
			t.Fatalf("%s: response carries legacy headers: %v", m.method, h2)
		}
	}
}

// testEveryResponseEchoesID is FR-1.18: for string and integer IDs, every
// response, including transport, authentication and fail-closed errors,
// echoes the request ID and carries an integer error code.
func testEveryResponseEchoesID(t *testing.T, f *fixture) {
	reqtest.Verifies(t, "FR-1.18")
	access, _, _ := f.oauthLogin("")
	str := func(s string) *string { return &s }
	for _, id := range []string{`17`, `-4`, `0`, `"abc"`, `"0"`, `""`} {
		modern := func(method, params string) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":%q,"params":{%s%s}}`, id, method, params, modernMeta)
		}
		callHdr := modernHeaders(access, "tools/call")
		callHdr["Mcp-Name"] = "t_echo"
		legacyHdr := map[string]string{"Authorization": "Bearer " + access, "MCP-Protocol-Version": "2025-11-25"}
		cases := []struct {
			name string
			body string
			hdr  map[string]*string
		}{
			{"result", modern("tools/list", ""), hdrs(modernHeaders(access, "tools/list"))},
			{"call result", modern("tools/call", `"name":"t_echo","arguments":{"text":"x"},`), hdrs(callHdr)},
			{"policy denial", modern("tools/call", `"name":"t_secret","arguments":{},`), hdrs(map[string]string{"Authorization": "Bearer " + access, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "t_secret"})},
			{"schema error", modern("tools/call", `"name":"t_echo","arguments":{"text":1},`), hdrs(callHdr)},
			{"unknown method", modern("prompts/list", ""), hdrs(modernHeaders(access, "prompts/list"))},
			{"header mismatch", modern("tools/list", ""), hdrs(modernHeaders(access, "server/discover"))},
			{"missing meta version", fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/list","params":{}}`, id), hdrs(modernHeaders(access, "tools/list"))},
			{"bad token", modern("tools/list", ""), hdrs(modernHeaders("nope", "tools/list"))},
			{"wrong content type", modern("tools/list", ""), func() map[string]*string {
				h := hdrs(modernHeaders(access, "tools/list"))
				h["Content-Type"] = str("text/plain")
				return h
			}()},
			{"no event-stream accept", modern("tools/list", ""), func() map[string]*string {
				h := hdrs(modernHeaders(access, "tools/list"))
				h["Accept"] = str("application/json")
				return h
			}()},
			{"unsupported legacy version header", fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/list"}`, id), hdrs(map[string]string{"Authorization": "Bearer " + access, "MCP-Protocol-Version": "2024-01-01"})},
			{"legacy unknown method", fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"no/such/method","params":{}}`, id), hdrs(legacyHdr)},
			{"legacy call", fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"l"}}}`, id), hdrs(legacyHdr)},
			{"response object", fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{}}`, id), hdrs(modernHeaders(access, "tools/list"))},
		}
		for _, c := range cases {
			r, body := f.postRaw([]byte(c.body), c.hdr)
			rep := decodeRaw(t, body)
			if string(rep.ID) != id {
				t.Fatalf("%s: id %s echoed as %s (%d): %s", c.name, id, rep.ID, r.StatusCode, body)
			}
			if rep.Error != nil {
				if _, err := rep.Error.Code.Int64(); err != nil {
					t.Fatalf("%s: non-integer error code %q", c.name, rep.Error.Code)
				}
			} else if rep.Result == nil {
				t.Fatalf("%s: neither result nor error: %s", c.name, body)
			}
		}
		// Fail-closed (emergency stop) is answered before any session or
		// policy work, and still echoes the ID.
		if err := f.app.Gateway.Stop("test", "drill"); err != nil {
			t.Fatal(err)
		}
		r, body := f.postRaw([]byte(modern("tools/list", "")), hdrs(modernHeaders(access, "tools/list")))
		wantRPCError(t, "fail-closed", r.StatusCode, body, 503, edge.CodeGatewayFailClosed, id)
		if err := f.app.Gateway.Resume("test"); err != nil {
			t.Fatal(err)
		}
	}
}

// openListenStream opens a subscriptions/listen stream and returns the
// response and a channel of its lines.
func (f *fixture) openListenStream(ctx context.Context, access, id string) (*http.Response, <-chan string) {
	f.t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},%s}}`, id, modernMeta)
	req, _ := http.NewRequestWithContext(ctx, "POST", f.cfg.ResourceURI(), strings.NewReader(body))
	for k, v := range modernHeaders(access, "subscriptions/listen") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	r, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { r.Body.Close() })
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	return r, lines
}

// waitAck reads lines until the subscription acknowledgement.
func waitAck(t *testing.T, ctx context.Context, lines <-chan string) {
	t.Helper()
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("stream closed before the acknowledgement")
			}
			if strings.Contains(l, "notifications/subscriptions/acknowledged") {
				return
			}
		case <-ctx.Done():
			t.Fatal("no acknowledgement")
		}
	}
}

// completeOf reports whether line is the empty complete response for the
// subscription id.
func completeOf(line, id string) bool {
	d, ok := strings.CutPrefix(line, "data: ")
	if !ok {
		return false
	}
	var m struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			ResultType string                     `json:"resultType"`
			Meta       map[string]json.RawMessage `json:"_meta"`
		} `json:"result"`
	}
	return json.Unmarshal([]byte(d), &m) == nil && string(m.ID) == id && m.Result.ResultType == "complete" &&
		string(m.Result.Meta["io.modelcontextprotocol/subscriptionId"]) == id
}

// endsWithComplete reads lines to the end of the stream and reports
// whether the last data line is the complete response for id.
func endsWithComplete(t *testing.T, ctx context.Context, lines <-chan string, id string) {
	t.Helper()
	last := ""
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				if !completeOf(last, id) {
					t.Fatalf("stream closed; last data line %q is not the complete response for %s", last, id)
				}
				return
			}
			if strings.HasPrefix(l, "data: ") {
				last = l
			}
		case <-ctx.Done():
			t.Fatal("stream not closed")
		}
	}
}

// TestListenStreams is FR-1.38 and FR-1.37: a session may hold CP-20
// listen streams and the next is refused with -31005, closing one frees a
// slot; a stream the Gateway ends, at session end or at shutdown, ends
// with the empty complete response carrying the subscription ID.
func TestListenStreams(t *testing.T) {
	reqtest.Verifies(t, "FR-1.38", "FR-1.37")
	f := start(t, "listen_streams_per_session = 2")
	access, _, tb := f.oauthLogin("")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx1, close1 := context.WithCancel(ctx)
	_, lines0 := f.openListenStream(ctx1, access, `"L0"`)
	waitAck(t, ctx, lines0)
	_, lines1 := f.openListenStream(ctx, access, `"L1"`)
	waitAck(t, ctx, lines1)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"L2","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},%s}}`, modernMeta)
	status, _, resp := f.post(body, modernHeaders(access, "subscriptions/listen"))
	wantRPCError(t, "third listen", status, resp, 200, edge.CodeRateLimited, `"L2"`)
	if !strings.Contains(resp, edge.ReasonListenLimit) {
		t.Fatalf("reason: %s", resp)
	}
	// Another session has its own allowance.
	other, _, _ := f.oauthLogin("")
	_, otherLines := f.openListenStream(ctx, other, `42`)
	waitAck(t, ctx, otherLines)
	// Closing a stream frees its slot; a stream the client closes gets no
	// complete response.
	close1()
	deadline := time.Now().Add(5 * time.Second)
	for f.app.Gateway.ListenStreams() > 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	r, lines3 := f.openListenStream(ctx, access, `"L3"`)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("listen after close: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	waitAck(t, ctx, lines3)

	// Session end: both of the session's streams end with complete.
	f.app.Store.Terminate(tb["session_id"].(string))
	endsWithComplete(t, ctx, lines1, `"L1"`)
	endsWithComplete(t, ctx, lines3, `"L3"`)
	// Shutdown: the other session's stream ends with complete.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); f.stop() }()
	endsWithComplete(t, ctx, otherLines, `42`)
	wg.Wait()
}

// testDuplicateInFlightID is FR-1.21: a second request with the ID of a
// request still in flight in the same session is refused with -32600;
// the first completes, and the ID can be used again afterwards.
func testDuplicateInFlightID(t *testing.T, f *fixture) {
	reqtest.Verifies(t, "FR-1.21")
	access, _, _ := f.oauthLogin("")
	slowHdr := modernHeaders(access, "tools/call")
	slowHdr["Mcp-Name"] = "t_slow"
	slow := fmt.Sprintf(`{"jsonrpc":"2.0","id":"dup","method":"tools/call","params":{"name":"t_slow","arguments":{},%s}}`, modernMeta)
	type result struct {
		status int
		body   string
	}
	first := make(chan result, 1)
	go func() {
		s, _, b := f.post(slow, slowHdr)
		first <- result{s, b}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.app.Gateway.InFlight() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.app.Gateway.InFlight() == 0 {
		t.Fatal("first call never started")
	}
	echoHdr := modernHeaders(access, "tools/call")
	echoHdr["Mcp-Name"] = "t_echo"
	echo := fmt.Sprintf(`{"jsonrpc":"2.0","id":"dup","method":"tools/call","params":{"name":"t_echo","arguments":{"text":"d"},%s}}`, modernMeta)
	status, _, body := f.post(echo, echoHdr)
	wantRPCError(t, "duplicate", status, body, 400, -32600, `"dup"`)
	// Another session may use the same ID.
	other, _, _ := f.oauthLogin("")
	otherHdr := modernHeaders(other, "tools/list")
	if s, _, b := f.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":"dup","method":"tools/list","params":{%s}}`, modernMeta), otherHdr); s != 200 || decodeRaw(t, b).Error != nil {
		t.Fatalf("other session: %d %s", s, b)
	}
	r := <-first
	if rep := decodeRaw(t, r.body); string(rep.ID) != `"dup"` || (rep.Result == nil && rep.Error == nil) {
		t.Fatalf("first call: %d %s", r.status, r.body)
	}
	if status, _, body = f.post(echo, echoHdr); status != 200 || !strings.Contains(body, "echo:d") {
		t.Fatalf("id reuse after completion: %d %s", status, body)
	}
}
