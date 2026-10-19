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

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestLegacySessionHeadersIgnored is FR-1.16: on 2026-07-28 requests
// Mcp-Session-Id and Last-Event-ID headers change nothing (the edge drops
// Last-Event-ID before the SDK, which would refuse it), and neither header
// appears in the response.
func TestLegacySessionHeadersIgnored(t *testing.T) {
	reqtest.Verifies(t, "FR-1.16")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	for _, m := range []struct{ method, body, want string }{
		{"tools/list", fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta), `"t_echo"`},
		{"tools/call", fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"s"},"_meta":{%s}}}`, wireMeta), "echo:s"},
		{"server/discover", fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{"_meta":{%s}}}`, wireMeta), `"supportedVersions"`},
	} {
		plain := wireHeaders(tok, m.method)
		withLegacy := wireHeaders(tok, m.method)
		if m.method == "tools/call" {
			plain["Mcp-Name"], withLegacy["Mcp-Name"] = "t_echo", "t_echo"
		}
		withLegacy["Mcp-Session-Id"] = "legacy-session-that-does-not-exist"
		withLegacy["Last-Event-ID"] = "stream-1_3"
		s1, _, b1 := h.post(m.body, plain)
		s2, hdr, b2 := h.post(m.body, withLegacy)
		if s1 != 200 || s2 != 200 || !strings.Contains(b2, m.want) || decodeReply(t, b2).Error != nil {
			t.Fatalf("%s: %d %s / %d %s", m.method, s1, b1, s2, b2)
		}
		if hdr.Get("Mcp-Session-Id") != "" || hdr.Get("Last-Event-ID") != "" {
			t.Fatalf("%s: response carries legacy headers: %v", m.method, hdr)
		}
	}
}

// onePolicy grants exactly one tool.
const onePolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["one"], "default_template": "one"}},
  "templates": {"one": {"rules": [{"id": "one-echo", "server": "t", "tools": ["echo"]}]}}
}`

// TestBaselineMethodSet is FR-1.11: server/discover, tools/list,
// tools/call and subscriptions/listen each return a conforming result for
// a session with one granted tool.
func TestBaselineMethodSet(t *testing.T) {
	reqtest.Verifies(t, "FR-1.11")
	h := newHarness(t, harnessOpts{policy: onePolicy})
	_, tok := h.session("one")

	status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":"d","method":"server/discover","params":{"_meta":{%s}}}`, wireMeta), wireHeaders(tok, "server/discover"))
	r := decodeReply(t, body)
	caps, _ := r.Result["capabilities"].(map[string]any)
	if status != 200 || r.Error != nil || r.Result["supportedVersions"] == nil || caps["tools"] == nil || string(r.ID) != `"d"` {
		t.Fatalf("server/discover: %d %s", status, body)
	}

	status, _, body = h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta), wireHeaders(tok, "tools/list"))
	r = decodeReply(t, body)
	tools, _ := r.Result["tools"].([]any)
	if status != 200 || r.Error != nil || len(tools) != 1 || string(r.ID) != "7" {
		t.Fatalf("tools/list: %d %s", status, body)
	}
	if tl := tools[0].(map[string]any); tl["name"] != "t_echo" || tl["inputSchema"] == nil {
		t.Fatalf("tools/list tool: %v", tl)
	}

	hdr := wireHeaders(tok, "tools/call")
	hdr["Mcp-Name"] = "t_echo"
	status, _, body = h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"b"},"_meta":{%s}}}`, wireMeta), hdr)
	r = decodeReply(t, body)
	content, _ := r.Result["content"].([]any)
	if status != 200 || r.Error != nil || len(content) != 1 || content[0].(map[string]any)["text"] != "echo:b" {
		t.Fatalf("tools/call: %d %s", status, body)
	}

	// subscriptions/listen: an event stream whose first message acknowledges
	// the subscription.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/mcp", strings.NewReader(
		fmt.Sprintf(`{"jsonrpc":"2.0","id":"L","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{%s}}}`, wireMeta)))
	for k, v := range wireHeaders(tok, "subscriptions/listen") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("listen: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "data:") && strings.Contains(line, "acknowledged") {
			return
		}
	}
	t.Fatalf("listen stream ended without an acknowledgement: %v", sc.Err())
}

// pagedBackend has five tools.
func pagedBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "paged", Version: "1"}, nil)
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		mcp.AddTool(s, &mcp.Tool{Name: n}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
		})
	}
	return s
}

const pagedPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["all"], "default_template": "all"}},
  "templates": {"all": {"rules": [{"id": "all", "server": "t", "tools": ["a", "b", "c", "d", "e"]}]}}
}`

// TestCatalogPagination is FR-1.23: tools/list returns pages of at most
// CP-19 tools (configured to 2 here) with an opaque nextCursor while tools
// remain, and the pages form the complete catalog without duplicates.
//
// FR-1.24 and SR-5.7-2: a random cursor, a cursor with one byte changed, a
// cursor issued to another session and a cursor issued under a superseded
// policy revision each get -32602; an issued cursor still works for its
// own session and revision.
func TestCatalogPagination(t *testing.T) {
	reqtest.Verifies(t, "FR-1.23", "FR-1.24", "SR-5.7-2")
	h := newHarness(t, harnessOpts{backend: pagedBackend, policy: pagedPolicy, limits: "catalog_page_size = 2"})
	_, tok := h.session("all")
	seen := map[string]int{}
	cursor := ""
	var sizes []int
	for page := 0; page < 10; page++ {
		params := `"_meta":{` + wireMeta + `}`
		if cursor != "" {
			params = fmt.Sprintf(`"cursor":%q,%s`, cursor, params)
		}
		status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{%s}}`, page+1, params), wireHeaders(tok, "tools/list"))
		r := decodeReply(t, body)
		if status != 200 || r.Error != nil {
			t.Fatalf("page %d: %d %s", page, status, body)
		}
		tools, _ := r.Result["tools"].([]any)
		sizes = append(sizes, len(tools))
		if len(tools) > 2 {
			t.Fatalf("page %d has %d tools, CP-19 is 2", page, len(tools))
		}
		for _, tl := range tools {
			seen[tl.(map[string]any)["name"].(string)]++
		}
		next, _ := r.Result["nextCursor"].(string)
		if next == "" {
			break
		}
		// The cursor must not carry a tool name. (Checking for the names'
		// common prefix "t_" failed about one run in twenty: the sealed
		// cursor is base64url, and "t_" occurs in random text of its
		// length that often.)
		for name := range seen {
			if strings.Contains(next, name) {
				t.Fatalf("cursor %q exposes the tool name %s", next, name)
			}
		}
		cursor = next
	}
	if fmt.Sprint(sizes) != "[2 2 1]" {
		t.Fatalf("page sizes %v", sizes)
	}
	for _, n := range []string{"t_a", "t_b", "t_c", "t_d", "t_e"} {
		if seen[n] != 1 {
			t.Fatalf("%s seen %d times: %v", n, seen[n], seen)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("union %v", seen)
	}
	// A cursor the Gateway did not issue.
	status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{"cursor":"not-a-cursor","_meta":{%s}}}`, wireMeta), wireHeaders(tok, "tools/list"))
	wantError(t, "random cursor", status, body, 400, -32602)

	list := func(tok, cursor string) (int, string) {
		t.Helper()
		status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":100,"method":"tools/list","params":{"cursor":%q,"_meta":{%s}}}`, cursor, wireMeta), wireHeaders(tok, "tools/list"))
		return status, body
	}
	// A fresh first-page cursor of this session works.
	_, _, body = h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":98,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta), wireHeaders(tok, "tools/list"))
	issued, _ := decodeReply(t, body).Result["nextCursor"].(string)
	if status, body := list(tok, issued); status != 200 || decodeReply(t, body).Error != nil {
		t.Fatalf("issued cursor: %d %s", status, body)
	}
	// One byte changed, at the start, the middle and the end.
	for _, i := range []int{0, len(issued) / 2, len(issued) - 1} {
		b := []byte(issued)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		status, body := list(tok, string(b))
		wantError(t, fmt.Sprintf("cursor modified at %d", i), status, body, 400, -32602)
	}
	// The same cursor presented by another session.
	_, other := h.session("all")
	status, body = list(other, issued)
	wantError(t, "cursor of another session", status, body, 400, -32602)
	// The same cursor after a new policy revision is activated.
	snap, err := policy.Compile([]byte(strings.Replace(pagedPolicy, `"r1"`, `"r2"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.gw.ActivatePolicy("test", snap); err != nil {
		t.Fatal(err)
	}
	status, body = list(tok, issued)
	wantError(t, "cursor of a superseded revision", status, body, 400, -32602)
}

// headerBackend has a tool whose input schema carries an x-mcp-header
// annotation; the tool reports the region argument it received.
func headerBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "hdr", Version: "1"}, nil)
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"region": map[string]any{"type": "string", "x-mcp-header": "Region"},
		},
	}
	s.AddTool(&mcp.Tool{Name: "where", InputSchema: schema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a map[string]any
		_ = json.Unmarshal(req.Params.Arguments, &a)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("region=%v", a["region"])}}}, nil
	})
	return s
}

const headerPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["h"], "default_template": "h"}},
  "templates": {"h": {"rules": [{"id": "h", "server": "t", "tools": ["where"]}]}}
}`

// TestHeaderAnnotationsRemoved is FR-1.28: the presented input schema has
// no x-mcp-header annotation, and Mcp-Param-* request headers have no
// effect on the call (neither required nor applied).
func TestHeaderAnnotationsRemoved(t *testing.T) {
	reqtest.Verifies(t, "FR-1.28")
	h := newHarness(t, harnessOpts{backend: headerBackend, policy: headerPolicy})
	_, tok := h.session("h")
	status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta), wireHeaders(tok, "tools/list"))
	if status != 200 || !strings.Contains(body, `"region"`) || strings.Contains(body, "x-mcp-header") {
		t.Fatalf("tools/list: %d %s", status, body)
	}
	call := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t_where","arguments":{"region":"eu"},"_meta":{%s}}}`, wireMeta)
	hdr := wireHeaders(tok, "tools/call")
	hdr["Mcp-Name"] = "t_where"
	// Without the header that the annotation would have required: accepted.
	if status, _, body = h.post(call, hdr); status != 200 || !strings.Contains(body, "region=eu") {
		t.Fatalf("no header: %d %s", status, body)
	}
	// A conflicting header: ignored, the body argument is used.
	hdr["Mcp-Param-Region"] = "us"
	if status, _, body = h.post(call, hdr); status != 200 || !strings.Contains(body, "region=eu") {
		t.Fatalf("conflicting header: %d %s", status, body)
	}
	// A header for an absent argument does not add it.
	noArg := fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t_where","arguments":{},"_meta":{%s}}}`, wireMeta)
	if status, _, body = h.post(noArg, hdr); status != 200 || !strings.Contains(body, `region=\u003cnil\u003e`) {
		t.Fatalf("header without argument: %d %s", status, body)
	}
}

// TestResponseIDEcho is FR-1.18 in part: results and errors echo string
// and integer request IDs, and error codes are integers.
//
// Partial: this covers method-level errors only; the transport,
// authentication and fail-closed cases are in the end-to-end
// TestEveryResponseEchoesID.
func TestResponseIDEcho(t *testing.T) {
	reqtest.Partial(t, "FR-1.18")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	callHdr := wireHeaders(tok, "tools/call")
	callHdr["Mcp-Name"] = "t_nothere"
	for _, id := range []string{`17`, `"abc"`, `"0"`, `-4`} {
		cases := []struct {
			body string
			hdr  map[string]string
		}{
			{fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/list","params":{"_meta":{%s}}}`, id, wireMeta), wireHeaders(tok, "tools/list")},
			{fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"prompts/list","params":{"_meta":{%s}}}`, id, wireMeta), wireHeaders(tok, "prompts/list")},
			{fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"t_nothere","_meta":{%s}}}`, id, wireMeta), callHdr},
			{fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/list","params":{"_meta":{}}}`, id), wireHeaders(tok, "tools/list")},
		}
		for _, c := range cases {
			_, _, body := h.post(c.body, c.hdr)
			r := decodeReply(t, body)
			if string(r.ID) != id {
				t.Fatalf("id %s echoed as %s: %s", id, r.ID, body)
			}
			if r.Error != nil {
				if _, err := r.Error.Code.Int64(); err != nil {
					t.Fatalf("non-integer error code %q", r.Error.Code)
				}
			}
		}
	}
}

// TestUnqualifiedFeaturesRejected is SR-5.6-1 in part: resources,
// prompts, completion, logging and task methods are rejected with -32601,
// and neither era advertises a capability other than tools.
//
// Partial here: the absence of server-initiated requests (sampling,
// elicitation, roots) toward the harness is shown by the conformance suite
// (internal/conformance), which verifies SR-5.6-1.
func TestUnqualifiedFeaturesRejected(t *testing.T) {
	reqtest.Partial(t, "SR-5.6-1")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	for _, m := range []string{"resources/list", "resources/read", "resources/templates/list", "resources/subscribe", "prompts/list", "prompts/get",
		"completion/complete", "logging/setLevel", "tasks/get", "tasks/list", "tasks/cancel", "tasks/result"} {
		hdr := wireHeaders(tok, m)
		params := `"_meta":{` + wireMeta + `}`
		switch m {
		case "resources/read":
			hdr["Mcp-Name"] = "x"
			params = `"uri":"x",` + params
		case "resources/subscribe":
			params = `"uri":"x",` + params
		case "prompts/get":
			hdr["Mcp-Name"] = "x"
			params = `"name":"x",` + params
		}
		status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{%s}}`, m, params), hdr)
		r := decodeReply(t, body)
		if r.Error == nil || r.Error.Code.String() != "-32601" {
			t.Fatalf("%s: %d %s", m, status, body)
		}
	}
	_, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{%s}}}`, wireMeta), wireHeaders(tok, "server/discover"))
	caps, _ := decodeReply(t, body).Result["capabilities"].(map[string]any)
	if len(caps) != 1 || caps["tools"] == nil {
		t.Fatalf("2026-07-28 capabilities: %v", caps)
	}
	_, _, body = h.post(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`, map[string]string{"Authorization": "Bearer " + tok})
	caps, _ = decodeReply(t, body).Result["capabilities"].(map[string]any)
	if len(caps) != 1 || caps["tools"] == nil {
		t.Fatalf("2025-11-25 capabilities: %v", caps)
	}
}
