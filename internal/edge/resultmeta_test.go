package edge

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// checkResultMeta fails unless a result carries resultType "complete"
// (FR-1.14) and _meta.io.modelcontextprotocol/serverInfo naming the
// Gateway (FR-1.15).
func checkResultMeta(t *testing.T, name string, result map[string]any) {
	t.Helper()
	if result["resultType"] != "complete" {
		t.Fatalf("%s: resultType %v: %v", name, result["resultType"], result)
	}
	meta, _ := result["_meta"].(map[string]any)
	si, _ := meta[mcp.MetaKeyServerInfo].(map[string]any)
	if si["name"] != "secure-mcp-gateway" || si["version"] != backend.Version {
		t.Fatalf("%s: serverInfo %v", name, meta)
	}
}

// TestResultMetaOnEveryBaselineMethod is FR-1.14 and FR-1.15: the result of
// each 2026-07-28 baseline method (server/discover, tools/list, tools/call,
// including a held-capable streamed call, and the empty complete result
// that ends a listen stream) carries resultType "complete" and the
// Gateway's serverInfo.
func TestResultMetaOnEveryBaselineMethod(t *testing.T) {
	reqtest.Verifies(t, "FR-1.14", "FR-1.15")
	h := newHarness(t, harnessOpts{policy: onePolicy})
	_, tok := h.session("one")
	for _, m := range []struct{ method, params string }{
		{"server/discover", ""},
		{"tools/list", ""},
		{"tools/call", `"name":"t_echo","arguments":{"text":"b"},`},
		{"tools/call", `"name":"t_echo","arguments":{"text":"p"},"_meta":{"progressToken":"p1",` + wireMeta + `},`},
	} {
		hdr := wireHeaders(tok, m.method)
		if m.method == "tools/call" {
			hdr["Mcp-Name"] = "t_echo"
		}
		params := m.params + `"_meta":{` + wireMeta + `}`
		if strings.Contains(m.params, "progressToken") {
			params = strings.TrimSuffix(m.params, ",")
		}
		status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{%s}}`, m.method, params), hdr)
		if data, ok := lastEventData(body); ok {
			body = data
		}
		r := decodeReply(t, body)
		if status != 200 || r.Error != nil {
			t.Fatalf("%s: %d %s", m.method, status, body)
		}
		checkResultMeta(t, m.method+" "+m.params, r.Result)
	}

	// subscriptions/listen: the Gateway ends the stream with an empty
	// complete result (FR-1.37).
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
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		if strings.Contains(data, "acknowledged") {
			h.gw.EndListenStreams()
			continue
		}
		r := decodeReply(t, data)
		if r.Result == nil {
			continue
		}
		checkResultMeta(t, "subscriptions/listen", r.Result)
		return
	}
	t.Fatalf("listen stream ended without a complete result: %v", sc.Err())
}

// lastEventData returns the data of the last event of an event-stream
// body.
func lastEventData(body string) (string, bool) {
	var last string
	found := false
	for _, line := range strings.Split(body, "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok {
			last, found = d, true
		}
	}
	return last, found
}

// relayBackend has three tools: text returns text content, structured
// returns structuredContent, failing returns isError; meta returns the
// _meta keys it received.
func relayBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "relay", Version: "1"}, nil)
	add := func(name string, res func(req *mcp.CallToolRequest) *mcp.CallToolResult) {
		s.AddTool(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return res(req), nil
		})
	}
	add("text", func(*mcp.CallToolRequest) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "raw text"}}}
	})
	add("structured", func(*mcp.CallToolRequest) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"v":"raw"}`}}, StructuredContent: map[string]any{"v": "raw"}}
	})
	add("failing", func(*mcp.CallToolRequest) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "raw failure"}}, IsError: true}
	})
	add("meta", func(req *mcp.CallToolRequest) *mcp.CallToolResult {
		keys := []string{}
		for k := range req.Params.Meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(keys, ",")}}}
	})
	return s
}

const relayPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["all"], "default_template": "all"}},
  "templates": {"all": {"rules": [{"id": "all", "server": "t", "tools": ["text", "structured", "failing", "meta"]}]}}
}`

// rewriteFilter is a mandatory response filter that replaces all three
// result members of the text, structured and failing tools when the
// call's arguments ask for it, and records what each call carried.
type rewriteFilter struct {
	mu    sync.Mutex
	calls []pipeline.Call
}

func (*rewriteFilter) ID() string { return "rewrite-test" }

func (f *rewriteFilter) FilterResponse(_ context.Context, call *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	f.mu.Lock()
	f.calls = append(f.calls, *call)
	f.mu.Unlock()
	if call.Tool != "text" && call.Tool != "structured" && call.Tool != "failing" {
		return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
	}
	out := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "filtered " + call.Tool}},
		StructuredContent: map[string]any{"v": "filtered"}, IsError: call.Tool != "failing"}
	return pipeline.ResponseVerdict{Action: pipeline.Transform, Result: out, ReasonCode: "REWRITTEN"}, nil
}

// TestToolResultRelayAfterTransform is FR-1.31: for text, structured and
// error results, the harness receives content, structuredContent and
// isError exactly as the response filter left them (each member replaced,
// isError inverted), and nothing of the backend's original members.
func TestToolResultRelayAfterTransform(t *testing.T) {
	reqtest.Verifies(t, "FR-1.31")
	rf := &rewriteFilter{}
	f := pipeline.NewFilters()
	if err := f.RegisterResponse(rf, pipeline.Registration{Order: 500, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, harnessOpts{backend: relayBackend, policy: relayPolicy, filters: f})
	_, tok := h.session("all")
	for _, tool := range []string{"text", "structured", "failing"} {
		hdr := wireHeaders(tok, "tools/call")
		hdr["Mcp-Name"] = "t_" + tool
		status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t_%s","arguments":{},"_meta":{%s}}}`, tool, wireMeta), hdr)
		r := decodeReply(t, body)
		if status != 200 || r.Error != nil {
			t.Fatalf("%s: %d %s", tool, status, body)
		}
		if strings.Contains(body, "raw") {
			t.Fatalf("%s: a pre-filter member reached the harness: %s", tool, body)
		}
		content, _ := r.Result["content"].([]any)
		if len(content) != 1 || content[0].(map[string]any)["text"] != "filtered "+tool {
			t.Fatalf("%s: content %v", tool, r.Result["content"])
		}
		if sc, _ := r.Result["structuredContent"].(map[string]any); sc["v"] != "filtered" {
			t.Fatalf("%s: structuredContent %v", tool, r.Result["structuredContent"])
		}
		if isErr, _ := r.Result["isError"].(bool); isErr != (tool != "failing") {
			t.Fatalf("%s: isError %v", tool, r.Result["isError"])
		}
	}
}

// TestTraceContextAndClientInfo is FR-1.44 and FR-1.45 at the edge: a valid
// traceparent and the clientInfo of a request reach the pipeline call as
// observation attributes (pipeline.Call.TraceParent, ClientInfo), the
// backend receives none of traceparent, tracestate, baggage or clientInfo
// in its _meta, and an invalid traceparent is not recorded. The
// observation record itself is checked end to end in
// internal/e2e.TestTraceContextObserved.
func TestTraceContextAndClientInfo(t *testing.T) {
	reqtest.Partial(t, "FR-1.44", "FR-1.45")
	rf := &rewriteFilter{}
	f := pipeline.NewFilters()
	if err := f.RegisterResponse(rf, pipeline.Registration{Order: 500, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, harnessOpts{backend: relayBackend, policy: relayPolicy, filters: f})
	_, tok := h.session("all")
	const tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
	call := func(traceparent string) string {
		t.Helper()
		meta := fmt.Sprintf(`"traceparent":%q,"tracestate":"vendor=x","baggage":"user=alice",%q:{"name":"forged-client","version":"9.9"},%s`,
			traceparent, mcp.MetaKeyClientInfo, wireMeta)
		hdr := wireHeaders(tok, "tools/call")
		hdr["Mcp-Name"] = "t_meta"
		status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t_meta","arguments":{},"_meta":{%s}}}`, meta), hdr)
		r := decodeReply(t, body)
		if status != 200 || r.Error != nil {
			t.Fatalf("%d %s", status, body)
		}
		content, _ := r.Result["content"].([]any)
		return content[0].(map[string]any)["text"].(string)
	}
	seen := call(tp)
	for _, k := range []string{"traceparent", "tracestate", "baggage", mcp.MetaKeyClientInfo} {
		if strings.Contains(seen, k) {
			t.Fatalf("backend received _meta %q (keys %q)", k, seen)
		}
	}
	call("00-00000000000000000000000000000000-00f067aa0ba902b7-01")
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if len(rf.calls) != 2 {
		t.Fatalf("%d calls seen", len(rf.calls))
	}
	if c := rf.calls[0]; c.TraceParent != tp || c.ClientInfo != "forged-client/9.9" {
		t.Fatalf("observation attributes: %q %q", c.TraceParent, c.ClientInfo)
	}
	if c := rf.calls[1]; c.TraceParent != "" {
		t.Fatalf("invalid traceparent recorded: %q", c.TraceParent)
	}
}

func TestValidTraceparent(t *testing.T) {
	for s, want := range map[string]bool{
		"00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01":       true,
		"01-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01-extra": true,
		"00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01-extra": false,
		"ff-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01":       false,
		"00-0AF7651916CD43DD8448EB211C80319C-00f067aa0ba902b7-01":       false,
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01":       false,
		"00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01":       false,
		"00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7":          false,
		"": false,
	} {
		if validTraceparent(s) != want {
			t.Errorf("%q: want %v", s, want)
		}
	}
	if _, ci := selfAsserted(mcp.Meta{mcp.MetaKeyClientInfo: map[string]any{"name": "a\x1bb", "version": strings.Repeat("v", 300)}}); len(ci) != maxClientInfo || strings.ContainsRune(ci, 0x1b) {
		t.Fatalf("clientInfo not bounded or not cleaned: %q", ci)
	}
}
