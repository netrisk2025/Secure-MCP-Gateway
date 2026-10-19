package conformance

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// suite carries the state shared by the checks.
type suite struct {
	t   *testing.T
	ex  examples
	v   *validator
	r   *report
	gw  *gateway
	be  *scripted
	mu  sync.Mutex
	err []int // every JSON-RPC error code the Gateway returned

	// bridges, when set, are the stdio adapters every request is also
	// sent through and compared with a direct connection (bridge_test.go).
	bridges []*bridge
}

// check validates x against def and records the outcome under dir.
func (s *suite) check(dir, def, what string, x any) {
	s.t.Helper()
	if err := s.v.validateValue(def, x); err != nil {
		s.r.add(dir, "FAIL %s does not validate as %s", what, def)
		s.t.Errorf("%s: %s does not validate as %s: %v\n%v", dir, what, def, err, x)
		return
	}
	s.r.add(dir, "%s validates as `%s`", what, def)
}

// checkError validates an error response: against def as a whole message
// when def is a response definition, else against its error member.
func (s *suite) checkError(dir, def, what string, m map[string]any) {
	s.t.Helper()
	if s.v.validateValue(def, m) == nil {
		s.r.add(dir, "%s validates as `%s`", what, def)
		return
	}
	s.check(dir, def, what+" (error member)", m["error"])
}

func (s *suite) note(r response) response {
	for _, raw := range r.Messages {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			if c := errorCode(m); c != 0 {
				s.mu.Lock()
				s.err = append(s.err, c)
				s.mu.Unlock()
			}
		}
	}
	return r
}

func (s *suite) send(msg map[string]any) response {
	raw, err := json.Marshal(msg)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.post(raw, headersFor(msg))
}

func (s *suite) post(body []byte, hdr map[string]string) response {
	r := s.note(s.gw.post(body, hdr))
	for _, b := range s.bridges {
		b.compare(s.t, body, hdr, r)
	}
	return r
}

// call sends a tools/call for a backend tool built from the CallToolRequest
// example (its _meta and shape), with the given arguments.
func (s *suite) call(tool string, args map[string]any, progress string) response {
	msg := s.ex.one(s.t, "CallToolRequest")
	params := msg["params"].(map[string]any)
	params["name"] = public(tool)
	params["arguments"] = args
	if progress != "" {
		params["_meta"].(map[string]any)["progressToken"] = progress
	}
	msg["id"] = "call-" + tool
	return s.send(msg)
}

// TestConformanceSuite is FR-12.9 and FR-1.19, and covers SR-5.6-1 (every
// unqualified feature refused, only tools advertised, no server-initiated
// request reaching the harness) and FR-1.42 (no logging capability, no
// notifications/message northbound). See the package comment.
func TestConformanceSuite(t *testing.T) {
	reqtest.Verifies(t, "FR-12.9", "FR-1.19", "SR-5.6-1", "FR-1.42")
	ex := loadExamples(t)
	s := &suite{t: t, ex: ex, v: newValidator(t), r: &report{}}
	s.be = newBackend(t, ex)
	s.gw = startGateway(t, s.be)

	t.Run("schema", s.schema)
	t.Run("discover", s.discover)
	t.Run("tools", s.tools)
	t.Run("call", s.callTool)
	t.Run("server-initiated", s.serverInitiated)
	t.Run("errors", s.errors)
	t.Run("unsupported", s.unsupported)
	t.Run("notifications", s.notifications)
	t.Run("listen", s.listen)
	t.Run("southbound", s.southbound)
	t.Run("codes", s.codes)
	s.untouched()

	dirs := ex.dirs()
	for _, d := range dirs {
		if len(s.r.rows[d]) == 0 {
			t.Errorf("no result reported for example directory %s", d)
		}
	}
	md := s.r.markdown(dirs)
	t.Log("\n" + md)
	if p := os.Getenv("SMCP_CONFORMANCE_REPORT"); p != "" {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(md), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// schema: every example validates against the definition it is named
// after.
func (s *suite) schema(t *testing.T) {
	for _, d := range s.ex.dirs() {
		ok := 0
		for _, e := range s.ex[d] {
			if err := s.v.validate(d, e.Raw); err != nil {
				t.Errorf("example %s/%s does not validate: %v", d, e.Name, err)
				continue
			}
			ok++
		}
		s.r.add(d, "schema.json: %d of %d examples valid", ok, len(s.ex[d]))
	}
}

func (s *suite) discover(t *testing.T) {
	r := s.send(s.ex.one(t, "DiscoverRequest"))
	m := r.last()
	if r.Status != 200 || m == nil {
		t.Fatalf("server/discover: %d %s", r.Status, r.Body)
	}
	s.r.add("DiscoverRequest", "sent: HTTP %d", r.Status)
	s.check("DiscoverResultResponse", "DiscoverResultResponse", "server/discover response", m)
	s.check("DiscoverResult", "DiscoverResult", "server/discover result", m["result"])
	s.check("ServerCapabilities", "ServerCapabilities", "advertised capabilities", m["result"].(map[string]any)["capabilities"])
	// Only tools is advertised, in both eras (SR-5.6-1, FR-1.42).
	if caps, _ := m["result"].(map[string]any)["capabilities"].(map[string]any); len(caps) != 1 || caps["tools"] == nil {
		t.Errorf("2026-07-28 capabilities: %v", caps)
	}
	legacy := s.post([]byte(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"conformance","version":"1"}}}`), nil)
	if res, _ := legacy.last()["result"].(map[string]any); res == nil {
		t.Errorf("legacy initialize: %s", legacy.Body)
	} else if caps, _ := res["capabilities"].(map[string]any); len(caps) != 1 || caps["tools"] == nil {
		t.Errorf("2025-11-25 capabilities: %v", caps)
	}
	s.r.add("ServerCapabilities", "only `tools` is advertised, in both eras (no logging, resources, prompts, completions or extensions)")
	s.r.add("ClientCapabilities", "sent in every request's _meta (empty object, as in the examples)")
}

func (s *suite) tools(t *testing.T) {
	r := s.send(s.ex.one(t, "ListToolsRequest"))
	m := r.last()
	if r.Status != 200 || m == nil || m["result"] == nil {
		t.Fatalf("tools/list: %d %s", r.Status, r.Body)
	}
	s.r.add("ListToolsRequest", "sent: HTTP %d", r.Status)
	s.check("ListToolsResultResponse", "ListToolsResultResponse", "tools/list response", m)
	s.check("ListToolsResult", "ListToolsResult", "tools/list result", m["result"])
	presented := map[string]map[string]any{}
	for _, tl := range m["result"].(map[string]any)["tools"].([]any) {
		tm := tl.(map[string]any)
		presented[tm["name"].(string)] = tm
		if err := s.v.validateValue("Tool", tm); err != nil {
			t.Errorf("presented tool %v does not validate as Tool: %v", tm["name"], err)
		}
	}
	missing := []string{}
	for _, e := range s.ex["Tool"] {
		var tool map[string]any
		_ = json.Unmarshal(e.Raw, &tool)
		if presented[public(tool["name"].(string))] == nil {
			missing = append(missing, e.Name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("Tool examples served by the backend but not presented: %v", missing)
		s.r.add("Tool", "FAIL not presented: %v", missing)
	} else {
		s.r.add("Tool", "served southbound by the backend; each presented under its public name and every presented tool validates as `Tool`")
	}
	// A cursor the Gateway did not issue.
	msg := s.ex.one(t, "ListToolsRequest")
	msg["params"].(map[string]any)["cursor"] = "not-issued"
	if c := errorCode(s.send(msg).last()); c != -32602 {
		t.Errorf("invalid cursor: code %d", c)
	}
	s.r.add("PaginatedRequestParams", "tools/list with a cursor the Gateway did not issue gets -32602 (FR-1.24)")
}

func (s *suite) callTool(t *testing.T) {
	// The CallToolRequest example, with the tool's public name.
	msg := s.ex.one(t, "CallToolRequest")
	msg["params"].(map[string]any)["name"] = public("get_weather")
	r := s.send(msg)
	m := r.last()
	if r.Status != 200 || m["result"] == nil {
		t.Fatalf("tools/call: %d %s", r.Status, r.Body)
	}
	s.r.add("CallToolRequest", "sent with the public name %s: HTTP %d", public("get_weather"), r.Status)
	s.r.add("CallToolRequestParams", "carried by the CallToolRequest example")
	s.check("CallToolResultResponse", "CallToolResultResponse", "tools/call response", m)

	// Each CallToolResult example, returned by the backend and relayed:
	// the harness receives a valid result whose content, structuredContent
	// and isError are the example's.
	contentDirs := map[string]bool{}
	for i, e := range s.ex["CallToolResult"] {
		r := s.call(fmt.Sprintf("result_%d", i), map[string]any{}, "")
		m := r.last()
		res, _ := m["result"].(map[string]any)
		if res == nil {
			t.Errorf("CallToolResult/%s: %d %s", e.Name, r.Status, r.Body)
			continue
		}
		s.check("CallToolResult", "CallToolResult", "relayed result of "+e.Name, res)
		var want map[string]any
		_ = json.Unmarshal(e.Raw, &want)
		if want["isError"] == false {
			delete(want, "isError") // false and absent are the same
		}
		for _, k := range []string{"content", "structuredContent", "isError"} {
			if !reflect.DeepEqual(want[k], res[k]) {
				t.Errorf("CallToolResult/%s: %s changed in relay: %v -> %v", e.Name, k, want[k], res[k])
			}
		}
		for _, c := range res["content"].([]any) {
			typ := c.(map[string]any)["type"].(string)
			def := map[string]string{"text": "TextContent", "image": "ImageContent", "audio": "AudioContent", "resource": "EmbeddedResource", "resource_link": "ResourceLink"}[typ]
			if def != "" {
				s.check(def, def, "a relayed "+typ+" content block", c)
				contentDirs[def] = true
			}
		}
	}
	s.r.add("CallToolResult", "content, structuredContent and isError of every example reach the harness unchanged")

	// Each content block example, returned alone by the backend.
	for _, d := range contentBlocks {
		r := s.call("content_"+d, map[string]any{}, "")
		m := r.last()
		res, _ := m["result"].(map[string]any)
		if res == nil {
			s.r.add(d, "returned by the backend in a result: the harness got error %d", errorCode(m))
			continue
		}
		var want any
		_ = json.Unmarshal(s.ex[d][0].Raw, &want)
		c, _ := res["content"].([]any)
		if len(c) != 1 || !reflect.DeepEqual(c[0], want) {
			t.Errorf("%s: relayed content %v", d, res["content"])
		}
		s.check(d, d, "returned by the backend in a result and relayed unchanged; it", c[0])
	}

	// Arguments that do not match the input schema.
	r = s.call("get_weather", map[string]any{"location": 7}, "")
	s.checkError("InvalidParamsError", "InvalidParamsError", "tools/call with arguments violating the schema", r.last())
	// A tool outside the catalog.
	r = s.call("no_such_tool", map[string]any{}, "")
	s.checkError("InvalidParamsError", "InvalidParamsError", "tools/call of an unknown tool", r.last())

	// InputRequiredResult (MRTR) is not relayed: -31010 (FR-5.24).
	for i, e := range s.ex["InputRequiredResult"] {
		r := s.call(fmt.Sprintf("input_%d", i), map[string]any{}, "")
		if c := errorCode(r.last()); c != -31010 {
			t.Errorf("InputRequiredResult/%s: code %d: %s", e.Name, c, r.Body)
		}
	}
	s.r.add("InputRequiredResult", "returned by the backend; the harness gets -31010 INPUT_REQUIRED_UNSUPPORTED (FR-5.24, MRTR deferred)")
	for _, d := range []string{"InputRequests", "InputResponses"} {
		s.r.add(d, "part of the MRTR exchange, which is deferred from 1.0 (SRS Appendix N); not relayed")
	}
}

// serverInitiated: the backend sends each server-initiated request example
// during a call; the Gateway answers it -32601 southbound (FR-5.20) and no
// such request reaches the harness.
func (s *suite) serverInitiated(t *testing.T) {
	for _, d := range serverRequests {
		r := s.call("server_"+d, map[string]any{}, "p-"+d)
		var method string
		_ = json.Unmarshal(s.ex[d][0].Raw, &struct {
			Method *string `json:"method"`
		}{&method})
		got := ""
		for _, raw := range r.Messages {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			if m["method"] == method {
				t.Errorf("%s reached the harness", d)
			}
			if res, ok := m["result"].(map[string]any); ok {
				if c, ok := res["content"].([]any); ok && len(c) > 0 {
					got, _ = c[0].(map[string]any)["text"].(string)
				}
			}
		}
		if got != "error -32601" {
			t.Errorf("%s: the Gateway's southbound answer was %q", d, got)
		}
		s.r.add(d, "sent by the backend during a call: the Gateway answered -32601 southbound and the harness stream carried no %s (FR-5.20)", method)
	}
	logReq := s.ex.one(t, "CallToolRequest")
	logReq["params"].(map[string]any)["name"] = public("log_then_result")
	logReq["params"].(map[string]any)["arguments"] = map[string]any{}
	logReq["params"].(map[string]any)["_meta"].(map[string]any)["progressToken"] = "p-log"
	logReq["params"].(map[string]any)["_meta"].(map[string]any)["io.modelcontextprotocol/logLevel"] = "debug"
	logReq["id"] = "call-log"
	r := s.send(logReq)
	for _, raw := range r.Messages {
		if strings.Contains(string(raw), `"notifications/message"`) {
			t.Error("notifications/message reached the harness")
		}
	}
	s.r.add("LoggingMessageNotification", "sent by the backend during a streamed call whose request asked for logLevel debug: withheld from the harness (FR-1.42)")
	s.r.add("LoggingMessageNotificationParams", "carried by the LoggingMessageNotification example")
}

func (s *suite) errors(t *testing.T) {
	list := s.ex.one(t, "ListToolsRequest")
	raw, _ := json.Marshal(list)
	// A header that disagrees with the body.
	hdr := headersFor(list)
	hdr["Mcp-Method"] = "tools/call"
	r := s.post(raw, hdr)
	if r.Status != 400 {
		t.Errorf("header mismatch: HTTP %d", r.Status)
	}
	s.checkError("HeaderMismatchError", "HeaderMismatchError", fmt.Sprintf("Mcp-Method header disagreeing with the body (HTTP %d)", r.Status), r.last())
	// A protocol version the Gateway does not support.
	bad := s.ex.one(t, "ListToolsRequest")
	bad["params"].(map[string]any)["_meta"].(map[string]any)["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
	r = s.send(bad)
	s.checkError("UnsupportedProtocolVersionError", "UnsupportedProtocolVersionError", fmt.Sprintf("request with protocol version 2099-01-01 (HTTP %d)", r.Status), r.last())
	// A body that is not JSON.
	r = s.post([]byte(`{"jsonrpc":"2.0","id":1,"method":`), headersFor(list))
	s.checkError("ParseError", "ParseError", fmt.Sprintf("a body that is not JSON (HTTP %d)", r.Status), r.last())
	s.r.add("MissingRequiredClientCapabilityError", "not produced: the Gateway requires no client capability for the baseline methods")
	s.r.add("InternalError", "not produced by these checks; internal faults are mapped to Appendix B codes")
}

// unsupported: methods outside the tools-only baseline are refused with
// -32601 (FR-1.10, SR-5.6-1).
func (s *suite) unsupported(t *testing.T) {
	for _, d := range []string{"CompleteRequest", "GetPromptRequest", "ListPromptsRequest", "ListResourcesRequest", "ListResourceTemplatesRequest", "ReadResourceRequest"} {
		r := s.send(s.ex.one(t, d))
		m := r.last()
		if c := errorCode(m); c != -32601 {
			t.Errorf("%s: code %d: %s", d, c, r.Body)
		}
		s.checkError(d, "MethodNotFoundError", fmt.Sprintf("refused (HTTP %d)", r.Status), m)
		s.r.add("MethodNotFoundError", "%s refused", d)
	}
	// Task-extension, subscription and logging methods (SR-5.6-1).
	for _, method := range []string{"resources/subscribe", "logging/setLevel", "tasks/get", "tasks/list", "tasks/cancel", "tasks/result"} {
		msg := s.ex.one(t, "ListToolsRequest")
		msg["method"], msg["id"] = method, "m-"+method
		if method == "resources/subscribe" {
			msg["params"].(map[string]any)["uri"] = "file:///x"
		}
		if c := errorCode(s.send(msg).last()); c != -32601 {
			t.Errorf("%s: code %d", method, c)
		}
	}
	s.r.add("MethodNotFoundError", "resources/subscribe, logging/setLevel and tasks/get, list, cancel and result refused")
	for _, d := range []string{"CompleteRequestParams", "CompleteResult", "CompleteResultResponse", "GetPromptRequestParams", "GetPromptResult", "GetPromptResultResponse",
		"ListPromptsResult", "ListPromptsResultResponse", "ListResourcesResult", "ListResourcesResultResponse", "ListResourceTemplatesResult",
		"ListResourceTemplatesResultResponse", "ReadResourceResult", "ReadResourceResultResponse", "PromptListChangedNotification",
		"ResourceListChangedNotification", "ResourceUpdatedNotification", "ResourceUpdatedNotificationParams", "Resource",
		"TextResourceContents", "BlobResourceContents"} {
		if s.ex[d] != nil {
			s.r.add(d, "not produced: resources, prompts and completion are not relayed (tools-only baseline, FR-1.10)")
		}
	}
}

func (s *suite) notifications(t *testing.T) {
	n := s.ex.one(t, "CancelledNotification")
	raw, _ := json.Marshal(n)
	hdr := headersFor(n)
	if hdr["MCP-Protocol-Version"] == "" {
		hdr["MCP-Protocol-Version"] = "2026-07-28"
	}
	r := s.post(raw, hdr)
	if r.Status != http.StatusAccepted || len(r.Messages) != 0 {
		t.Errorf("notifications/cancelled: %d %q", r.Status, r.Body)
	}
	s.r.add("CancelledNotification", "sent: HTTP %d with no body (FR-1.5); in-flight cancellation is TestStreamCloseCancelsWithinOneSecond", r.Status)
	s.r.add("CancelledNotificationParams", "carried by the CancelledNotification example")

	// Progress: the backend reports progress with the southbound token; the
	// harness receives it with its own token.
	r = s.call("progress_then_result", map[string]any{}, "harness-token")
	found := false
	for _, raw := range r.Messages {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if m["method"] == "notifications/progress" {
			found = true
			s.check("ProgressNotification", "ProgressNotification", "relayed progress", m)
			if m["params"].(map[string]any)["progressToken"] != "harness-token" {
				t.Errorf("progress token %v", m["params"])
			}
		}
	}
	if !found {
		t.Errorf("no progress relayed: %s", r.Body)
	}
	s.r.add("ProgressNotificationParams", "carried by the relayed progress notification")
}

// listen: the SubscriptionsListenRequest example opens a stream; its
// acknowledgement, a list_changed after a policy activation and the
// complete result that ends it each validate.
func (s *suite) listen(t *testing.T) {
	msg := s.ex.one(t, "SubscriptionsListenRequest")
	raw, _ := json.Marshal(msg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", s.gw.url, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+s.gw.token)
	for k, v := range headersFor(msg) {
		req.Header.Set(k, v)
	}
	resp, err := s.gw.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	s.r.add("SubscriptionsListenRequest", "sent: HTTP %d, %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	sc := bufio.NewScanner(resp.Body)
	step := 0
	for sc.Scan() {
		d, ok := strings.CutPrefix(sc.Text(), "data:")
		if !ok {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(d)), &m); err != nil {
			t.Fatal(err)
		}
		switch {
		case m["method"] == "notifications/subscriptions/acknowledged":
			s.check("SubscriptionsAcknowledgedNotification", "SubscriptionsAcknowledgedNotification", "listen acknowledgement", m)
			// Remove one tool: the session's catalog changes.
			names := s.be.names()
			tools, _ := json.Marshal(names[1:])
			snap, err := policy.Compile([]byte(fmt.Sprintf(`{"revision": "r2", "framework_profiles": {"dev": {"templates": ["all"], "default_template": "all"}},
  "templates": {"all": {"rules": [{"id": "all", "server": %q, "tools": %s}]}}}`, alias, tools)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.gw.app.Gateway.ActivatePolicy("conformance", snap); err != nil {
				t.Fatal(err)
			}
			step = 1
		case m["method"] == "notifications/tools/list_changed":
			s.check("ToolListChangedNotification", "ToolListChangedNotification", "list_changed after a policy activation", m)
			s.gw.app.Gateway.EndListenStreams()
			step = 2
		case m["result"] != nil:
			s.check("SubscriptionsListenResultResponse", "SubscriptionsListenResultResponse", "the complete result ending the stream", m)
			s.check("SubscriptionsListenResult", "SubscriptionsListenResult", "its result", m["result"])
			if step != 2 {
				t.Errorf("listen stream ended at step %d", step)
			}
			return
		}
	}
	t.Fatalf("listen stream ended early at step %d: %v", step, sc.Err())
}

// southbound: every line the Gateway sent the backend is a valid JSON-RPC
// message, and the CallToolRequest example's name and arguments reached
// the backend unchanged.
func (s *suite) southbound(t *testing.T) {
	lines := s.be.received()
	sawCall := false
	for _, l := range lines {
		if err := s.v.validate("JSONRPCMessage", []byte(l)); err != nil {
			t.Errorf("southbound line does not validate as JSONRPCMessage: %v\n%s", err, l)
		}
		var m struct {
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal([]byte(l), &m)
		if m.Method == "tools/call" && m.Params.Name == "get_weather" && m.Params.Arguments["location"] == "New York" {
			sawCall = true
		}
	}
	if !sawCall {
		t.Error("the CallToolRequest example's call did not reach the backend unchanged")
	}
	s.r.add("JSONRPCMessage", "n/a")
	delete(s.r.rows, "JSONRPCMessage")
	s.r.add("CallToolRequest", "southbound: %d lines the Gateway sent all validate as `JSONRPCMessage` (2025-11-25 era southbound); name and arguments reached the backend unchanged", len(lines))
}

// reservedCode matches integer literals in the JSON-RPC reserved range
// -32000 to -32099 in Go source.
var reservedCode = regexp.MustCompile(`-320[0-9][0-9]\b`)

// codes is FR-1.19: across every response of the suite, codes in -32020 to
// -32099 are only those schema.json defines, and -32002 and -32042 never
// occur; the Go sources outside tests use no other code in that range.
func (s *suite) codes(t *testing.T) {
	defined := map[int]bool{-32020: true, -32021: true, -32022: true}
	s.mu.Lock()
	seen := append([]int(nil), s.err...)
	s.mu.Unlock()
	counts := map[int]int{}
	for _, c := range seen {
		counts[c]++
		if (c <= -32020 && c >= -32099 && !defined[c]) || c == -32002 || c == -32042 {
			t.Errorf("the Gateway returned undefined reserved code %d", c)
		}
	}
	t.Logf("error codes returned: %v", counts)
	allowed := map[string]bool{"-32000": true, "-32020": true, "-32021": true, "-32022": true}
	root := filepath.Join("..", "..")
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, lit := range reservedCode.FindAllString(string(raw), -1) {
				if !allowed[lit] {
					t.Errorf("%s uses reserved code %s", p, lit)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	codes := []string{}
	for c, n := range counts {
		codes = append(codes, strconv.Itoa(c)+"×"+strconv.Itoa(n))
	}
	t.Logf("FR-1.19: %d error responses; codes %s", len(seen), strings.Join(codes, " "))
}

// untouched gives the remaining example directories their row: types the
// Gateway never produces or relays because the features are outside the
// tools-only baseline.
func (s *suite) untouched() {
	why := map[string]string{
		"ToolResultContent": "sampling content; sampling is not relayed (FR-5.20)", "ToolUseContent": "sampling content; sampling is not relayed (FR-5.20)",
		"SamplingMessage": "sampling is not relayed (FR-5.20)", "ModelPreferences": "sampling is not relayed (FR-5.20)",
		"CreateMessageRequestParams": "sampling is not relayed (FR-5.20)", "CreateMessageResult": "sampling is not relayed (FR-5.20)",
		"ElicitRequestFormParams": "elicitation is not relayed (FR-5.20)", "ElicitRequestURLParams": "elicitation is not relayed (FR-5.20)",
		"ElicitResult": "elicitation is not relayed (FR-5.20)", "BooleanSchema": "elicitation schema; elicitation is not relayed",
		"NumberSchema": "elicitation schema; elicitation is not relayed", "StringSchema": "elicitation schema; elicitation is not relayed",
		"TitledMultiSelectEnumSchema": "elicitation schema; elicitation is not relayed", "TitledSingleSelectEnumSchema": "elicitation schema; elicitation is not relayed",
		"UntitledMultiSelectEnumSchema": "elicitation schema; elicitation is not relayed", "UntitledSingleSelectEnumSchema": "elicitation schema; elicitation is not relayed",
		"ListRootsResult": "roots are not relayed (FR-5.20)", "Root": "roots are not relayed (FR-5.20)",
		"TextContent": "", "EmbeddedResource": "",
	}
	for _, d := range s.ex.dirs() {
		if len(s.r.rows[d]) > 1 {
			continue
		}
		if w, ok := why[d]; ok && w != "" {
			s.r.add(d, "not produced: %s", w)
		} else if len(s.r.rows[d]) <= 1 {
			s.r.add(d, "schema check only")
		}
	}
}
