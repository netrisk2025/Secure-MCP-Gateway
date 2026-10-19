package conformance

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
)

// scripted is the stdio MCP server behind the Gateway. It speaks
// the 2025-11-25 era the Gateway uses southbound, presents the Tool
// examples plus the tools below, answers tools/call from the examples and
// records every line the Gateway sent it.
//
//   - get_weather: the CallToolRequest example's tool; returns the
//     CallToolResult example result-with-unstructured-text.
//   - result_<n>: returns the n-th CallToolResult example.
//   - input_<n>: returns the n-th InputRequiredResult example.
//   - server_<Dir>: sends the server-initiated request example of Dir to
//     the Gateway, waits for its answer and returns the answer's error
//     code as text.
//   - log_then_result: sends the LoggingMessageNotification example, then
//     returns a text result.
type scripted struct {
	ex    examples
	tools []map[string]any
	calls map[string]func(id json.RawMessage, w func(any)) // by backend tool name

	mu      sync.Mutex
	lines   []string
	pending map[string]json.RawMessage // probe request ID -> tools/call ID
}

// serverRequests are the server-initiated request examples the backend
// sends during a call.
var serverRequests = []string{"CreateMessageRequest", "ElicitRequest", "ListRootsRequest"}

// contentBlocks are the content block examples the backend returns, one
// per call.
var contentBlocks = []string{"TextContent", "ImageContent", "AudioContent", "ResourceLink", "EmbeddedResource"}

func newBackend(t *testing.T, ex examples) *scripted {
	t.Helper()
	b := &scripted{ex: ex, calls: map[string]func(json.RawMessage, func(any)){}, pending: map[string]json.RawMessage{}}
	seen := map[string]bool{}
	for _, e := range ex["Tool"] {
		var tool map[string]any
		if err := json.Unmarshal(e.Raw, &tool); err != nil {
			t.Fatal(err)
		}
		name, _ := tool["name"].(string)
		if seen[name] {
			continue // two examples show calculate_sum with different schema dialects
		}
		seen[name] = true
		b.tools = append(b.tools, tool)
		b.calls[name] = func(id json.RawMessage, w func(any)) {
			w(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}}})
		}
	}
	empty := map[string]any{"type": "object"}
	result := func(raw json.RawMessage) func(json.RawMessage, func(any)) {
		return func(id json.RawMessage, w func(any)) {
			w(map[string]any{"jsonrpc": "2.0", "id": id, "result": raw})
		}
	}
	var weather json.RawMessage
	for i, e := range ex["CallToolResult"] {
		name := fmt.Sprintf("result_%d", i)
		b.tools = append(b.tools, map[string]any{"name": name, "description": "returns CallToolResult/" + e.Name, "inputSchema": empty})
		b.calls[name] = result(e.Raw)
		if e.Name == "result-with-unstructured-text" {
			weather = e.Raw
		}
	}
	b.tools = append(b.tools, map[string]any{"name": "get_weather", "description": "the CallToolRequest example's tool",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"location": map[string]any{"type": "string"}}, "required": []any{"location"}}})
	b.calls["get_weather"] = result(weather)
	for i, e := range ex["InputRequiredResult"] {
		name := fmt.Sprintf("input_%d", i)
		b.tools = append(b.tools, map[string]any{"name": name, "description": "returns InputRequiredResult/" + e.Name, "inputSchema": empty})
		b.calls[name] = result(e.Raw)
	}
	for _, dir := range serverRequests {
		var req map[string]any
		if err := json.Unmarshal(ex[dir][0].Raw, &req); err != nil {
			t.Fatal(err)
		}
		probeID := "probe-" + dir
		req["jsonrpc"], req["id"] = "2.0", probeID
		name := "server_" + dir
		b.tools = append(b.tools, map[string]any{"name": name, "description": "sends " + dir, "inputSchema": empty})
		b.calls[name] = func(id json.RawMessage, w func(any)) {
			b.mu.Lock()
			b.pending[`"`+probeID+`"`] = id
			b.mu.Unlock()
			w(req)
		}
	}
	for _, dir := range contentBlocks {
		block := ex[dir][0].Raw
		name := "content_" + dir
		b.tools = append(b.tools, map[string]any{"name": name, "description": "returns a " + dir + " block", "inputSchema": empty})
		b.calls[name] = func(id json.RawMessage, w func(any)) {
			w(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"content": []any{block}}})
		}
	}
	b.tools = append(b.tools, map[string]any{"name": "progress_then_result", "description": "reports progress, then returns", "inputSchema": empty})
	logMsg := ex.one(t, "LoggingMessageNotification")
	b.tools = append(b.tools, map[string]any{"name": "log_then_result", "description": "logs, then returns", "inputSchema": empty})
	b.calls["log_then_result"] = func(id json.RawMessage, w func(any)) {
		w(logMsg)
		w(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "logged"}}}})
	}
	return b
}

// names returns the backend tool names.
func (b *scripted) names() []string {
	var out []string
	for _, tl := range b.tools {
		out = append(out, tl["name"].(string))
	}
	sort.Strings(out)
	return out
}

// received returns the lines the Gateway sent.
func (b *scripted) received() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.lines...)
}

func (b *scripted) serve(ctx context.Context, in io.Reader, out io.Writer) error {
	var wmu sync.Mutex
	w := func(v any) {
		raw, _ := json.Marshal(v)
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = out.Write(append(raw, '\n'))
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	for sc.Scan() {
		line := sc.Text()
		b.mu.Lock()
		b.lines = append(b.lines, line)
		b.mu.Unlock()
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
				Meta struct {
					ProgressToken json.RawMessage `json:"progressToken"`
				} `json:"_meta"`
			} `json:"params"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		switch {
		case m.Method == "" && len(m.ID) > 0: // the Gateway's answer to a probe
			b.mu.Lock()
			callID := b.pending[string(m.ID)]
			delete(b.pending, string(m.ID))
			b.mu.Unlock()
			if callID != nil {
				text := "answered without an error"
				if m.Error != nil {
					text = fmt.Sprintf("error %d", m.Error.Code)
				}
				w(map[string]any{"jsonrpc": "2.0", "id": callID, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}})
			}
		case m.Method == "initialize":
			w(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"protocolVersion": "2025-11-25",
				"capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "conformance", "version": "1"}}})
		case m.Method == "tools/list":
			w(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"tools": b.tools}})
		case m.Method == "ping":
			w(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{}})
		case m.Method == "tools/call" && m.Params.Name == "progress_then_result":
			// The ProgressNotification example, with the token the Gateway
			// sent southbound.
			var n map[string]any
			_ = json.Unmarshal(b.ex["ProgressNotification"][0].Raw, &n)
			n["params"].(map[string]any)["progressToken"] = m.Params.Meta.ProgressToken
			w(n)
			w(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "done"}}}})
		case m.Method == "tools/call":
			if f := b.calls[m.Params.Name]; f != nil {
				f(m.ID, w)
			} else {
				w(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32602, "message": "Unknown tool " + strings.TrimSpace(m.Params.Name)}})
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return sc.Err()
}
