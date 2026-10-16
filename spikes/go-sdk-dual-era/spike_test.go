package dualera

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "spike", Version: "0"}, &mcp.ServerOptions{
		SupportedProtocolVersions: []string{"2026-07-28", "2025-11-25"},
	})
	type args struct {
		Name string `json:"name"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "greet", Description: "say hi"}, func(ctx context.Context, req *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "hi " + a.Name}}}, nil, nil
	})
	return s
}

type resp struct {
	status  int
	headers http.Header
	body    string
}

func post(t *testing.T, url, body string, hdr map[string]string) resp {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, r.Header, string(b)}
}

const modernMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"c","version":"0"}}`

func show(t *testing.T, label string, r resp) {
	t.Logf("%s -> HTTP %d  Mcp-Session-Id=%q  Content-Type=%q\n    body=%s", label, r.status, r.headers.Get("Mcp-Session-Id"), r.headers.Get("Content-Type"), strings.TrimSpace(r.body))
}

func run(t *testing.T, stateless bool) {
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return newServer() }, &mcp.StreamableHTTPOptions{Stateless: stateless, JSONResponse: true})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Modern era
	show(t, "modern server/discover", post(t, srv.URL, fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{%s}}`, modernMeta), map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"}))
	show(t, "modern tools/list", post(t, srv.URL, fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{%s}}`, modernMeta), map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"}))
	show(t, "modern tools/call", post(t, srv.URL, fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"greet","arguments":{"name":"bob"},%s}}`, modernMeta), map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "greet"}))
	show(t, "modern tools/call (no Mcp-* headers)", post(t, srv.URL, fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"greet","arguments":{"name":"bob"},%s}}`, modernMeta), nil))

	// Legacy era on the same handler
	init := post(t, srv.URL, `{"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"legacy","version":"0"}}}`, nil)
	show(t, "legacy initialize", init)
	sid := init.headers.Get("Mcp-Session-Id")
	legacyHdr := map[string]string{"MCP-Protocol-Version": "2025-11-25"}
	if sid != "" {
		legacyHdr["Mcp-Session-Id"] = sid
	}
	show(t, "legacy notifications/initialized", post(t, srv.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, legacyHdr))
	show(t, "legacy tools/list", post(t, srv.URL, `{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}`, legacyHdr))
	show(t, "legacy tools/call", post(t, srv.URL, `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"greet","arguments":{"name":"ann"}}}`, legacyHdr))
	// Old-era version request: must be answered with 2025-11-25 per FR-1.17
	show(t, "legacy initialize 2025-06-18", post(t, srv.URL, `{"jsonrpc":"2.0","id":13,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"0"}}}`, nil))
	// Unsupported modern version
	show(t, "modern unsupported version", post(t, srv.URL, `{"jsonrpc":"2.0","id":14,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`, map[string]string{"MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "server/discover"}))
	// GET on the endpoint
	r, _ := http.Get(srv.URL)
	t.Logf("GET -> HTTP %d", r.StatusCode)
	r.Body.Close()

}

func TestStateful(t *testing.T)  { run(t, false) }
func TestStateless(t *testing.T) { run(t, true) }
