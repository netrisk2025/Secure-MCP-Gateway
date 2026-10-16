package dualera

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Does subscriptions/listen work in stateless mode, and does a tool-list change reach it?
func TestStatelessListen(t *testing.T) {
	s := newServer()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true})
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"L1","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},%s}}`, modernMeta)
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "subscriptions/listen")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	t.Logf("listen -> HTTP %d Content-Type=%q", r.StatusCode, r.Header.Get("Content-Type"))
	go func() {
		time.Sleep(300 * time.Millisecond)
		mcp.AddTool(s, &mcp.Tool{Name: "second", Description: "x"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	}()
	sc := bufio.NewScanner(r.Body)
	deadline := time.After(2 * time.Second)
	done := make(chan struct{})
	go func() {
		for sc.Scan() {
			line := sc.Text()
			if line != "" {
				t.Logf("SSE: %s", line)
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-deadline:
		t.Log("(stream still open after 2s; cancelling)")
	}
}
