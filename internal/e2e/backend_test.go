package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMain doubles as the backend MCP server: when SMCP_E2E_BACKEND is set
// the test binary serves a small stdio server and exits. The Gateway under
// test launches it as a subprocess, so the tests need no external server.
func TestMain(m *testing.M) {
	if os.Getenv("SMCP_E2E_BACKEND") == "1" {
		runBackend()
		return
	}
	os.Exit(m.Run())
}

func runBackend() {
	s := mcp.NewServer(&mcp.Implementation{Name: "e2e-backend", Version: "1"}, nil)
	type echoArgs struct {
		Text string `json:"text" jsonschema:"text to echo"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echo text"}, func(ctx context.Context, req *mcp.CallToolRequest, a echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "dotted.name", Description: "name with a dot"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "dotted"}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "secret", Description: "never permitted"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "leak"}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "write", Description: "approval-obligated"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "wrote"}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "rpcerror", Description: "returns a JSON-RPC error"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return nil, nil, &jsonrpc.Error{Code: -32001, Message: "internal backend detail that must not leak"}
	})
	mcp.AddTool(s, &mcp.Tool{Name: "slow", Description: "sleeps"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "slow"}}}, nil, nil
	})
	type bigArgs struct {
		KiB int `json:"kib"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "big", Description: "returns kib kilobytes"}, func(ctx context.Context, req *mcp.CallToolRequest, a bigArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", a.KiB*1024)}}}, nil, nil
	})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "backend:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

var _ = json.Marshal
