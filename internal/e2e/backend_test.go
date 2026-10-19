package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestMain doubles as the backend MCP server: when SMCP_E2E_BACKEND is set
// the test binary serves a small stdio server and exits. The Gateway under
// test launches it as a subprocess, so the tests need no external server.
func TestMain(m *testing.M) {
	if os.Getenv("SMCP_E2E_BACKEND") == "reasons" {
		runReasonsBackend()
		return
	}
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
		// With a progress token, two progress notifications precede the
		// result (protocol_test.go).
		if tok := req.Params.GetProgressToken(); tok != nil {
			for i := 1; i <= 2; i++ {
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Progress: float64(i), Total: 2, Message: fmt.Sprintf("step %d", i)})
			}
		}
		// "show-meta" echoes the _meta keys the backend received
		// (TestTraceContextObserved).
		if a.Text == "show-meta" {
			keys := []string{}
			for k := range req.Params.Meta {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "meta:" + strings.Join(keys, ",")}}}, nil, nil
		}
		// SMCP_E2E_CALL_LOG names a file that gets one line per call the
		// backend received (TestJournalUnwritableDuringTraffic).
		if p := os.Getenv("SMCP_E2E_CALL_LOG"); p != "" {
			if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				fmt.Fprintln(f, a.Text)
				f.Close()
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
	})
	// southbound returns everything the server received from the Gateway
	// for the call: the raw request parameters (name, arguments, _meta) and
	// the process environment (SR-2.10-1).
	mcp.AddTool(s, &mcp.Tool{Name: "southbound", Description: "reports what the server received"}, func(ctx context.Context, req *mcp.CallToolRequest, a map[string]any) (*mcp.CallToolResult, any, error) {
		b, _ := json.Marshal(map[string]any{"params": req.Params, "env": os.Environ()})
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
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
	// egress_get sends one request through the Egress Broker proxy
	// (HTTP_PROXY) with an egress capability delivered with the call and
	// reports the status and the broker's reason code
	// (TestEgressLimitObligationEndToEnd).
	type egressArgs struct {
		Port int    `json:"port"`
		Path string `json:"path"`
		Body int    `json:"body"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "egress_get", Description: "fetch through the egress broker"}, func(ctx context.Context, req *mcp.CallToolRequest, a egressArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: egressGet(req.Params.Meta, a.Port, a.Path, a.Body)}}}, nil, nil
	})
	type bigArgs struct {
		KiB int `json:"kib"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "big", Description: "returns kib kilobytes"}, func(ctx context.Context, req *mcp.CallToolRequest, a bigArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", a.KiB*1024)}}}, nil, nil
	})
	// noisy writes 10 MiB of diagnostic output before answering (FR-5.15).
	mcp.AddTool(s, &mcp.Tool{Name: "noisy", Description: "writes to stderr"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		block := strings.Repeat(strings.Repeat(stderrMarker, 1024/len(stderrMarker))+"\n", 64) // 64 lines of about 1 KiB
		for i := 0; i < 10*1024/64; i++ {
			_, _ = os.Stderr.WriteString(block)
		}
		// A notification the Gateway does not forward (no client token);
		// it is recorded as server-asserted evidence (SR-6.18-1).
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: "noisy", Progress: 1, Message: "noisy done"})
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "quiet"}}}, nil, nil
	})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "backend:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

var _ = json.Marshal

// TestStderrBoundedAndNotForwarded: a server that writes 10 MiB to stderr
// keeps at most the CP-37 1 MiB ring of it, and none of it reaches the
// harness, in the SDK client's view or on the wire (FR-5.15).
func TestStderrBoundedAndNotForwarded(t *testing.T) {
	reqtest.Verifies(t, "FR-5.15")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	res, err := f.mcpClient(access).CallTool(context.Background(), &mcp.CallToolParams{Name: "t_noisy", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), stderrMarker) || res.Content[0].(*mcp.TextContent).Text != "quiet" {
		t.Fatalf("result %s", raw[:min(len(raw), 200)])
	}
	status, _, body := f.post(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"t_noisy","arguments":{},`+modernMeta+`}}`,
		map[string]string{"Authorization": "Bearer " + access, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "t_noisy"})
	if status != 200 || strings.Contains(body, stderrMarker) || !strings.Contains(body, "quiet") {
		t.Fatalf("wire response %d %.200s", status, body)
	}
	s := f.app.Registry.Servers()["t"]
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(s.Stderr(), stderrMarker) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(s.Stderr()); got == 0 || got > 1<<20 || !strings.Contains(s.Stderr(), stderrMarker) {
		t.Fatalf("stderr buffer holds %d bytes", got)
	}
}

// stderrMarker fills the noisy tool's diagnostic output.
const stderrMarker = "STDERR-ONLY-0123456789abcdef "
