package edge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func strictBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "strict", Version: "1"}, nil)
	schema := map[string]any{"type": "object", "additionalProperties": false, "required": []any{"path"},
		"properties": map[string]any{"path": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer"}}}
	s.AddTool(&mcp.Tool{Name: "echo", InputSchema: schema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil
	})
	return s
}

// TestArgumentSchemaValidation: arguments that violate the tool's input
// schema by type, by a missing required member or by an additional
// property are blocked with SCHEMA_INVALID before dispatch; valid
// arguments run. The schema validated is the presented tool definition,
// which for a packaged server is the signed manifest's (FR-1.27) (SR-1.8-1).
func TestArgumentSchemaValidation(t *testing.T) {
	reqtest.Verifies(t, "SR-1.8-1")
	h := newHarness(t, harnessOpts{backend: strictBackend, policy: onePolicy})
	_, tok := h.session("one")
	cs := h.client(tok)
	for name, args := range map[string]map[string]any{
		"type":                 {"path": "/tmp/a", "limit": "ten"},
		"required":             {"limit": 3},
		"additionalProperties": {"path": "/tmp/a", "extra": true},
	} {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: args})
		var we *jsonrpc.Error
		if err == nil {
			t.Fatalf("%s: arguments accepted", name)
		}
		if !errors.As(err, &we) || we.Code != jsonrpc.CodeInvalidParams || !strings.Contains(string(we.Data), `"reasonCode":"SCHEMA_INVALID"`) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseDispatched }) != nil {
		t.Fatal("an invalid call was dispatched")
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"path": "/tmp/a", "limit": 3}})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != "ran" {
		t.Fatalf("valid call: %v %v", res, err)
	}
}
