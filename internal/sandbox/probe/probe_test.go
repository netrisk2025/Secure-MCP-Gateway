package probe

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// The probe presents the capability delivered for the destination it
// fetches, and none for a destination it holds no capability for.
func TestEgressToken(t *testing.T) {
	meta := mcp.Meta{pipeline.EgressAuthMeta: map[string]any{
		"header": pipeline.EgressAuthHeader,
		"destinations": []any{
			map[string]any{"host": "127.0.0.1", "ports": []any{8080}, "tokens": []any{"t1", "t2"}},
		},
	}}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Meta: meta}}
	if got := egressToken(req, "http://127.0.0.1:8080/x"); got != "t1" {
		t.Errorf("granted destination: %q, want t1", got)
	}
	if got := egressToken(req, "http://127.0.0.1:8544/"); got != "" {
		t.Errorf("other port: %q, want none", got)
	}
	if got := egressToken(&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{}}, "http://127.0.0.1:8080/"); got != "" {
		t.Errorf("no capabilities delivered: %q, want none", got)
	}
}
