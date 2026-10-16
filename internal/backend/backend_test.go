package backend

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestPublicName(t *testing.T) {
	reqtest.Verifies(t, "FR-1.26")
	cases := map[[2]string]string{
		{"a", "search"}:        "a_search",
		{"b", "search"}:        "b_search",
		{"c", "files.read"}:    "c_files_read",
		{"c", "get-user info"}: "c_get_user_info",
	}
	for in, want := range cases {
		if got := PublicName(in[0], in[1]); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
	if PublicName("c", "a.b") != PublicName("c", "a_b") {
		t.Fatal("sanitized names must collide so FR-1.49 can detect them")
	}
}

func TestCheckToolDefinition(t *testing.T) {
	reqtest.Verifies(t, "FR-5.22")
	ok := &mcp.Tool{Name: "x", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"file.path-1": map[string]any{"type": "string"}}}}
	if err := CheckToolDefinition(ok); err != nil {
		t.Fatal(err)
	}
	long := &mcp.Tool{Name: "x", InputSchema: map[string]any{"type": "object", "properties": map[string]any{strings.Repeat("p", 65): map[string]any{}}}}
	if err := CheckToolDefinition(long); err == nil {
		t.Error("65-character property accepted")
	}
	space := &mcp.Tool{Name: "x", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"has space": map[string]any{}}}}
	if err := CheckToolDefinition(space); err == nil {
		t.Error("property with a space accepted")
	}
	if err := CheckToolDefinition(&mcp.Tool{Name: "x"}); err == nil {
		t.Error("null inputSchema accepted")
	}
}
