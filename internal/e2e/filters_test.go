package e2e

import (
	"context"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
)

// TestDefaultInspectionChains checks the wiring of internal/app: a Gateway
// started from configuration runs the default mandatory request and
// response filters, reports them in provenance, and refuses a request the
// unicode-control filter blocks.
func TestDefaultInspectionChains(t *testing.T) {
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	prov, _ := res.Meta["local.smcpgw/provenance"].(map[string]any)
	var applied []string
	for _, v := range prov["filters"].([]any) {
		applied = append(applied, v.(string))
	}
	for _, id := range append(append([]string{"schema-validate"}, filters.DefaultMandatoryRequest...), filters.DefaultMandatoryResponse...) {
		if !slices.Contains(applied, id) {
			t.Errorf("%s did not run: %v", id, applied)
		}
	}
	if prov["disposition"] != "release" {
		t.Fatalf("%v", prov)
	}
	we, data := callErr(t, cs, "t_echo", map[string]any{"text": "x\u202ey"})
	if we.Code != -31001 || data["reasonCode"] != filters.ReasonUnicodeControl {
		t.Fatalf("%v %v", we, data)
	}
	if f.app.Inspector == nil || len(f.app.Inspector.Library().All()) < len(filters.RequiredRuleSets) {
		t.Fatal("inspector not wired")
	}
}
