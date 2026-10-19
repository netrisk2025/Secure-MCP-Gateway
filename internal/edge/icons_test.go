package edge

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func dataURI(mime string, b []byte) string {
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(b)
}

var (
	iconPNG  = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	iconJPEG = append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, make([]byte, 100)...)
)

func iconBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "icons", Version: "1"}, nil)
	icons := []mcp.Icon{
		{Source: "https://tracker.example/pixel.png", MIMEType: "image/png"},
		{Source: dataURI("image/svg+xml", []byte(`<svg onload="alert(1)"/>`))},
		{Source: dataURI("image/png", iconPNG), Sizes: []string{"16x16"}},
		{Source: dataURI("image/jpeg", iconJPEG)},
		{Source: dataURI("image/png", iconJPEG)},                                                      // magic bytes do not match
		{Source: dataURI("image/png", append(append([]byte{}, iconPNG...), make([]byte, 64<<10)...))}, // over 64 KiB
		{Source: "data:image/png," + string(iconPNG)},                                                 // not base64
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Icons: icons}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, nil, nil
	})
	return s
}

// adminManifest presents the live tools as a verified manifest that
// classifies "slow" as a gateway-admin tool.
type adminManifest struct{}

func (adminManifest) Tools(ctx context.Context, spec pipeline.ServerSpec, live pipeline.LiveLister) (pipeline.ToolSet, error) {
	ts, err := pipeline.LiveManifest{}.Tools(ctx, spec, live)
	for _, tl := range ts.Tools {
		if tl.Name == "slow" {
			tl.Meta = mcp.Meta{policy.MetaToolClass: policy.ClassGatewayAdmin}
		}
	}
	ts.Verified, ts.Source = true, "manifest:test"
	return ts, err
}

// TestGatewayAdminToolsNeverPresented: a tool whose verified manifest
// class is gateway-admin is absent from the catalog and cannot be called
// although the policy grants it; the Gateway's own control operations are
// never tools (SR-3.12-1).
func TestGatewayAdminToolsNeverPresented(t *testing.T) {
	reqtest.Verifies(t, "SR-3.12-1")
	h := newHarness(t, harnessOpts{manifests: adminManifest{}})
	_, tok := h.session("ro") // grants echo, slow and big
	cs := h.client(tok)
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range lt.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "t_big,t_echo" {
		t.Fatalf("catalog %v", names)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_slow", Arguments: map[string]any{"ms": 1}}); err == nil {
		t.Fatal("a gateway-admin tool was called")
	}
}

// TestPresentedIcons: of a tool's icons, only data: URIs of PNG or JPEG
// images of at most 64 KiB whose magic bytes match are presented; remote
// URLs, SVG, mismatched, oversized and non-base64 icons are removed
// (SR-5.18-2).
func TestPresentedIcons(t *testing.T) {
	reqtest.Verifies(t, "SR-5.18-2")
	h := newHarness(t, harnessOpts{backend: iconBackend, policy: onePolicy})
	_, tok := h.session("one")
	lt, err := h.client(tok).ListTools(context.Background(), nil)
	if err != nil || len(lt.Tools) != 1 {
		t.Fatalf("%v %v", lt, err)
	}
	icons := lt.Tools[0].Icons
	if len(icons) != 2 || icons[0].Source != dataURI("image/png", iconPNG) || icons[0].Sizes[0] != "16x16" || icons[1].Source != dataURI("image/jpeg", iconJPEG) {
		var got []string
		for _, ic := range icons {
			got = append(got, ic.Source[:min(len(ic.Source), 40)])
		}
		t.Fatalf("presented icons: %s", strings.Join(got, " | "))
	}
}
