package edge

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 32)...)

// responseBackend returns structured content for an output schema and
// image content of several kinds.
func responseBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "responses", Version: "1"}, nil)
	in := map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"type": "string"}}}
	out := map[string]any{"type": "object", "properties": map[string]any{"n": map[string]any{"type": "integer"}}, "required": []any{"n"}, "additionalProperties": false}
	s.AddTool(&mcp.Tool{Name: "shape", InputSchema: in, OutputSchema: out}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "shape"}}}
		switch {
		case strings.Contains(string(req.Params.Arguments), "good"):
			res.StructuredContent = map[string]any{"n": 3}
		case strings.Contains(string(req.Params.Arguments), "wrongtype"):
			res.StructuredContent = map[string]any{"n": "three"}
		case strings.Contains(string(req.Params.Arguments), "extra"):
			res.StructuredContent = map[string]any{"n": 3, "secret": "x"}
		}
		return res, nil
	})
	img := func(name, mimeType string, data []byte) {
		mcp.AddTool(s, &mcp.Tool{Name: name}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "img"}, &mcp.ImageContent{MIMEType: mimeType, Data: data}}}, nil, nil
		})
	}
	img("png", "image/png", pngBytes)
	img("fakepng", "image/png", []byte("GIF89a-not-a-png-at-all"))
	img("bigpng", "image/png", append(append([]byte{}, pngBytes...), make([]byte, 4096)...))
	img("gif", "image/gif", []byte("GIF89a......"))
	return s
}

const responsePolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
  "templates": {"ro": {"rules": [{"id": "r", "server": "t", "tools": ["shape", "png", "fakepng", "bigpng", "gif"]}]}}
}`

func responseHarness(t *testing.T) *harness {
	t.Helper()
	cfg := config.Filters{ContentTypes: config.FilterContentTypes{Allow: []string{"image/png"}, MaxBytes: 1024}}
	in, err := filters.New(filters.Options{Config: cfg, Evidence: &recorder{}, Log: diag.Discard(), ResultBytes: 1 << 20, RequestBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	f := pipeline.NewFilters()
	if err := in.Register(f); err != nil {
		t.Fatal(err)
	}
	return newHarness(t, harnessOpts{filters: f, backend: responseBackend, policy: responsePolicy})
}

// TestOutputSchemaWithholds is SR-5.20-2: when the tool declares an output
// schema, a result whose structuredContent is missing or does not validate
// is withheld (-31003) and recorded; a conforming result is released.
func TestOutputSchemaWithholds(t *testing.T) {
	reqtest.Verifies(t, "SR-5.20-2")
	h := responseHarness(t)
	_, tok := h.session("ro")
	cs := h.client(tok)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_shape", Arguments: map[string]any{"mode": "good"}})
	if err != nil || res.IsError {
		t.Fatalf("conforming result: %v %+v", err, res)
	}
	for _, mode := range []string{"wrongtype", "extra", "missing"} {
		we, data := callErr(t, cs, "t_shape", map[string]any{"mode": mode})
		if we.Code != CodeResponseWithheld || strings.Contains(string(we.Data), "three") {
			t.Fatalf("%s: %+v %v", mode, we, data)
		}
		corr, _ := data["correlationId"].(string)
		if ev := h.rec.find(func(e audit.Event) bool { return e.CorrelationID == corr && e.Phase == audit.PhaseWithheld }); ev == nil {
			t.Fatalf("%s: no withheld event", mode)
		}
		if ev := h.rec.find(func(e audit.Event) bool { return e.CorrelationID == corr && e.Phase == audit.PhaseDelivered }); ev != nil {
			t.Fatalf("%s: withheld result was delivered", mode)
		}
	}
}

// TestContentTypeGate is SR-5.18-1: through the Gateway, image content is
// kept only when [filters.content_types] allows its MIME type, its magic
// bytes match and it is within the size bound; otherwise it is replaced by
// a removal notice. (Audio and binary embedded-resource content go through
// the same check: internal/filters TestResponseFilters.)
func TestContentTypeGate(t *testing.T) {
	reqtest.Verifies(t, "SR-5.18-1")
	h := responseHarness(t)
	_, tok := h.session("ro")
	cs := h.client(tok)
	for name, want := range map[string]string{"t_png": "", "t_fakepng": "magic-mismatch", "t_bigpng": "too-large", "t_gif": "type-not-allowed"} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
		if err != nil || len(res.Content) != 2 {
			t.Fatalf("%s: %v %+v", name, err, res)
		}
		img, isImage := res.Content[1].(*mcp.ImageContent)
		if want == "" {
			if !isImage || string(img.Data) != string(pngBytes) {
				t.Fatalf("%s: allowed image not released intact: %#v", name, res.Content[1])
			}
			continue
		}
		txt, ok := res.Content[1].(*mcp.TextContent)
		if isImage || !ok || !strings.Contains(txt.Text, "removed by content-type-gate") || !strings.Contains(txt.Text, want) {
			t.Fatalf("%s: %#v", name, res.Content[1])
		}
	}
}
