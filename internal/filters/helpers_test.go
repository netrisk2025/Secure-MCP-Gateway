package filters

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// memRec is an in-memory audit.Recorder.
type memRec struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memRec) Record(e audit.Event) error {
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
	return nil
}
func (m *memRec) Commit(e audit.Event) error { return m.Record(e) }

func (m *memRec) find(pred func(audit.Event) bool) []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Event
	for _, e := range m.events {
		if pred(e) {
			out = append(out, e)
		}
	}
	return out
}

func newTestInspector(t *testing.T, o Options) *Inspector {
	t.Helper()
	if o.Log == nil {
		o.Log = diag.Discard()
	}
	in, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// chain returns registered chains over a fresh inspector.
func chain(t *testing.T, o Options) (*Inspector, *pipeline.Filters, *memRec) {
	t.Helper()
	rec := &memRec{}
	if o.Evidence == nil {
		o.Evidence = rec
	}
	in := newTestInspector(t, o)
	f := pipeline.NewFilters()
	if err := in.Register(f); err != nil {
		t.Fatal(err)
	}
	return in, f, rec
}

func strSchema(props ...string) map[string]any {
	p := map[string]any{}
	for _, n := range props {
		p[n] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": p}
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func runReq(f *pipeline.Filters, call *pipeline.Call, args any) (json.RawMessage, []string, *pipeline.RequestVerdict) {
	return f.RunRequest(context.Background(), call, mustJSON(args))
}

func textResult(texts ...string) *mcp.CallToolResult {
	res := &mcp.CallToolResult{}
	for _, s := range texts {
		res.Content = append(res.Content, &mcp.TextContent{Text: s})
	}
	return res
}

func firstText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if t, ok := res.Content[0].(*mcp.TextContent); ok {
		return t.Text
	}
	return ""
}

// unsplit removes the corpus split marker from a literal.
func unsplit(s string) string { return strings.ReplaceAll(s, splitMarker, "") }

type auditEvent = audit.Event
