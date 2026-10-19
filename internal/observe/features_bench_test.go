package observe

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The FR-11 reference workload's result: a 64 KiB text file read through
// the reference server (internal/perf).
func referenceResult() *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("0123456789abcdef", 64<<10/16)}}}
}

// BenchmarkResponseFeatures64K is the observe-response probe's feature
// extraction for the reference result (FR-11.4 profiling).
func BenchmarkResponseFeatures64K(b *testing.B) {
	res := referenceResult()
	b.ReportAllocs()
	for b.Loop() {
		ResponseFeatures(res, nil, false)
	}
}

// BenchmarkArgumentFeatures is the observe-request probe's feature
// extraction for the reference call's arguments.
func BenchmarkArgumentFeatures(b *testing.B) {
	args := json.RawMessage(`{"path":"64k.txt"}`)
	b.ReportAllocs()
	for b.Loop() {
		ArgumentFeatures(args)
	}
}

// entropyReference is the plain definition of Entropy: Shannon entropy over
// the code points of s, counted in a map.
func entropyReference(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// TestEntropyMatchesDefinition: the counting fast path for ASCII gives the
// entropy of the definition for ASCII, non-ASCII, mixed and invalid UTF-8
// text.
func TestEntropyMatchesDefinition(t *testing.T) {
	for _, s := range []string{"", "a", "aab", "0123456789abcdef", strings.Repeat("0123456789abcdef", 4096), "héllo wörld ✓✓✓", "x\u200bz\u202e",
		"\xff\xfe\xfd ascii", strings.Repeat("日本語テキスト and ascii ", 300)} {
		if got, want := Entropy(s), entropyReference(s); math.Abs(got-want) > 1e-9 {
			t.Fatalf("Entropy(%.20q) = %v, want %v", s, got, want)
		}
	}
	// Text parts are counted as their concatenation.
	parts := []string{"héllo", "", "✓ab", strings.Repeat("0123456789abcdef", 300), "z"}
	h, n := entropyOfParts(parts)
	if all := strings.Join(parts, ""); math.Abs(h-entropyReference(all)) > 1e-9 || n != len([]rune(all)) {
		t.Fatalf("entropyOfParts %v %d, concatenation %v %d", h, n, entropyReference(all), len([]rune(all)))
	}
}

// TestResponseFeaturesURLsAndBytes: response_bytes is the length of the
// result's JSON encoding and embedded_url_count counts absolute URLs in
// text, also when the text is large or has no URL.
func TestResponseFeaturesURLsAndBytes(t *testing.T) {
	for _, res := range []*mcp.CallToolResult{
		referenceResult(),
		{Content: []mcp.Content{&mcp.TextContent{Text: "a <https://x.example/a>, (http://y.example) and ftp://z.example/f."}}},
		{Content: []mcp.Content{&mcp.TextContent{Text: "no scheme here: example.com/path ://bare"}}, IsError: true},
		{Content: []mcp.Content{&mcp.TextContent{Text: "\"quoted <html> & escapes\u2028\""}}, StructuredContent: map[string]any{"k": "v"}},
		{Content: []mcp.Content{&mcp.TextContent{Text: "ctl \x00\x01\x1f\b\f\n\r\t\x7f \\ bad \xff\xc3 sep \u2029 é ✓ 𝄞"}, &mcp.TextContent{Text: ""},
			&mcp.ImageContent{Data: []byte{1, 2}, MIMEType: "image/png"}, &mcp.TextContent{Text: "second", Meta: mcp.Meta{"k": "<v>"}}}},
	} {
		v := ResponseFeatures(res, nil, false)
		raw, _ := json.Marshal(res)
		if v["response_bytes"] != int64(len(raw)) {
			t.Fatalf("response_bytes %v, want %d", v["response_bytes"], len(raw))
		}
		want := 0
		for _, c := range res.Content {
			x, ok := c.(*mcp.TextContent)
			if !ok {
				continue
			}
			for _, f := range strings.Fields(x.Text) {
				if looksLikeURL(strings.Trim(f, `"'()<>[],.`)) {
					want++
				}
			}
		}
		if v["embedded_url_count"] != int64(want) {
			t.Fatalf("embedded_url_count %v, want %d", v["embedded_url_count"], want)
		}
	}
}

// TestServerExecutionEndsAtResponse: the completed event is written after
// response inspection, so server execution (P-101) ends at its
// responded_at, and response inspection counts in P-213.
func TestServerExecutionEndsAtResponse(t *testing.T) {
	c, fa := newCollector(t, Options{SamplingRate: 1, Parameters: DefaultCatalog().DefaultParameters()})
	base := audit.Event{CorrelationID: "corr-r", SessionID: "s", PrincipalID: "p", ServerRevision: "live-abc", ToolRevision: "live-abc/read"}
	ev := func(phase audit.Phase, d time.Duration, detail any) {
		e := base
		e.Class, e.Phase, e.Time, e.Detail = "call", phase, ts(d), detail
		c.Observe(e)
	}
	ev(audit.PhaseRequested, 0, nil)
	ev(audit.PhaseDispatched, 3*time.Millisecond, nil)
	ev(audit.PhaseCompleted, 13*time.Millisecond, map[string]any{"responded_at": ts(8 * time.Millisecond)})
	ev(audit.PhaseDelivered, 15*time.Millisecond, nil)
	c.Sync()
	recs := fa.records()
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	if v := recs[0].Values; v["server_execution_time"] != 5.0 || v["gateway_overhead"] != 10.0 {
		t.Fatalf("server execution %v, overhead %v; want 5 and 10", v["server_execution_time"], v["gateway_overhead"])
	}
}
