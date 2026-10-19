package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

const inspectionPolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
  "templates": {"ro": {"rules": [{"id": "ro-t", "server": "t", "tools": ["echo", "token", "leak", "adder", "clock"]}]}}
}`

// The registered secret of the inspection backend.
const inspectionSecret = "registered-value-0123456789"

func inspectionBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "inspection-backend", Version: "1"}, nil)
	type textArgs struct {
		Text string `json:"text"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echoes text."}, func(ctx context.Context, req *mcp.CallToolRequest, a textArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "token", Description: "Returns a credential-shaped string."}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		// Split so that repository secret scanners do not flag the fixture.
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "key=" + "AKIA" + "IOSFODNN7EXAMPLE"}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "leak", Description: "Returns the registered secret."}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "here: " + inspectionSecret}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "adder", Description: "Adds two numbers."}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "3"}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "clock", Description: "Returns the time."}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "12:00"}}}, nil, nil
	})
	return s
}

func inspectionHarness(t *testing.T, cfg config.Filters) (*harness, *filters.Inspector, *recorder) {
	t.Helper()
	rec := &recorder{}
	in, err := filters.New(filters.Options{Config: cfg, Evidence: rec, Log: diag.Discard(), ResultBytes: 1 << 20, RequestBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	f := pipeline.NewFilters()
	if err := in.Register(f); err != nil {
		t.Fatal(err)
	}
	in.Fingerprints().Register("vault:test", inspectionSecret)
	h := newHarness(t, harnessOpts{filters: f, screen: in, backend: inspectionBackend, policy: inspectionPolicy,
		limits: "principal_calls_per_minute = 1000"})
	return h, in, rec
}

func provenance(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(res.Meta["local.smcpgw/provenance"])
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

type corpusSample struct {
	Label, Text, Note string
}

func injectionCorpus(t *testing.T) []corpusSample {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "filters", "testdata", "corpus", "prompt-injection.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []corpusSample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var s corpusSample
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// TestInjectionTagsEndToEnd is FR-4.17: the injection corpus is sent as
// arguments and returned in the result. Every positive sample yields a
// provenance tag from injection-detect and injection-marker and a nonzero
// P-043 and P-143 parameter in the filter evidence; every result is
// released with the same content and disposition as without the filters.
func TestInjectionTagsEndToEnd(t *testing.T) {
	reqtest.Verifies(t, "FR-4.17")
	reqtest.Partial(t, "FR-4.7") // evidence side; the observation record is internal/e2e TestFilterFindingsReachObservation
	h, _, rec := inspectionHarness(t, config.Filters{MandatoryRequest: []string{filters.IDInjectionDetect}, MandatoryResponse: []string{filters.IDInjectionMarker}})
	_, tok := h.session("ro")
	cs := h.client(tok)
	for _, s := range injectionCorpus(t) {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": s.Text}})
		if err != nil || res.IsError {
			t.Fatalf("%s: %v", s.Note, err)
		}
		if got := res.Content[0].(*mcp.TextContent).Text; got != "echo:"+s.Text {
			t.Fatalf("%s: content changed to %q", s.Note, got)
		}
		p := provenance(t, res)
		if p["disposition"] != "release" {
			t.Fatalf("%s: disposition %v", s.Note, p["disposition"])
		}
		tags, _ := p["tags"].([]any)
		seen := map[string]bool{}
		for _, tg := range tags {
			m := tg.(map[string]any)
			seen[m["filter"].(string)] = true
			if m["ruleSetVersion"] == "" || m["rule"] == "" || m["tag"] != true {
				t.Fatalf("%s: tag %v", s.Note, m)
			}
		}
		decision, _ := p["decisionId"].(string)
		params := func(stage string) map[string]any {
			ev := rec.find(func(e audit.Event) bool {
				d, _ := e.Detail.(map[string]any)
				return e.Class == "filter" && e.DecisionID == decision && d["stage"] == stage
			})
			if ev == nil {
				t.Fatalf("%s: no %s filter event", s.Note, stage)
			}
			d := ev.Detail.(map[string]any)
			for _, entry := range d["filters"].([]map[string]any) {
				if _, ok := entry["duration_us"]; !ok {
					t.Fatalf("no duration in %v", entry)
				}
			}
			return d["parameters"].(map[string]any)
		}
		p043, p143 := params(pipeline.StageRequest)["P-043"].(float64), params(pipeline.StageResponse)["P-143"].(float64)
		switch s.Label {
		case "positive":
			if !seen[filters.IDInjectionDetect] || !seen[filters.IDInjectionMarker] || p043 <= 0 || p143 <= 0 {
				t.Errorf("%s: tags %v P-043 %v P-143 %v", s.Note, seen, p043, p143)
			}
		default:
			if len(tags) != 0 || p043 != 0 || p143 != 0 {
				t.Errorf("%s: false positive %v", s.Note, tags)
			}
		}
	}
}

// TestReleaseDispositions is FR-4.11: one fixture per disposition. A clean
// result is released, a result with a credential is redacted with markers,
// and a result carrying a registered secret is withheld with -31003.
func TestReleaseDispositions(t *testing.T) {
	reqtest.Verifies(t, "FR-4.11")
	h, _, _ := inspectionHarness(t, config.Filters{})
	_, tok := h.session("ro")
	cs := h.client(tok)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_clock", Arguments: map[string]any{}})
	if err != nil || provenance(t, res)["disposition"] != "release" {
		t.Fatalf("%v %v", err, res)
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_token", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; txt != "key=[REDACTED:aws-access-key-id]" || provenance(t, res)["disposition"] != "redact" {
		t.Fatalf("%q %v", txt, provenance(t, res))
	}
	we, data := callErr(t, cs, "t_leak", map[string]any{})
	if we.Code != CodeResponseWithheld || data["reasonCode"] != "SECRET_LEAK" || strings.Contains(string(we.Data), inspectionSecret) {
		t.Fatalf("%v %v", we, data)
	}
	if ev := h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseWithheld && e.ReasonCode == "SECRET_LEAK" }); ev == nil {
		t.Fatal("no withheld event")
	}
	// A request-side block maps to -31001 with the filter's reason code.
	we, data = callErr(t, cs, "t_echo", map[string]any{"text": "ad\u202emin"})
	if we.Code != CodePolicyDenied || data["reasonCode"] != filters.ReasonUnicodeControl {
		t.Fatalf("%v %v", we, data)
	}
}

// TestPresentationRescan is FR-1.52: after a rule-set version that blocks
// one tool's description is activated, a new catalog omits that tool,
// presents the others and records a metadata_blocked event naming the
// rule.
func TestPresentationRescan(t *testing.T) {
	reqtest.Verifies(t, "FR-1.52")
	dir := t.TempDir()
	if _, err := filters.ExportEmbedded(dir); err != nil {
		t.Fatal(err)
	}
	lib, err := filters.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := lib.Get(filters.RuleSetMetadata, "")
	next := *base
	next.Version = "2099.1.0"
	next.Rules = append(append([]*filters.Rule{}, base.Rules...), &filters.Rule{ID: "no-adding", Kind: "regex", Pattern: `\badds two numbers\b`, RequestAction: "block", ResponseAction: "block"})
	if err := filters.AddVersion(dir, &next); err != nil {
		t.Fatal(err)
	}
	h, in, rec := inspectionHarness(t, config.Filters{RulesDir: dir})
	list := func() map[string]bool {
		_, tok := h.session("ro")
		cs := h.client(tok)
		res, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, tl := range res.Tools {
			out[tl.Name] = true
		}
		return out
	}
	if got := list(); !got["t_adder"] || !got["t_clock"] {
		t.Fatalf("before: %v", got)
	}
	if err := in.UseRuleSet(filters.RuleSetMetadata, "2099.1.0"); err != nil {
		t.Fatal(err)
	}
	got := list()
	if got["t_adder"] || !got["t_clock"] || !got["t_echo"] {
		t.Fatalf("after: %v", got)
	}
	ev := rec.find(func(e audit.Event) bool { return e.Outcome == "metadata_blocked" })
	if ev == nil {
		t.Fatal("no metadata_blocked event")
	}
	f := ev.Detail.(map[string]any)["findings"].([]pipeline.Finding)[0]
	if f.Rule != "no-adding" || f.RuleSetVersion != "2099.1.0" || ev.Detail.(map[string]any)["tool"] != "adder" {
		t.Fatalf("%+v %+v", ev, f)
	}
	// The omitted tool is not callable either.
	_, tok := h.session("ro")
	cs := h.client(tok)
	if we, _ := callErr(t, cs, "t_adder", map[string]any{}); we.Message != "Unknown tool" {
		t.Fatalf("%v", we)
	}
}
