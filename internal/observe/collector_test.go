package observe

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

type fakeAnalyzer struct {
	mu       sync.Mutex
	band     func(r *Record) string
	captured []*Record
	learned  []*Record
}

func (f *fakeAnalyzer) TransitionSurprise(*Record, string) (float64, bool) { return 1.5, true }
func (f *fakeAnalyzer) Score(r *Record) *anomaly.Result {
	b := anomaly.Normal
	if f.band != nil {
		b = f.band(r)
	}
	return &anomaly.Result{Band: b, SnapshotID: "snap-1", Combined: 0.5, Contributor: "request_bytes"}
}
func (f *fakeAnalyzer) Learn(r *Record) { f.mu.Lock(); f.learned = append(f.learned, r); f.mu.Unlock() }
func (f *fakeAnalyzer) Captured(r *Record) {
	f.mu.Lock()
	f.captured = append(f.captured, r)
	f.mu.Unlock()
}
func (f *fakeAnalyzer) records() []*Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*Record(nil), f.captured...)
}

func ts(d time.Duration) string { return t0.Add(d).Format(time.RFC3339Nano) }

// call feeds the evidence events of one delivered call, with a request and
// a response probe, as the edge and the observation filters produce them.
func call(c *Collector, corr, session, tool string, at time.Duration, args string) {
	base := audit.Event{CorrelationID: corr, SessionID: session, PrincipalID: "p-" + session, ServerRevision: "live-abc", ToolRevision: "live-abc/" + tool}
	ev := func(class string, phase audit.Phase, d time.Duration, decision string) {
		e := base
		e.Class, e.Phase, e.Time, e.DecisionID, e.PolicyRevision = class, phase, ts(at+d), decision, "rev-1"
		c.Observe(e)
	}
	ev("call", audit.PhaseRequested, 0, "")
	vals, digest := ArgumentFeatures(json.RawMessage(args))
	c.Offer(&Probe{CorrelationID: corr, ServerID: "fs", Template: "tpl", ArgsDigest: digest, Values: vals})
	ev("decision", audit.PhaseAuthorized, 2*time.Millisecond, "dec-"+corr)
	ev("call", audit.PhaseDispatched, 3*time.Millisecond, "dec-"+corr)
	c.Offer(&Probe{Response: true, CorrelationID: corr, Values: map[string]any{"response_bytes": int64(len(corr) * 10)}})
	ev("call", audit.PhaseCompleted, 13*time.Millisecond, "dec-"+corr)
	ev("call", audit.PhaseDelivered, 15*time.Millisecond, "dec-"+corr)
}

func newCollector(t *testing.T, o Options) (*Collector, *fakeAnalyzer) {
	t.Helper()
	fa := &fakeAnalyzer{}
	if o.Analyzer == nil {
		o.Analyzer = fa
	}
	if o.Queue == 0 {
		o.Queue = 100000
	}
	c := New(o)
	go c.Run()
	t.Cleanup(c.Close)
	return c, fa
}

func TestRecordAssemblyJoinsByCorrelation(t *testing.T) {
	reqtest.Verifies(t, "FR-10.3")
	c, fa := newCollector(t, Options{SamplingRate: 1, Parameters: DefaultCatalog().DefaultParameters()})
	for i := 0; i < 1000; i++ {
		call(c, fmt.Sprintf("corr-%04d", i), fmt.Sprintf("s%d", i%10), []string{"read", "write"}[i%2], time.Duration(i)*time.Second,
			fmt.Sprintf(`{"path":"/tmp/f%d","n":%d}`, i, i))
	}
	c.Sync()
	recs := fa.records()
	if len(recs) != 1000 || c.Stats().Assembled != 1000 || c.Stats().Pending != 0 {
		t.Fatalf("%d records, stats %+v", len(recs), c.Stats())
	}
	for _, r := range recs {
		var i int
		fmt.Sscanf(r.CorrelationID, "corr-%04d", &i)
		want := map[string]any{"session_id": fmt.Sprintf("s%d", i%10), "principal_id": fmt.Sprintf("p-s%d", i%10), "tool_name": []string{"read", "write"}[i%2],
			"response_bytes": int64(len(r.CorrelationID) * 10), "decision_outcome": "permit", "release_outcome": "released"}
		for k, v := range want {
			if r.Values[k] != v {
				t.Fatalf("%s: %s = %v, want %v", r.CorrelationID, k, r.Values[k], v)
			}
		}
		if r.Values["request_bytes"] != int64(len(fmt.Sprintf(`{"path":"/tmp/f%d","n":%d}`, i, i))) || r.ServerID != "fs" {
			t.Fatalf("%s: request probe not joined: %v", r.CorrelationID, r.Values["request_bytes"])
		}
		if r.Values["server_execution_time"] != 10.0 || r.Values["end_to_end_latency"] != 15.0 || r.Values["gateway_overhead"] != 5.0 {
			t.Fatalf("timings %v %v %v", r.Values["server_execution_time"], r.Values["end_to_end_latency"], r.Values["gateway_overhead"])
		}
	}
}

func TestParameterSelection(t *testing.T) {
	reqtest.Verifies(t, "FR-10.4")
	sel := []string{"request_bytes", "argument_count", "response_bytes", "end_to_end_latency", "calls_in_session"}
	c, fa := newCollector(t, Options{SamplingRate: 1, Parameters: sel})
	call(c, "c1", "s1", "read", 0, `{"a":"b"}`)
	c.Sync()
	r := fa.records()[0]
	want := map[string]bool{}
	for _, p := range append(sel, Identifiers...) {
		want[p] = true
	}
	cat := DefaultCatalog()
	for k := range r.Values {
		if _, isParam := cat.Lookup(k); isParam && !want[k] {
			t.Fatalf("unselected parameter %s captured", k)
		}
	}
	for p := range want {
		if _, ok := r.Values[p]; !ok && p != "baseline_snapshot_id" {
			t.Fatalf("selected parameter %s missing", p)
		}
	}
	if r.Values["baseline_snapshot_id"] != "snap-1" {
		t.Fatal("identifier P-087 missing")
	}
}

func TestFeatureExtractionFixture(t *testing.T) {
	reqtest.Partial(t, "FR-10.5")
	args := `{"b":{"x":"aab","y":[1,"https://example.com/p"]},"a":"/etc/passwd","c":"x\u200bz"}`
	v, digest := ArgumentFeatures(json.RawMessage(args))
	if digest == "" {
		t.Fatal("no digest")
	}
	ints := map[string]int64{"request_bytes": int64(len(args)), "argument_count": 3, "argument_max_depth": 3,
		"path_argument_count": 1, "url_argument_count": 1, "unicode_control_count": 1}
	for k, want := range ints {
		if v[k] != want {
			t.Fatalf("%s = %v, want %d", k, v[k], want)
		}
	}
	lens := v["argument_string_lengths"].([]int64)
	if fmt.Sprint(lens) != "[11 3 21 3]" {
		t.Fatalf("string lengths %v", lens)
	}
	text := "/etc/passwd" + "aab" + "https://example.com/p" + "x\u200bz"
	if math.Abs(v["argument_entropy"].(float64)-Entropy(text)) > 1e-12 {
		t.Fatal("entropy over concatenated leaves")
	}
	// Reference entropy: "aab" = -(2/3 log2 2/3 + 1/3 log2 1/3).
	if math.Abs(Entropy("aab")-0.9182958340544896) > 1e-9 || Entropy("") != 0 || Entropy("aaaa") != 0 {
		t.Fatal("entropy reference")
	}
	res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "see https://a.example/x and more text"}, &mcp.ImageContent{Data: []byte{1}, MIMEType: "image/png"}},
		StructuredContent: map[string]any{"a": 1, "b": map[string]any{"c": 2}}}
	rv := ResponseFeatures(res, func(any) string { return "" }, true)
	if rv["response_token_estimate"] != int64(len("see https://a.example/x and more text")/4) || rv["structured_field_count"] != int64(3) ||
		rv["embedded_url_count"] != int64(1) || rv["output_schema_conformance"] != "conforms" {
		t.Fatalf("response features %v", rv)
	}
	parts := rv["content_parts_by_type"].(map[string]int64)
	if parts["text"] != 1 || parts["image"] != 1 {
		t.Fatalf("parts %v", parts)
	}
	raw, _ := json.Marshal(res)
	if rv["response_bytes"] != int64(len(raw)) {
		t.Fatal("response bytes")
	}
}

func TestDeterministicSampling(t *testing.T) {
	reqtest.Verifies(t, "FR-10.6")
	run := func() map[string]bool {
		c, fa := newCollector(t, Options{SamplingRate: 0.1})
		for i := 0; i < 10000; i++ {
			call(c, fmt.Sprintf("call-%05d", i), "s", "read", time.Duration(i)*time.Millisecond, `{}`)
		}
		c.Sync()
		out := map[string]bool{}
		for _, r := range fa.records() {
			out[r.CorrelationID] = true
		}
		if d := c.Drops()[DropSampledDown]; int(d)+len(out) != 10000 {
			t.Fatalf("sampled-down count %d + captured %d != 10000", d, len(out))
		}
		return out
	}
	a, b := run(), run()
	frac := float64(len(a)) / 10000
	if math.Abs(frac-0.1) > 0.01 {
		t.Fatalf("captured fraction %v", frac)
	}
	if len(a) != len(b) {
		t.Fatal("replay selected a different set")
	}
	for k := range a {
		if !b[k] {
			t.Fatal("replay selected a different set")
		}
	}
}

// SetPolicy replaces the selection and sampling rate of a running
// collector, concurrently with assembly (run with -race).
func TestSetPolicyWhileRunning(t *testing.T) {
	reqtest.Partial(t, "FR-10.6")
	c, fa := newCollector(t, Options{SamplingRate: 0, Parameters: []string{"request_bytes"}})
	call(c, "before", "s", "read", 0, `{"a":"b"}`)
	c.Sync()
	if n := len(fa.records()); n != 0 {
		t.Fatalf("captured %d at rate 0", n)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			call(c, fmt.Sprintf("during-%d", i), "s", "read", time.Duration(i+1)*time.Second, `{}`)
		}
	}()
	c.SetPolicy([]string{"argument_count"}, nil, 1)
	<-done
	call(c, "after", "s", "read", time.Hour, `{"a":"b"}`)
	c.Sync()
	var after *Record
	for _, r := range fa.records() {
		if r.CorrelationID == "after" {
			after = r
		}
	}
	if after == nil || after.Capture != "sampled" {
		t.Fatalf("record after SetPolicy: %+v", after)
	}
	if _, ok := after.Values["argument_count"]; !ok {
		t.Fatal("new selection not applied")
	}
	if _, ok := after.Values["request_bytes"]; ok {
		t.Fatal("old selection still applied")
	}
	if !c.Selected("argument_count") || c.Selected("request_bytes") {
		t.Fatal("Selected reports the old selection")
	}
}

func TestCaptureEscalation(t *testing.T) {
	reqtest.Partial(t, "FR-10.7")
	fa := &fakeAnalyzer{band: func(r *Record) string {
		if r.CorrelationID == "odd" {
			return anomaly.Abnormal
		}
		return anomaly.Normal
	}}
	c, _ := newCollector(t, Options{SamplingRate: 0, Parameters: []string{"request_bytes"}, Escalation: []string{"argument_entropy", "argument_string_lengths"}, Analyzer: fa})
	call(c, "normal", "s", "read", 0, `{"a":"b"}`)
	call(c, "odd", "s", "read", time.Second, `{"a":"b"}`)
	c.Sync()
	recs := fa.records()
	if len(recs) != 1 || recs[0].CorrelationID != "odd" || recs[0].Capture != "escalated" {
		t.Fatalf("captured %+v", recs)
	}
	for _, p := range []string{"request_bytes", "argument_entropy", "argument_string_lengths", "anomaly_band"} {
		if _, ok := recs[0].Values[p]; !ok {
			t.Fatalf("escalated capture lacks %s", p)
		}
	}
}

func TestNonBlockingAndDropAccounting(t *testing.T) {
	reqtest.Partial(t, "FR-10.1", "FR-10.8")
	c := New(Options{Queue: 16, SamplingRate: 1, Analyzer: &fakeAnalyzer{}})
	// Run is not started: consumption is stalled.
	start := time.Now()
	for i := 0; i < 1000; i++ {
		c.Observe(audit.Event{CorrelationID: fmt.Sprint(i), Class: "call", Phase: audit.PhaseRequested, Time: ts(0)})
	}
	for i := 0; i < 500; i++ {
		c.Offer(&Probe{CorrelationID: fmt.Sprint(i)})
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("offers blocked for %v", d)
	}
	if got := c.Drops()[DropQueueFull]; got != 1500-16 {
		t.Fatalf("queue_full drops %d, want %d", got, 1500-16)
	}
	go c.Run()
	c.Sync()
	c.Close()
	// Calls that never end are dropped as unterminated.
	now := t0
	c2 := New(Options{Analyzer: &fakeAnalyzer{}, PendingTTL: time.Minute, Now: func() time.Time { return now }})
	go c2.Run()
	defer c2.Close()
	c2.Observe(audit.Event{CorrelationID: "x", Class: "call", Phase: audit.PhaseRequested, Time: ts(0)})
	c2.Offer(&Probe{CorrelationID: "orphan"})
	c2.Sync()
	now = t0.Add(2 * time.Minute)
	c2.expire()
	d := c2.Drops()
	if d[DropUnfinished] != 1 || d[DropOrphanProbe] != 1 {
		t.Fatalf("drops %v", d)
	}
}

func TestGatewayOverheadAndApprovalWait(t *testing.T) {
	reqtest.Partial(t, "FR-10.10")
	c, fa := newCollector(t, Options{SamplingRate: 1, Parameters: []string{"gateway_overhead", "t_approval_wait", "approval_state"}})
	base := audit.Event{CorrelationID: "a1", SessionID: "s", PrincipalID: "p", ToolRevision: "r/t"}
	at := func(class string, phase audit.Phase, d time.Duration, outcome string) {
		e := base
		e.Class, e.Phase, e.Time, e.Outcome = class, phase, ts(d), outcome
		c.Observe(e)
	}
	at("call", audit.PhaseRequested, 0, "")
	at("approval", "", 5*time.Millisecond, "requested")                      // E-07 service
	at("approval", audit.PhaseAuthorized, 2005*time.Millisecond, "approved") // edge, after the hold
	at("call", audit.PhaseDispatched, 2010*time.Millisecond, "")
	at("call", audit.PhaseCompleted, 2110*time.Millisecond, "ok")
	at("call", audit.PhaseDelivered, 2112*time.Millisecond, "release")
	c.Sync()
	r := fa.records()[0]
	// e2e 2112 − exec 100 − approval wait 2000 = 12 ms.
	if r.Values["t_approval_wait"] != 2000.0 || r.Values["gateway_overhead"] != 12.0 {
		t.Fatalf("wait %v overhead %v", r.Values["t_approval_wait"], r.Values["gateway_overhead"])
	}
	if st := r.Values["approval_state"].(map[string]any); st["outcome"] != "approved" || st["required"] != true {
		t.Fatalf("approval state %v", st)
	}
}

func TestSequenceFeaturesAndRefusals(t *testing.T) {
	c, fa := newCollector(t, Options{SamplingRate: 1, Parameters: DefaultCatalog().DefaultParameters()})
	call(c, "q1", "s", "list", 0, `{"d":"/"}`)
	call(c, "q2", "s", "read", 10*time.Second, `{"p":"/a"}`)
	call(c, "q3", "s", "read", 20*time.Second, `{"p":"/a"}`)
	call(c, "q4", "s", "read", 90*time.Second, `{"p":"/b"}`)
	// A call denied by policy.
	c.Observe(audit.Event{CorrelationID: "q5", SessionID: "s", PrincipalID: "p-s", ToolRevision: "x/write", Class: "call", Phase: audit.PhaseRequested, Time: ts(91 * time.Second)})
	c.Observe(audit.Event{CorrelationID: "q5", Class: "decision", Phase: audit.PhaseDenied, DecisionID: "d5", Time: ts(91*time.Second + time.Millisecond)})
	c.Sync()
	recs := fa.records()
	by := map[string]*Record{}
	for _, r := range recs {
		by[r.CorrelationID] = r
	}
	if by["q3"].Values["previous_tool"] != "read" || by["q3"].Values["repeated_identical_calls"] != int64(2) || by["q4"].Values["repeated_identical_calls"] != int64(1) {
		t.Fatalf("sequence %v", by["q3"].Values)
	}
	if by["q2"].Values["inter_call_interval"] != int64(10000) || by["q3"].Values["calls_per_minute_session"] != int64(3) ||
		by["q4"].Values["calls_per_minute_session"] != int64(1) || by["q4"].Values["distinct_tools_in_session"] != int64(2) ||
		by["q4"].Values["calls_in_session"] != int64(4) || by["q2"].Values["transition_surprise"] != 1.5 {
		t.Fatalf("q2 %v\nq4 %v", by["q2"].Values, by["q4"].Values)
	}
	if by["q5"].Values["decision_outcome"] != "deny" || by["q5"].Values["release_outcome"] != "refused" || by["q5"].Values["tool_name"] != "write" {
		t.Fatalf("denied call %v", by["q5"].Values)
	}
}

func TestSampleHashUniform(t *testing.T) {
	n := 0
	for i := 0; i < 100000; i++ {
		h := SampleHash(fmt.Sprint(i))
		if h < 0 || h >= 1 {
			t.Fatal("hash outside [0,1)")
		}
		if h < 0.5 {
			n++
		}
	}
	if n < 49000 || n > 51000 {
		t.Fatalf("hash not uniform: %d", n)
	}
}

func TestCatalog(t *testing.T) {
	cat := DefaultCatalog()
	if len(cat.Params) < 90 || cat.Version == "" {
		t.Fatal("catalog not loaded")
	}
	for _, n := range Computed {
		if _, ok := cat.Lookup(n); !ok {
			t.Fatalf("computed parameter %s not in catalog", n)
		}
	}
	if _, err := cat.Resolve([]string{"P-024", "request_bytes", "nope"}); err == nil {
		t.Fatal("unknown parameter resolved")
	}
	names, _ := cat.Resolve([]string{"P-024", "request_bytes"})
	if len(names) != 1 {
		t.Fatal("duplicates not merged")
	}
}

// TestAnomalyResponseEscalation: the Anomaly Response Policy decides which
// bands escalate capture (bands below EscalateFrom alert only), whether an
// uncharacterized call is escalated, and which extra parameters each band
// adds (FR-8.14, FR-8.10).
func TestAnomalyResponseEscalation(t *testing.T) {
	reqtest.Partial(t, "FR-8.14", "FR-8.10", "FR-8.9", "FR-10.7")
	bands := map[string]string{"e": anomaly.Elevated, "a": anomaly.Abnormal, "c": anomaly.Critical, "u": anomaly.Uncharacterized, "n": anomaly.Normal}
	fa := &fakeAnalyzer{band: func(r *Record) string { return bands[r.CorrelationID] }}
	c, _ := newCollector(t, Options{SamplingRate: 0, Parameters: []string{"request_bytes"}, Analyzer: fa,
		EscalateFrom: anomaly.Abnormal, EscalateUncharacterized: true,
		EscalationByBand: map[string][]string{anomaly.Abnormal: {"argument_entropy"}, anomaly.Critical: {"argument_string_lengths"}}})
	for i, id := range []string{"e", "a", "c", "u", "n"} {
		call(c, id, "s", "read", time.Duration(i)*time.Second, `{"a":"b"}`)
	}
	c.Sync()
	got := map[string]*Record{}
	for _, r := range fa.records() {
		got[r.CorrelationID] = r
	}
	if got["e"] != nil || got["n"] != nil {
		t.Fatalf("elevated (alert only) or normal call captured: %v", got)
	}
	for _, id := range []string{"a", "c", "u"} {
		if got[id] == nil || got[id].Capture != "escalated" {
			t.Fatalf("%s not escalated: %+v", id, got[id])
		}
	}
	has := func(id, p string) bool { _, ok := got[id].Values[p]; return ok }
	if !has("a", "argument_entropy") || has("a", "argument_string_lengths") {
		t.Errorf("abnormal call parameters: %v", got["a"].Values)
	}
	if !has("c", "argument_entropy") || !has("c", "argument_string_lengths") {
		t.Errorf("critical call lacks the parameters of abnormal and critical: %v", got["c"].Values)
	}
	if has("u", "argument_entropy") {
		t.Errorf("uncharacterized call got band parameters: %v", got["u"].Values)
	}

	// Scope (FR-8.9): out-of-scope calls are neither sampled nor
	// escalated and are counted as out_of_scope; framework_type is filled
	// from the principal.
	fa3 := &fakeAnalyzer{band: func(r *Record) string { return bands[r.CorrelationID] }}
	c3, _ := newCollector(t, Options{SamplingRate: 1, Parameters: []string{"framework_type"}, Analyzer: fa3,
		FrameworkOf: func(p string) string { return map[string]string{"p-in": "codex"}[p] },
		InScope:     func(r *Record) bool { return r.Str("framework_type") == "codex" }})
	call(c3, "n", "in", "read", 0, `{}`)
	call(c3, "c", "out", "read", time.Second, `{}`)
	c3.Sync()
	recs := fa3.records()
	if len(recs) != 1 || recs[0].CorrelationID != "n" || recs[0].Str("framework_type") != "codex" {
		t.Fatalf("scoped capture: %+v", recs)
	}
	if c3.Drops()[DropOutOfScope] != 1 {
		t.Fatalf("drops %v", c3.Drops())
	}

	// EscalateFrom "off": every band alerts only.
	fa2 := &fakeAnalyzer{band: func(*Record) string { return anomaly.Critical }}
	c2, _ := newCollector(t, Options{SamplingRate: 0, Analyzer: fa2, EscalateFrom: "off"})
	call(c2, "x", "s", "read", 0, `{}`)
	c2.Sync()
	if len(fa2.records()) != 0 {
		t.Fatal("capture escalated with escalate_capture_band off")
	}
}

// TestDeferredResponseFeatures: the response features that read the text
// parts are left out until finish runs, which the collector does on its own
// goroutine for a probe that carries it; the record then has the same
// values ResponseFeatures computes on the call path.
func TestDeferredResponseFeatures(t *testing.T) {
	res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "see https://a.example/x and " + strings.Repeat("0123456789abcdef", 4096)},
		&mcp.ImageContent{Data: []byte{1}, MIMEType: "image/png"}, &mcp.TextContent{Text: "ünïcode   <tail>"}}}
	want := ResponseFeatures(res, nil, false)
	vals, finish := ResponseFeaturesDeferred(res, nil, false)
	for _, k := range []string{"response_bytes", "response_entropy", "response_token_estimate", "embedded_url_count"} {
		if _, ok := vals[k]; ok {
			t.Fatalf("%s computed before finish", k)
		}
	}
	if vals["content_parts_by_type"].(map[string]int64)["text"] != 2 || vals["output_schema_conformance"] != "no_schema" {
		t.Fatalf("shape features %v", vals)
	}
	c, fa := newCollector(t, Options{SamplingRate: 1, Parameters: DefaultCatalog().DefaultParameters()})
	base := audit.Event{CorrelationID: "corr-d", SessionID: "s", PrincipalID: "p", ServerRevision: "live-abc", ToolRevision: "live-abc/read"}
	ev := func(phase audit.Phase, d time.Duration) {
		e := base
		e.Class, e.Phase, e.Time = "call", phase, ts(d)
		c.Observe(e)
	}
	ev(audit.PhaseRequested, 0)
	ev(audit.PhaseDispatched, time.Millisecond)
	c.Offer(&Probe{Response: true, CorrelationID: "corr-d", Values: vals, Finish: finish})
	ev(audit.PhaseCompleted, 2*time.Millisecond)
	ev(audit.PhaseDelivered, 3*time.Millisecond)
	c.Sync()
	recs := fa.records()
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	raw, _ := json.Marshal(res)
	if recs[0].Values["response_bytes"] != int64(len(raw)) {
		t.Fatalf("response_bytes %v, want %d", recs[0].Values["response_bytes"], len(raw))
	}
	for _, k := range []string{"response_bytes", "response_entropy", "response_token_estimate", "embedded_url_count"} {
		if recs[0].Values[k] != want[k] {
			t.Fatalf("%s = %v, want %v", k, recs[0].Values[k], want[k])
		}
	}
}
