package analytics

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

type recordSink struct {
	mu   sync.Mutex
	recs []*observe.Record
}

func (r *recordSink) TransitionSurprise(*observe.Record, string) (float64, bool) { return 0, false }
func (r *recordSink) Score(*observe.Record) *anomaly.Result                      { return nil }
func (r *recordSink) Learn(rec *observe.Record) {
	r.mu.Lock()
	r.recs = append(r.recs, rec)
	r.mu.Unlock()
}
func (r *recordSink) Captured(*observe.Record) {}

// TestSecretFingerprintsRegisteredWithCollector is the E-29 side of
// FR-6.10: with the Secret Broker's fingerprints registered
// (SetSecretScanner), the observe-request and observe-response probes
// count a delivered secret in the arguments and in the result, raw,
// Base64-encoded and as a 12-character fragment, and the collector reports
// the count as secret_fingerprint_matches (P-142) even when no filter
// event reported one; a call without the secret counts zero, and the
// probe-internal keys never reach the record. Without registration the
// probes add nothing.
func TestSecretFingerprintsRegisteredWithCollector(t *testing.T) {
	reqtest.Partial(t, "FR-6.10")
	const secret = "s3cr3t-value-0123456789-abcdef"
	fps := secrets.NewFingerprints()
	fps.Register("api-token", 1, []byte(secret))

	cfg := parse(t, "store = \"jsonl\"")
	cfg.State.Dir = t.TempDir()
	svc, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	sink := &recordSink{}
	col := observe.New(observe.Options{Analyzer: sink, Queue: 1000, SamplingRate: 1, Parameters: observe.DefaultCatalog().DefaultParameters()})
	go col.Run()
	defer col.Close()
	svc.Collector = col

	run := func(corr, args, result string) *observe.Record {
		t.Helper()
		base := audit.Event{CorrelationID: corr, SessionID: "s", PrincipalID: "p", ServerRevision: "live-x", ToolRevision: "live-x/echo"}
		ev := func(class string, phase audit.Phase) {
			e := base
			e.Class, e.Phase, e.Time = class, phase, time.Now().UTC().Format(time.RFC3339Nano)
			col.Observe(e)
		}
		call := &pipeline.Call{CorrelationID: corr, SessionID: "s", PrincipalID: "p", Server: "ref", Tool: "echo"}
		ev("call", audit.PhaseRequested)
		if _, err := (&requestProbe{s: svc}).FilterRequest(context.Background(), call, []byte(args)); err != nil {
			t.Fatal(err)
		}
		ev("call", audit.PhaseDispatched)
		res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result}}}
		if _, err := (&responseProbe{s: svc}).FilterResponse(context.Background(), call, res); err != nil {
			t.Fatal(err)
		}
		ev("call", audit.PhaseCompleted)
		ev("call", audit.PhaseDelivered)
		col.Sync()
		sink.mu.Lock()
		defer sink.mu.Unlock()
		for _, r := range sink.recs {
			if r.CorrelationID == corr {
				return r
			}
		}
		t.Fatalf("no record for %s", corr)
		return nil
	}

	clean := run("c0", `{"text":"hello"}`, "nothing here")
	if _, ok := clean.Values["secret_fingerprint_matches"]; ok {
		t.Fatalf("without registration the probes count matches: %v", clean.Values["secret_fingerprint_matches"])
	}

	svc.SetSecretScanner(func(b []byte) int { return len(fps.Scan(b)) })
	for name, c := range map[string]struct {
		args, result string
		want         int64
	}{
		"none":            {`{"text":"hello"}`, "nothing here", 0},
		"raw in result":   {`{"text":"hello"}`, "leak: " + secret, 1},
		"base64 result":   {`{"text":"hello"}`, base64.StdEncoding.EncodeToString([]byte(secret)), 1},
		"fragment result": {`{"text":"hello"}`, "x" + secret[5:17] + "y", 1},
		"raw in args":     {`{"text":"` + secret + `"}`, "ok", 1},
		"args and result": {`{"text":"` + secret + `"}`, secret, 2},
	} {
		r := run("c-"+name, c.args, c.result)
		if got := r.Values["secret_fingerprint_matches"]; got != c.want {
			t.Errorf("%s: secret_fingerprint_matches = %v, want %d", name, got, c.want)
		}
		for _, k := range []string{observe.ProbeSecretMatchesRequest, observe.ProbeSecretMatchesResponse} {
			if _, ok := r.Values[k]; ok {
				t.Errorf("%s: probe key %s reached the record", name, k)
			}
		}
	}
	svc.SetSecretScanner(nil)
	if r := run("c-off", `{"text":"`+secret+`"}`, secret); r.Values["secret_fingerprint_matches"] != nil {
		t.Fatalf("after unregistering: %v", r.Values["secret_fingerprint_matches"])
	}
}
