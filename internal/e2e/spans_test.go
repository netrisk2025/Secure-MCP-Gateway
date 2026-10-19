package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// slowFilter is a deliberately slow request filter: it waits 150 ms and
// burns 5 ms of CPU on every call. The ranking below compares wall-clock
// totals over six calls, and a single journal fsync in the launch
// authorization stage took 185 ms on a CI runner (PR 117), more than six
// 30 ms filter runs; six 155 ms runs keep the filter well above such an
// outlier.
type slowFilter struct{}

func (slowFilter) ID() string { return "slow-filter" }

func (slowFilter) FilterRequest(_ context.Context, _ *pipeline.Call, _ json.RawMessage) (pipeline.RequestVerdict, error) {
	time.Sleep(150 * time.Millisecond)
	burnCPU(5 * time.Millisecond)
	return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
}

// burnCPU burns d of the thread's CPU time, not of wall-clock time: on a
// loaded host a loop timed by the wall clock can get much less CPU than
// its duration, so the 2 ms CPU floor checked below would fail (as the
// same pattern did in internal/pipeline, CI run 39038412680). Without a
// thread CPU clock it burns d of wall-clock time.
func burnCPU(d time.Duration) {
	spin := func(d time.Duration) {
		for t0 := time.Now(); time.Since(t0) < d; {
		}
	}
	for total := time.Duration(0); total < d; {
		c, ok := pipeline.MeasureCPU(func() { spin(250 * time.Microsecond) })
		if !ok {
			spin(d)
			return
		}
		total += c
	}
}

// TestStageSpansAndPolicyCost traces calls through a Gateway wired as
// cmd/smcpd wires the Observation Collector:
//
//   - FR-10.2: every call emits a span for each pipeline stage it passes
//     (authenticate, session check, decision, request inspection with one
//     span per filter, including the observation probe that scores the
//     request, launch authorization, dispatch, response inspection with its
//     filters, including the response probe, and release authorization),
//     in FR-4.3 order, each with the stage,
//     monotonic start and end, thread CPU time, the correlation ID and,
//     after the decision, the policy revision and decisive rule revision;
//   - FR-10.11: with a deliberately slow filter, the collector's
//     aggregation by policy revision, rule, filter and Observation Policy
//     ranks that filter first among filters, and above every stage it is
//     not part of.
//
// FR-10.2 is partial: a call without an approval obligation has no
// approval span, and only the edge's stages are instrumented (the other
// elements of FR-10.1 emit no spans of their own).
func TestStageSpansAndPolicyCost(t *testing.T) {
	reqtest.Partial(t, "FR-10.2")
	reqtest.Verifies(t, "FR-10.11")
	var mu sync.Mutex
	var batches [][]pipeline.StageSpan
	of := startObservationWith(t, "sampling_rate = 1.0\nflush_interval = \"20ms\"\n", func(f *pipeline.Filters) error {
		return f.RegisterRequest(slowFilter{}, pipeline.Registration{Order: 500, Mandatory: true})
	}, func(sp []pipeline.StageSpan) {
		mu.Lock()
		batches = append(batches, append([]pipeline.StageSpan(nil), sp...))
		mu.Unlock()
	})
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	const calls = 6
	for i := range calls {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": fmt.Sprint("span ", i)}}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(batches)
		mu.Unlock()
		if n >= calls {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d span batches, want %d", n, calls)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	spans := batches[len(batches)-1]
	mu.Unlock()
	order := []string{pipeline.SpanAuthenticate, pipeline.SpanSessionCheck, pipeline.SpanDecision, pipeline.SpanRequestInspection,
		pipeline.SpanLaunchAuthorization, pipeline.SpanDispatch, pipeline.SpanResponseInspection, pipeline.SpanReleaseAuthorization}
	byStage := map[string]pipeline.StageSpan{}
	filters := map[string]pipeline.StageSpan{}
	corr := spans[0].CorrelationID
	cpuClock := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	for _, s := range spans {
		if s.CorrelationID == "" || s.CorrelationID != corr {
			t.Fatalf("span %s has correlation ID %q, want %q", s.Stage, s.CorrelationID, corr)
		}
		if s.End.Before(s.Start) || s.Start.IsZero() {
			t.Fatalf("span %s: start %v end %v", s.Stage, s.Start, s.End)
		}
		if s.CPUMeasured != cpuClock || s.CPU < 0 {
			t.Fatalf("span %s: CPU %v measured %v", s.Stage, s.CPU, s.CPUMeasured)
		}
		if s.Stage == pipeline.SpanFilter {
			filters[s.Filter] = s
		} else {
			byStage[s.Stage] = s
		}
	}
	var prev time.Time
	for _, st := range order {
		s, ok := byStage[st]
		if !ok {
			t.Fatalf("no %s span; spans %+v", st, spans)
		}
		if s.Start.Before(prev) {
			t.Fatalf("%s starts before the previous stage", st)
		}
		prev = s.Start
		decided := st != pipeline.SpanAuthenticate && st != pipeline.SpanSessionCheck && st != pipeline.SpanDecision
		if decided && (s.PolicyRevision != "r1" || s.Rule != "r1/ro/ro-t") {
			t.Fatalf("%s span policy objects %q %q", st, s.PolicyRevision, s.Rule)
		}
	}
	for _, id := range []string{"slow-filter", "observe-request", "observe-response", "schema-validate"} {
		if _, ok := filters[id]; !ok {
			t.Fatalf("no span for filter %s; filters %v", id, filters)
		}
	}
	slow := filters["slow-filter"]
	if slow.Duration() < 150*time.Millisecond || (cpuClock && slow.CPU < 2*time.Millisecond) {
		t.Fatalf("slow filter span %v, CPU %v", slow.Duration(), slow.CPU)
	}
	if cpuClock && byStage[pipeline.SpanRequestInspection].CPU < slow.CPU {
		t.Fatalf("request inspection CPU %v does not include the slow filter's %v", byStage[pipeline.SpanRequestInspection].CPU, slow.CPU)
	}

	// FR-10.11 through the control API.
	var cost struct {
		PolicyObjects []map[string]any `json:"policy_objects"`
		Filters       []map[string]any `json:"filters"`
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		code, body := of.admin("GET", "/api/v1/observations/cost", of.operator, nil)
		raw, _ := json.Marshal(body)
		_ = json.Unmarshal(raw, &cost)
		if code == 200 && len(cost.Filters) > 0 && cost.Filters[0]["spans"].(float64) >= calls {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cost: %d %v", code, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if cost.Filters[0]["filter_id"] != "slow-filter" || cost.Filters[0]["policy_revision"] != "r1" || cost.Filters[0]["rule_id"] != "r1/ro/ro-t" ||
		cost.Filters[0]["observation_policy"] == nil {
		t.Fatalf("filters ranked %v", cost.Filters)
	}
	for _, r := range cost.PolicyObjects {
		if r["filter_id"] == "slow-filter" {
			break // every row above it is a stage containing it
		}
		if st := r["stage"]; st != pipeline.SpanRequestInspection {
			t.Fatalf("%v ranks above the slow filter: %v", st, cost.PolicyObjects)
		}
	}
}
