package observe

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// TestCostAggregation: the collector aggregates span time per stage and
// policy object with the Observation Policy in force for every call, ranks
// the largest total first, and passes to the sink the spans of the calls
// whose record was captured.
func TestCostAggregation(t *testing.T) {
	var mu sync.Mutex
	var sunk []string
	// With a sampling rate of 0.5, one call's record is captured and the
	// other's is not.
	var kept, dropped string
	for i := 0; kept == "" || dropped == ""; i++ {
		id := fmt.Sprintf("c%d", i)
		if SampleHash(id) < 0.5 {
			kept = id
		} else {
			dropped = id
		}
	}
	c := New(Options{PolicyID: "obs-1", SamplingRate: 0.5, Analyzer: &fakeAnalyzer{}, SpanSink: func(policy string, sp []pipeline.StageSpan) {
		mu.Lock()
		sunk = append(sunk, policy+"/"+sp[0].CorrelationID)
		mu.Unlock()
	}})
	go c.Run()
	t0 := time.Now()
	span := func(corr, stage, filter string, d time.Duration) pipeline.StageSpan {
		return pipeline.StageSpan{Stage: stage, CorrelationID: corr, Start: t0, End: t0.Add(d), CPU: d / 2, PolicyRevision: "r1", Rule: "r1/ro/a", Filter: filter}
	}
	for i, corr := range []string{kept, dropped} {
		call(c, corr, "s", "read", time.Duration(i)*time.Second, `{}`) // its record first, as from the edge
		c.OfferSpans([]pipeline.StageSpan{
			span(corr, pipeline.SpanDecision, "", time.Millisecond),
			span(corr, pipeline.SpanFilter, "fast", time.Duration(i+1)*time.Millisecond),
			span(corr, pipeline.SpanFilter, "slow", 30*time.Millisecond),
		})
	}
	c.OfferSpans(nil)
	c.Close()
	rows := c.Cost(true)
	if len(rows) != 2 || rows[0].Filter != "slow" || rows[0].Spans != 2 || rows[0].TotalMs != 60 || rows[0].CPUMs != 30 || rows[0].MeanMs != 30 ||
		rows[0].ObservationPolicy != "obs-1" || rows[0].Rule != "r1/ro/a" || rows[1].Filter != "fast" || rows[1].TotalMs != 3 || rows[1].MaxMs != 2 {
		t.Fatalf("filter cost %+v", rows)
	}
	if all := c.Cost(false); len(all) != 3 || all[0].Filter != "slow" || all[2].Stage != pipeline.SpanDecision {
		t.Fatalf("cost %+v", all)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sunk) != 1 || sunk[0] != "obs-1/"+kept {
		t.Fatalf("sink %v, want only the captured call %s", sunk, kept)
	}
}
