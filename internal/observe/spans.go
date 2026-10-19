package observe

import (
	"sort"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Call-path timing spans (FR-10.2) and policy cost attribution (FR-10.11).
//
// The edge emits one batch of pipeline.StageSpan per tool call when the
// call ends: a span per FR-4.3 stage and per filter run, with monotonic
// start and end, thread CPU time, the correlation ID and the policy
// revision, decisive rule revision and filter that caused the work. The
// collector takes them through its bounded queue (never blocking the
// call), adds the Observation Policy in force, aggregates span time per
// stage and policy object for every call, and hands the batch to
// Options.SpanSink for storage when the call's observation record was
// captured (sampled, escalated or for a campaign). Storing about 20 span
// rows for every call was most of the Observation Store's cost per call
// (FR-11.4); the aggregate, which the cost route reports, still covers
// every call. The call's terminal event is queued before its spans (the
// evidence fan-out offers it before the call returns), so the record is
// decided when the spans arrive.

// CostKey is the policy object a span's time is attributed to.
type CostKey struct {
	Stage             string `json:"stage"`
	PolicyRevision    string `json:"policy_revision"`
	Rule              string `json:"rule_id"`
	Filter            string `json:"filter_id"`
	ObservationPolicy string `json:"observation_policy"`
}

// CostRow is the aggregated time of one CostKey.
type CostRow struct {
	CostKey
	Spans   int64   `json:"spans"`
	TotalMs float64 `json:"total_ms"`
	CPUMs   float64 `json:"cpu_ms"`
	MeanMs  float64 `json:"mean_ms"`
	MaxMs   float64 `json:"max_ms"`
}

type costAgg struct {
	mu   sync.Mutex
	rows map[CostKey]*CostRow
}

// OfferSpans queues the spans of one call. It never blocks; a full queue
// drops them and counts the drop.
func (c *Collector) OfferSpans(spans []pipeline.StageSpan) {
	if len(spans) == 0 {
		return
	}
	c.offer(item{spans: spans})
}

// onSpans aggregates a batch and passes it to the sink.
func (c *Collector) onSpans(spans []pipeline.StageSpan) {
	policyID := c.o.PolicyID
	if c.o.CurrentPolicy != nil {
		policyID = c.o.CurrentPolicy()
	}
	c.cost.mu.Lock()
	if c.cost.rows == nil {
		c.cost.rows = map[CostKey]*CostRow{}
	}
	for _, s := range spans {
		k := CostKey{Stage: s.Stage, PolicyRevision: s.PolicyRevision, Rule: s.Rule, Filter: s.Filter, ObservationPolicy: policyID}
		r := c.cost.rows[k]
		if r == nil {
			r = &CostRow{CostKey: k}
			c.cost.rows[k] = r
		}
		d := float64(s.Duration()) / float64(time.Millisecond)
		r.Spans++
		r.TotalMs += d
		r.CPUMs += float64(s.CPU) / float64(time.Millisecond)
		r.MaxMs = max(r.MaxMs, d)
	}
	c.cost.mu.Unlock()
	if c.o.SpanSink != nil && c.spansKept(spans[0].CorrelationID) {
		c.o.SpanSink(policyID, spans)
	}
}

// Cost returns the aggregated span time per stage and policy object since
// the collector started, the largest total first (FR-10.11). With
// filtersOnly, only filter spans are returned, which ranks filters by
// cost.
func (c *Collector) Cost(filtersOnly bool) []CostRow {
	c.cost.mu.Lock()
	out := make([]CostRow, 0, len(c.cost.rows))
	for _, r := range c.cost.rows {
		if filtersOnly && r.Stage != pipeline.SpanFilter {
			continue
		}
		row := *r
		if row.Spans > 0 {
			row.MeanMs = row.TotalMs / float64(row.Spans)
		}
		out = append(out, row)
	}
	c.cost.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalMs != out[j].TotalMs {
			return out[i].TotalMs > out[j].TotalMs
		}
		return out[i].Stage+out[i].Filter < out[j].Stage+out[j].Filter
	})
	return out
}
