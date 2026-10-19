package observe

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestEscalationDuringSampling is FR-10.7 as its verification states it:
// with 10% sampling, a call scored abnormal is captured whether or not the
// sampler selected it, in full (marked "escalated") and with the
// escalation parameters, while the normal calls are captured only as
// sampled and without them.
func TestEscalationDuringSampling(t *testing.T) {
	reqtest.Verifies(t, "FR-10.7")
	odd := map[string]bool{}
	for i := 0; i < 400; i += 37 {
		odd[fmt.Sprintf("c-%03d", i)] = true
	}
	fa := &fakeAnalyzer{band: func(r *Record) string {
		if odd[r.CorrelationID] {
			return anomaly.Abnormal
		}
		return anomaly.Normal
	}}
	esc := []string{"argument_entropy", "argument_string_lengths"}
	c, _ := newCollector(t, Options{SamplingRate: 0.1, Parameters: []string{"request_bytes"}, Escalation: esc, Analyzer: fa})
	for i := range 400 {
		call(c, fmt.Sprintf("c-%03d", i), "s", "read", time.Duration(i)*time.Second, `{"a":"bcd"}`)
	}
	c.Sync()
	escalated, sampled := 0, 0
	for _, r := range fa.records() {
		switch {
		case odd[r.CorrelationID]:
			escalated++
			if r.Capture != "escalated" {
				t.Errorf("%s captured as %q", r.CorrelationID, r.Capture)
			}
			for _, p := range append([]string{"request_bytes", "anomaly_band"}, esc...) {
				if _, ok := r.Values[p]; !ok {
					t.Errorf("%s lacks %s", r.CorrelationID, p)
				}
			}
		default:
			sampled++
			if r.Capture != "sampled" {
				t.Errorf("%s captured as %q", r.CorrelationID, r.Capture)
			}
			for _, p := range esc {
				if _, ok := r.Values[p]; ok {
					t.Errorf("sampled %s carries escalation parameter %s", r.CorrelationID, p)
				}
			}
		}
	}
	if escalated != len(odd) {
		t.Fatalf("%d of %d abnormal calls captured", escalated, len(odd))
	}
	if sampled == 0 || sampled > 80 {
		t.Fatalf("%d normal calls captured at 10%% sampling", sampled)
	}
}
