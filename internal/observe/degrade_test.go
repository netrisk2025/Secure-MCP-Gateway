package observe

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// rawCall is call with a request probe that also carries the S3 parameter
// raw_arguments.
func rawCall(c *Collector, corr, session string, at time.Duration) {
	base := audit.Event{CorrelationID: corr, SessionID: session, PrincipalID: "p-" + session, ServerRevision: "live-abc", ToolRevision: "live-abc/read"}
	ev := func(class string, phase audit.Phase, d time.Duration) {
		e := base
		e.Class, e.Phase, e.Time, e.DecisionID, e.PolicyRevision = class, phase, ts(at+d), "dec-"+corr, "rev-1"
		c.Observe(e)
	}
	ev("call", audit.PhaseRequested, 0)
	c.Offer(&Probe{CorrelationID: corr, ServerID: "fs", Template: "tpl", Values: map[string]any{"request_bytes": int64(10), "raw_arguments": `{"a":"b"}`}})
	ev("decision", audit.PhaseAuthorized, time.Millisecond)
	ev("call", audit.PhaseDispatched, 2*time.Millisecond)
	ev("call", audit.PhaseCompleted, 3*time.Millisecond)
	ev("call", audit.PhaseDelivered, 4*time.Millisecond)
}

// TestCaptureFollowsDegradationStage: as the degradation stage rises the
// collector reduces normal-band sampling to a tenth (stage 1), stops
// capturing S3 parameters (stage 2), pauses campaigns (stage 3) and shrinks
// its per-session cache to the floor (stage 4); at stage 0 nothing changes
// (FR-9.12, collector part).
func TestCaptureFollowsDegradationStage(t *testing.T) {
	reqtest.Partial(t, "FR-9.12")
	var stage atomic.Int32
	campaign := []Campaign{{ID: "cp-1", Parameters: []string{"request_bytes"}, Rate: 1}}
	c, fa := newCollector(t, Options{SamplingRate: 1, Parameters: []string{"request_bytes", "raw_arguments"}, MaxSessions: 40,
		Campaigns: func() []Campaign { return campaign }, Degradation: func() int { return int(stage.Load()) }})
	run := func(prefix string, n int) []*Record {
		before := len(fa.records())
		for i := 0; i < n; i++ {
			rawCall(c, fmt.Sprintf("%s-%04d", prefix, i), fmt.Sprintf("%s-s%d", prefix, i), time.Duration(i)*time.Millisecond)
		}
		c.Sync()
		return fa.records()[before:]
	}
	// Stage 0: every call captured with its S3 value and the campaign.
	recs := run("s0", 200)
	if len(recs) != 200 || recs[0].Values["raw_arguments"] == nil || len(recs[0].Campaigns) != 1 {
		t.Fatalf("stage 0: %d records, first %+v", len(recs), recs[0])
	}
	// Stage 1: normal-band sampling at a tenth; campaigns still capture,
	// so count only the sampled ones.
	stage.Store(1)
	recs = run("s1", 2000)
	sampled := 0
	for _, r := range recs {
		if r.Capture == "sampled" {
			sampled++
		}
	}
	if sampled < 150 || sampled > 250 || c.Drops()[DropDegraded] != 0 {
		// With campaigns active every call is still captured (by the
		// campaign), so nothing is dropped as degraded.
		t.Fatalf("stage 1: %d of 2000 sampled, %d dropped as degraded", sampled, c.Drops()[DropDegraded])
	}
	// Stage 2: S3 parameters no longer captured.
	stage.Store(2)
	for _, r := range run("s2", 50) {
		if _, ok := r.Values["raw_arguments"]; ok {
			t.Fatal("stage 2: an S3 parameter was captured")
		}
	}
	// Stage 3: campaigns paused; the calls sampled out are dropped as
	// degraded.
	stage.Store(3)
	recs = run("s3", 1000)
	for _, r := range recs {
		if len(r.Campaigns) != 0 || r.Capture != "sampled" {
			t.Fatalf("stage 3: %+v", r)
		}
	}
	if d := c.Drops()[DropDegraded]; d == 0 || int(d)+len(recs) != 1000 {
		t.Fatalf("stage 3: %d captured, %d dropped as degraded", len(recs), d)
	}
	// Stage 4: the per-session cache shrinks to a quarter of MaxSessions.
	stage.Store(4)
	run("s4", 60)
	if n := c.Stats().Sessions; n > 10 {
		t.Fatalf("stage 4: %d sessions cached, floor is 10", n)
	}
	// Back to stage 0: full sampling and S3 capture again.
	stage.Store(0)
	recs = run("b0", 20)
	if len(recs) != 20 || recs[0].Values["raw_arguments"] == nil || len(recs[0].Campaigns) != 1 {
		t.Fatalf("after recovery: %d records", len(recs))
	}
}
