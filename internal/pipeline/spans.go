package pipeline

import (
	"context"
	"runtime"
	"time"
)

// Stages of the call pipeline that emit timing spans (FR-10.2), in FR-4.3
// order. Request and response scoring run inside the inspection stages as
// the observation probes, so their time is part of those stages and of the
// probes' filter spans.
const (
	SpanAuthenticate         = "authenticate"
	SpanSessionCheck         = "session_check"
	SpanDecision             = "decision"
	SpanRequestInspection    = "request_inspection"
	SpanApproval             = "approval"
	SpanLaunchAuthorization  = "launch_authorization"
	SpanDispatch             = "dispatch"
	SpanResponseInspection   = "response_inspection"
	SpanReleaseAuthorization = "release_authorization"
	// SpanFilter is the span of one filter run inside an inspection stage;
	// its Filter field names the filter.
	SpanFilter = "filter"
)

// StageSpan is one timing span of a tool call (FR-10.2): the stage, the
// monotonic start and end (time.Now readings), the CPU time spent by the
// Gateway in the stage, the call's correlation ID and the policy objects
// that caused the work: the policy revision and decisive rule revision of
// the call's decision (empty before the decision) and, for a filter span,
// the filter ID.
type StageSpan struct {
	Stage          string
	CorrelationID  string
	Start, End     time.Time
	CPU            time.Duration
	CPUMeasured    bool // false where the platform has no per-thread CPU clock
	PolicyRevision string
	Rule           string
	Filter         string
}

// Duration is End minus Start on the monotonic clock.
func (s StageSpan) Duration() time.Duration { return s.End.Sub(s.Start) }

// SpanSink receives the spans of one call when the call ends. It runs on
// the call's goroutine and must not block (E-29 queues them).
type SpanSink func([]StageSpan)

// cpuAccount measures the thread CPU time of one goroutine's work. The
// goroutine is locked to its OS thread only while it runs: wait unlocks it
// for a blocking wait, whose time is not counted, and locks it again
// afterwards. A goroutine that blocks while locked to its thread can resume
// only on that thread, so when every processor is busy its wake-up waits
// for that thread to be scheduled; held across a whole call, the lock
// added milliseconds to each wait and put observation over its FR-11.4
// budget.
type cpuAccount struct {
	ok      bool          // the platform has a per-thread CPU clock
	running bool          // a segment is open and the goroutine is locked
	mark    time.Duration // thread CPU time at the start of the segment
	total   time.Duration
}

// resume opens a segment: it locks the goroutine and reads the clock.
func (a *cpuAccount) resume() {
	runtime.LockOSThread()
	a.mark, a.ok = threadCPU()
	a.running = true
}

// pause closes the open segment, if any, and unlocks the goroutine.
func (a *cpuAccount) pause() {
	if !a.running {
		return
	}
	if a.ok {
		d, _ := threadCPU()
		a.total += d - a.mark
	}
	a.running = false
	runtime.UnlockOSThread()
}

// wait runs fn outside the open segment (fn alone when none is open).
func (a *cpuAccount) wait(fn func()) {
	if !a.running {
		fn()
		return
	}
	a.pause()
	defer a.resume()
	fn()
}

type cpuAccountKey struct{}

// WaitUnmeasured runs fn, a wait for another goroutine, a process or the
// network, from a filter run under the chain's CPU measurement: the
// filter's goroutine is unlocked from its OS thread for the wait, and the
// wait is not counted in the filter's CPU time. Outside a measured filter
// run it just runs fn.
func WaitUnmeasured(ctx context.Context, fn func()) {
	if a, ok := ctx.Value(cpuAccountKey{}).(*cpuAccount); ok && a != nil {
		a.wait(fn)
		return
	}
	fn()
}

// SpanTimer records the spans of one call on its goroutine. Each stage
// locks the goroutine to its OS thread so that the thread CPU time read at
// its boundaries is the call's own; Wait leaves the lock off for the
// stage's blocking waits.
type SpanTimer struct {
	ok    bool
	cur   *cpuAccount // the open stage's account
	corr  string
	spans []StageSpan
	// PolicyRevision and Rule are set once the call is decided and are
	// copied into every later span.
	PolicyRevision, Rule string
}

// NewSpanTimer starts recording the spans of the call corr.
func NewSpanTimer(corr string) *SpanTimer {
	_, ok := threadCPU()
	// About 20 spans per call: the stages and the filter runs.
	return &SpanTimer{ok: ok, corr: corr, spans: make([]StageSpan, 0, 24)}
}

// Start begins a stage; the returned function ends it. The stage's CPU
// time is the thread CPU time of the call's goroutine in the stage outside
// its waits (Wait); AddFilterRuns adds the CPU time of the stage's filters.
func (t *SpanTimer) Start(stage string) func() {
	if t.cur != nil {
		t.cur.pause() // a stage left open
	}
	a := &cpuAccount{}
	t.cur = a
	start := time.Now()
	a.resume()
	return func() {
		a.pause()
		if t.cur == a {
			t.cur = nil
		}
		t.spans = append(t.spans, StageSpan{Stage: stage, CorrelationID: t.corr, Start: start, End: time.Now(), CPU: a.total,
			CPUMeasured: t.ok, PolicyRevision: t.PolicyRevision, Rule: t.Rule})
	}
}

// Wait runs fn, a wait of the open stage (for filter goroutines, the
// server, the approver or the journal), with the goroutine unlocked from
// its thread; the wait is not counted in the stage's CPU time. A nil timer
// or a timer without an open stage just runs fn.
func (t *SpanTimer) Wait(fn func()) {
	if t == nil || t.cur == nil {
		fn()
		return
	}
	t.cur.wait(fn)
}

// Add records a span measured elsewhere (authentication before the call
// handler, filter runs on their own goroutines).
func (t *SpanTimer) Add(s StageSpan) {
	s.CorrelationID = t.corr
	if s.PolicyRevision == "" {
		s.PolicyRevision, s.Rule = t.PolicyRevision, t.Rule
	}
	t.spans = append(t.spans, s)
}

// AddFilterRuns records one span per filter run, and adds the filters' CPU
// time (spent on their own goroutines) to the stage span that contains
// them, which must be the last span recorded.
func (t *SpanTimer) AddFilterRuns(runs []FilterRun) {
	var cpu time.Duration
	for _, r := range runs {
		cpu += r.CPU
		t.Add(StageSpan{Stage: SpanFilter, Start: r.Start, End: r.Start.Add(r.Duration), CPU: r.CPU, CPUMeasured: t.ok, Filter: r.Filter})
	}
	for i := len(t.spans) - 1; i >= 0; i-- {
		if t.spans[i].Stage != SpanFilter {
			t.spans[i].CPU += cpu
			break
		}
	}
}

// Finish ends a stage left open and returns the spans in order of their
// start.
func (t *SpanTimer) Finish() []StageSpan {
	if t.cur != nil {
		t.cur.pause()
		t.cur = nil
	}
	return t.spans
}

// MeasureCPU runs fn locked to its OS thread and returns the thread CPU
// time it used (0, false where the platform has no per-thread clock).
func MeasureCPU(fn func()) (time.Duration, bool) {
	return measureCPU(context.Background(), func(context.Context) { fn() })
}

// measureCPU is MeasureCPU for a function that may wait: fn receives a
// context with which WaitUnmeasured unlocks it for its waits.
func measureCPU(ctx context.Context, fn func(context.Context)) (time.Duration, bool) {
	a := &cpuAccount{}
	a.resume()
	defer a.pause()
	fn(context.WithValue(ctx, cpuAccountKey{}, a))
	a.pause()
	return a.total, a.ok
}
