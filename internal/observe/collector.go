// Package observe is the Observation Collector (E-29): it assembles one
// observation record per tool call from the evidence events of the call
// (audit.Observer) and from the request and response probes of the
// inspection pipelines, computes the Parameter Catalog features, applies
// deterministic sampling, capture escalation and parameter selection, and
// counts every drop by reason (ArchitectureV2 §4 E-29, FR-10.1 to
// FR-10.11). It never blocks a call: every input is offered to a bounded
// queue and dropped, counted, when the queue is full.
package observe

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Record is one assembled observation record. Values are keyed by
// Parameter Catalog name.
type Record struct {
	CorrelationID string
	Time          time.Time // time of the call's requested event
	End           time.Time // time of its terminal event
	ServerID      string    // server alias, when a probe saw it
	Values        map[string]any
	Score         *anomaly.Result
	ArgsDigest    string
	// Capture is why the record is stored: "sampled", "escalated",
	// "campaign" or "" (not stored).
	Capture   string
	Campaigns []string
	Spans     []Span
}

// Str returns a string value.
func (r *Record) Str(name string) string { s, _ := r.Values[name].(string); return s }

// Float returns a numeric value.
func (r *Record) Float(name string) (float64, bool) {
	switch x := r.Values[name].(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	case int:
		return float64(x), true
	}
	return 0, false
}

// Released reports whether the call's result was released.
func (r *Record) Released() bool { return r.Str("release_outcome") == "released" }

// Span is one timing span (FR-10.2) derived by the collector.
type Span struct {
	Stage        string
	Start, End   time.Time
	Monotonic    bool // measured with the monotonic clock (otherwise from evidence timestamps)
	PolicyObject string
}

// Probe carries what the request or response inspection stage saw of a
// call. Probes are sent by the observation filters (internal/analytics).
type Probe struct {
	Response      bool
	CorrelationID string
	Time          time.Time
	ServerID      string
	Template      string
	EndUser       string
	DecisiveRules []string
	Obligations   []string
	ArgsDigest    string
	Values        map[string]any
	Score         *anomaly.Result // synchronous scoring result
	CaptureCost   time.Duration   // the probe's own cost (P-211)
	ScoringCost   time.Duration   // synchronous scoring cost (P-210)
	// Finish, when set, completes Values off the call path: the collector
	// calls it on its own goroutine when it takes the probe, and adds its
	// time to CaptureCost (ResponseFeaturesDeferred).
	Finish func()
}

// Analyzer is the baseline and scoring side of the collector: it is
// implemented by internal/analytics over the Baseline Engine (E-30) and the
// Anomaly Scorer (E-31).
type Analyzer interface {
	// TransitionSurprise returns P-061 for the record (ok false for the
	// first call of a session).
	TransitionSurprise(r *Record, prevTool string) (float64, bool)
	// Score scores an assembled record asynchronously (nil when scoring is
	// off or synchronous).
	Score(r *Record) *anomaly.Result
	// Learn offers the record to the baseline.
	Learn(r *Record)
	// Captured receives every record selected for storage.
	Captured(r *Record)
}

// Campaign is the capture contribution of an active research campaign.
type Campaign struct {
	ID         string
	Parameters []string
	Rate       float64
	Matches    func(r *Record) bool
}

// Options configure a Collector.
type Options struct {
	Catalog    *Catalog
	PolicyID   string   // Observation Policy ID recorded with records
	Parameters []string // selected parameter names (identifiers are added)
	Escalation []string // added when the call's capture is escalated
	// EscalateFrom is the lowest band whose calls get capture escalation
	// ("" for elevated, "off" for none); EscalateUncharacterized escalates
	// calls whose context has no baseline (FR-8.14).
	EscalateFrom            string
	EscalateUncharacterized bool
	// EscalationByBand adds parameters for escalated calls of a band and
	// every higher band (FR-8.10).
	EscalationByBand map[string][]string
	// InScope, when set, limits Observation Policy capture (sampling and
	// escalation) to the calls it accepts (FR-8.9); campaigns keep their
	// own scope. FrameworkOf fills framework_type from the principal ID.
	InScope      func(r *Record) bool
	FrameworkOf  func(principal string) string
	SamplingRate float64 // normal-band capture rate (CP-31: 0.1)
	Queue        int     // input queue bound (default 4096)
	// Batch is how long inputs wait in the queue before the collector
	// takes them (default 10 ms; it takes them sooner when the queue is
	// half full). The collector is woken per batch, not per input, so that
	// an offer from the call path does not wake it.
	Batch       time.Duration
	PendingTTL  time.Duration
	MaxSessions int
	Analyzer    Analyzer
	Campaigns   func() []Campaign
	Now         func() time.Time
	// Degradation returns the observation path's degradation stage
	// (FR-9.12): 1 or more reduces normal-band sampling to a tenth, 2 or
	// more stops capturing S3 parameters, 3 or more pauses campaigns, 4
	// shrinks the per-session cache to a quarter of MaxSessions. nil is
	// stage 0.
	Degradation func() int
	// SpanSink receives each call's stage spans (FR-10.2) with the
	// Observation Policy ID in force, on the collector's goroutine.
	SpanSink func(policyID string, spans []pipeline.StageSpan)
	// CurrentPolicy returns the Observation Policy ID in force when it can
	// change while the collector runs; nil means PolicyID.
	CurrentPolicy func() string
}

// Degradation stages the collector acts on (see Options.Degradation).
const (
	stageReducedSampling = 1
	stageS3Suspended     = 2
	stageCampaignsPaused = 3
	stageCachesShrunk    = 4
)

// DropDegraded counts records not captured because degradation reduced
// normal-band sampling (FR-9.12).
const DropDegraded = "degraded"

func (c *Collector) stage() int {
	if c.o.Degradation == nil {
		return 0
	}
	return c.o.Degradation()
}

// Drop reasons counted in P-246.
const (
	DropQueueFull   = "queue_full"
	DropSampledDown = "sampled_down"
	DropOutOfScope  = "out_of_scope"
	DropUnfinished  = "unterminated"
	DropOrphanProbe = "orphan_probe"
	DropStoreQueue  = "store_queue_full"
	DropStoreError  = "store_error"
	DropObserver    = "observer_queue_full"
)

type item struct {
	ev    *audit.Event
	probe *Probe
	spans []pipeline.StageSpan
	flush chan struct{}
}

type pending struct {
	rec                       *Record
	requested, dispatched     time.Time
	completed, approvalStart  time.Time
	approvalEnd, lastActivity time.Time
	approval                  map[string]any
	decisionDenied            bool
	sawDecision               bool
	reqProbe, respProbe       *Probe
}

type sessionSeq struct {
	calls      int64
	lastTool   string
	lastTime   time.Time
	window     []time.Time
	tools      map[string]bool
	lastDigest string
	run        int64
	seen       time.Time
}

// Collector assembles observation records.
type Collector struct {
	o    Options
	ch   chan item
	kick chan struct{} // take the queued inputs now

	mu        sync.Mutex
	pending   map[string]*pending
	sessions  map[string]*sessionSeq
	principal map[string][]time.Time
	drops     map[string]uint64
	early     map[string][]earlyProbe
	// keepSpans holds the calls whose record was captured until their
	// call-path spans arrive: only those spans are stored.
	keepSpans map[string]struct{}
	sel       atomic.Pointer[selection] // replaced whole by SetPolicy

	assembled atomic.Uint64
	captured  atomic.Uint64
	cost      costAgg // FR-10.11
	done      chan struct{}
	inMu      sync.RWMutex // guards ch against send after close
	closed    bool
}

// selection is the Observation Policy's capture selection: the selected
// parameters (identifiers included), the escalation parameters and the
// normal-band sampling rate. It is never modified after it is stored.
type selection struct {
	params   map[string]bool
	escalate map[string]bool
	rate     float64
}

func newSelection(parameters, escalation []string, rate float64) *selection {
	s := &selection{params: map[string]bool{}, escalate: map[string]bool{}, rate: rate}
	for _, p := range parameters {
		s.params[p] = true
	}
	for _, p := range Identifiers {
		s.params[p] = true
	}
	for _, p := range escalation {
		s.escalate[p] = true
	}
	return s
}

// SetPolicy replaces the parameter selection, the escalation parameters
// and the sampling rate. Records assembled after the call use the new
// selection; a published Observation Policy or Audit Profile applies
// without a restart.
func (c *Collector) SetPolicy(parameters, escalation []string, rate float64) {
	c.sel.Store(newSelection(parameters, escalation, rate))
}

// New returns a collector; Run must be started.
func New(o Options) *Collector {
	if o.Catalog == nil {
		o.Catalog = DefaultCatalog()
	}
	if o.Queue <= 0 {
		o.Queue = 4096
	}
	if o.Batch <= 0 {
		o.Batch = 10 * time.Millisecond
	}
	if o.PendingTTL <= 0 {
		o.PendingTTL = 10 * time.Minute
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = 10000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	c := &Collector{o: o, ch: make(chan item, o.Queue), kick: make(chan struct{}, 1), pending: map[string]*pending{}, sessions: map[string]*sessionSeq{},
		principal: map[string][]time.Time{}, drops: map[string]uint64{}, early: map[string][]earlyProbe{}, keepSpans: map[string]struct{}{},
		done: make(chan struct{})}
	c.SetPolicy(o.Parameters, o.Escalation, o.SamplingRate)
	return c
}

// NonBlockingObserver marks the collector as an audit.NonBlocking observer:
// Observe is a non-blocking offer to the collector's bounded queue, which
// counts its drops (DropQueueFull), so the evidence fan-out calls it
// directly.
func (c *Collector) NonBlockingObserver() {}

// Observe implements audit.Observer. It never blocks.
func (c *Collector) Observe(ev audit.Event) {
	if ev.CorrelationID == "" {
		return
	}
	c.offer(item{ev: &ev})
}

func (c *Collector) offer(it item) {
	c.inMu.RLock()
	defer c.inMu.RUnlock()
	if c.closed {
		return
	}
	select {
	case c.ch <- it:
	default:
		c.Drop(DropQueueFull, 1)
	}
	if len(c.ch)*2 >= cap(c.ch) {
		c.wake()
	}
}

// wake makes Run take the queued inputs now.
func (c *Collector) wake() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Offer queues a probe. It never blocks.
func (c *Collector) Offer(p *Probe) { c.offer(item{probe: p}) }

// Drop counts n drops for a reason (P-246).
func (c *Collector) Drop(reason string, n uint64) {
	c.mu.Lock()
	c.drops[reason] += n
	c.mu.Unlock()
}

// Drops returns the drop counters.
func (c *Collector) Drops() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.drops))
	for k, v := range c.drops {
		out[k] = v
	}
	return out
}

// Stats are collector counters for status and meta-metrics.
type Stats struct {
	Assembled  uint64            `json:"assembled"`
	Captured   uint64            `json:"captured"`
	Pending    int               `json:"pending"`
	QueueDepth int               `json:"queue_depth"`
	QueueCap   int               `json:"queue_capacity"`
	Sessions   int               `json:"sessions"`
	Drops      map[string]uint64 `json:"drops"`
}

// Stats reports counters.
func (c *Collector) Stats() Stats {
	c.mu.Lock()
	st := Stats{Pending: len(c.pending), Sessions: len(c.sessions), QueueDepth: len(c.ch), QueueCap: cap(c.ch)}
	c.mu.Unlock()
	st.Assembled, st.Captured, st.Drops = c.assembled.Load(), c.captured.Load(), c.Drops()
	return st
}

// Sync waits until every input queued before the call is processed (tests
// and shutdown).
func (c *Collector) Sync() {
	ch := make(chan struct{})
	c.inMu.RLock()
	if c.closed {
		c.inMu.RUnlock()
		return
	}
	select {
	case c.ch <- item{flush: ch}:
		c.inMu.RUnlock()
		c.wake()
		<-ch
	case <-c.done:
		c.inMu.RUnlock()
	}
}

// Run processes inputs until Close, a batch at a time: every Batch
// interval, when the queue is half full, and for Sync and Close.
func (c *Collector) Run() {
	defer close(c.done)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	batch := time.NewTicker(c.o.Batch)
	defer batch.Stop()
	for {
		select {
		case <-batch.C:
		case <-c.kick:
		case <-t.C:
			c.expire()
			continue
		}
		if !c.take() {
			return
		}
	}
}

// take processes the queued inputs; it reports false once the queue is
// closed and empty.
func (c *Collector) take() bool {
	for {
		select {
		case it, ok := <-c.ch:
			if !ok {
				return false
			}
			switch {
			case it.flush != nil:
				close(it.flush)
			case it.probe != nil:
				c.onProbe(it.probe)
			case it.spans != nil:
				c.onSpans(it.spans)
			case it.ev != nil:
				c.onEvent(it.ev)
			}
		default:
			return true
		}
	}
}

// Close stops Run after the queued inputs are processed.
// Run must have been started.
func (c *Collector) Close() {
	c.inMu.Lock()
	if !c.closed {
		c.closed = true
		close(c.ch)
	}
	c.inMu.Unlock()
	c.wake()
	<-c.done
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (c *Collector) get(corr string, now time.Time) *pending {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending[corr]
	if p == nil {
		p = &pending{rec: &Record{CorrelationID: corr, Values: map[string]any{}}}
		c.pending[corr] = p
	}
	p.lastActivity = now
	return p
}

// onProbe attaches a probe to its call. A probe can arrive before the
// call's requested event, because evidence reaches the collector through
// the fan-out queue while probes come straight from the call path; such a
// probe waits in early until the event arrives or PendingTTL passes.
func (c *Collector) onProbe(pr *Probe) {
	if pr.Finish != nil {
		st := time.Now()
		pr.Finish()
		pr.Finish = nil
		pr.CaptureCost += time.Since(st)
	}
	c.mu.Lock()
	p := c.pending[pr.CorrelationID]
	if p == nil {
		if len(c.early) >= c.o.Queue {
			c.mu.Unlock()
			c.Drop(DropOrphanProbe, 1)
			return
		}
		c.early[pr.CorrelationID] = append(c.early[pr.CorrelationID], earlyProbe{pr, c.o.Now()})
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	p.attach(pr, c.o.Now())
}

type earlyProbe struct {
	p  *Probe
	at time.Time
}

func (p *pending) attach(pr *Probe, now time.Time) {
	p.lastActivity = now
	if pr.Response {
		p.respProbe = pr
	} else {
		p.reqProbe = pr
	}
}

// terminal phases end a call.
var terminal = map[audit.Phase]bool{audit.PhaseDelivered: true, audit.PhaseDenied: true, audit.PhaseFiltered: true,
	audit.PhaseWithheld: true, audit.PhaseFailed: true, audit.PhaseIndeterminate: true}

func (c *Collector) onEvent(ev *audit.Event) {
	ts := parseTime(ev.Time)
	if ev.Class == "call" && ev.Phase == audit.PhaseRequested {
		p := c.get(ev.CorrelationID, c.o.Now())
		c.mu.Lock()
		early := c.early[ev.CorrelationID]
		delete(c.early, ev.CorrelationID)
		c.mu.Unlock()
		for _, e := range early {
			p.attach(e.p, c.o.Now())
		}
		p.requested = ts
		r := p.rec
		r.Time = ts
		r.Values["principal_id"] = ev.PrincipalID
		if c.o.FrameworkOf != nil {
			if f := c.o.FrameworkOf(ev.PrincipalID); f != "" {
				r.Values["framework_type"] = f
			}
		}
		r.Values["session_id"] = ev.SessionID
		r.Values["server_revision"] = ev.ServerRevision
		if _, tool, ok := strings.Cut(ev.ToolRevision, "/"); ok {
			r.Values["tool_name"] = tool
		}
		r.Values["mcp_method"] = "tools/call"
		return
	}
	c.mu.Lock()
	p := c.pending[ev.CorrelationID]
	c.mu.Unlock()
	if p == nil {
		return // not a tool call, or its requested event was dropped
	}
	p.lastActivity = c.o.Now()
	switch {
	case ev.Class == "approval" && ev.Phase == "" && ev.Outcome == "requested":
		p.approvalStart = ts
	case ev.Class == "approval" && ev.Phase != "":
		p.approvalEnd = ts
		d, _ := ev.Detail.(map[string]any)
		p.approval = map[string]any{"required": true, "outcome": ev.Outcome}
		if d != nil && d["approval_id"] != nil && d["approval_id"] != "" {
			p.approval["approval_id"] = d["approval_id"]
		}
	case ev.Class == "filter":
		filterValues(p.rec.Values, ev)
	case ev.Class == "decision" && ev.Phase == audit.PhaseDenied:
		p.decisionDenied = true
	case ev.Class == "decision" && ev.Phase == audit.PhaseAuthorized:
		p.sawDecision = true
	case ev.Phase == audit.PhaseDispatched:
		p.dispatched = ts
	case ev.Phase == audit.PhaseCompleted:
		p.completed = ts
		// The completed event follows response inspection; the backend's
		// response time ends server execution (P-101).
		if d, ok := ev.Detail.(map[string]any); ok {
			if at, ok := d["responded_at"].(string); ok {
				p.completed = parseTime(at)
			}
		}
		if p.completed.IsZero() {
			p.completed = ts
		}
	}
	if ev.DecisionID != "" {
		p.sawDecision = true
	}
	if terminal[ev.Phase] {
		c.mu.Lock()
		delete(c.pending, ev.CorrelationID)
		c.mu.Unlock()
		c.finish(p, ev, ts)
	}
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func (c *Collector) finish(p *pending, ev *audit.Event, end time.Time) {
	r := p.rec
	r.End = end
	v := r.Values
	if ev.PolicyRevision != "" {
		v["policy_revision"] = ev.PolicyRevision
	}
	// Decision and release (P-080, P-160, P-161).
	switch {
	case p.decisionDenied:
		v["decision_outcome"] = "deny"
	case p.sawDecision:
		v["decision_outcome"] = "permit"
	default:
		v["decision_outcome"] = "not_evaluated"
	}
	switch ev.Phase {
	case audit.PhaseDelivered:
		v["release_outcome"] = "released"
		v["delivery_confirmation"] = "committed"
	case audit.PhaseWithheld:
		v["release_outcome"] = "withheld"
	case audit.PhaseFiltered:
		v["release_outcome"] = "blocked"
	case audit.PhaseDenied:
		v["release_outcome"] = "refused"
	default:
		v["release_outcome"] = string(ev.Phase)
	}
	if ev.ReasonCode != "" {
		v["reason_code"] = ev.ReasonCode
	}
	// Probes.
	for _, pr := range []*Probe{p.reqProbe, p.respProbe} {
		if pr == nil {
			continue
		}
		for k, x := range pr.Values {
			v[k] = x
		}
		if pr.ServerID != "" {
			r.ServerID = pr.ServerID
		}
		if pr.Template != "" {
			v["session_template"] = pr.Template
		}
		if pr.EndUser != "" {
			v["end_user_claim"] = pr.EndUser
		}
		if len(pr.DecisiveRules) > 0 {
			v["decisive_rule_ids"] = pr.DecisiveRules
		}
		if pr.Obligations != nil {
			v["obligations_applied"] = pr.Obligations
		}
		if pr.ArgsDigest != "" {
			r.ArgsDigest = pr.ArgsDigest
		}
		if pr.Score != nil {
			r.Score = mergeScore(r.Score, pr.Score)
		}
	}
	combineSecretMatches(v)
	// Timings (P-101, P-162, P-206, P-213) from evidence timestamps.
	var exec, wait time.Duration
	if !p.requested.IsZero() {
		v["end_to_end_latency"] = ms(end.Sub(p.requested))
	}
	if !p.dispatched.IsZero() {
		stop := p.completed
		if stop.IsZero() {
			stop = end
		}
		exec = stop.Sub(p.dispatched)
		v["server_execution_time"] = ms(exec)
		r.Spans = append(r.Spans, Span{Stage: "dispatch", Start: p.dispatched, End: stop, PolicyObject: ev.PolicyRevision})
		r.Spans = append(r.Spans, Span{Stage: "pre_dispatch", Start: p.requested, End: p.dispatched, PolicyObject: ev.PolicyRevision})
		if !p.completed.IsZero() {
			r.Spans = append(r.Spans, Span{Stage: "release", Start: p.completed, End: end, PolicyObject: ev.PolicyRevision})
		}
	}
	if p.approval != nil {
		start := p.approvalStart
		if start.IsZero() {
			start = p.approvalEnd
		}
		wait = p.approvalEnd.Sub(start)
		p.approval["wait_ms"] = ms(wait)
		v["approval_state"] = p.approval
		r.Spans = append(r.Spans, Span{Stage: "approval_wait", Start: start, End: p.approvalEnd, PolicyObject: ev.PolicyRevision})
	} else {
		v["approval_state"] = map[string]any{"required": false}
	}
	v["t_approval_wait"] = ms(wait)
	if !p.requested.IsZero() {
		v["gateway_overhead"] = ms(end.Sub(p.requested) - exec - wait)
	}
	var capCost, scoreCost time.Duration
	for _, pr := range []*Probe{p.reqProbe, p.respProbe} {
		if pr != nil {
			capCost += pr.CaptureCost
			scoreCost += pr.ScoringCost
		}
	}
	c.sequence(r)
	// Asynchronous scoring (FR-10.28) when no synchronous score exists.
	if r.Score == nil && c.o.Analyzer != nil {
		st := time.Now()
		r.Score = c.o.Analyzer.Score(r)
		scoreCost += time.Since(st)
	}
	if r.Score != nil {
		v["anomaly_band"] = r.Score.Band
		v["baseline_snapshot_id"] = r.Score.SnapshotID
		v["max_abs_z"] = map[string]any{"z": r.Score.Combined, "feature": r.Score.Contributor}
	}
	v["t_capture"] = ms(capCost)
	v["t_scoring"] = ms(scoreCost)
	c.assembled.Add(1)
	if c.o.Analyzer != nil {
		c.o.Analyzer.Learn(r)
	}
	c.capture(r)
}

// sequence computes the session and principal sequence features (P-007,
// P-060 to P-066).
func (c *Collector) sequence(r *Record) {
	sid, pid, tool := r.Str("session_id"), r.Str("principal_id"), r.Str("tool_name")
	t := r.Time
	if t.IsZero() {
		t = r.End
	}
	c.mu.Lock()
	s := c.sessions[sid]
	if s == nil {
		s = &sessionSeq{tools: map[string]bool{}}
		c.sessions[sid] = s
		c.evictSessionsLocked()
	}
	s.seen = c.o.Now()
	s.calls++
	prev := s.lastTool
	var interval float64 = -1
	if !s.lastTime.IsZero() {
		interval = ms(t.Sub(s.lastTime))
	}
	s.window = append(prune(s.window, t), t)
	s.tools[tool] = true
	key := tool + "\x00" + r.ArgsDigest
	if r.ArgsDigest != "" && key == s.lastDigest {
		s.run++
	} else {
		s.run = 1
	}
	s.lastDigest = key
	s.lastTool, s.lastTime = tool, t
	pw := append(prune(c.principal[pid], t), t)
	c.principal[pid] = pw
	calls, perMin, distinct, run := s.calls, int64(len(s.window)), int64(len(s.tools)), s.run
	c.mu.Unlock()

	v := r.Values
	v["calls_in_session"] = calls
	v["calls_per_minute_session"] = perMin
	v["calls_per_minute_principal"] = int64(len(pw))
	v["distinct_tools_in_session"] = distinct
	v["repeated_identical_calls"] = run
	if interval >= 0 {
		v["inter_call_interval"] = int64(interval)
	}
	if prev != "" {
		v["previous_tool"] = prev
		if c.o.Analyzer != nil {
			if sv, ok := c.o.Analyzer.TransitionSurprise(r, prev); ok {
				v["transition_surprise"] = sv
			}
		}
	}
}

// PeekSequence returns the sequence features a new call of the session
// would get, without recording it (synchronous scoring).
func (c *Collector) PeekSequence(session string, now time.Time) (prevTool string, interval float64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sessions[session]
	if s == nil {
		return "", 0, false
	}
	return s.lastTool, ms(now.Sub(s.lastTime)), true
}

func prune(w []time.Time, now time.Time) []time.Time {
	cut := now.Add(-time.Minute)
	i := 0
	for i < len(w) && !w[i].After(cut) {
		i++
	}
	return w[i:]
}

func (c *Collector) evictSessionsLocked() {
	limit := c.o.MaxSessions
	if c.stage() >= stageCachesShrunk {
		limit = max(limit/4, 1) // the cache floor (FR-9.12)
	}
	if len(c.sessions) <= limit {
		return
	}
	type kv struct {
		id   string
		seen time.Time
	}
	all := make([]kv, 0, len(c.sessions))
	for id, s := range c.sessions {
		all = append(all, kv{id, s.seen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for _, e := range all[:len(all)-limit] {
		delete(c.sessions, e.id)
	}
}

// SampleHash maps a correlation ID to [0, 1) for deterministic sampling
// (FR-10.6).
func SampleHash(corr string) float64 {
	sum := sha256.Sum256([]byte(corr))
	return float64(binary.BigEndian.Uint64(sum[:8])>>11) / (1 << 53)
}

// capture applies sampling, escalation, campaigns and parameter selection.
func (c *Collector) capture(r *Record) {
	sel := map[string]bool{}
	band := ""
	if r.Score != nil {
		band = r.Score.Band
	}
	h := SampleHash(r.CorrelationID)
	cur := c.sel.Load()
	inScope := c.o.InScope == nil || c.o.InScope(r)
	stage := c.stage()
	rate := cur.rate
	if stage >= stageReducedSampling {
		rate /= 10
	}
	degraded := false
	switch {
	case !inScope:
	case c.escalates(band):
		r.Capture = "escalated" // FR-10.7: full capture with the band's escalation parameters
		for p := range cur.params {
			sel[p] = true
		}
		for p := range cur.escalate {
			sel[p] = true
		}
		for b, ps := range c.o.EscalationByBand {
			if band != anomaly.Uncharacterized && anomaly.Rank(band) >= anomaly.Rank(b) {
				for _, p := range ps {
					sel[p] = true
				}
			}
		}
		sel["anomaly_band"], sel["max_abs_z"] = true, true // the reason for the escalation
	case h < rate:
		r.Capture = "sampled"
		for p := range cur.params {
			sel[p] = true
		}
	case h < cur.rate:
		degraded = true // sampled at the normal rate, not at the reduced one
	}
	if c.o.Campaigns != nil && stage < stageCampaignsPaused {
		for _, cp := range c.o.Campaigns() {
			if cp.Matches != nil && !cp.Matches(r) {
				continue
			}
			if SampleHash(cp.ID+"\x00"+r.CorrelationID) >= cp.Rate {
				continue
			}
			r.Campaigns = append(r.Campaigns, cp.ID)
			for _, p := range cp.Parameters {
				sel[p] = true
			}
			for _, p := range Identifiers {
				sel[p] = true
			}
			if r.Capture == "" {
				r.Capture = "campaign"
			}
		}
	}
	if r.Capture == "" {
		switch {
		case degraded:
			c.Drop(DropDegraded, 1)
		case inScope:
			c.Drop(DropSampledDown, 1)
		default:
			c.Drop(DropOutOfScope, 1)
		}
		return
	}
	if stage >= stageS3Suspended {
		for k := range sel {
			if p, ok := c.o.Catalog.Lookup(k); ok && p.Sensitivity == "S3" {
				delete(sel, k)
			}
		}
	}
	for k := range r.Values {
		if !sel[k] && !metaKeys[k] {
			delete(r.Values, k)
		}
	}
	c.captured.Add(1)
	c.mu.Lock()
	if len(c.keepSpans) >= c.o.Queue {
		clear(c.keepSpans) // spans that never arrived
	}
	c.keepSpans[r.CorrelationID] = struct{}{}
	c.mu.Unlock()
	if c.o.Analyzer != nil {
		c.o.Analyzer.Captured(r)
	}
}

// spansKept reports whether the record of the call corr was captured, and
// forgets it.
func (c *Collector) spansKept(corr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.keepSpans[corr]
	delete(c.keepSpans, corr)
	return ok
}

// escalates reports whether a call of band gets capture escalation under
// the Anomaly Response Policy (FR-8.14).
func (c *Collector) escalates(band string) bool {
	if band == anomaly.Uncharacterized {
		return c.o.EscalateUncharacterized
	}
	from := c.o.EscalateFrom
	if from == "" {
		from = anomaly.Elevated
	}
	return from != "off" && anomaly.Rank(band) >= anomaly.Rank(anomaly.Elevated) && anomaly.Rank(band) >= anomaly.Rank(from)
}

// metaKeys are record fields that are not catalog parameters but are kept
// with every stored record.
var metaKeys = map[string]bool{"policy_revision": true, "reason_code": true}

// expire drops calls that never reached a terminal event.
func (c *Collector) expire() {
	now := c.o.Now()
	c.mu.Lock()
	n := 0
	for id, p := range c.pending {
		if now.Sub(p.lastActivity) > c.o.PendingTTL {
			delete(c.pending, id)
			n++
		}
	}
	orphans := 0
	for id, e := range c.early {
		if now.Sub(e[0].at) > c.o.PendingTTL {
			delete(c.early, id)
			orphans += len(e)
		}
	}
	if orphans > 0 {
		c.drops[DropOrphanProbe] += uint64(orphans)
	}
	for id, s := range c.sessions {
		if now.Sub(s.seen) > 24*time.Hour {
			delete(c.sessions, id)
		}
	}
	for id, w := range c.principal {
		if len(prune(w, now)) == 0 {
			delete(c.principal, id)
		}
	}
	c.mu.Unlock()
	if n > 0 {
		c.Drop(DropUnfinished, uint64(n))
	}
}

// Selected reports whether a parameter is in the policy selection.
func (c *Collector) Selected(name string) bool { return c.sel.Load().params[name] }

// SelectedParameters lists the policy selection (identifiers included).
func (c *Collector) SelectedParameters() []string {
	params := c.sel.Load().params
	out := make([]string, 0, len(params))
	for p := range params {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// mergeScore combines the request-time and response-time scores of a call:
// the result with the larger |z| (the more severe band) is kept and the
// actions of both are recorded.
func mergeScore(a, b *anomaly.Result) *anomaly.Result {
	if a == nil {
		return b
	}
	keep, other := a, b
	if anomaly.Rank(b.Band) > anomaly.Rank(a.Band) || (anomaly.Rank(b.Band) == anomaly.Rank(a.Band) && math.Abs(b.Combined) > math.Abs(a.Combined)) {
		keep, other = b, a
	}
	out := *keep
	out.Features = append(append([]anomaly.FeatureScore{}, keep.Features...), other.Features...)
	for _, act := range other.Actions {
		if !slices.Contains(out.Actions, act) {
			out.Actions = append(out.Actions, act)
		}
	}
	return &out
}

// Probe value keys of the collector's own secret-fingerprint matches
// (FR-6.10): the probes scan arguments and results with the fingerprints
// the Secret Broker registered with the collector. They are combined into
// secret_fingerprint_matches (P-142) and never stored themselves.
const (
	ProbeSecretMatchesRequest  = "_secret_fingerprint_matches_request"
	ProbeSecretMatchesResponse = "_secret_fingerprint_matches_response"
)

// combineSecretMatches sets secret_fingerprint_matches (P-142) to the
// larger of the filter chain's count and the collector's own count over
// the request and the response, and removes the probe keys.
func combineSecretMatches(v map[string]any) {
	own, seen := int64(0), false
	for _, k := range []string{ProbeSecretMatchesRequest, ProbeSecretMatchesResponse} {
		if n, ok := v[k].(int64); ok {
			own += n
			seen = true
		}
		delete(v, k)
	}
	if !seen {
		return
	}
	var cur int64
	switch x := v["secret_fingerprint_matches"].(type) {
	case int64:
		cur = x
	case int:
		cur = int64(x)
	case float64:
		cur = int64(x)
	}
	v["secret_fingerprint_matches"] = max(own, cur)
}

// filterParams maps the parameter IDs of a filter evidence event (written
// by internal/filters) to their catalog names.
var filterParams = map[string]string{"P-043": "injection_detect_score", "P-044": "unicode_control_count", "P-140": "filter_hits",
	"P-141": "redaction_count", "P-142": "secret_fingerprint_matches", "P-143": "injection_marker_score", "P-144": "pii_hits"}

// filterValues copies one filter chain run into the record (FR-4.7): the
// finding parameters of the run (P-043, P-044, P-140 to P-144) and the
// time of each filter, by filter ID, and of the stage (P-205
// t_request_filters, P-209 t_response_filters, in ms).
func filterValues(v map[string]any, ev *audit.Event) {
	d, _ := ev.Detail.(map[string]any)
	if d == nil {
		return
	}
	if params, ok := d["parameters"].(map[string]any); ok {
		for id, x := range params {
			if name := filterParams[id]; name != "" {
				v[name] = x
			}
		}
	}
	var runs []map[string]any
	switch x := d["filters"].(type) {
	case []map[string]any:
		runs = x
	case []any:
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				runs = append(runs, m)
			}
		}
	}
	timing := map[string]any{}
	var total float64
	for _, r := range runs {
		id, _ := r["id"].(string)
		if id == "" {
			continue
		}
		var us float64
		switch n := r["duration_us"].(type) {
		case int64:
			us = float64(n)
		case float64:
			us = n
		case json.Number:
			us, _ = n.Float64()
		}
		timing[id] = us / 1000
		total += us / 1000
	}
	timing["total"] = total
	if stage, _ := d["stage"].(string); stage == "response" {
		v["t_response_filters"] = timing
	} else {
		v["t_request_filters"] = timing
	}
}
