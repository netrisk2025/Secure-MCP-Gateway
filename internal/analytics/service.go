// Package analytics wires SS-10 Observation & Analytics and the Observation
// Store into the Gateway: the Observation Collector (E-29) as an evidence
// observer and as observation filters in the inspection pipelines, the
// Observation Store (E-27), the Behavior Baseline Engine (E-30), the
// Anomaly Scorer (E-31) and the Research Dataset Service (E-32), with the
// control API routes /api/v1/observations*, /api/v1/baselines*,
// /api/v1/anomalies* and /api/v1/research*.
//
// Observation never gates enforcement: a store that cannot be opened leaves
// the Gateway running without analytics (FR-9), and every hand-off from the
// call path is a non-blocking offer to a bounded queue (FR-10.1).
package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/research"
)

// Options build a Service.
type Options struct {
	Config  *config.Config
	Log     *slog.Logger
	Catalog *observe.Catalog // default the shipped catalog
	Now     func() time.Time
	// FrameworkOf returns a principal's framework type, for the
	// framework_type parameter and Observation Policy scope (FR-8.9).
	FrameworkOf func(principal string) string
}

// scopeFilter is the collector's Observation Policy scope test (FR-8.9),
// nil when the scope matches every call.
func scopeFilter(sc config.ObservationScope) func(*observe.Record) bool {
	if sc.Empty() {
		return nil
	}
	in := func(list []string, v string) bool { return len(list) == 0 || slices.Contains(list, v) }
	return func(r *observe.Record) bool {
		return in(sc.Principals, r.Str("principal_id")) && in(sc.Frameworks, r.Str("framework_type")) &&
			in(sc.Templates, r.Str("session_template")) && in(sc.Servers, r.ServerID) && in(sc.Tools, r.ServerID+"/"+r.Str("tool_name"))
	}
}

// Service is the running analytics subsystem.
type Service struct {
	// S is the settings the service started with. The settings that can
	// change while it runs (Update) are read through cur().
	S         Settings
	Catalog   *observe.Catalog
	Store     obsstore.Store
	Collector *observe.Collector
	Baselines *baseline.Manager
	Scorer    *anomaly.Scorer
	Campaigns *research.Campaigns
	Exporter  *research.Exporter

	log      *slog.Logger
	now      func() time.Time
	writer   *writer
	storeErr error
	degrade  *degrader
	sources  MetricSources // guarded by mu
	live     atomic.Pointer[Settings]
	scanner  atomic.Pointer[func([]byte) int] // secret fingerprints (FR-6.10)

	mu        sync.Mutex
	rec       audit.Recorder
	dropped   func() uint64
	lastCPU   time.Duration
	lastTick  time.Time
	lastRows  int64
	lastAssem uint64
	started   bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// Disabled reports a service that is configured off.
func (s *Service) Disabled() bool { return s == nil || !s.S.Enabled }

// Tables returns the store schemas for a catalog: records (one column per
// per-call parameter plus record metadata), spans, metrics (one column per
// periodic parameter) and scores.
func Tables(cat *observe.Catalog) []obsstore.Table {
	typ := func(p observe.Param) string {
		switch p.DataType {
		case "integer":
			return obsstore.BigInt
		case "number":
			return obsstore.Double
		}
		return obsstore.Varchar
	}
	rec := obsstore.Table{Name: "records", Columns: []obsstore.Column{
		{Name: "ts", Type: obsstore.Timestamp}, {Name: "correlation_id", Type: obsstore.Varchar}, {Name: "server_id", Type: obsstore.Varchar},
		{Name: "policy_revision", Type: obsstore.Varchar}, {Name: "reason_code", Type: obsstore.Varchar}, {Name: "capture", Type: obsstore.Varchar},
		{Name: "campaign_id", Type: obsstore.Varchar}, {Name: "observation_policy", Type: obsstore.Varchar}, {Name: "catalog_version", Type: obsstore.Varchar},
	}}
	for _, p := range cat.PerCall() {
		rec.Columns = append(rec.Columns, obsstore.Column{Name: p.Name, Type: typ(p)})
	}
	met := obsstore.Table{Name: "metrics", Columns: []obsstore.Column{{Name: "ts", Type: obsstore.Timestamp}, {Name: "interval_seconds", Type: obsstore.Double}}}
	for _, p := range cat.Periodic() {
		met.Columns = append(met.Columns, obsstore.Column{Name: p.Name, Type: typ(p)})
	}
	spans := obsstore.Table{Name: "spans", Columns: []obsstore.Column{
		{Name: "ts", Type: obsstore.Timestamp}, {Name: "correlation_id", Type: obsstore.Varchar}, {Name: "stage", Type: obsstore.Varchar},
		{Name: "duration_ms", Type: obsstore.Double}, {Name: "monotonic", Type: obsstore.BigInt}, {Name: "policy_revision", Type: obsstore.Varchar},
		{Name: "observation_policy", Type: obsstore.Varchar}, {Name: "principal_id", Type: obsstore.Varchar}, {Name: "tool_name", Type: obsstore.Varchar},
		// Call-path spans (FR-10.2, monotonic = 1): thread CPU time and the
		// decisive rule revision and filter that caused the work (FR-10.11).
		{Name: "cpu_ms", Type: obsstore.Double}, {Name: "rule_id", Type: obsstore.Varchar}, {Name: "filter_id", Type: obsstore.Varchar},
	}}
	scores := obsstore.Table{Name: "scores", Columns: []obsstore.Column{
		{Name: "ts", Type: obsstore.Timestamp}, {Name: "correlation_id", Type: obsstore.Varchar}, {Name: "snapshot_id", Type: obsstore.Varchar},
		{Name: "context", Type: obsstore.Varchar}, {Name: "combined", Type: obsstore.Double}, {Name: "contributing_feature", Type: obsstore.Varchar},
		{Name: "band", Type: obsstore.Varchar}, {Name: "features", Type: obsstore.Varchar}, {Name: "actions", Type: obsstore.Varchar},
		{Name: "mode", Type: obsstore.Varchar}, {Name: "principal_id", Type: obsstore.Varchar}, {Name: "session_id", Type: obsstore.Varchar},
		{Name: "tool_name", Type: obsstore.Varchar},
	}}
	return []obsstore.Table{rec, met, spans, scores}
}

// New builds the service. Configuration errors are returned; a store that
// cannot be opened is not an error: the service then runs without storage
// and reports the cause in its status.
func New(o Options) (*Service, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Catalog == nil {
		o.Catalog = observe.DefaultCatalog()
	}
	st, err := Resolve(o.Config, o.Catalog)
	if err != nil {
		return nil, err
	}
	s := &Service{S: st, Catalog: o.Catalog, log: o.Log, now: o.Now}
	live := st
	s.live.Store(&live)
	if !st.Enabled {
		return s, nil
	}
	if s.Scorer, err = anomaly.New(st.Thresholds); err != nil {
		return nil, err
	}
	eng, err := baseline.NewEngine(st.Baseline, o.Now)
	if err != nil {
		return nil, err
	}
	if s.Baselines, err = baseline.NewManager(eng, baseline.ManagerOptions{Dir: filepath.Join(st.Dir, "baselines"), Interval: st.SnapshotInterval,
		Records: st.SnapshotRecords, Auto: st.Auto, Loader: s.Scorer, Log: o.Log}); err != nil {
		return nil, fmt.Errorf("observation baselines: %w", err)
	}
	if s.Campaigns, err = research.OpenCampaigns(filepath.Join(st.Dir, "research", "campaigns.json"), o.Catalog, o.Now); err != nil {
		return nil, fmt.Errorf("research campaigns: %w", err)
	}
	s.Store, s.storeErr = openStore(obsstore.Options{Dir: filepath.Join(st.Dir, "store"), Backend: st.Store, Tables: Tables(o.Catalog), MemoryLimit: st.MemoryLimit})
	if s.storeErr != nil {
		o.Log.Error("observation store unavailable; observation records are counted and dropped", "err", s.storeErr)
	} else {
		s.writer = newWriter(s.Store, st.FlushRecords, st.FlushInterval, st.Queue, o.Log)
		s.Exporter = &research.Exporter{Store: s.Store, Catalog: o.Catalog, Campaigns: s.Campaigns, Snapshots: s.Baselines.Store(),
			Dir: st.ExportDir, KeyDir: st.KeyDir, Now: o.Now}
	}
	s.degrade = newDegrader(st.MemoryLimit, s.writer.underPressure, o.Log)
	s.Collector = observe.New(observe.Options{Catalog: o.Catalog, PolicyID: st.PolicyID, Parameters: st.Parameters, Escalation: st.Escalation, Degradation: s.degrade.Stage,
		EscalateFrom: st.EscalateCapture, EscalateUncharacterized: st.Uncharacterized != "record", EscalationByBand: st.EscalationByBand,
		InScope: scopeFilter(st.Scope), FrameworkOf: o.FrameworkOf,
		SamplingRate: st.SamplingRate, Queue: st.Queue, Analyzer: (*analyzer)(s), Campaigns: s.Campaigns.Active, Now: o.Now,
		SpanSink: s.writeSpans, CurrentPolicy: func() string { return s.cur().PolicyID }})
	return s, nil
}

// openStore opens the Observation Store from a thread of lowered priority
// (lowPriority), so that the worker threads DuckDB starts with the
// database inherit it; the thread ends with the goroutine.
func openStore(o obsstore.Options) (obsstore.Store, error) {
	type opened struct {
		st  obsstore.Store
		err error
	}
	ch := make(chan opened, 1)
	go func() {
		lowPriority()
		st, err := obsstore.Open(o)
		ch <- opened{st, err}
	}()
	r := <-ch
	return r.st, r.err
}

// cur returns the settings in force: S with the changes Update applied.
func (s *Service) cur() *Settings {
	if l := s.live.Load(); l != nil {
		return l
	}
	return &s.S
}

// Current returns a copy of the settings in force.
func (s *Service) Current() Settings { return *s.cur() }

// Update applies new observation settings while the service runs (the
// observation objects published from the console, G-03, G-04, G-06). The
// Observation Policy ID, parameter selection, sampling rate, escalation
// parameters, retention, band thresholds, scoring mode and the approval
// and withhold bands apply at once. Settings the running components were
// built with are not changed; their names are returned and they apply at
// the next start: "enabled", "baseline.contexts" and "memory_limit_bytes".
// A configuration that does not resolve is refused and nothing changes.
func (s *Service) Update(cfg *config.Config) (restart []string, err error) {
	if s == nil {
		return nil, nil
	}
	st, err := Resolve(cfg, s.Catalog)
	if err != nil {
		return nil, err
	}
	if st.Enabled != s.S.Enabled {
		restart = append(restart, "enabled")
	}
	if s.Disabled() {
		return restart, nil
	}
	if !slices.Equal(st.Baseline.Dimensions, s.S.Baseline.Dimensions) {
		restart = append(restart, "baseline.contexts")
	}
	if st.MemoryLimit != s.S.MemoryLimit {
		restart = append(restart, "memory_limit_bytes")
	}
	// The collector and the anomaly response were built with these.
	if !slices.Equal(st.Baseline.Features, s.S.Baseline.Features) {
		restart = append(restart, "baseline.features")
	}
	if st.EscalateCapture != s.S.EscalateCapture || st.Uncharacterized != s.S.Uncharacterized ||
		!reflect.DeepEqual(st.EscalationByBand, s.S.EscalationByBand) {
		restart = append(restart, "anomaly_response")
	}
	if !reflect.DeepEqual(st.Scope, s.S.Scope) {
		restart = append(restart, "scope")
	}
	if err := s.Scorer.SetThresholds(st.Thresholds); err != nil {
		return nil, err
	}
	next := *s.cur()
	next.PolicyID, next.Parameters, next.Escalation, next.SamplingRate = st.PolicyID, st.Parameters, st.Escalation, st.SamplingRate
	next.Retention, next.Thresholds = st.Retention, st.Thresholds
	next.Scoring, next.RequireApproval, next.Withhold = st.Scoring, st.RequireApproval, st.Withhold
	s.live.Store(&next)
	s.Collector.SetPolicy(st.Parameters, st.Escalation, st.SamplingRate)
	s.log.Info("observation settings updated", "policy_id", st.PolicyID, "scoring", st.Scoring, "restart_required", restart)
	return restart, nil
}

// SpanSink returns the sink for the edge's call-path spans (FR-10.2), or
// nil when observation is disabled.
func (s *Service) SpanSink() pipeline.SpanSink {
	if s.Disabled() {
		return nil
	}
	return s.Collector.OfferSpans
}

// writeSpans stores call-path spans in the spans table.
func (s *Service) writeSpans(policyID string, spans []pipeline.StageSpan) {
	if s.writer == nil {
		return
	}
	for _, sp := range spans {
		s.writer.offer("spans", obsstore.Row{"ts": sp.Start, "correlation_id": sp.CorrelationID, "stage": sp.Stage,
			"duration_ms": float64(sp.Duration()) / float64(time.Millisecond), "monotonic": int64(1), "policy_revision": sp.PolicyRevision,
			"observation_policy": policyID, "cpu_ms": float64(sp.CPU) / float64(time.Millisecond), "rule_id": sp.Rule, "filter_id": sp.Filter})
	}
}

// Observer returns the evidence observer to register in app.Options
// (nil when disabled).
func (s *Service) Observer() audit.Observer {
	if s.Disabled() {
		return nil
	}
	return s.Collector
}

// RegisterFilters adds the observation filters to the inspection
// pipelines: "observe-request" (mandatory, order 1000, after every other
// request filter) and "observe-response" (mandatory, order 1000).
func (s *Service) RegisterFilters(f *pipeline.Filters) error {
	if s.Disabled() {
		return nil
	}
	// The probes' work is bounded and never blocks, so they run inline.
	if err := f.RegisterRequest(&requestProbe{s}, pipeline.Registration{Order: 1000, Mandatory: true, Inline: true}); err != nil {
		return err
	}
	return f.RegisterResponse(&responseProbe{s}, pipeline.Registration{Order: 1000, Mandatory: true, Inline: true})
}

// Start registers the control API routes, sets the evidence recorder and
// starts the background loops. dropped reports the evidence fan-out's drops
// for this observer (may be nil).
func (s *Service) Start(ctx context.Context, rec audit.Recorder, admin *adminapi.Server, dropped func() uint64) {
	if admin != nil {
		s.Register(admin)
	}
	if s.Disabled() {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.rec, s.dropped, s.cancel, s.started = rec, dropped, cancel, true
	s.lastTick = s.now()
	s.mu.Unlock()
	s.Baselines.SetRecorder(rec)
	s.wg.Add(3)
	// The collector keeps the calls' priority: it runs Go code throughout,
	// and a goroutine locked to a low-priority thread keeps its processor
	// slot (P) while the kernel withholds the thread, which on a busy host
	// took the slot from calls for longer than the collector's own work.
	// The writer spends its time in DuckDB (cgo), which hands the slot back.
	go func() { defer s.wg.Done(); s.Collector.Run() }()
	go func() { defer s.wg.Done(); lowPriority(); s.Baselines.Run(ctx) }()
	go func() { defer s.wg.Done(); s.loop(ctx) }()
	if s.writer != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.writer.run(ctx) }()
	}
}

// Sync waits until every observation offered before the call is assembled
// and its rows are in the store (tests). It gives up after five seconds.
func (s *Service) Sync() {
	if s.Disabled() {
		return
	}
	s.Collector.Sync()
	if s.writer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.writer.sync(ctx)
	}
}

// Close drains the collector and the writer and saves state.
func (s *Service) Close() {
	if s.Disabled() {
		return
	}
	s.mu.Lock()
	started, cancel := s.started, s.cancel
	s.mu.Unlock()
	if started {
		s.Collector.Close()
		cancel()
		s.wg.Wait()
	}
	if err := s.Baselines.Close(); err != nil {
		s.log.Warn("baseline state not saved", "err", err)
	}
	if err := s.Campaigns.Flush(); err != nil {
		s.log.Warn("campaign counters not saved", "err", err)
	}
	if s.Store != nil {
		s.Store.Close()
	}
}

// degradeInterval is how often the degradation stage moves one step
// (FR-9.12). It is half the Health & Safety Monitor's interval, so that a
// stage change is reported within 2 seconds of the overload (FR-7.11).
const degradeInterval = 500 * time.Millisecond

// retainInterval is how often retention runs: at start and then hourly,
// well within FR-9.14's once a day.
var retainInterval = time.Hour

// loop runs the meta-metrics sampler (FR-10.9), the campaign clock
// (FR-10.31) and retention (daily, FR-9.14 for D-09/D-13).
func (s *Service) loop(ctx context.Context) {
	mt := time.NewTicker(s.S.MetricsInterval)
	defer mt.Stop()
	ct := time.NewTicker(time.Second)
	defer ct.Stop()
	dt := time.NewTicker(degradeInterval)
	defer dt.Stop()
	rt := time.NewTicker(retainInterval)
	defer rt.Stop()
	s.retain()
	for {
		select {
		case <-ctx.Done():
			return
		case <-mt.C:
			s.sampleMetrics()
		case <-ct.C:
			s.tickCampaigns()
		case <-dt.C:
			s.degrade.step()
		case <-rt.C:
			s.retain()
		}
	}
}

func (s *Service) tickCampaigns() {
	tr, err := s.Campaigns.Tick()
	if err != nil {
		s.log.Warn("campaign state not saved", "err", err)
	}
	for _, t := range tr {
		s.audit(audit.Event{Class: "research", Origin: "E-32", Outcome: t.To, Detail: map[string]any{"from": t.From, "reason": t.Reason}})
	}
}

func (s *Service) retain() {
	if s.Store == nil {
		return
	}
	removed, err := s.Store.Retain(s.now(), s.cur().Retention)
	if err != nil {
		s.log.Warn("observation retention failed", "err", err)
		return
	}
	if len(removed) > 0 {
		s.audit(audit.Event{Class: "observation", Origin: "E-27", Outcome: "retention", Detail: map[string]any{"removed": removed}})
	}
	if s.Exporter == nil {
		return
	}
	// Exported research datasets follow the same retention (FR-9.14).
	datasets, err := s.Exporter.Retain(s.now(), s.cur().Retention)
	if err != nil {
		s.log.Warn("research dataset retention failed", "err", err)
	}
	if len(datasets) > 0 {
		s.audit(audit.Event{Class: "research", Origin: "E-28", Outcome: "retention", Detail: map[string]any{"removed_datasets": datasets}})
	}
}

func (s *Service) recorder() audit.Recorder {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec
}

// audit records a non-call evidence event; failures are logged, since
// analytics events never gate enforcement.
func (s *Service) audit(ev audit.Event) {
	rec := s.recorder()
	if rec == nil {
		return
	}
	if ev.PolicyStatus == "" {
		ev.PolicyStatus = "not_evaluated"
	}
	if err := rec.Record(ev); err != nil {
		s.log.Error("evidence write failed", "class", ev.Class, "err", err)
	}
}

// Drops returns P-246: the collector's counters plus the evidence fan-out
// and writer drops.
func (s *Service) Drops() map[string]uint64 {
	d := s.Collector.Drops()
	s.mu.Lock()
	f := s.dropped
	s.mu.Unlock()
	if f != nil {
		if n := f(); n > 0 {
			d[observe.DropObserver] = n
		}
	}
	if s.writer != nil {
		for k, v := range s.writer.drops() {
			d[k] += v
		}
	}
	return d
}

// writeRecord stores a captured record and its spans.
func (s *Service) writeRecord(r *observe.Record) {
	if s.writer == nil {
		s.Collector.Drop(observe.DropStoreError, 1)
		return
	}
	row := obsstore.Row{"ts": r.Time, "correlation_id": r.CorrelationID, "capture": r.Capture, "observation_policy": s.cur().PolicyID,
		"catalog_version": s.Catalog.Version}
	if r.Time.IsZero() {
		row["ts"] = r.End
	}
	if r.ServerID != "" {
		row["server_id"] = r.ServerID
	}
	if len(r.Campaigns) > 0 {
		row["campaign_id"] = r.Campaigns[0]
	}
	for k, v := range r.Values {
		row[k] = v
	}
	if len(r.Campaigns) > 0 {
		b, _ := json.Marshal(row)
		for _, id := range s.Campaigns.Account(r.Campaigns, int64(len(b))) {
			s.audit(audit.Event{Class: "research", Origin: "E-32", Outcome: research.Completed, ReasonCode: "CAMPAIGN_QUOTA_REACHED",
				Detail: map[string]any{"campaign_id": id}})
		}
	}
	s.writer.offer("records", row)
	for _, sp := range r.Spans {
		mono := int64(0)
		if sp.Monotonic {
			mono = 1
		}
		s.writer.offer("spans", obsstore.Row{"ts": sp.Start, "correlation_id": r.CorrelationID, "stage": sp.Stage,
			"duration_ms": float64(sp.End.Sub(sp.Start)) / float64(time.Millisecond), "monotonic": mono, "policy_revision": sp.PolicyObject,
			"observation_policy": s.cur().PolicyID, "principal_id": r.Str("principal_id"), "tool_name": r.Str("tool_name")})
	}
}

// writeScore stores a scoring record (FR-10.29) and, for elevated or
// worse, records anomaly evidence.
func (s *Service) writeScore(r *observe.Record, res *anomaly.Result, mode string) {
	if res == nil {
		return
	}
	feats, _ := json.Marshal(res.Features)
	acts, _ := json.Marshal(res.Actions)
	ts := r.Time
	if ts.IsZero() {
		ts = r.End
	}
	if s.writer != nil {
		s.writer.offer("scores", obsstore.Row{"ts": ts, "correlation_id": r.CorrelationID, "snapshot_id": res.SnapshotID, "context": res.Context,
			"combined": res.Combined, "contributing_feature": res.Contributor, "band": res.Band, "features": string(feats), "actions": string(acts),
			"mode": mode, "principal_id": r.Str("principal_id"), "session_id": r.Str("session_id"), "tool_name": r.Str("tool_name")})
	}
	if anomaly.Rank(res.Band) >= anomaly.Rank(anomaly.Elevated) {
		s.audit(audit.Event{Class: "anomaly", Origin: "E-31", CorrelationID: r.CorrelationID, SessionID: r.Str("session_id"),
			PrincipalID: r.Str("principal_id"), ServerRevision: r.Str("server_revision"), Outcome: res.Band,
			ReasonCode: "ANOMALY_" + upper(res.Band), PolicyStatus: "evaluated",
			Detail: map[string]any{"snapshot_id": res.SnapshotID, "context": res.Context, "combined": res.Combined,
				"contributing_feature": res.Contributor, "features": res.Features, "actions": res.Actions, "mode": mode}})
		if anomaly.Rank(res.Band) >= anomaly.Rank(anomaly.Abnormal) {
			s.log.Warn("anomalous tool call", "band", res.Band, "z", strconv.FormatFloat(res.Combined, 'f', 2, 64),
				"feature", res.Contributor, "correlation", r.CorrelationID)
		}
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
