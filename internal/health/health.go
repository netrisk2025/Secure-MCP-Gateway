// Package health is the Health & Safety Monitor (E-23): it evaluates its
// checks once per second (FR-7.11), reports the Gateway health as
// `healthy`, `degraded` or `fail-closed` with the active causes (FR-7.12),
// and holds the Gateway fail-closed while a critical cause is latched
// (FR-7.13).
//
// A check returns the causes that are active now. A critical cause latches
// at once and the edge refuses MCP requests and launch authorizations with
// FAIL_CLOSED while any latch is held (Gate). A latch is released only
// after its cause has been clear for Recovery (10 seconds) without
// interruption and, for an integrity cause, after an administrator
// acknowledged it (Ack). Non-critical causes make the state `degraded`
// while they are active and never block calls.
//
// Every state change is recorded in the evidence journal (class `health`).
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// States.
const (
	Healthy    = "healthy"
	Degraded   = "degraded"
	FailClosed = "fail-closed"
)

// Cause is one active health cause.
type Cause struct {
	Name      string `json:"name"`
	Critical  bool   `json:"critical"`
	Integrity bool   `json:"integrity,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Check reports the causes active at now. It is called from the monitor's
// goroutine once per interval and must return quickly; slow probes cache
// their result (see Every).
type Check func(now time.Time) []Cause

// Defaults (FR-7.11, FR-7.13).
const (
	DefaultInterval = time.Second
	DefaultRecovery = 10 * time.Second
)

// Options configure a Monitor.
type Options struct {
	Interval time.Duration
	Recovery time.Duration
	Now      func() time.Time
	Evidence audit.Recorder // health transitions and acknowledgments; may be nil in tests
	Log      *slog.Logger
	// Info is merged into every report (profile, release label, version).
	Info func() map[string]any
}

type latch struct {
	cause        Cause
	since        time.Time
	clearedSince time.Time // zero while the cause is active
	acked        bool
	ackedBy      string
}

// Monitor evaluates checks and holds the fail-closed latch.
type Monitor struct {
	o Options

	mu      sync.Mutex
	checks  []namedCheck
	quotas  []*Quota
	active  map[string]Cause
	latches map[string]*latch
	state   string
	checked time.Time

	gate atomic.Pointer[[]string]
}

type namedCheck struct {
	name string
	fn   Check
}

// New returns a monitor in state healthy with no checks.
func New(o Options) *Monitor {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.Recovery <= 0 {
		o.Recovery = DefaultRecovery
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	m := &Monitor{o: o, active: map[string]Cause{}, latches: map[string]*latch{}, state: Healthy}
	empty := []string{}
	m.gate.Store(&empty)
	return m
}

// SetEvidence sets the recorder for state changes and acknowledgments; the
// monitor is created before the journal is open, so it is set afterwards.
func (m *Monitor) SetEvidence(rec audit.Recorder) {
	m.mu.Lock()
	m.o.Evidence = rec
	m.mu.Unlock()
}

// SetInfo sets the function whose result is merged into every report.
func (m *Monitor) SetInfo(f func() map[string]any) {
	m.mu.Lock()
	m.o.Info = f
	m.mu.Unlock()
}

// Register adds a check. Elements that own a dependency (vault, graph
// mirror, Observation Store, memory manager) register their own.
func (m *Monitor) Register(name string, c Check) {
	m.mu.Lock()
	m.checks = append(m.checks, namedCheck{name, c})
	m.mu.Unlock()
}

// Run evaluates every Interval until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.o.Interval)
	defer t.Stop()
	m.Evaluate()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Evaluate()
		}
	}
}

// Evaluate runs every check once and updates the state.
func (m *Monitor) Evaluate() {
	now := m.o.Now()
	m.mu.Lock()
	checks := append([]namedCheck(nil), m.checks...)
	m.mu.Unlock()
	active := map[string]Cause{}
	for _, c := range checks {
		for _, cause := range safeRun(c, now, m.o.Log) {
			if prev, ok := active[cause.Name]; ok && prev.Critical && !cause.Critical {
				continue
			}
			active[cause.Name] = cause
		}
	}

	m.mu.Lock()
	m.active, m.checked = active, now
	for name, c := range active {
		if !c.Critical {
			continue
		}
		l, ok := m.latches[name]
		if !ok {
			m.latches[name] = &latch{cause: c, since: now}
			continue
		}
		if !l.clearedSince.IsZero() && c.Integrity {
			l.acked, l.ackedBy = false, "" // re-raised: a new acknowledgment is needed
		}
		l.cause, l.clearedSince = c, time.Time{}
	}
	for name, l := range m.latches {
		if _, still := active[name]; still && active[name].Critical {
			continue
		}
		if l.clearedSince.IsZero() {
			l.clearedSince = now
		}
		if now.Sub(l.clearedSince) >= m.o.Recovery && (!l.cause.Integrity || l.acked) {
			delete(m.latches, name)
		}
	}
	gate := make([]string, 0, len(m.latches))
	for name := range m.latches {
		gate = append(gate, name)
	}
	sort.Strings(gate)
	m.gate.Store(&gate)
	state := Healthy
	switch {
	case len(m.latches) > 0:
		state = FailClosed
	case len(active) > 0:
		state = Degraded
	}
	prev := m.state
	m.state = state
	causes := m.causeNamesLocked()
	rec := m.o.Evidence
	m.mu.Unlock()

	if state != prev {
		m.o.Log.Warn("health state changed", "from", prev, "to", state, "causes", causes)
		if rec != nil {
			if err := rec.Commit(audit.Event{Class: "health", Origin: "E-23", Outcome: state, ReasonCode: "HEALTH_" + reasonOf(state), PolicyStatus: "not_evaluated",
				Detail: map[string]any{"previous": prev, "causes": causes}}); err != nil {
				m.o.Log.Error("evidence write failed", "err", err)
			}
		}
	}
}

func reasonOf(state string) string {
	switch state {
	case FailClosed:
		return "FAIL_CLOSED"
	case Degraded:
		return "DEGRADED"
	}
	return "HEALTHY"
}

func safeRun(c namedCheck, now time.Time, log *slog.Logger) (out []Cause) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("health check panicked", "check", c.name, "panic", fmt.Sprint(r))
			out = []Cause{{Name: "check_failed", Critical: true, Detail: c.name}}
		}
	}()
	return c.fn(now)
}

func (m *Monitor) causeNamesLocked() []string {
	seen := map[string]bool{}
	var out []string
	for n := range m.latches {
		seen[n] = true
		out = append(out, n)
	}
	for n := range m.active {
		if !seen[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Gate returns the latched critical causes; non-empty means fail-closed.
// It is safe to call on every request.
func (m *Monitor) Gate() []string { return *m.gate.Load() }

// State returns the current state.
func (m *Monitor) State() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// CauseReport is one cause in a report.
type CauseReport struct {
	Cause
	Active      bool       `json:"active"`
	Since       *time.Time `json:"since,omitempty"`
	ClearedAt   *time.Time `json:"cleared_at,omitempty"`
	AckRequired bool       `json:"ack_required,omitempty"`
	AckedBy     string     `json:"acked_by,omitempty"`
}

// Report is the monitor's health report (FR-7.12).
type Report struct {
	State     string         `json:"state"`
	Causes    []CauseReport  `json:"causes"`
	CheckedAt time.Time      `json:"checked_at"`
	Info      map[string]any `json:"info,omitempty"`
	// Quotas are the storage quota levels (FR-9.15).
	Quotas []QuotaLevel `json:"quotas,omitempty"`
}

// Report returns the current report.
func (m *Monitor) Report() Report {
	m.mu.Lock()
	r := Report{State: m.state, CheckedAt: m.checked.UTC(), Causes: []CauseReport{}}
	for name, l := range m.latches {
		cr := CauseReport{Cause: l.cause, Active: false}
		if a, ok := m.active[name]; ok && a.Critical {
			cr.Active, cr.Cause = true, a
		}
		since := l.since.UTC()
		cr.Since = &since
		if !l.clearedSince.IsZero() {
			c := l.clearedSince.UTC()
			cr.ClearedAt = &c
		}
		cr.AckRequired = l.cause.Integrity && !l.acked
		cr.AckedBy = l.ackedBy
		r.Causes = append(r.Causes, cr)
	}
	for name, c := range m.active {
		if _, latched := m.latches[name]; latched {
			continue
		}
		r.Causes = append(r.Causes, CauseReport{Cause: c, Active: true})
	}
	info := m.o.Info
	m.mu.Unlock()
	sort.Slice(r.Causes, func(i, k int) bool { return r.Causes[i].Name < r.Causes[k].Name })
	if info != nil {
		r.Info = info()
	}
	if q := m.Quotas(); len(q) > 0 {
		r.Quotas = q
	}
	return r
}

// ErrNotLatched is returned by Ack for a cause that is not latched or does
// not need acknowledgment.
var ErrNotLatched = errors.New("no latched integrity cause by that name")

// Ack records an administrator's acknowledgment of a latched integrity
// cause. The latch is still held until the cause has been clear for the
// recovery period.
func (m *Monitor) Ack(cause, actor string) error {
	m.mu.Lock()
	l, ok := m.latches[cause]
	if !ok || !l.cause.Integrity {
		m.mu.Unlock()
		return ErrNotLatched
	}
	l.acked, l.ackedBy = true, actor
	rec := m.o.Evidence
	m.mu.Unlock()
	if rec != nil {
		if err := rec.Commit(audit.Event{Class: "admin", Origin: "E-23", Outcome: "acknowledged", ReasonCode: "HEALTH_ACK", PolicyStatus: "not_evaluated",
			Detail: map[string]any{"actor": actor, "cause": cause}}); err != nil {
			return err
		}
	}
	return nil
}

// Every wraps a slow check so that it runs at most once per period; the
// cached causes are returned in between.
func Every(period time.Duration, c Check) Check {
	var (
		mu   sync.Mutex
		last time.Time
		out  []Cause
	)
	return func(now time.Time) []Cause {
		mu.Lock()
		defer mu.Unlock()
		if last.IsZero() || now.Sub(last) >= period || now.Before(last) {
			out, last = c(now), now
		}
		return out
	}
}
