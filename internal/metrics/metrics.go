// Package metrics serves the Gateway's Prometheus text exposition at
// /metrics on a loopback address (FR-17.4, CP-51), written directly without
// an exporter process or client library.
//
// Metric set (FR-17.5), with labels limited to server_alias, tool (the
// public tool name), outcome and reason_code:
//
//	smcp_calls_total{server_alias,tool,outcome,reason_code}  counter
//	smcp_decision_latency_seconds                            histogram
//	smcp_journal_flush_seconds                               histogram
//	smcp_health_state                                        gauge 0 healthy, 1 degraded, 2 fail-closed
//	smcp_active_sessions                                     gauge
//	smcp_pending_approvals                                   gauge
//	smcp_backend_instances_running{server_alias}             gauge
//
// Call counts and decision latency come from evidence events through an
// audit.Observer, so they count exactly what the journal recorded; the
// journal flush histogram is fed by audit.Journal.SetFlushObserver.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Labels allowed by FR-17.5.
var AllowedLabels = []string{"server_alias", "tool", "outcome", "reason_code", "channel"}

// Histogram is a fixed-bucket histogram.
type Histogram struct {
	mu      sync.Mutex
	bounds  []float64
	buckets []uint64
	sum     float64
	count   uint64
}

// NewHistogram returns a histogram with the given upper bounds in seconds.
func NewHistogram(bounds ...float64) *Histogram {
	return &Histogram{bounds: bounds, buckets: make([]uint64, len(bounds))}
}

// Observe records one value in seconds.
func (h *Histogram) Observe(d time.Duration) {
	v := d.Seconds()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, b := range h.bounds {
		if v <= b {
			h.buckets[i]++
		}
	}
	h.sum += v
	h.count++
}

// Count returns the number of observations.
func (h *Histogram) Count() uint64 { h.mu.Lock(); defer h.mu.Unlock(); return h.count }

func (h *Histogram) write(w io.Writer, name, help string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for i, b := range h.bounds {
		fmt.Fprintf(w, "%s_bucket{le=\"%s\"} %d\n", name, formatFloat(b), h.buckets[i])
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %s\n%s_count %d\n", name, h.count, name, formatFloat(h.sum), name, h.count)
}

func formatFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// callKey is one label combination of smcp_calls_total.
type callKey struct{ alias, tool, outcome, reason string }

// ToolName maps an event's tool revision to the server alias and public
// tool name; ok is false when unknown.
type ToolName func(toolRevision string) (alias, tool string, ok bool)

// Sources are the gauges' live inputs. Nil functions report 0.
type Sources struct {
	HealthState     func() string
	ActiveSessions  func() int
	PendingApproval func() int
	Backends        func() []string // aliases of running instances
}

// Registry holds the metric values.
type Registry struct {
	tools   ToolName
	src     Sources
	Flush   *Histogram
	Decided *Histogram

	mu        sync.Mutex
	calls     map[callKey]uint64
	requested map[string]time.Time // correlation ID -> requested event time
	held      map[string]bool      // correlation IDs held for approval
}

// maxPending bounds the correlation table of in-flight calls.
const maxPending = 10000

// New returns an empty registry.
func New(tools ToolName, src Sources) *Registry {
	if tools == nil {
		tools = func(string) (string, string, bool) { return "", "", false }
	}
	latency := []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1}
	return &Registry{tools: tools, src: src, Flush: NewHistogram(latency...), Decided: NewHistogram(latency...),
		calls: map[callKey]uint64{}, requested: map[string]time.Time{}, held: map[string]bool{}}
}

// terminal reports whether the event ends a call.
func terminal(ev audit.Event) bool {
	switch ev.Phase {
	case audit.PhaseDelivered, audit.PhaseDenied, audit.PhaseFailed, audit.PhaseIndeterminate, audit.PhaseWithheld:
		return true
	case audit.PhaseFiltered:
		return ev.Outcome == "block"
	}
	return false
}

// Observe implements audit.Observer.
func (r *Registry) Observe(ev audit.Event) {
	if ev.CorrelationID == "" || ev.ToolRevision == "" {
		return
	}
	at, _ := time.Parse(time.RFC3339Nano, ev.Time)
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case ev.Phase == audit.PhaseRequested:
		if len(r.requested) < maxPending {
			r.requested[ev.CorrelationID] = at
		}
		return
	case ev.Class == "approval":
		r.held[ev.CorrelationID] = true
	case ev.Class == "decision" && (ev.Phase == audit.PhaseAuthorized || ev.Phase == audit.PhaseDenied):
		// Decision latency: requested to decision, for calls not held for
		// approval (an approval wait is not decision time).
		if t0, ok := r.requested[ev.CorrelationID]; ok && !r.held[ev.CorrelationID] && !at.IsZero() && !t0.IsZero() && !at.Before(t0) {
			r.Decided.Observe(at.Sub(t0))
		}
		delete(r.requested, ev.CorrelationID)
	}
	if terminal(ev) {
		alias, tool, _ := r.tools(ev.ToolRevision)
		outcome := string(ev.Phase)
		if ev.Phase == audit.PhaseFiltered {
			outcome = "blocked"
		}
		r.calls[callKey{alias, tool, outcome, ev.ReasonCode}]++
		delete(r.requested, ev.CorrelationID)
		delete(r.held, ev.CorrelationID)
	}
}

// Calls returns the count for one label combination (tests).
func (r *Registry) Calls(alias, tool, outcome, reason string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[callKey{alias, tool, outcome, reason}]
}

func escape(v string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v)
}

// HealthValue maps a health state to the gauge value.
func HealthValue(state string) int {
	switch state {
	case "degraded":
		return 1
	case "fail-closed":
		return 2
	}
	return 0
}

// Write writes the exposition.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	keys := make([]callKey, 0, len(r.calls))
	for k := range r.calls {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, k int) bool {
		a, b := keys[i], keys[k]
		return a.alias+"\x00"+a.tool+"\x00"+a.outcome+"\x00"+a.reason < b.alias+"\x00"+b.tool+"\x00"+b.outcome+"\x00"+b.reason
	})
	fmt.Fprintf(w, "# HELP smcp_calls_total Tool calls by terminal outcome and reason code.\n# TYPE smcp_calls_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(w, "smcp_calls_total{server_alias=\"%s\",tool=\"%s\",outcome=\"%s\",reason_code=\"%s\"} %d\n",
			escape(k.alias), escape(k.tool), escape(k.outcome), escape(k.reason), r.calls[k])
	}
	r.mu.Unlock()
	r.Decided.write(w, "smcp_decision_latency_seconds", "Time from the requested event to the decision event, for calls not held for approval.")
	r.Flush.write(w, "smcp_journal_flush_seconds", "Duration of evidence journal fsyncs.")
	gauge := func(name, help string, v int) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
	}
	state := ""
	if r.src.HealthState != nil {
		state = r.src.HealthState()
	}
	gauge("smcp_health_state", "Gateway health: 0 healthy, 1 degraded, 2 fail-closed.", HealthValue(state))
	n := 0
	if r.src.ActiveSessions != nil {
		n = r.src.ActiveSessions()
	}
	gauge("smcp_active_sessions", "Active harness sessions.", n)
	n = 0
	if r.src.PendingApproval != nil {
		n = r.src.PendingApproval()
	}
	gauge("smcp_pending_approvals", "Approvals waiting for a decision.", n)
	fmt.Fprintf(w, "# HELP smcp_backend_instances_running Running backend server instances.\n# TYPE smcp_backend_instances_running gauge\n")
	if r.src.Backends != nil {
		aliases := r.src.Backends()
		sort.Strings(aliases)
		for _, a := range aliases {
			fmt.Fprintf(w, "smcp_backend_instances_running{server_alias=\"%s\"} 1\n", escape(a))
		}
	}
}

// Handler serves GET /metrics.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, req *http.Request) {
		if !loopbackHost(req.Host) {
			// A browser page whose name re-resolves to 127.0.0.1 (DNS
			// rebinding) sends its own name as Host; only scrapers that
			// address the loopback listener directly are answered.
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		r.Write(w)
	})
	return mux
}

// loopbackHost reports whether a Host header names a loopback address or
// localhost, with or without a port.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ErrNotLoopback is returned for a metrics address that is not loopback.
var ErrNotLoopback = errors.New("metrics address must be a loopback address (FR-17.4)")

// Listen binds the metrics listener, refusing a non-loopback address.
func Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); (ip == nil && host != "localhost") || (ip != nil && !ip.IsLoopback()) {
		return nil, fmt.Errorf("%w: %s", ErrNotLoopback, addr)
	}
	return net.Listen("tcp", addr)
}

// Serve runs the metrics HTTP server on ln until ctx ends.
func (r *Registry) Serve(ctx context.Context, ln net.Listener, log *slog.Logger) error {
	srv := &http.Server{Handler: r.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}
