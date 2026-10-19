package metrics

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var labelName = regexp.MustCompile(`([a-z_]+)="`)

// LabelNames returns every label name used in an exposition.
func labelNames(expo string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(expo, "\n") {
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "{") {
			continue
		}
		inner := line[strings.Index(line, "{")+1 : strings.LastIndex(line, "}")]
		for _, m := range labelName.FindAllStringSubmatch(inner, -1) {
			out[m[1]] = true
		}
	}
	return out
}

func TestExpositionFromEvidence(t *testing.T) {
	// FR-17.5 metric set and label restriction, from synthetic evidence;
	// internal/e2e scrapes a running Gateway.
	reqtest.Partial(t, "FR-17.5")
	tools := func(rev string) (string, string, bool) {
		if rev == "srv@1/echo" {
			return "t", "t_echo", true
		}
		return "", "", false
	}
	r := New(tools, Sources{HealthState: func() string { return "degraded" }, ActiveSessions: func() int { return 2 },
		PendingApproval: func() int { return 1 }, Backends: func() []string { return []string{"t"} }})
	t0 := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	ev := func(corr string, class string, ph audit.Phase, outcome, reason string, at time.Duration) audit.Event {
		return audit.Event{CorrelationID: corr, Class: class, Phase: ph, Outcome: outcome, ReasonCode: reason, ToolRevision: "srv@1/echo", Time: t0.Add(at).Format(time.RFC3339Nano)}
	}
	for _, e := range []audit.Event{
		ev("c1", "call", audit.PhaseRequested, "", "", 0),
		ev("c1", "decision", audit.PhaseAuthorized, "permit", "PERMIT", 2*time.Millisecond),
		ev("c1", "call", audit.PhaseDispatched, "", "", 3*time.Millisecond),
		ev("c1", "call", audit.PhaseDelivered, "release", "", 5*time.Millisecond),
		ev("c2", "call", audit.PhaseRequested, "", "", 0),
		ev("c2", "decision", audit.PhaseDenied, "deny", "NO_RULE", time.Millisecond),
		ev("c3", "call", audit.PhaseRequested, "", "", 0),
		ev("c3", "approval", audit.PhaseAuthorized, "approved", "APPROVED", 5*time.Second),
		ev("c3", "decision", audit.PhaseAuthorized, "permit", "PERMIT", 5*time.Second),
		ev("c3", "call", audit.PhaseFailed, "backend_error", "BACKEND_ERROR", 6*time.Second),
		ev("c4", "call", audit.PhaseRequested, "", "", 0),
		ev("c4", "filter", audit.PhaseFiltered, "block", "SECRET_FOUND", time.Millisecond),
	} {
		r.Observe(e)
	}
	r.Observe(audit.Event{Class: "gateway", Outcome: "started"}) // not a call
	r.Flush.Observe(3 * time.Millisecond)
	if r.Calls("t", "t_echo", "delivered", "") != 1 || r.Calls("t", "t_echo", "denied", "NO_RULE") != 1 ||
		r.Calls("t", "t_echo", "failed", "BACKEND_ERROR") != 1 || r.Calls("t", "t_echo", "blocked", "SECRET_FOUND") != 1 {
		t.Fatal("call counts wrong")
	}
	// Decision latency excludes the call held for approval.
	if r.Decided.Count() != 2 {
		t.Fatalf("decision latency samples %d", r.Decided.Count())
	}
	var buf bytes.Buffer
	r.Write(&buf)
	expo := buf.String()
	for _, want := range []string{
		`smcp_calls_total{server_alias="t",tool="t_echo",outcome="delivered",reason_code=""} 1`,
		`smcp_decision_latency_seconds_bucket{le="0.0025"} 2`,
		`smcp_decision_latency_seconds_count 2`,
		`smcp_journal_flush_seconds_bucket{le="0.0025"} 0`,
		`smcp_journal_flush_seconds_bucket{le="0.005"} 1`,
		"smcp_health_state 1", "smcp_active_sessions 2", "smcp_pending_approvals 1",
		`smcp_backend_instances_running{server_alias="t"} 1`,
		"# TYPE smcp_calls_total counter", "# TYPE smcp_decision_latency_seconds histogram",
	} {
		if !strings.Contains(expo, want) {
			t.Errorf("exposition lacks %q", want)
		}
	}
	allowed := map[string]bool{"le": true}
	for _, l := range AllowedLabels {
		allowed[l] = true
	}
	for l := range labelNames(expo) {
		if !allowed[l] {
			t.Errorf("label %s is not allowed by FR-17.5", l)
		}
	}
	if len(r.requested) != 0 || len(r.held) != 0 {
		t.Fatalf("correlation tables not pruned: %d %d", len(r.requested), len(r.held))
	}
}

func TestListenRefusesNonLoopback(t *testing.T) {
	reqtest.Partial(t, "FR-17.4")
	for _, a := range []string{"0.0.0.0:0", "192.0.2.1:9464", "example.com:9464"} {
		if _, err := Listen(a); !errors.Is(err, ErrNotLoopback) {
			t.Errorf("%s: %v", a, err)
		}
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if HealthValue("healthy") != 0 || HealthValue("degraded") != 1 || HealthValue("fail-closed") != 2 {
		t.Fatal("health values")
	}
}
