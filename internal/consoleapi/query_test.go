package consoleapi

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAuditQueryFilters: the audit query API filters by time range,
// principal, session, server, tool, rule, outcome, event class and policy
// revision, and pages with a cursor of at most 500 events (FR-7.3).
func TestAuditQueryFilters(t *testing.T) {
	reqtest.Verifies(t, "FR-7.3")
	f := newFixture(t, nil)
	// Two calls of different principals, servers, tools, rules and
	// revisions, each a requested and a decision event, then 600 admin
	// events for paging.
	for i, c := range []struct{ p, s, srv, tool, rev, rule, outcome string }{
		{"alice", "s1", "fs", "read_file", "r1", "fs-read", "permit"},
		{"bob", "s2", "git", "log", "r2", "git-log", "deny"},
	} {
		corr := fmt.Sprintf("c%d", i)
		f.record(
			audit.Event{Class: "call", Phase: audit.PhaseRequested, CorrelationID: corr, SessionID: c.s, PrincipalID: c.p, ServerRevision: "rev-" + c.srv,
				ToolRevision: "rev-" + c.srv + "/" + c.tool, Detail: map[string]any{"server": c.srv, "tool": c.tool}},
			audit.Event{Class: "decision", Phase: audit.PhaseAuthorized, CorrelationID: corr, SessionID: c.s, PrincipalID: c.p, PolicyRevision: c.rev,
				ServerRevision: "rev-" + c.srv, ToolRevision: "rev-" + c.srv + "/" + c.tool, Outcome: c.outcome,
				Detail: map[string]any{"decisive_rules": []string{c.rev + "/dev/" + c.rule}}},
		)
	}
	for i := 0; i < 600; i++ {
		f.record(audit.Event{Class: "admin", Outcome: "noop", ReasonCode: "TEST"})
	}
	count := func(q string) int {
		t.Helper()
		code, out := f.do("GET", "/api/v1/audit/events?limit=500&"+q, nil)
		if code != 200 {
			t.Fatalf("%s: %d %v", q, code, out)
		}
		return len(out["events"].([]any))
	}
	for q, want := range map[string]int{
		"principal_id=alice":                    2,
		"session_id=s2":                         2,
		"server=fs":                             1, // the requested event names the alias
		"server=rev-git":                        2, // both events carry the server revision
		"tool=log":                              2,
		"tool=rev-fs/read_file":                 2,
		"rule=git-log":                          1,
		"rule=r1/dev/fs-read":                   1,
		"outcome=deny":                          1,
		"class=decision":                        2,
		"policy_revision=r2":                    1,
		"class=call&principal_id=bob":           1,
		"since=2000-01-01T00:00:00Z&class=call": 2,
		"until=2000-01-01T00:00:00Z":            0,
	} {
		if got := count(q); got != want {
			t.Errorf("%s: %d events, want %d", q, got, want)
		}
	}
	now := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	if got := count("class=decision&until=" + now); got != 2 {
		t.Errorf("until in the future: %d", got)
	}
	// Paging: at most 500 per page, cursor continues.
	code, out := f.do("GET", "/api/v1/audit/events?limit=500&class=admin", nil)
	if code != 200 || len(out["events"].([]any)) != 500 || out["next_before"] == "" {
		t.Fatalf("page 1: %d %d", code, len(out["events"].([]any)))
	}
	_, out = f.do("GET", "/api/v1/audit/events?limit=500&class=admin&before="+out["next_before"].(string), nil)
	if len(out["events"].([]any)) != 100 || out["next_before"] != "" {
		t.Fatalf("page 2: %d next %v", len(out["events"].([]any)), out["next_before"])
	}
	if code, _ := f.do("GET", "/api/v1/audit/events?limit=501", nil); code != 400 {
		t.Fatalf("limit above 500: %d", code)
	}
}
