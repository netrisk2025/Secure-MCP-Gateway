package policy

import (
	"slices"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const recordDoc = `{
  "revision": "rec1",
  "framework_profiles": {"dev": {"templates": ["rw"], "default_template": "rw"}},
  "templates": {
    "rw": {"calls_per_minute": 30, "rules": [
      {"id": "rw-read", "server": "fs", "tools": ["read_file", "stat"], "filters": ["secret-args"]},
      {"id": "rw-write", "server": "fs", "tools": ["write_file"], "approval": true, "calls_per_minute": 5},
      {"id": "no-stat", "effect": "deny", "server": "fs", "tools": ["stat"]},
      {"id": "git-log", "server": "git", "tools": ["log"]}
    ]}
  }
}`

// TestDecisionRecordFields is FR-3.11: permit, deny and default-deny
// fixtures each return a decision ID, outcome, reason code, considered,
// applicable and decisive rule IDs, effective obligations, selected route,
// policy revision ID, baseline snapshot ID and evaluation duration, with
// the values each fixture calls for.
func TestDecisionRecordFields(t *testing.T) {
	reqtest.Verifies(t, "FR-3.11")
	d := NewDecider(mustCompile(t, recordDoc), 60)
	snapshot := "snap-7"
	d.SetBaseline(func() string { return snapshot })
	slow := 0
	d.evalHook = func() { slow++; time.Sleep(time.Millisecond) } // permits: a duration of at least 1 ms
	all := []string{"rw-read", "rw-write", "no-stat", "git-log"}
	base := Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "rw"}
	for _, c := range []struct {
		name, server, tool, outcome, reason, route string
		applicable, decisive                       []string
		approval                                   bool
		rate                                       int
		filters                                    []string
	}{
		{"permit", "fs", "write_file", Permit, ReasonPermit, "fs", []string{"rw-write"}, []string{"rw-write"}, true, 5, nil},
		{"permit with filter", "fs", "read_file", Permit, ReasonPermit, "fs", []string{"rw-read"}, []string{"rw-read"}, false, 30, []string{"secret-args"}},
		{"deny rule", "fs", "stat", Deny, ReasonDenyRule, "", []string{"rw-read", "no-stat"}, []string{"no-stat"}, false, 0, nil},
		{"default deny", "fs", "delete", Deny, ReasonNoPermit, "", nil, nil, false, 0, nil},
	} {
		req := base
		req.Server, req.Tool = c.server, c.tool
		dec := d.Decide(req)
		if dec.ID == "" || dec.Outcome != c.outcome || dec.ReasonCode != c.reason || dec.Route != c.route || dec.PolicyRevision != "rec1" ||
			dec.BaselineSnapshot != snapshot || dec.Duration <= 0 || (c.outcome == Permit && dec.Duration < time.Millisecond) {
			t.Errorf("%s: %+v", c.name, dec)
		}
		if !slices.Equal(dec.ConsideredRules, all) || !slices.Equal(dec.ApplicableRules, c.applicable) || !slices.Equal(dec.DecisiveRules, c.decisive) {
			t.Errorf("%s rules: considered %v applicable %v decisive %v", c.name, dec.ConsideredRules, dec.ApplicableRules, dec.DecisiveRules)
		}
		ob := dec.Obligations
		if ob.Approval != c.approval || ob.CallsPerMinute != c.rate || !slices.Equal(ob.Filters, c.filters) {
			t.Errorf("%s obligations: %+v", c.name, ob)
		}
	}
	if slow == 0 {
		t.Fatal("the evaluation hook did not run")
	}
	// Each decision has its own ID; without a loaded baseline the ID is empty.
	snapshot = ""
	a, b := d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "rw", Server: "git", Tool: "log"}),
		d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "rw", Server: "git", Tool: "log"})
	if a.ID == b.ID || a.BaselineSnapshot != "" || a.Outcome != Permit || a.Route != "git" {
		t.Fatalf("%+v %+v", a, b)
	}
}
