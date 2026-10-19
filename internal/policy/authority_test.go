package policy

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestApprovalFloor: a tool whose manifest side-effect class is write,
// external or execute gets the approval obligation under a policy with no
// approval rule; read-class and unclassified tools do not (SR-1.18-1).
func TestApprovalFloor(t *testing.T) {
	reqtest.Verifies(t, "SR-1.18-1")
	s := mustCompile(t, `{"revision": "f1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}},
  "templates": {"t": {"rules": [{"id": "all", "server": "srv", "tools": ["w", "x", "e", "r", "u"]}]}}}`)
	d := NewDecider(s, 1000)
	for tool, class := range map[string]string{"w": SideWrite, "x": SideExternal, "e": SideExecute, "r": SideRead, "u": ""} {
		dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "srv", Tool: tool, SideEffect: class})
		want := class == SideWrite || class == SideExternal || class == SideExecute
		if dec.Outcome != Permit || dec.Obligations.Approval != want || dec.Obligations.ApprovalReason != "" {
			t.Fatalf("%s (%q): %+v", tool, class, dec)
		}
	}
	// The floor holds in a tainted session too, and a rule's own approval
	// is kept: a policy can add approval but not remove the floor.
	d.Taint("s2")
	dec := d.Decide(Request{PrincipalID: "p", SessionID: "s2", Profile: "dev", Template: "t", Server: "srv", Tool: "w", SideEffect: SideWrite})
	if !dec.Obligations.Approval {
		t.Fatalf("tainted session: %+v", dec)
	}
}

// TestProfileServerCeiling: publication rejects a template granting a
// server that no framework profile using it permits (SR-1-3), and a
// session of a profile with a server ceiling is denied other servers even
// when its template names them (SR-1-2).
func TestProfileServerCeiling(t *testing.T) {
	reqtest.Verifies(t, "SR-1-3")
	reqtest.Partial(t, "SR-1-2")
	base := `{"revision": "c1",
  "framework_profiles": {
    "narrow": {"templates": ["shared"], "default_template": "shared", "servers": ["fs"]},
    "wide": {"templates": ["shared", "web"], "default_template": "shared"}
  },
  "templates": {
    "shared": {"rules": [{"id": "fs", "server": "fs", "tools": ["read_file"]}, {"id": "git", "server": "git", "tools": ["log"]}]},
    "web": {"rules": [{"id": "fetch", "server": "fetch", "tools": ["fetch"]}]}
  }}`
	s := mustCompile(t, base) // "wide" is unrestricted, so "shared" may grant git
	d := NewDecider(s, 1000)
	if dec := d.Decide(Request{PrincipalID: "p", SessionID: "a", Profile: "narrow", Template: "shared", Server: "git", Tool: "log"}); dec.Outcome != Deny || dec.ReasonCode != ReasonNoPermit {
		t.Fatalf("narrow profile reached git: %+v", dec)
	}
	if dec := d.Decide(Request{PrincipalID: "p", SessionID: "a", Profile: "narrow", Template: "shared", Server: "fs", Tool: "read_file"}); dec.Outcome != Permit {
		t.Fatalf("narrow profile denied fs: %+v", dec)
	}
	if dec := d.Decide(Request{PrincipalID: "p", SessionID: "b", Profile: "wide", Template: "shared", Server: "git", Tool: "log"}); dec.Outcome != Permit {
		t.Fatalf("wide profile denied git: %+v", dec)
	}
	// When every profile using the template has a ceiling without git, the
	// template is rejected, naming the rule, the server and the profiles.
	strict := strings.Replace(base, `"wide": {"templates": ["shared", "web"], "default_template": "shared"}`,
		`"wide": {"templates": ["shared", "web"], "default_template": "shared", "servers": ["fs", "fetch"]}`, 1)
	_, err := Compile([]byte(strict))
	if err == nil || !strings.Contains(err.Error(), `rule "git" grants server "git"`) || !strings.Contains(err.Error(), "narrow, wide") {
		t.Fatalf("template beyond every profile accepted: %v", err)
	}
}

// TestOverlappingPermitsRejected: publication rejects two permits for the
// same tool and names both rules. Permit rules cannot carry routes or
// argument scopes that could be combined, so every overlap is rejected
// (SR-1.9-1; Compile is the validation every publication runs).
func TestOverlappingPermitsRejected(t *testing.T) {
	reqtest.Verifies(t, "SR-1.9-1")
	_, err := Compile([]byte(`{"revision": "o1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}},
  "templates": {"t": {"rules": [
    {"id": "first", "server": "fs", "tools": ["read_file", "list"]},
    {"id": "second", "server": "fs", "tools": ["write_file", "read_file"], "approval": true}
  ]}}}`))
	if err == nil || !strings.Contains(err.Error(), `"first"`) || !strings.Contains(err.Error(), `"second"`) || !strings.Contains(err.Error(), "fs/read_file") {
		t.Fatalf("overlap accepted or not named: %v", err)
	}
}

// TestRecheckDoesNotCount: a re-decision returns a new decision with the
// same outcome and obligations and consumes no rate window or quota
// (SR-5.12-1).
func TestRecheckDoesNotCount(t *testing.T) {
	reqtest.Partial(t, "SR-5.12-1")
	s := mustCompile(t, `{"revision": "q1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}},
  "templates": {"t": {"calls_per_session": 1, "rules": [{"id": "r", "server": "fs", "tools": ["read_file"], "filters": ["path-canonicalize"]}]}}}`)
	d := NewDecider(s, 1)
	req := Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "fs", Tool: "read_file"}
	first := d.Decide(req)
	again := d.Recheck(req)
	if first.Outcome != Permit || again.Outcome != Permit || again.ID == first.ID || strings.Join(again.Obligations.Filters, ",") != "path-canonicalize" {
		t.Fatalf("first %+v recheck %+v", first, again)
	}
	// The quota of one call was spent by the first decision only.
	if dec := d.Decide(req); dec.ReasonCode != ReasonQuota {
		t.Fatalf("second call: %+v", dec)
	}
}

func TestRuleRevisionID(t *testing.T) {
	if got := RuleRevisionID("r2", "dev", "read-fs"); got != "r2/dev/read-fs" {
		t.Fatal(got)
	}
}
