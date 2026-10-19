package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const taintDoc = `{
  "revision": "t1",
  "framework_profiles": {"dev": {"templates": ["work", "strict"], "default_template": "work"}},
  "templates": {
    "work": {"rules": [
      {"id": "web", "server": "web", "tools": ["fetch"], "side_effect": "read", "source_trust": "untrusted"},
      {"id": "fs-read", "server": "fs", "tools": ["read_file"], "side_effect": "read", "source_trust": "trusted"},
      {"id": "fs-write", "server": "fs", "tools": ["write_file"], "side_effect": "write"},
      {"id": "mail", "server": "mail", "tools": ["send"], "side_effect": "external"},
      {"id": "misc", "server": "misc", "tools": ["thing"]}
    ]},
    "strict": {"taint_action": "deny", "rules": [
      {"id": "s-web", "server": "web", "tools": ["fetch"], "side_effect": "read", "source_trust": "untrusted"},
      {"id": "s-write", "server": "fs", "tools": ["write_file"], "side_effect": "write"},
      {"id": "s-mail", "server": "mail", "tools": ["send"], "side_effect": "external"}
    ]}
  }
}`

func mustCompile(t *testing.T, src string) *Snapshot {
	t.Helper()
	s, err := Compile([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDenyPrecedence(t *testing.T) {
	reqtest.Verifies(t, "SR-1.4-1")
	src := strings.Replace(doc, `{"id": "ro-fs", "server": "fs", "tools": ["read_file", "list_directory"]}`,
		`{"id": "ro-fs", "server": "fs", "tools": ["read_file", "list_directory"]}, {"id": "no-list", "effect": "deny", "server": "fs", "tools": ["list_directory"]}`, 1)
	src = strings.Replace(src, `{"id": "rw-fs", "server": "fs", "tools": ["read_file", "write_file"], "approval": true}`,
		`{"id": "rw-fs", "server": "fs", "tools": ["read_file", "write_file"], "approval": true}, {"id": "no-fs", "effect": "deny", "server": "fs", "tools": ["*"]}`, 1)
	s := mustCompile(t, src)
	d := NewDecider(s, 60)
	dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "list_directory"})
	if dec.Outcome != Deny || dec.ReasonCode != ReasonDenyRule || len(dec.DecisiveRules) != 1 || dec.DecisiveRules[0] != "no-list" ||
		len(dec.ApplicableRules) != 2 {
		t.Fatalf("permit and deny both applicable, deny must win: %+v", dec)
	}
	if dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file"}); dec.Outcome != Permit {
		t.Fatalf("unrelated permit: %+v", dec)
	}
	// A wildcard deny covers every tool of the server, including permitted ones.
	for _, tool := range []string{"read_file", "write_file"} {
		if dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "rw", Server: "fs", Tool: tool}); dec.ReasonCode != ReasonDenyRule {
			t.Fatalf("%s: %+v", tool, dec)
		}
	}
	// Denied tools are not presented.
	for _, g := range s.Grants("ro") {
		if g.Tool == "list_directory" {
			t.Fatal("denied tool in the catalog")
		}
	}
	if len(s.Grants("rw")) != 0 {
		t.Fatalf("wildcard deny left grants: %+v", s.Grants("rw"))
	}
	// Publication rejects obligations on deny rules and wildcards on permits.
	for name, bad := range map[string]string{
		"deny with approval": strings.Replace(src, `"effect": "deny", "server": "fs", "tools": ["list_directory"]`, `"effect": "deny", "approval": true, "server": "fs", "tools": ["list_directory"]`, 1),
		"permit wildcard":    strings.Replace(src, `"tools": ["read_file", "list_directory"]`, `"tools": ["*"]`, 1),
		"unknown effect":     strings.Replace(src, `"effect": "deny"`, `"effect": "maybe"`, 1),
	} {
		if _, err := Compile([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSessionTaintObligation(t *testing.T) {
	// The Gateway half (marking on release, -31002/-31001 to the harness)
	// is verified end to end in internal/e2e.
	reqtest.Partial(t, "SR-5.13-2")
	s := mustCompile(t, taintDoc)
	d := NewDecider(s, 600)
	req := func(sess, tmpl, server, tool string) Request {
		return Request{PrincipalID: "p", SessionID: sess, Profile: "dev", Template: tmpl, Server: server, Tool: tool}
	}
	// Untainted: no taint obligation on any tool.
	for _, r := range []Request{req("a", "work", "fs", "write_file"), req("a", "work", "mail", "send")} {
		if dec := d.Decide(r); dec.Outcome != Permit || dec.Obligations.Approval || dec.Tainted {
			t.Fatalf("untainted %s: %+v", r.Tool, dec)
		}
	}
	// Reading an untrusted-source tool marks its result as tainting.
	dec := d.Decide(req("a", "work", "web", "fetch"))
	if dec.Outcome != Permit || !dec.TaintsSession || dec.SourceTrust != TrustUntrusted {
		t.Fatalf("untrusted read: %+v", dec)
	}
	if dec := d.Decide(req("a", "work", "fs", "read_file")); dec.TaintsSession {
		t.Fatalf("trusted read taints: %+v", dec)
	}
	d.Taint("a")
	for _, c := range []struct {
		server, tool string
		approval     bool
	}{{"fs", "write_file", true}, {"mail", "send", true}, {"misc", "thing", true}, {"fs", "read_file", false}, {"web", "fetch", false}} {
		dec := d.Decide(req("a", "work", c.server, c.tool))
		if dec.Outcome != Permit || dec.Obligations.Approval != c.approval || !dec.Tainted {
			t.Fatalf("tainted %s/%s: %+v", c.server, c.tool, dec)
		}
		if c.approval && dec.Obligations.ApprovalReason != ReasonTaintApproval {
			t.Fatalf("reason: %+v", dec.Obligations)
		}
	}
	// A fresh session is untainted.
	if dec := d.Decide(req("b", "work", "fs", "write_file")); dec.Obligations.Approval || dec.Tainted {
		t.Fatalf("fresh session: %+v", dec)
	}
	// taint_action deny refuses write and external tools.
	d.Taint("c")
	for _, c := range [][2]string{{"fs", "write_file"}, {"mail", "send"}} {
		if dec := d.Decide(req("c", "strict", c[0], c[1])); dec.Outcome != Deny || dec.ReasonCode != ReasonTaintDenied {
			t.Fatalf("strict %s: %+v", c[1], dec)
		}
	}
	if dec := d.Decide(req("c", "strict", "web", "fetch")); dec.Outcome != Permit {
		t.Fatalf("strict read: %+v", dec)
	}
	// Ending the session drops the mark.
	d.EndSession("a")
	if d.Tainted("a") {
		t.Fatal("taint survived the session")
	}
}

func TestTaintClassesRestrictOnly(t *testing.T) {
	reqtest.Partial(t, "SR-5.13-2")
	s := mustCompile(t, taintDoc)
	d := NewDecider(s, 600)
	// The manifest says write; the rule's "read" cannot relax it.
	r := Request{PrincipalID: "p", SessionID: "x", Template: "work", Server: "fs", Tool: "read_file", SideEffect: SideWrite}
	if dec := d.Decide(r); dec.SideEffect != SideWrite {
		t.Fatalf("side effect relaxed: %+v", dec)
	}
	// The manifest says untrusted; the rule's "trusted" cannot relax it.
	r.SourceTrust = TrustUntrusted
	if dec := d.Decide(r); dec.SourceTrust != TrustUntrusted || !dec.TaintsSession {
		t.Fatalf("source trust relaxed: %+v", dec)
	}
	for _, c := range []struct{ a, b, want string }{
		{"", "", ""}, {SideRead, "", SideRead}, {"", SideExternal, SideExternal}, {SideWrite, SideRead, SideWrite}, {SideExternal, SideExecute, SideExecute},
	} {
		if got := EffectiveSideEffect(c.a, c.b); got != c.want {
			t.Errorf("EffectiveSideEffect(%q,%q) = %q", c.a, c.b, got)
		}
	}
	if EffectiveSourceTrust(TrustTrusted, "") != TrustTrusted || EffectiveSourceTrust("", "") != "" || EffectiveSourceTrust(TrustTrusted, TrustUntrusted) != TrustUntrusted {
		t.Fatal("source trust combination")
	}
	if TaintGated(SideRead) || !TaintGated("") || !TaintGated(SideExecute) {
		t.Fatal("gating")
	}
}

func TestBurstWindow(t *testing.T) {
	// CP-11 "60 calls/min, burst 10".
	reqtest.Partial(t, "FR-3.13")
	s := mustCompile(t, doc)
	d := NewDecider(s, 60)
	d.SetBurst(10)
	now := time.Now()
	d.SetNow(func() time.Time { return now })
	req := Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file"}
	for i := 0; i < 10; i++ {
		if dec := d.Decide(req); dec.Outcome != Permit {
			t.Fatalf("call %d: %+v", i, dec)
		}
	}
	dec := d.Decide(req)
	if dec.ReasonCode != ReasonRateLimited || dec.Obligations.Burst != 10 || dec.Obligations.CallsPerMinute != 60 {
		t.Fatalf("burst not applied: %+v", dec)
	}
	// The burst window is 10/60 of a minute.
	now = now.Add(10*time.Second + time.Millisecond)
	if dec := d.Decide(req); dec.Outcome != Permit {
		t.Fatalf("after the burst window: %+v", dec)
	}
	// The burst never exceeds a smaller rate bound.
	d2 := NewDecider(s, 60)
	d2.SetBurst(10)
	d2.SetNow(func() time.Time { return now })
	rw := Request{PrincipalID: "q", SessionID: "s2", Template: "rw", Server: "fs", Tool: "read_file"}
	d2.Decide(rw)
	d2.Decide(rw)
	if dec := d2.Decide(rw); dec.ReasonCode != ReasonRateLimited || dec.Obligations.Burst != 2 {
		t.Fatalf("burst above the template rate: %+v", dec)
	}
}

func TestSessionQuota(t *testing.T) {
	src := strings.Replace(doc, `"ro": {"rules"`, `"ro": {"calls_per_session": 3, "rules"`, 1)
	src = strings.Replace(src, `"approval": true}`, `"approval": true, "calls_per_session": 1}`, 1)
	s := mustCompile(t, src)
	d := NewDecider(s, 60)
	a := Request{PrincipalID: "p", SessionID: "s1", Template: "ro", Server: "fs", Tool: "read_file"}
	for i := 0; i < 3; i++ {
		if dec := d.Decide(a); dec.Outcome != Permit || dec.Obligations.CallsPerSession != 3 {
			t.Fatalf("call %d: %+v", i, dec)
		}
	}
	if dec := d.Decide(a); dec.Outcome != Deny || dec.ReasonCode != ReasonQuota || dec.Obligations.CallsPerSession != 3 {
		t.Fatalf("quota: %+v", dec)
	}
	b := a
	b.SessionID = "s2"
	if dec := d.Decide(b); dec.Outcome != Permit {
		t.Fatalf("quota is per session: %+v", dec)
	}
	// Rule quota inside a template with a rate bound of 2.
	rw := Request{PrincipalID: "q", SessionID: "s3", Template: "rw", Server: "fs", Tool: "write_file"}
	if dec := d.Decide(rw); dec.Outcome != Permit || dec.Obligations.CallsPerSession != 1 {
		t.Fatalf("%+v", dec)
	}
	if dec := d.Decide(rw); dec.ReasonCode != ReasonQuota {
		t.Fatalf("rule quota: %+v", dec)
	}
	// A refusal for another reason consumes no quota.
	d3 := NewDecider(s, 1)
	now := time.Now()
	d3.SetNow(func() time.Time { return now })
	rate := Request{PrincipalID: "r", SessionID: "s4", Template: "ro", Server: "fs", Tool: "read_file"}
	d3.Decide(rate)
	if dec := d3.Decide(rate); dec.ReasonCode != ReasonRateLimited {
		t.Fatalf("%+v", dec)
	}
	for i := 0; i < 2; i++ {
		now = now.Add(61 * time.Second)
		if dec := d3.Decide(rate); dec.Outcome != Permit {
			t.Fatalf("rate refusal consumed quota (call %d): %+v", i, dec)
		}
	}
	now = now.Add(61 * time.Second)
	if dec := d3.Decide(rate); dec.ReasonCode != ReasonQuota {
		t.Fatalf("%+v", dec)
	}
	d.EndSession("s1")
	if dec := d.Decide(a); dec.Outcome != Permit {
		t.Fatalf("quota state not dropped with the session: %+v", dec)
	}
}

func TestEvaluationBounds(t *testing.T) {
	reqtest.Verifies(t, "SR-1.20-1")
	var rules []string
	for i := 0; i < 300; i++ {
		rules = append(rules, fmt.Sprintf(`{"id": "r%d", "server": "fs", "tools": ["t%d"]}`, i, i))
	}
	src := fmt.Sprintf(`{"revision": "big", "framework_profiles": {"p": {"templates": ["many"], "default_template": "many"}},
	  "templates": {"many": {"rules": [%s]}}}`, strings.Join(rules, ","))
	s := mustCompile(t, src)
	d := NewDecider(s, 60)
	if dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "many", Server: "fs", Tool: "t1"}); dec.Outcome != Deny || dec.ReasonCode != ReasonEvalBound {
		t.Fatalf("300 candidate rules: %+v", dec)
	}
	d.SetBounds(512, DefaultDeadline)
	if dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "many", Server: "fs", Tool: "t1"}); dec.Outcome != Permit {
		t.Fatalf("within a raised bound: %+v", dec)
	}
	// Deadline: a slow evaluation is denied and consumes no window.
	d2 := NewDecider(mustCompile(t, doc), 60)
	d2.SetBounds(DefaultCandidateBound, 5*time.Millisecond)
	d2.evalHook = func() { time.Sleep(20 * time.Millisecond) }
	if dec := d2.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file"}); dec.ReasonCode != ReasonEvalBound {
		t.Fatalf("slow evaluation: %+v", dec)
	}
	if d2.Counters() != 0 {
		t.Fatal("a bounded evaluation consumed rate windows")
	}
}

func TestProfileMustStillPermitTemplate(t *testing.T) {
	reqtest.Partial(t, "SR-1-2")
	s := mustCompile(t, doc)
	d := NewDecider(s, 60)
	ok := Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "ro", Server: "fs", Tool: "read_file"}
	if dec := d.Decide(ok); dec.Outcome != Permit {
		t.Fatalf("%+v", dec)
	}
	narrowed := strings.Replace(strings.Replace(doc, `"templates": ["ro", "rw"]`, `"templates": ["rw"]`, 1), `"default_template": "ro"`, `"default_template": "rw"`, 1)
	if _, err := d.Replace(mustCompile(t, strings.Replace(narrowed, `"r1"`, `"r2"`, 1))); err != nil {
		t.Fatal(err)
	}
	if dec := d.Decide(ok); dec.Outcome != Deny || dec.ReasonCode != ReasonNoTemplate {
		t.Fatalf("profile no longer lists the template: %+v", dec)
	}
	unknown := ok
	unknown.Profile = "gone"
	if dec := d.Decide(unknown); dec.ReasonCode != ReasonNoTemplate {
		t.Fatalf("unknown profile: %+v", dec)
	}
}

func TestCanonicalDigest(t *testing.T) {
	reqtest.Partial(t, "FR-3.8")
	a := mustCompile(t, doc)
	// Key order and whitespace do not change the canonical form.
	reordered := `{"templates": {"rw": {"rules": [{"approval": true, "tools": ["read_file", "write_file"], "server": "fs", "id": "rw-fs"}], "calls_per_minute": 2},
	  "ro": {"rules": [{"server": "fs", "id": "ro-fs", "tools": ["read_file", "list_directory"]}]}},
	  "framework_profiles": {"dev": {"default_template": "ro", "templates": ["ro", "rw"]}}, "revision": "r1"}`
	b := mustCompile(t, reordered)
	if a.Digest != b.Digest || string(a.Raw) != string(b.Raw) {
		t.Fatalf("canonical forms differ:\n%s\n%s", a.Raw, b.Raw)
	}
	again := mustCompile(t, string(a.Raw))
	if again.Digest != a.Digest {
		t.Fatal("canonical form is not a fixed point")
	}
	if a.Document().Templates["rw"].CallsPerMinute != 2 {
		t.Fatal("Document() lost content")
	}
	if _, err := Canonical([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}
