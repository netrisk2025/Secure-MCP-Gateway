package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const egressLimitsDoc = `{"revision": "e1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}},
  "templates": {"t": {"rules": [
    {"id": "r", "server": "web", "tools": ["fetch"], "egress_limits": {"request_bytes": 1000, "response_bytes": 2000, "timeout_ms": 300}},
    {"id": "plain", "server": "web", "tools": ["echo"]}]}}}`

// TestEgressLimitObligation: a permit rule's egress_limits become the
// decision's egress-limit obligation (FR-5.38, part of the egress grants
// obligation of FR-3.12); a rule without them carries none. The schema
// refuses empty, zero and unknown members, a deny rule cannot carry them,
// and the revision diff reports a loosened bound as widening.
func TestEgressLimitObligation(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	d := NewDecider(mustCompile(t, egressLimitsDoc), 60)
	dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "web", Tool: "fetch"})
	l := dec.Obligations.EgressLimits
	if dec.Outcome != Permit || l == nil || l.RequestBytes != 1000 || l.ResponseBytes != 2000 || l.Timeout() != 300*time.Millisecond {
		t.Fatalf("decision %+v obligations %+v", dec, l)
	}
	if dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "web", Tool: "echo"}); dec.Obligations.EgressLimits != nil {
		t.Fatalf("a rule without egress_limits carries %+v", dec.Obligations.EgressLimits)
	}
	if (*EgressLimits)(nil).Timeout() != 0 {
		t.Fatal("nil limits have a timeout")
	}

	bad := map[string]string{
		"empty":     `"egress_limits": {}`,
		"zero":      `"egress_limits": {"request_bytes": 0}`,
		"unknown":   `"egress_limits": {"rate": 5}`,
		"too long":  `"egress_limits": {"timeout_ms": 3600001}`,
		"not a map": `"egress_limits": 5`,
	}
	for name, frag := range bad {
		src := strings.Replace(egressLimitsDoc, `"egress_limits": {"request_bytes": 1000, "response_bytes": 2000, "timeout_ms": 300}`, frag, 1)
		if _, err := Compile([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	deny := strings.Replace(egressLimitsDoc, `{"id": "plain", "server": "web", "tools": ["echo"]}`,
		`{"id": "plain", "server": "web", "tools": ["echo"]}, {"id": "no", "effect": "deny", "server": "web", "tools": ["x"], "egress_limits": {"request_bytes": 5}}`, 1)
	if _, err := Compile([]byte(deny)); err == nil || !strings.Contains(err.Error(), "deny rule") {
		t.Fatalf("deny rule with egress_limits: %v", err)
	}

	a := mustCompile(t, egressLimitsDoc)
	tighter := mustCompile(t, strings.Replace(strings.Replace(egressLimitsDoc, `"e1"`, `"e2"`, 1), `"timeout_ms": 300`, `"timeout_ms": 200`, 1))
	if rep := Diff(a, tighter); rep.Same || rep.Widening {
		t.Fatalf("tighter limits: %+v", rep)
	}
	looser := mustCompile(t, strings.Replace(strings.Replace(egressLimitsDoc, `"e1"`, `"e2"`, 1), `"response_bytes": 2000, `, ``, 1))
	if rep := Diff(a, looser); !rep.Widening || len(rep.Changes) != 1 || !strings.Contains(rep.Changes[0].Before, "egress_limits=1000/2000/300ms") {
		t.Fatalf("removed bound: %+v", rep)
	}
	if !classifyChanged(a, looser) {
		t.Fatal("simulation does not report the changed obligation")
	}
}

// classifyChanged reports whether simulating the fetch call under a and b
// classifies the outcome as obligations_changed.
func classifyChanged(a, b *Snapshot) bool {
	req := Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "web", Tool: "fetch"}
	return classify(outcomeOf(NewDecider(a, 60).Decide(req)), outcomeOf(NewDecider(b, 60).Decide(req))) == SimObligations
}
