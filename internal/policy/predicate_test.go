package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func predicateDoc(when string) string {
	return fmt.Sprintf(`{"revision": "p1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}},
  "templates": {"t": {"rules": [{"id": "r", "server": "fs", "tools": ["op"], "when": %s}]}}}`, when)
}

func decideArgs(t *testing.T, d *Decider, args string) Decision {
	t.Helper()
	return d.Decide(Request{PrincipalID: "p", SessionID: fmt.Sprint(time.Now().UnixNano()), Profile: "dev", Template: "t", Server: "fs", Tool: "op",
		Arguments: json.RawMessage(args)})
}

// TestPredicateOperators: each operator of the fixed set permits the
// arguments it describes and denies others; an unknown operator is refused
// when the document is validated (SR-1.7-1).
func TestPredicateOperators(t *testing.T) {
	reqtest.Verifies(t, "SR-1.7-1")
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name, when string
		permit     []string
		deny       []string
	}{
		{"eq", `[{"arg": "mode", "op": "eq", "value": "read"}]`, []string{`{"mode":"read"}`}, []string{`{"mode":"write"}`, `{"mode":1}`}},
		{"in", `[{"arg": "n", "op": "in", "value": [1, 2, 3]}]`, []string{`{"n":2}`}, []string{`{"n":4}`, `{"n":"2"}`}},
		{"range", `[{"arg": "limit", "op": "range", "min": 1, "max": 100}]`, []string{`{"limit":1}`, `{"limit":100}`, `{"limit":50.5}`},
			[]string{`{"limit":0}`, `{"limit":101}`, `{"limit":"5"}`}},
		{"path_within", `[{"arg": "path", "op": "path_within", "value": ["/data", "/srv/app/"]}]`,
			[]string{`{"path":"/data"}`, `{"path":"/data/a/b.txt"}`, `{"path":"/srv/app/x/../y"}`},
			[]string{`{"path":"/data/../etc/passwd"}`, `{"path":"/database"}`, `{"path":"data/x"}`, `{"path":"/srv/app\\..\\x"}`}},
		{"url_in", `[{"arg": "url", "op": "url_in", "value": ["https://api.example.com", "http://localhost:8080"]}]`,
			[]string{`{"url":"https://api.example.com/v1/x"}`, `{"url":"https://API.example.com:443/"}`, `{"url":"http://localhost:8080/a"}`},
			[]string{`{"url":"http://api.example.com/"}`, `{"url":"https://api.example.com:8443/"}`, `{"url":"https://evil.example.com/"}`, `{"url":"https://u:p@api.example.com/"}`}},
		{"data_class_in", `[{"arg": "classification", "op": "data_class_in", "value": ["public", "internal"]}]`,
			[]string{`{"classification":"internal"}`}, []string{`{"classification":"secret"}`}},
		{"nested arg", `[{"arg": "opts.depth", "op": "range", "max": 3}]`, []string{`{"opts":{"depth":2}}`}, []string{`{"opts":{"depth":4}}`, `{"opts":5}`}},
	} {
		s, err := Compile([]byte(predicateDoc(c.when)))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		d := NewDecider(s, 100000)
		d.SetNow(func() time.Time { return now })
		for _, a := range c.permit {
			if dec := decideArgs(t, d, a); dec.Outcome != Permit {
				t.Errorf("%s: %s denied: %+v", c.name, a, dec)
			}
		}
		for _, a := range c.deny {
			if dec := decideArgs(t, d, a); dec.Outcome != Deny || dec.ReasonCode != ReasonNoPermit || dec.FailedPredicate == "" {
				t.Errorf("%s: %s permitted: %+v", c.name, a, dec)
			}
		}
	}
	// expiry: the decision time must fall in the interval.
	s := mustCompile(t, predicateDoc(`[{"op": "expiry", "not_before": "2026-10-01T00:00:00Z", "not_after": "2026-11-01T00:00:00Z"}]`))
	d := NewDecider(s, 1000)
	for at, want := range map[time.Time]string{
		time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC): Permit,
		time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC):  Deny,
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC):  Deny,
	} {
		d.SetNow(func() time.Time { return at })
		if dec := decideArgs(t, d, `{}`); dec.Outcome != want {
			t.Errorf("expiry at %s: %s", at, dec.Outcome)
		}
	}
	// approval: an approval state the call needs, as an obligation.
	s = mustCompile(t, predicateDoc(`[{"op": "approval", "value": "required"}]`))
	if dec := decideArgs(t, NewDecider(s, 1000), `{}`); dec.Outcome != Permit || !dec.Obligations.Approval {
		t.Fatalf("approval predicate: %+v", dec)
	}
	// Only the fixed operator set validates.
	for _, bad := range []string{
		`[{"arg": "x", "op": "regex", "value": ".*"}]`,
		`[{"arg": "x", "op": "eq"}]`,
		`[{"op": "eq", "value": 1}]`,
		`[{"arg": "x", "op": "range"}]`,
		`[{"arg": "x", "op": "path_within", "value": ["relative"]}]`,
		`[{"arg": "x", "op": "url_in", "value": ["https://h/path"]}]`,
		`[{"op": "approval", "value": "optional"}]`,
	} {
		if _, err := Compile([]byte(predicateDoc(bad))); err == nil {
			t.Errorf("invalid predicate accepted: %s", bad)
		}
	}
	if !slices.Equal(Operators, []string{"eq", "in", "range", "path_within", "url_in", "data_class_in", "expiry", "approval"}) {
		t.Fatalf("operators %v", Operators)
	}
}

// TestMissingAttributeDenies: a permit whose predicate names an argument
// that is missing, of the wrong type or whose arguments are not an object
// does not match, and the call is denied (SR-1.7-2).
func TestMissingAttributeDenies(t *testing.T) {
	reqtest.Verifies(t, "SR-1.7-2")
	d := NewDecider(mustCompile(t, predicateDoc(`[{"arg": "path", "op": "path_within", "value": ["/data"]}]`)), 1000)
	for _, args := range []string{`{}`, `{"other":"/data/x"}`, `{"path":7}`, `{"path":null}`, `[1,2]`, `not json`, ``} {
		dec := decideArgs(t, d, args)
		if dec.Outcome != Deny || dec.ReasonCode != ReasonNoPermit || !strings.Contains(dec.FailedPredicate, "path") || slices.Contains(dec.ApplicableRules, "r") {
			t.Fatalf("%q: %+v", args, dec)
		}
	}
	if dec := decideArgs(t, d, `{"path":"/data/x"}`); dec.Outcome != Permit {
		t.Fatalf("present attribute: %+v", dec)
	}
}

// TestPrerequisiteChecks: a call is denied with the matching reason when
// its principal is disabled, its credential is expired or revoked, its
// session is not active, its server revision is not enabled, or its tool
// has no explicit grant (SR-1.5-1).
func TestPrerequisiteChecks(t *testing.T) {
	reqtest.Verifies(t, "SR-1.5-1")
	d := NewDecider(mustCompile(t, doc), 1000)
	base := Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file"}
	if dec := d.Decide(base); dec.Outcome != Permit {
		t.Fatalf("baseline: %+v", dec)
	}
	for want, mod := range map[string]func(*Request){
		ReasonPrincipalDisabled:  func(r *Request) { r.PrincipalDisabled = true },
		ReasonCredentialInvalid:  func(r *Request) { r.CredentialInvalid = true },
		ReasonSessionState:       func(r *Request) { r.SessionInactive = true },
		ReasonRevisionNotEnabled: func(r *Request) { r.RevisionNotEnabled = true },
		ReasonNoPermit:           func(r *Request) { r.Tool = "write_file" },
	} {
		r := base
		mod(&r)
		if dec := d.Decide(r); dec.Outcome != Deny || dec.ReasonCode != want {
			t.Errorf("%s: %+v", want, dec)
		}
	}
}

// TestSingleRoute: exactly one eligible route permits; none or two deny
// (SR-1.11-1).
func TestSingleRoute(t *testing.T) {
	reqtest.Verifies(t, "SR-1.11-1")
	d := NewDecider(mustCompile(t, doc), 1000)
	r := Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file", RoutesKnown: true}
	for routes, want := range map[string]string{"": ReasonNoRoute, "fs": ReasonPermit, "fs,fs-b": ReasonAmbiguousRoute} {
		r.Routes = nil
		if routes != "" {
			r.Routes = strings.Split(routes, ",")
		}
		dec := d.Decide(r)
		if dec.ReasonCode != want || (want == ReasonPermit) != (dec.Outcome == Permit) {
			t.Errorf("routes %q: %+v", routes, dec)
		}
		if want == ReasonPermit && dec.Route != "fs" {
			t.Errorf("route %q", dec.Route)
		}
	}
}

// TestHighRiskFlags: granting a server of a high-risk class needs the
// class flagged on the template and on every framework profile using it;
// publication refuses the grant otherwise and a call without the flags is
// denied (SR-3.13-1).
func TestHighRiskFlags(t *testing.T) {
	reqtest.Verifies(t, "SR-3.13-1")
	mk := func(profileFlag, templateFlag string) string {
		return fmt.Sprintf(`{"revision": "h1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"%s}},
  "templates": {"t": {%s"rules": [{"id": "sh", "server": "shell", "tools": ["run"]}, {"id": "fs", "server": "fs", "tools": ["read"]}]}}}`, profileFlag, templateFlag)
	}
	classes := map[string][]string{"shell": {"code-execution"}, "fs": {"standard"}}
	both := mustCompile(t, mk(`, "high_risk": ["code-execution"]`, `"high_risk": ["code-execution"], `))
	if err := both.CheckHighRisk(classes); err != nil {
		t.Fatalf("flagged grant refused: %v", err)
	}
	for name, src := range map[string]string{
		"no flags":         mk("", ""),
		"template only":    mk("", `"high_risk": ["code-execution"], `),
		"profile only":     mk(`, "high_risk": ["code-execution"]`, ""),
		"other class flag": mk(`, "high_risk": ["general-sql"]`, `"high_risk": ["general-sql"], `),
	} {
		s := mustCompile(t, src)
		if err := s.CheckHighRisk(classes); err == nil || !strings.Contains(err.Error(), "code-execution") {
			t.Errorf("%s: publication accepted: %v", name, err)
		}
		dec := NewDecider(s, 1000).Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "shell", Tool: "run", RiskClasses: classes["shell"]})
		if dec.Outcome != Deny || dec.ReasonCode != ReasonHighRisk {
			t.Errorf("%s: call %+v", name, dec)
		}
		// A server of no high-risk class is unaffected.
		if dec := NewDecider(s, 1000).Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "fs", Tool: "read", RiskClasses: classes["fs"]}); dec.Outcome != Permit {
			t.Errorf("%s: standard server %+v", name, dec)
		}
	}
	if dec := NewDecider(both, 1000).Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "shell", Tool: "run", RiskClasses: classes["shell"]}); dec.Outcome != Permit {
		t.Fatalf("flagged call: %+v", dec)
	}
}

// TestObligationTypes: a permit expresses every obligation type: request
// and response filters, approval, rate limit, the session quota, and from
// outside the document the audit profile, observation policy, size limit,
// timeout, egress grants, secret grants, runtime profile and anomaly
// response (FR-3.12).
func TestObligationTypes(t *testing.T) {
	reqtest.Verifies(t, "FR-3.12")
	s := mustCompile(t, `{"revision": "o1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}},
  "templates": {"t": {"rules": [{"id": "r", "server": "web", "tools": ["fetch"], "approval": true, "calls_per_minute": 30, "calls_per_session": 9,
    "filters": ["url-canonicalize", "prompt-injection"]}]}}}`)
	d := NewDecider(s, 60)
	d.SetContext(func(server string) ObligationContext {
		return ObligationContext{AuditProfile: "audit_profile@3", ObservationPolicy: "obs-default", AnomalyResponse: "anomaly_response@2",
			SizeLimit: 1 << 20, Timeout: 30 * time.Second, EgressGrants: []string{server + ".example.com:443"}, SecretGrants: []string{"token"},
			RuntimeProfile: "enforced/podman"}
	})
	dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "web", Tool: "fetch"})
	ob := dec.Obligations
	if dec.Outcome != Permit || strings.Join(ob.Filters, ",") != "url-canonicalize,prompt-injection" || !ob.Approval || ob.CallsPerMinute != 30 ||
		ob.CallsPerSession != 9 || ob.AuditProfile != "audit_profile@3" || ob.ObservationPolicy != "obs-default" || ob.AnomalyResponse != "anomaly_response@2" ||
		ob.SizeLimit != 1<<20 || ob.Timeout != 30*time.Second || strings.Join(ob.EgressGrants, ",") != "web.example.com:443" ||
		strings.Join(ob.SecretGrants, ",") != "token" || ob.RuntimeProfile != "enforced/podman" {
		t.Fatalf("obligations %+v", ob)
	}
}

// TestObligationPrecedence is SR-1.10-1's test: the obligations that apply
// to a permitted call are combined restrict-only: the smallest rate bound
// of rule, template, profile and the CP-11 default, a burst never above
// that bound, the smallest session quota of rule and template, the rule's
// filters (the mandatory filters run on every call besides them, FR-4.4),
// and approval when any layer requires it (rule, approval predicate,
// approval floor, session taint). Overlapping permits are refused at
// publication (SR-1.9-1), so the rules combined are the permit and the
// layers above it; size, time and resource bounds and the retention and
// capture settings have one source each in release 1.0 and are carried
// unchanged (TestObligationTypes).
func TestObligationPrecedence(t *testing.T) {
	reqtest.Verifies(t, "SR-1.10-1")
	s := mustCompile(t, `{"revision": "c1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t", "calls_per_minute": 20}},
  "templates": {"t": {"calls_per_minute": 40, "calls_per_session": 5, "rules": [
    {"id": "r", "server": "fs", "tools": ["write"], "calls_per_minute": 50, "calls_per_session": 7, "filters": ["size-limit"],
     "when": [{"op": "approval", "value": "required"}]},
    {"id": "e", "server": "fs", "tools": ["edit"], "calls_per_session": 3, "filters": ["path-canonicalize", "unicode-control"]},
    {"id": "m", "server": "fs", "tools": ["move"], "side_effect": "write"}]}}}`)
	d := NewDecider(s, 60)
	d.SetBurst(30)
	dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "fs", Tool: "write", SideEffect: SideWrite})
	if dec.Outcome != Permit || dec.Obligations.CallsPerMinute != 20 || dec.Obligations.Burst != 20 || dec.Obligations.CallsPerSession != 5 ||
		!dec.Obligations.Approval || strings.Join(dec.Obligations.Filters, ",") != "size-limit" {
		t.Fatalf("predicate approval: %+v", dec.Obligations)
	}
	// The rule's quota is smaller than the template's; no rule approval,
	// but the manifest's write class sets the approval floor.
	dec = d.Decide(Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "fs", Tool: "edit", SideEffect: SideWrite})
	if dec.Outcome != Permit || dec.Obligations.CallsPerSession != 3 || !dec.Obligations.Approval || dec.Obligations.ApprovalReason != "" ||
		strings.Join(dec.Obligations.Filters, ",") != "path-canonicalize,unicode-control" {
		t.Fatalf("floor: %+v", dec.Obligations)
	}
	// A smaller CP-11 default wins over every policy bound, and the burst
	// is cut to it.
	d2 := NewDecider(s, 10)
	d2.SetBurst(30)
	dec = d2.Decide(Request{PrincipalID: "p", SessionID: "s2", Profile: "dev", Template: "t", Server: "fs", Tool: "move"})
	if dec.Outcome != Permit || dec.Obligations.CallsPerMinute != 10 || dec.Obligations.Burst != 10 || dec.Obligations.Approval {
		t.Fatalf("default bound: %+v", dec.Obligations)
	}
	// Session taint adds approval to a non-read tool that had none and
	// changes no bound.
	d2.Taint("s2")
	dec = d2.Decide(Request{PrincipalID: "p", SessionID: "s2", Profile: "dev", Template: "t", Server: "fs", Tool: "move"})
	if dec.Outcome != Permit || !dec.Obligations.Approval || dec.Obligations.ApprovalReason != ReasonTaintApproval ||
		dec.Obligations.CallsPerMinute != 10 || dec.Obligations.Burst != 10 {
		t.Fatalf("taint: %+v", dec.Obligations)
	}
}
