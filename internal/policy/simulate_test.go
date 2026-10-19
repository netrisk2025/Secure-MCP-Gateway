package policy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestDiff(t *testing.T) {
	a := mustCompile(t, doc)
	if rep := Diff(a, a); !rep.Same || rep.Widening || len(rep.Changes) != 0 {
		t.Fatalf("self diff: %+v", rep)
	}
	src := strings.Replace(doc, `"r1"`, `"r2"`, 1)
	src = strings.Replace(src, `"tools": ["read_file", "list_directory"]}`, `"tools": ["read_file", "search"]}, {"id": "no-x", "effect": "deny", "server": "fs", "tools": ["delete"]}`, 1)
	src = strings.Replace(src, `"approval": true}`, `"approval": false, "filters": ["path-canonicalize"]}`, 1)
	src = strings.Replace(src, `"rw": {"calls_per_minute": 2,`, `"rw": {"calls_per_minute": 1, "taint_action": "deny",`, 1)
	b := mustCompile(t, src)
	rep := Diff(a, b)
	kinds := map[string]int{}
	for _, c := range rep.Changes {
		kinds[c.Kind]++
	}
	want := map[string]int{"grant_added": 1, "grant_removed": 1, "grant_changed": 2, "deny_added": 1, "template_changed": 1}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("%s: got %d want %d (%+v)", k, kinds[k], n, rep.Changes)
		}
	}
	if !rep.Widening || rep.From != "r1" || rep.To != "r2" {
		t.Fatalf("a new grant and a removed approval widen: %+v", rep)
	}
	// The reverse direction removes a grant and adds approval, but also
	// re-adds list_directory, so it widens too; a pure narrowing does not.
	narrow := strings.Replace(strings.Replace(doc, `"r1"`, `"r3"`, 1), `"read_file", "list_directory"]`, `"read_file"]`, 1)
	if rep := Diff(a, mustCompile(t, narrow)); rep.Widening || len(rep.Changes) != 1 || rep.Changes[0].Kind != "grant_removed" {
		t.Fatalf("narrowing: %+v", rep)
	}
	if rep := Diff(nil, a); !rep.Widening || len(rep.Changes) == 0 {
		t.Fatalf("from empty: %+v", rep)
	}
	if rep := Diff(a, nil); rep.Widening {
		t.Fatalf("to empty: %+v", rep)
	}
}

func TestSimulateReportsDecisionChanges(t *testing.T) {
	reqtest.Partial(t, "FR-3.5")
	active := mustCompile(t, doc)
	cand := mustCompile(t, strings.Replace(strings.Replace(doc, `"r1"`, `"r2"`, 1), `"read_file", "list_directory"]`, `"read_file", "write_file"]`, 1))
	t0 := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	fx := []Fixture{
		{Time: t0, PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file"},
		{Time: t0.Add(time.Second), PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "list_directory"},
		{Time: t0.Add(2 * time.Second), PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "write_file"},
	}
	rep, err := Simulate(active, cand, fx, SimOptions{DefaultRate: 60})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ActiveRevision != "r1" || rep.CandidateRevision != "r2" || rep.Fixtures != 3 || rep.Changed != 2 {
		t.Fatalf("%+v", rep)
	}
	if rep.Counts[SimPermitToDeny] != 1 || rep.Counts[SimDenyToPermit] != 1 || rep.Counts[SimUnchanged] != 1 || len(rep.Results) != 2 {
		t.Fatalf("%+v", rep)
	}
	for _, r := range rep.Results {
		switch r.Fixture.Tool {
		case "list_directory":
			if r.Active.Outcome != Permit || r.Candidate.ReasonCode != ReasonNoPermit || r.Change != SimPermitToDeny {
				t.Fatalf("%+v", r)
			}
		case "write_file":
			if r.Active.ReasonCode != ReasonNoPermit || r.Candidate.Outcome != Permit || r.Change != SimDenyToPermit {
				t.Fatalf("%+v", r)
			}
		default:
			t.Fatalf("unchanged fixture reported: %+v", r)
		}
	}
	all, _ := Simulate(active, cand, fx, SimOptions{All: true})
	if len(all.Results) != 3 {
		t.Fatalf("All: %d results", len(all.Results))
	}
	if _, err := Simulate(active, cand, nil, SimOptions{}); !errors.Is(err, ErrNoFixtures) {
		t.Fatalf("no fixtures: %v", err)
	}
	// No active revision: the active side denies with NO_SNAPSHOT.
	rep, _ = Simulate(nil, cand, fx[:1], SimOptions{})
	if rep.Results[0].Active.ReasonCode != ReasonNoSnapshot || rep.Results[0].Change != SimDenyToPermit {
		t.Fatalf("%+v", rep)
	}
}

func TestSimulateReplaysRatesAndTaint(t *testing.T) {
	reqtest.Partial(t, "FR-3.5")
	active := mustCompile(t, taintDoc)
	// The candidate lowers the template rate to 2/min and denies on taint.
	cand := mustCompile(t, strings.Replace(strings.Replace(taintDoc, `"t1"`, `"t2"`, 1), `"work": {"rules"`, `"work": {"calls_per_minute": 2, "taint_action": "deny", "rules"`, 1))
	t0 := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	f := func(sec int, server, tool string) Fixture {
		return Fixture{Time: t0.Add(time.Duration(sec) * time.Second), PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "work", Server: server, Tool: tool}
	}
	// Out of order on purpose: replay sorts by time.
	fx := []Fixture{f(2, "fs", "write_file"), f(0, "web", "fetch"), f(1, "fs", "read_file"), f(70, "fs", "write_file")}
	rep, err := Simulate(active, cand, fx, SimOptions{DefaultRate: 60, All: true})
	if err != nil {
		t.Fatal(err)
	}
	byIndex := map[int]SimResult{}
	for _, r := range rep.Results {
		byIndex[r.Index] = r
	}
	// The fetch at t=0 tainted the session on both sides: active asks for
	// approval, the candidate denies.
	for _, i := range []int{0, 3} {
		if r := byIndex[i]; r.Active.Outcome != Permit || r.Active.ApprovalReason != ReasonTaintApproval || r.Candidate.ReasonCode != ReasonTaintDenied {
			t.Fatalf("tainted write %d: %+v", i, r)
		}
	}
	// The read is permitted on both sides; the lower rate bound is reported
	// as an obligation change.
	if r := byIndex[2]; r.Change != SimObligations || r.Candidate.CallsPerMinute != 2 {
		t.Fatalf("read: %+v", r)
	}
	// Rate windows follow the recorded times.
	reads := []Fixture{f(0, "fs", "read_file"), f(1, "fs", "read_file"), f(2, "fs", "read_file"), f(70, "fs", "read_file")}
	rep, _ = Simulate(active, cand, reads, SimOptions{DefaultRate: 60, All: true})
	got := []string{}
	for _, r := range rep.Results {
		got = append(got, r.Candidate.ReasonCode)
	}
	if strings.Join(got, ",") != "PERMIT,PERMIT,RATE_LIMITED,PERMIT" || rep.Counts[SimPermitToDeny] != 1 || rep.Counts[SimObligations] != 3 {
		t.Fatalf("candidate rate replay: %v %+v", got, rep.Counts)
	}
}

func TestParseFixtures(t *testing.T) {
	in := `# scenario
{"principal": "p", "session": "s", "template": "ro", "server": "fs", "tool": "read_file", "time": "2026-10-16T12:00:00Z"}

{"template": "ro", "server": "fs", "tool": "write_file"}
`
	fx, err := ParseFixtures(strings.NewReader(in))
	if err != nil || len(fx) != 2 || fx[1].PrincipalID != "simulated" || fx[0].Time.IsZero() {
		t.Fatalf("%+v %v", fx, err)
	}
	for _, bad := range []string{`{"template": "ro", "server": "fs", "tool": "x", "tol": 1}`, `{"server": "fs", "tool": "x"}`, `not json`} {
		if _, err := ParseFixtures(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
