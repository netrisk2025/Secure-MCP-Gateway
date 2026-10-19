package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const accSHA = "89abcdef0123456789abcdef0123456789abcdef"

// TestLoadScenariosFromSRS reads the real Appendix M table.
func TestLoadScenariosFromSRS(t *testing.T) {
	reqtest.Partial(t, "FR-19.4")
	sc, err := loadScenarios(filepath.Join("..", "..", "srs_build", "appendix2.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sc) != 21 {
		t.Fatalf("%d scenarios, want 21", len(sc))
	}
	for i, s := range sc {
		if want := fmt.Sprintf("AT-%02d", i+1); s.ID != want {
			t.Fatalf("row %d is %s, want %s", i, s.ID, want)
		}
		if s.Title == "" || s.Evidence == "" || len(s.Requirements) == 0 {
			t.Fatalf("incomplete row %+v", s)
		}
	}
	if at8 := sc[7]; !slices.Contains(at8.Requirements, "SR-4.7-2") || slices.ContainsFunc(at8.Requirements, func(r string) bool { return strings.Contains(r, "HF") }) {
		t.Fatalf("AT-08 requirements %v", at8.Requirements)
	}
	if at21 := sc[20]; !slices.Equal(at21.Requirements, []string{"FR-12.10", "FR-19.3"}) {
		t.Fatalf("AT-21 requirements %v", at21.Requirements)
	}
}

func scenarioRows(n int) []Scenario {
	var out []Scenario
	for i := 1; i <= n; i++ {
		out = append(out, Scenario{ID: fmt.Sprintf("AT-%02d", i), Title: fmt.Sprintf("Scenario %d", i), Evidence: "Automated", Requirements: []string{"FR-1.1"}})
	}
	return out
}

func atRecord(id, profile, commit, date, result string) string {
	return "| Field | Content |\n|---|---|\n" +
		"| Requirement or scenario | " + id + " |\n" +
		"| Commit | `" + commit + "` |\n" +
		"| Profile and platform | " + profile + "; linux/amd64 |\n" +
		"| Date | " + date + " |\n" +
		"| Executor | tester |\n" +
		"| Method | Demonstration |\n" +
		"| Result | " + result + " |\n\nSteps.\n\n"
}

// TestAcceptanceResults covers the per-profile result rules: a failing
// claim wins, a skipped test is not a result, records count only for the
// status commit, and the label needs an Enforced pass for every scenario.
func TestAcceptanceResults(t *testing.T) {
	reqtest.Partial(t, "FR-19.3", "FR-19.4")
	const pkg = "example.com/m/internal/acceptance"
	log := ev("output", pkg, "TestAT01", "    x.go:1: SCENARIO: AT-01 profile=enforced\n") + ev("pass", pkg, "TestAT01", "") +
		ev("output", pkg, "TestAT02a", "SCENARIO: AT-02 profile=enforced\n") + ev("fail", pkg, "TestAT02a", "") +
		ev("output", pkg, "TestAT02b", "SCENARIO: AT-02 profile=standalone\n") + ev("pass", pkg, "TestAT02b", "") +
		ev("output", pkg, "TestAT03", "SCENARIO: AT-03 profile=standalone\n") + ev("pass", pkg, "TestAT03", "") +
		ev("output", pkg, "TestAT04", "SCENARIO: AT-04 profile=enforced\n") + ev("skip", pkg, "TestAT04", "") +
		ev("output", pkg, "TestAT05", "SCENARIO: AT-05 profile=lab\n") + ev("pass", pkg, "TestAT05", "") + // no valid profile
		ev("output", pkg, "TestAT06", "SCENARIO: AT-06 AT-07 profile=standalone\n") // never finished
	tl, err := parseTestLog(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "AT-18.md"), atRecord("AT-18", "Enforced", accSHA, "2026-10-17", "pass"))
	writeFile(t, filepath.Join(dir, "AT-19.md"), atRecord("AT-19", "Enforced", recordSHA, "2026-10-17", "pass")+ // other commit
		atRecord("AT-19", "Standalone", accSHA, "2026-10-16", "pass")+atRecord("AT-19", "Standalone", accSHA, "2026-10-17", "fail"))
	recs, err := loadRecords(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if len(r.Problems) > 0 {
			t.Fatalf("record %s: %v", r.File, r.Problems)
		}
	}
	a := buildAcceptance(scenarioRows(21), tl, recs, "docs/verification", accSHA, "example.com/m")
	got := map[string][2]string{}
	for _, s := range a.Scenarios {
		got[s.ID] = [2]string{s.Enforced, s.Standalone}
	}
	want := map[string][2]string{
		"AT-01": {"pass", "not-run"}, "AT-02": {"fail", "pass"}, "AT-03": {"not-run", "pass"}, "AT-04": {"not-run", "not-run"},
		"AT-05": {"not-run", "not-run"}, "AT-06": {"not-run", "fail"}, "AT-07": {"not-run", "fail"},
		"AT-18": {"pass", "not-run"}, "AT-19": {"not-run", "fail"}, "AT-20": {"not-run", "not-run"},
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: enforced/standalone %v, want %v", id, got[id], w)
		}
	}
	if a.Label != LabelNotEnforced || a.EnforcedPassed != 2 || a.StandalonePassed != 2 || len(a.Reasons) != 19 {
		t.Fatalf("label %q enforced %d standalone %d reasons %d", a.Label, a.EnforcedPassed, a.StandalonePassed, len(a.Reasons))
	}
	if !strings.Contains(strings.Join(a.Reasons, "\n"), "AT-02 Scenario 2: failed in the Enforced profile") {
		t.Fatalf("reasons %v", a.Reasons)
	}
	md := renderAcceptance(a)
	if !strings.Contains(md, "not counted: recorded for another commit") || !strings.Contains(md, "Release label: **not enforced**") {
		t.Fatalf("markdown:\n%s", md)
	}
}

// TestReleaseLabel is the FR-19.3 inspection in miniature: a candidate with
// one unexecuted scenario is "not enforced", one with every scenario passing
// in the Enforced profile is "enforced", and status data of another commit
// never labels a release.
func TestReleaseLabel(t *testing.T) {
	reqtest.Partial(t, "FR-19.3")
	const pkg = "example.com/m/internal/acceptance"
	var all, missing strings.Builder
	for i := 1; i <= 21; i++ {
		name := fmt.Sprintf("TestAT%02d", i)
		line := ev("output", pkg, name, fmt.Sprintf("SCENARIO: AT-%02d profile=enforced\n", i)) + ev("pass", pkg, name, "")
		all.WriteString(line)
		if i != 13 {
			missing.WriteString(line)
		}
	}
	label := func(log, statusCommit, releaseCommit string) (string, []string, string) {
		tl, err := parseTestLog(strings.NewReader(log))
		if err != nil {
			t.Fatal(err)
		}
		a := buildAcceptance(scenarioRows(21), tl, nil, "", statusCommit, "example.com/m")
		dir := t.TempDir()
		b, _ := json.Marshal(map[string]any{"commit": statusCommit, "acceptance": a})
		status := writeFile(t, filepath.Join(dir, "status.json"), string(b))
		notes := filepath.Join(dir, "label.md")
		var out bytes.Buffer
		code, err := runLabel([]string{"-status", status, "-commit", releaseCommit, "-out", notes}, &out)
		if err != nil || code != 0 {
			t.Fatalf("label: %d %v", code, err)
		}
		md, _ := os.ReadFile(notes)
		l, reasons, _ := releaseLabel(statusCommit, &a, releaseCommit)
		if !strings.HasPrefix(out.String(), "release label: "+l+"\n") {
			t.Fatalf("output %q, label %q", out.String(), l)
		}
		return l, reasons, string(md)
	}
	if l, reasons, md := label(all.String(), accSHA, accSHA); l != LabelEnforced || len(reasons) != 0 || !strings.Contains(md, "Release label: **enforced**") {
		t.Fatalf("all passing: %q %v\n%s", l, reasons, md)
	}
	if l, reasons, md := label(missing.String(), accSHA, accSHA); l != LabelNotEnforced || len(reasons) != 1 || !strings.Contains(reasons[0], "AT-13") || !strings.Contains(md, "AT-13") {
		t.Fatalf("one unexecuted: %q %v\n%s", l, reasons, md)
	}
	if l, reasons, _ := label(all.String(), accSHA, recordSHA); l != LabelNotEnforced || !strings.Contains(reasons[0], "not the release commit") {
		t.Fatalf("other commit: %q %v", l, reasons)
	}
	if l, _, _ := releaseLabel(accSHA, nil, accSHA); l != LabelNotEnforced {
		t.Fatal("no acceptance data labelled enforced")
	}
	tl, _ := parseTestLog(strings.NewReader(all.String()))
	if a := buildAcceptance(scenarioRows(20), tl, nil, "", accSHA, "example.com/m"); a.Label != LabelNotEnforced {
		t.Fatal("20 scenarios labelled enforced")
	}
}
