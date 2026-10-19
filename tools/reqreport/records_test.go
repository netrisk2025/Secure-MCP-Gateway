package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const recordSHA = "0123456789abcdef0123456789abcdef01234567"

func record(id, method, result, date, evidence string) string {
	return "## " + id + "\n\n| Field | Content |\n|---|---|\n" +
		"| Requirement or scenario | " + id + " |\n" +
		"| Commit | `" + recordSHA + "` |\n" +
		"| Profile and platform | Standalone; darwin/arm64 |\n" +
		"| Date | " + date + " |\n" +
		"| Executor | tester |\n" +
		"| Method | " + method + " |\n" +
		"| Result | " + result + " |\n\n" +
		"Evidence:\n\n" + evidence + "\n\n"
}

// TestRecordsVerifyInspections covers SRS Section 2.6: a complete passing
// record verifies an Inspection, Analysis or Demonstration requirement;
// incomplete records, records whose method differs from the SRS method,
// records for Test-method requirements and records citing missing files do
// not count; the latest record decides.
func TestRecordsVerifyInspections(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "internal", "a", "a.go"), "package a\n")
	dir := filepath.Join(root, "docs", "verification")
	writeFile(t, filepath.Join(dir, "README.md"), record("FR-9", "Inspection", "pass", "2026-01-01", "- `internal/a/a.go:1`"))
	ok := "- `internal/a/a.go:1` declares the package; listens on `127.0.0.1:8443`"
	content := record("FR-2", "Inspection", "pass", "2026-10-16", ok) +
		record("FR-3", "Inspection", "pass", "2026-10-16", "- `internal/a/missing.go:4` gone") + // evidence file missing
		record("FR-4", "Analysis", "pass", "2026-10-16", ok) + // SRS method is Inspection
		record("FR-1.1", "Inspection", "pass", "2026-10-16", ok) + // SRS method is Test
		record("FR-5", "Inspection", "pass", "2026-10-16", "no references") + // inspection without evidence
		record("FR-6", "Demonstration", "pass", "2026-10-15", "steps") +
		record("FR-6", "Demonstration", "fail", "2026-10-16", "steps") + // later failure wins
		record("FR-7", "Analysis", "fail", "2026-10-15", "x") +
		record("FR-7", "Analysis", "pass", "2026-10-16", "x") + // later pass wins
		strings.Replace(record("FR-8", "Inspection", "pass", "2026-10-16", ok), "| Executor | tester |\n", "", 1) + // incomplete
		strings.Replace(record("SR-1-1", "Inspection", "pass", "2026-10-16", ok), recordSHA, "abc123", 1) + // short SHA
		record("FR-1.1", "Test", "pass", "2026-10-16", "manual check") + // supporting record: valid, never counts
		record("FR-2", "Test", "pass", "2026-10-16", "x") // Test record for an Inspection requirement
	writeFile(t, filepath.Join(dir, "inspections.md"), content)

	recs, err := loadRecords(dir, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 13 {
		t.Fatalf("%d records parsed (README must be skipped)", len(recs))
	}
	if recs[0].Fields["Commit"] != recordSHA || len(recs[0].Evidence) != 1 || recs[0].Evidence[0] != "internal/a/a.go:1" || recs[0].IDs[0] != "FR-2" {
		t.Fatalf("%+v", recs[0])
	}
	reqs := []Requirement{
		{ID: "FR-1.1", Method: "Test"}, {ID: "FR-2", Method: "Inspection"}, {ID: "FR-3", Method: "Inspection"},
		{ID: "FR-4", Method: "Inspection"}, {ID: "FR-5", Method: "Inspection"}, {ID: "FR-6", Method: "Demonstration"},
		{ID: "FR-7", Method: "Analysis"}, {ID: "FR-8", Method: "Inspection"}, {ID: "SR-1-1", Method: "Inspection"},
	}
	results := buildResults(reqs, &TestLog{}, "example.com/m")
	warnings := applyRecords(results, reqs, recs, "docs/verification")
	status := map[string]string{}
	for _, r := range results {
		status[r.ID] = r.Status
	}
	want := map[string]string{"FR-1.1": "unverified", "FR-2": "verified", "FR-3": "unverified", "FR-4": "unverified", "FR-5": "unverified",
		"FR-6": "failing", "FR-7": "verified", "FR-8": "unverified", "SR-1-1": "unverified"}
	for id, s := range want {
		if status[id] != s {
			t.Errorf("%s: %s, want %s", id, status[id], s)
		}
	}
	joined := strings.Join(warnings, "\n")
	for _, w := range []string{"evidence file internal/a/missing.go does not exist", "FR-4 is verified by Inspection, not Analysis", "FR-1.1 is verified by Test, not Inspection",
		"inspection without file:line evidence", "missing field Executor", "commit is not a full SHA", "FR-2 is verified by Inspection, not Test"} {
		if !strings.Contains(joined, w) {
			t.Errorf("no warning %q in:\n%s", w, joined)
		}
	}
	if strings.Contains(joined, "method Test") || strings.Count(joined, "FR-1.1") != 1 {
		t.Errorf("a supporting Test record must be accepted without a warning:\n%s", joined)
	}
	for _, r := range results {
		if r.ID == "FR-2" && (len(r.Claims) != 1 || !strings.HasPrefix(r.Claims[0].Test, "docs/verification/inspections.md:")) {
			t.Errorf("FR-2 claims %+v", r.Claims)
		}
	}
	if recs, err := loadRecords(filepath.Join(root, "absent"), root); err != nil || recs != nil {
		t.Fatalf("missing directory: %v %v", recs, err)
	}
}

// TestChildAnalysis: a parent whose Analysis reviews its children's results
// is verified only when every child is verified, including through a
// nested parent; other Analysis statements are left alone.
func TestChildAnalysis(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	const review = "Review the verification results of every FR-x child requirement; confirm each has passed."
	reqs := []Requirement{
		{ID: "FR-1", Method: "Analysis", Verify: review},
		{ID: "FR-1.1", Parent: "FR-1", Method: "Test"},
		{ID: "FR-1.2", Parent: "FR-1", Method: "Test"},
		{ID: "FR-2", Method: "Analysis", Verify: review},
		{ID: "FR-2.1", Parent: "FR-2", Method: "Test"},
		{ID: "FR-2.2", Parent: "FR-2", Method: "Test"},
		{ID: "FR-3", Method: "Analysis", Verify: "Compute the latency budget."},
		{ID: "FR-3.1", Parent: "FR-3", Method: "Test"},
		{ID: "FR-4", Method: "Analysis", Verify: review}, // no children
	}
	const pkg = "example.com/m/internal/a"
	log := ev("output", pkg, "TestA", "VERIFIES: FR-1.1 FR-1.2 FR-2.1 FR-3.1\n") + ev("pass", pkg, "TestA", "") +
		ev("output", pkg, "TestB", "PARTIAL: FR-2.2\n") + ev("pass", pkg, "TestB", "")
	tl, err := parseTestLog(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	results := buildResults(reqs, tl, "example.com/m")
	applyChildAnalysis(results, reqs)
	status := map[string]string{}
	for _, r := range results {
		status[r.ID] = r.Status
	}
	if status["FR-1"] != "verified" || status["FR-2"] != "partial" || status["FR-3"] != "unverified" || status["FR-4"] != "unverified" {
		t.Fatalf("%v", status)
	}
}

// TestChildAnalysisPartial: a parent with evidence for some children is
// partial, never verified, until every child is verified; a parent with a
// failing child, with no evidenced child, or with a claim of its own is
// left to its own claims; nested parents roll up.
func TestChildAnalysisPartial(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	const review = "Review the verification results of every FR-x child requirement; confirm each has passed."
	reqs := []Requirement{
		{ID: "FR-1", Method: "Analysis", Verify: review}, // one verified, one unverified child
		{ID: "FR-1.1", Parent: "FR-1", Method: "Test"},
		{ID: "FR-1.2", Parent: "FR-1", Method: "Test"},
		{ID: "FR-2", Method: "Analysis", Verify: review}, // a failing child
		{ID: "FR-2.1", Parent: "FR-2", Method: "Test"},
		{ID: "FR-2.2", Parent: "FR-2", Method: "Test"},
		{ID: "FR-3", Method: "Analysis", Verify: review}, // no evidence at all
		{ID: "FR-3.1", Parent: "FR-3", Method: "Test"},
		{ID: "FR-4", Method: "Analysis", Verify: review}, // nested: FR-4.1 is a partial parent
		{ID: "FR-4.1", Parent: "FR-4", Method: "Analysis", Verify: review},
		{ID: "FR-4.2", Parent: "FR-4.1", Method: "Test"}, // the nested parent's child
		{ID: "FR-5", Method: "Analysis", Verify: review}, // its own failing claim
		{ID: "FR-5.1", Parent: "FR-5", Method: "Test"},
		{ID: "FR-6", Method: "Analysis", Verify: "Compute the latency budget."}, // not a roll-up
		{ID: "FR-6.1", Parent: "FR-6", Method: "Test"},
	}
	const pkg = "example.com/m/internal/a"
	log := ev("output", pkg, "TestA", "VERIFIES: FR-1.1 FR-2.1 FR-5.1 FR-6.1\n") + ev("pass", pkg, "TestA", "") +
		ev("output", pkg, "TestB", "PARTIAL: FR-4.2\n") + ev("pass", pkg, "TestB", "") +
		ev("output", pkg, "TestC", "VERIFIES: FR-2.2 FR-5\n") + ev("fail", pkg, "TestC", "")
	tl, err := parseTestLog(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	results := buildResults(reqs, tl, "example.com/m")
	applyChildAnalysis(results, reqs)
	got := map[string]*ReqResult{}
	for _, r := range results {
		got[r.ID] = r
	}
	want := map[string]string{"FR-1": "partial", "FR-2": "unverified", "FR-3": "unverified", "FR-4": "partial", "FR-4.1": "partial", "FR-5": "failing", "FR-6": "unverified"}
	for id, st := range want {
		if got[id].Status != st {
			t.Errorf("%s: %s, want %s (%+v)", id, got[id].Status, st, got[id].Claims)
		}
	}
	if c := got["FR-1"].Claims; len(c) != 1 || c[0].Test != "analysis: 1 of 2 child requirements verified" || !c[0].Partial {
		t.Errorf("FR-1 claims %+v", c)
	}
	if c := got["FR-4"].Claims; len(c) != 1 || c[0].Test != "analysis: 0 of 1 child requirements verified" {
		t.Errorf("FR-4 claims %+v", c)
	}
}

// TestRunCountsRecords runs the command end to end with a records
// directory.
func TestRunCountsRecords(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	dir := t.TempDir()
	src := strings.Replace(reqSource, "V: Analysis | Review.", "V: Inspection | Inspect.", 1)
	writeFile(t, filepath.Join(dir, "srs", "req1.txt"), src)
	arch := writeFile(t, filepath.Join(dir, "arch.md"), archSource)
	gomod := writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.26\n")
	writeFile(t, filepath.Join(dir, "internal", "a", "a.go"), "package a\n")
	writeFile(t, filepath.Join(dir, "records", "inspections.md"), record("FR-1", "Inspection", "pass", "2026-10-16", "- `internal/a/a.go:1`"))
	in := writeFile(t, filepath.Join(dir, "go-test.json"), "")
	out := filepath.Join(dir, "build", "reqreport")
	args := []string{"-in", in, "-out", out, "-status", "", "-srs", filepath.Join(dir, "srs"), "-arch", arch,
		"-elements", "", "-gomod", gomod, "-commit", "deadbeef", "-agents", "", "-hostile", "",
		"-records", filepath.Join(dir, "records"), "-root", dir, "-appendix", ""}
	var stdout bytes.Buffer
	if code, err := run(args, nil, &stdout); err != nil || code != 0 {
		t.Fatalf("%d %v %s", code, err, stdout.String())
	}
	b, err := os.ReadFile(out + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Summary ReqSummary `json:"summary"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Verified != 1 || rep.Summary.Unverified != 2 {
		t.Fatalf("%+v", rep.Summary)
	}
}
