package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const reqSource = `## 4. Functional requirements (FR)

TEXT: Intro text with @ not at line start.

@FR-1 | Northbound MCP server
P: —
S: The Gateway SHALL do things.
A: E-01; E-02; F-01; X-01
V: Analysis | Review.
SRC: ARCH
R: Because.

@FR-1.1 | Listeners
P: FR-1
S: The Gateway SHALL listen.
A: E-02; F-01; I-01
V: Test | Check.
SRC: ARCH
R: Because.

@DISP SEC-1.1 | Covered elsewhere

@SR-1-1 | Capability ceiling
P: SEC-1
S: The Gateway SHALL cap.
A: E-05; E-14; F-10
V: Test | Check.
SRC: SEC
R: Because.
`

const archSource = `# Architecture

### SS-1 Harness Edge

#### E-01 Harness Interface Endpoint — T1
text
#### E-02 Protocol Mediator — T1

### SS-3 Policy

#### E-05 Policy Administration Service — T0
#### E-14 Local Server Registry — T1
`

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ev builds one go test -json line.
func ev(action, pkg, test, output string) string {
	m := map[string]any{"Time": "2026-10-16T10:00:00Z", "Action": action, "Package": pkg}
	if test != "" {
		m["Test"] = test
	}
	if output != "" {
		m["Output"] = output
	}
	b, _ := json.Marshal(m)
	return string(b) + "\n"
}

func TestLoadRequirements(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "req1.txt"), reqSource)
	reqs, err := loadRequirements(dir)
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	for _, r := range reqs {
		parts = append(parts, fmt.Sprintf("{%s %s %v %q %s %q}", r.ID, r.Title, r.Elements, r.Parent, r.Method, r.Verify))
	}
	got := "[" + strings.Join(parts, " ") + "]"
	want := `[{FR-1 Northbound MCP server [E-01 E-02] "" Analysis "Review."} {FR-1.1 Listeners [E-02] "FR-1" Test "Check."} {SR-1-1 Capability ceiling [E-05 E-14] "" Test "Check."}]`
	if got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	if reqs[2].Element() != "E-05" {
		t.Fatalf("primary element %s", reqs[2].Element())
	}
	if _, err := loadRequirements(t.TempDir()); err == nil {
		t.Fatal("empty directory accepted")
	}
}

// TestLoadRequirementsSkipsDeferred: a record with a DEFER: line (SRS
// Section 2.7, Appendix N) is not part of the requirement set.
func TestLoadRequirementsSkipsDeferred(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "req1.txt"), reqSource+`
@FR-1.2 | Deferred listener
P: FR-1
S: The Gateway SHALL listen elsewhere.
A: E-01; F-01
V: Test | Check.
SRC: ARCH
R: Because.
DEFER: Not in release 1.0.
`)
	reqs, err := loadRequirements(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reqs {
		if r.ID == "FR-1.2" {
			t.Fatal("deferred requirement loaded")
		}
	}
	if len(reqs) != 3 {
		t.Fatalf("loaded %d requirements, want 3", len(reqs))
	}
}

func TestLoadAndMergeElements(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	dir := t.TempDir()
	arch := writeFile(t, filepath.Join(dir, "arch.md"), archSource)
	els, err := loadElements(arch)
	if err != nil {
		t.Fatal(err)
	}
	if len(els) != 4 || els[0].Name != "Harness Interface Endpoint" || els[0].Subsystem != "SS-1" || els[2].Subsystem != "SS-3" {
		t.Fatalf("%+v", els)
	}
	// Missing status file: defaults kept.
	if els, err = mergeElementStatus(els, filepath.Join(dir, "absent.json")); err != nil || els[0].Implementation != "not-started" {
		t.Fatalf("%v %+v", err, els[0])
	}
	st := writeFile(t, filepath.Join(dir, "elements.json"), `[{"id":"E-01","implementation":"partial","packages":["internal/edge"],"note":"slice"}]`)
	if els, err = mergeElementStatus(els, st); err != nil {
		t.Fatal(err)
	}
	if els[0].Implementation != "partial" || strings.Join(els[0].Packages, ",") != "internal/edge" || els[0].Note != "slice" || els[1].Implementation != "not-started" {
		t.Fatalf("%+v", els[:2])
	}
	bad := writeFile(t, filepath.Join(dir, "bad.json"), `[{"id":"E-01","implementation":"done"}]`)
	if _, err := mergeElementStatus(els, bad); err == nil {
		t.Fatal("bad implementation value accepted")
	}
	unknown := writeFile(t, filepath.Join(dir, "unknown.json"), `[{"id":"E-99","implementation":"partial"}]`)
	if _, err := mergeElementStatus(els, unknown); err == nil {
		t.Fatal("unknown element accepted")
	}
}

func TestParseTestLog(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	const pkg = "example.com/m/internal/a"
	var in strings.Builder
	in.WriteString("not json at all\n")
	// Full claim, passing.
	in.WriteString(ev("run", pkg, "TestFull", ""))
	in.WriteString(ev("output", pkg, "TestFull", "    a_test.go:10: VERIFIES: FR-1.1 SR-1-1\n"))
	in.WriteString(ev("pass", pkg, "TestFull", ""))
	// Subtest with a partial claim split across two output events.
	in.WriteString(ev("output", pkg, "TestTable/case_one/deep", "    a_test.go:20: PARTIAL: FR-"))
	in.WriteString(ev("output", pkg, "TestTable/case_one/deep", "1 junk\n"))
	in.WriteString(ev("pass", pkg, "TestTable/case_one/deep", ""))
	in.WriteString(ev("pass", pkg, "TestTable/case_one", ""))
	in.WriteString(ev("pass", pkg, "TestTable", ""))
	// Skipped claiming test.
	in.WriteString(ev("output", pkg, "TestSkipped", "    a_test.go:30: VERIFIES: FR-1\n"))
	in.WriteString(ev("skip", pkg, "TestSkipped", ""))
	// A test cut off by a panic: no terminal event.
	in.WriteString(ev("output", pkg, "TestCrashed", "    a_test.go:40: VERIFIES: FR-9.9\n"))
	in.WriteString(ev("fail", pkg, "", ""))
	// A package that fails to build.
	in.WriteString(ev("fail", "example.com/m/internal/broken", "", ""))
	in.WriteString(ev("skip", "example.com/m/internal/notests", "", ""))

	log, err := parseTestLog(strings.NewReader(in.String()))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*TestRun{}
	for _, tr := range log.Tests {
		byName[tr.Name] = tr
	}
	if c := byName["TestFull"].Claims; len(c) != 2 || c[0].ID != "FR-1.1" || c[1].ID != "SR-1-1" || c[0].Partial {
		t.Fatalf("TestFull claims %+v", c)
	}
	deep := byName["TestTable/case_one/deep"]
	if deep == nil || len(deep.Claims) != 1 || deep.Claims[0] != (Claim{ID: "FR-1", Partial: true}) {
		t.Fatalf("subtest %+v", deep)
	}
	if byName["TestSkipped"].Result != "skip" || byName["TestCrashed"].Result != "" {
		t.Fatalf("results %q %q", byName["TestSkipped"].Result, byName["TestCrashed"].Result)
	}
	sum := summarizeTests(log)
	// 4 passing tests (incl. subtests), 1 skip, 1 crashed + 1 broken package.
	if sum.Passed != 4 || sum.Skipped != 1 || sum.Failed != 2 || sum.Total != 7 || len(sum.Packages) != 2 {
		t.Fatalf("%+v", sum)
	}

	results := buildResults([]Requirement{{ID: "FR-1", Elements: []string{"E-01"}}, {ID: "FR-1.1", Elements: []string{"E-02"}}, {ID: "SR-1-1", Elements: []string{"E-05"}}, {ID: "FR-2", Elements: []string{"E-02"}}}, log, "example.com/m")
	status := map[string]string{}
	for _, r := range results {
		status[r.ID] = r.Status
	}
	want := map[string]string{"FR-1": "partial", "FR-1.1": "verified", "SR-1-1": "verified", "FR-2": "unverified", "FR-9.9": "failing"}
	for id, s := range want {
		if status[id] != s {
			t.Errorf("%s: %s, want %s", id, status[id], s)
		}
	}
	for _, r := range results {
		if r.ID == "FR-1" {
			// Full subtest name kept, package relative to the module.
			var names []string
			for _, c := range r.Claims {
				names = append(names, c.Test)
			}
			if strings.Join(names, ",") != "internal/a.TestSkipped,internal/a.TestTable/case_one/deep" {
				t.Errorf("FR-1 tests %v", names)
			}
		}
		if r.ID == "FR-9.9" && r.InSRS {
			t.Error("FR-9.9 marked as in the SRS")
		}
	}
}

func TestComputeStatus(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	full := func(r string) ClaimRef { return ClaimRef{Result: r} }
	part := func(r string) ClaimRef { return ClaimRef{Result: r, Partial: true} }
	cases := []struct {
		claims []ClaimRef
		want   string
	}{
		{nil, StatusUnverified},
		{[]ClaimRef{full("skip")}, StatusUnverified},
		{[]ClaimRef{full("pass")}, StatusVerified},
		{[]ClaimRef{part("pass")}, StatusPartial},
		{[]ClaimRef{part("pass"), full("pass")}, StatusVerified},
		{[]ClaimRef{full("pass"), part("fail")}, StatusFailing},
		{[]ClaimRef{full("fail"), full("pass")}, StatusFailing},
		{[]ClaimRef{part("skip"), full("skip")}, StatusUnverified},
	}
	for i, c := range cases {
		if got := computeStatus(c.claims); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

func TestCoverage(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	profile := `mode: atomic
example.com/m/internal/a/a.go:1.1,2.2 3 0
example.com/m/internal/a/a.go:3.1,4.2 1 5
example.com/m/internal/b/b.go:1.1,2.2 4 0
example.com/m/internal/a/a.go:1.1,2.2 3 2
example.com/m/main.go:1.1,2.2 2 0
`
	cov, err := parseCoverProfile(strings.NewReader(profile), "example.com/m")
	if err != nil {
		t.Fatal(err)
	}
	// a: 4/4 (duplicate block covered in the second binary), b: 0/4, root: 0/2.
	if cov.TotalPct != 40 || fmt.Sprint(cov.Packages) != "[{. 0} {internal/a 100} {internal/b 0}]" {
		t.Fatalf("%+v", cov)
	}
	if _, err := parseCoverProfile(strings.NewReader("mode: set\nbad line\n"), ""); err == nil {
		t.Fatal("malformed profile accepted")
	}
	total, err := parseCoverFuncTotal("example.com/m/a.go:3:\tF\t\t100.0%\ntotal:\t\t\t(statements)\t\t42.86%\n")
	if err != nil || total != 42.9 {
		t.Fatalf("%v %v", total, err)
	}
	if _, err := parseCoverFuncTotal("nothing"); err == nil {
		t.Fatal("missing total accepted")
	}
}

func TestHistory(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	var h []HistoryEntry
	for i := 0; i < maxHistory+5; i++ {
		h = appendHistory(h, HistoryEntry{Commit: fmt.Sprint(i)})
	}
	if len(h) != maxHistory || h[0].Commit != "5" || h[len(h)-1].Commit != fmt.Sprint(maxHistory+4) {
		t.Fatalf("len %d first %s last %s", len(h), h[0].Commit, h[len(h)-1].Commit)
	}
	h = appendHistory(h, HistoryEntry{Commit: "100", TestsPassed: 9})
	if len(h) != maxHistory || h[len(h)-1].Commit != "100" || h[len(h)-1].TestsPassed != 9 {
		t.Fatal("re-run of a commit not moved to the end")
	}
	for _, e := range h[:len(h)-1] {
		if e.Commit == "100" {
			t.Fatal("duplicate commit entry kept")
		}
	}

	dir := t.TempDir()
	st := Status{Schema: 1, Commit: "abc", GeneratedAt: "2026-10-16T00:00:00Z"}
	st.Tests.Passed = 3
	st.Coverage.TotalPct = 12.5
	st.Requirements.Verified = 2
	stPath := filepath.Join(dir, "status.json")
	if err := writeJSON(stPath, st); err != nil {
		t.Fatal(err)
	}
	hPath := filepath.Join(dir, "history.json")
	for i := 0; i < 2; i++ { // second run for the same commit replaces the first
		if err := runHistory(stPath, hPath); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(hPath)
	var got []map[string]any
	if err := json.Unmarshal(b, &got); err != nil || len(got) != 1 {
		t.Fatalf("%v %s", err, b)
	}
	for _, k := range []string{"commit", "generatedAt", "testsPassed", "testsFailed", "coveragePct", "verified", "partial", "unverified"} {
		if _, ok := got[0][k]; !ok {
			t.Errorf("history entry lacks %s", k)
		}
	}
	writeFile(t, hPath, "{not an array")
	if err := runHistory(stPath, hPath); err != nil {
		t.Fatalf("corrupt history blocked publishing: %v", err)
	}
}

func TestRunWritesContractDocuments(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "srs", "req1.txt"), reqSource)
	arch := writeFile(t, filepath.Join(dir, "arch.md"), archSource)
	gomod := writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.26\n")
	const pkg = "example.com/m/internal/a"
	log := ev("output", pkg, "TestA", "VERIFIES: FR-1.1\n") + ev("pass", pkg, "TestA", "") +
		ev("output", pkg, "TestB", "VERIFIES: SR-1-1\n") + ev("fail", pkg, "TestB", "") + ev("fail", pkg, "", "")
	in := writeFile(t, filepath.Join(dir, "go-test.json"), log)
	out := filepath.Join(dir, "build", "reqreport")
	statusPath := filepath.Join(dir, "build", "status.json")
	args := []string{"-in", in, "-out", out, "-status", statusPath, "-srs", filepath.Join(dir, "srs"), "-arch", arch,
		"-elements", "", "-gomod", gomod, "-commit", "deadbeef", "-agents", "", "-hostile", "", "-appendix", ""}
	var stdout bytes.Buffer
	code, err := run(args, nil, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Fatalf("exit %d with a failing requirement", code)
	}
	b, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "generatedAt", "commit", "commitUrl", "runUrl", "tests", "coverage", "requirements", "elements", "agents", "hostile", "ci"} {
		if _, ok := st[k]; !ok {
			t.Errorf("status.json lacks %s", k)
		}
	}
	if st["agents"] == nil || st["hostile"] == nil {
		t.Error("agents and hostile must be arrays, not null")
	}
	reqs := st["requirements"].(map[string]any)
	if reqs["total"] != float64(3) || reqs["verified"] != float64(1) || reqs["failing"] != float64(1) || reqs["unverified"] != float64(1) {
		t.Fatalf("requirements %v", reqs)
	}
	if ci := st["ci"].(map[string]any); ci["conclusion"] != "failure" {
		t.Fatalf("ci %v", ci)
	}
	md, _ := os.ReadFile(out + ".md")
	if !strings.Contains(string(md), "## Failing") || !strings.Contains(string(md), "internal/a.TestB") {
		t.Fatalf("markdown lacks the failing section:\n%s", md)
	}
	if _, err := os.Stat(out + ".json"); err != nil {
		t.Fatal(err)
	}
}

func TestLessID(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	ids := []string{"SR-1-1", "FR-10.1", "FR-2.10", "FR-2.9", "FR-1", "SR-1.2-1"}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if lessID(ids[j], ids[i]) {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	if got := strings.Join(ids, " "); got != "FR-1 FR-2.9 FR-2.10 FR-10.1 SR-1-1 SR-1.2-1" {
		t.Fatalf("order %s", got)
	}
}

// TestPlaywrightClaims parses the events console/e2e/reqreport.ts and
// console/e2e/claims.mjs write for the console acceptance tests (FR-8.34):
// the same `go test -json` shape, with test names that hold spaces and ">".
func TestPlaywrightClaims(t *testing.T) {
	reqtest.Partial(t, "FR-8.34")
	const in = `{"Time":"2026-10-17T03:23:19.470Z","Action":"run","Package":"console/e2e/chromium","Test":"console.spec.ts > administrator signs in"}
{"Time":"2026-10-17T03:23:20.162Z","Action":"output","Package":"console/e2e/chromium","Test":"console.spec.ts > administrator signs in","Output":"    PARTIAL: FR-8.3\n"}
{"Time":"2026-10-17T03:23:20.162Z","Action":"output","Package":"console/e2e/chromium","Test":"console.spec.ts > administrator signs in","Output":"    PARTIAL: FR-8.28\n"}
{"Time":"2026-10-17T03:23:20.162Z","Action":"pass","Package":"console/e2e/chromium","Test":"console.spec.ts > administrator signs in","Elapsed":0.69}
{"Time":"2026-10-17T03:23:21.000Z","Action":"run","Package":"console/e2e/webkit","Test":"views.spec.ts > G-03 audit profile tuning"}
{"Time":"2026-10-17T03:23:21.000Z","Action":"output","Package":"console/e2e/webkit","Test":"views.spec.ts > G-03 audit profile tuning","Output":"    PARTIAL: FR-8.5\n"}
{"Time":"2026-10-17T03:23:21.000Z","Action":"fail","Package":"console/e2e/webkit","Test":"views.spec.ts > G-03 audit profile tuning","Elapsed":1}
{"Time":"2026-10-17T03:23:22.000Z","Action":"output","Package":"console/e2e/browsers","Test":"TestConsoleViewsClaimTheirRequirements","Output":"    VERIFIES: FR-8.34\n"}
{"Time":"2026-10-17T03:23:22.000Z","Action":"pass","Package":"console/e2e/browsers","Test":"TestConsoleViewsClaimTheirRequirements","Elapsed":0}
{"Time":"2026-10-17T03:23:22.000Z","Action":"fail","Package":"console/e2e/webkit"}
`
	log, err := parseTestLog(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	results := buildResults([]Requirement{{ID: "FR-8.3"}, {ID: "FR-8.5"}, {ID: "FR-8.28"}, {ID: "FR-8.34"}}, log, "github.com/ethan03805/secure-mcp-gateway")
	status := map[string]string{}
	for _, r := range results {
		status[r.ID] = r.Status
		if r.ID == "FR-8.3" && (len(r.Claims) != 1 || r.Claims[0].Test != "console/e2e/chromium.console.spec.ts > administrator signs in") {
			t.Errorf("FR-8.3 claims %+v", r.Claims)
		}
	}
	want := map[string]string{"FR-8.3": "partial", "FR-8.28": "partial", "FR-8.5": "failing", "FR-8.34": "verified"}
	for id, s := range want {
		if status[id] != s {
			t.Errorf("%s: %s, want %s", id, status[id], s)
		}
	}
}
