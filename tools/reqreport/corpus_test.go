package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestCorpusRatesPublished is the publishing half of FR-19.5: the CORPUS
// lines that internal/filters TestCorpusRates logs for each rule-set
// version reach status.json (published to the site-data branch by the CI
// status job) as one rate pair per rule-set version with its targets; a
// version whose rate exceeds its target makes the measuring test fail,
// and the published entry says so. internal/filters TestCorpusRates is
// the measuring half.
func TestCorpusRatesPublished(t *testing.T) {
	reqtest.Partial(t, "FR-19.5") // with internal/filters.TestCorpusRates
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "srs", "req1.txt"), reqSource)
	arch := writeFile(t, filepath.Join(dir, "arch.md"), archSource)
	gomod := writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.26\n")
	const pkg = "example.com/m/internal/filters"
	line := func(rs, ver, fp, fn string) string {
		return "    corpus_test.go:117: CORPUS rule_set=" + rs + " version=" + ver + " positives=12 negatives=20 fp_rate=" + fp + " fn_rate=" + fn +
			" target_fp=0.0500 target_fn=0.1000\n"
	}
	log := ev("output", pkg, "TestCorpusRates", line("prompt-injection", "3", "0.0000", "0.0833")) +
		ev("output", pkg, "TestCorpusRates", line("metadata", "2", "0.0500", "0.0000")) +
		ev("pass", pkg, "TestCorpusRates", "") +
		ev("output", pkg, "TestRaised", line("pii", "4", "0.1500", "0.0000")) +
		ev("fail", pkg, "TestRaised", "") + ev("fail", pkg, "", "")
	in := writeFile(t, filepath.Join(dir, "go-test.json"), log)
	statusPath := filepath.Join(dir, "build", "status.json")
	args := []string{"-in", in, "-out", filepath.Join(dir, "build", "reqreport"), "-status", statusPath, "-srs", filepath.Join(dir, "srs"), "-arch", arch,
		"-elements", "", "-gomod", gomod, "-commit", "deadbeef", "-agents", "", "-hostile", "", "-appendix", ""}
	if _, err := run(args, nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Corpora []CorpusRate `json:"corpora"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Corpora) != 3 {
		t.Fatalf("corpora %+v", st.Corpora)
	}
	want := []CorpusRate{
		{RuleSet: "metadata", Version: "2", Positives: 12, Negatives: 20, FPRate: 0.05, FNRate: 0, TargetFP: 0.05, TargetFN: 0.1, Test: "internal/filters.TestCorpusRates", Passed: true},
		{RuleSet: "pii", Version: "4", Positives: 12, Negatives: 20, FPRate: 0.15, FNRate: 0, TargetFP: 0.05, TargetFN: 0.1, Test: "internal/filters.TestRaised", Passed: false},
		{RuleSet: "prompt-injection", Version: "3", Positives: 12, Negatives: 20, FPRate: 0, FNRate: 0.0833, TargetFP: 0.05, TargetFN: 0.1, Test: "internal/filters.TestCorpusRates", Passed: true},
	}
	for i, w := range want {
		if st.Corpora[i] != w {
			t.Errorf("corpus %d: %+v, want %+v", i, st.Corpora[i], w)
		}
	}
	// No corpus lines: an empty array, not null.
	in2 := writeFile(t, filepath.Join(dir, "none.json"), ev("pass", pkg, "TestX", "")+ev("pass", pkg, "", ""))
	args[1] = in2
	if _, err := run(args, nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(statusPath)
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	if c, ok := raw["corpora"].([]any); !ok || len(c) != 0 {
		t.Fatalf("corpora without measurements: %v", raw["corpora"])
	}
}
