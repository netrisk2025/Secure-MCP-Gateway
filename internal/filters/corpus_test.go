package filters

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// splitMarker separates secret-shaped corpus samples so that repository
// secret scanners do not flag them; the loader removes it.
const splitMarker = "⟨⟩"

type sample struct {
	Label string `json:"label"`
	Text  string `json:"text"`
	Note  string `json:"note"`
}

func loadCorpus(t *testing.T, name string) []sample {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "corpus", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var s sample
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Label != "positive" && s.Label != "negative" {
			t.Fatalf("%s: label %q", name, s.Label)
		}
		s.Text = strings.ReplaceAll(s.Text, splitMarker, "")
		out = append(out, s)
	}
	return out
}

// detector returns whether a rule-set version flags a text. The metadata
// rule set is evaluated the way the metadata scan applies it: together with
// the unicode-control rules, on a tool description.
func detector(in *Inspector, rs *RuleSet) func(string) bool {
	if rs.ID == RuleSetMetadata {
		return func(s string) bool {
			return blocking(in.ScanTool("x", &mcp.Tool{Name: "t", Description: s}, nil, nil))
		}
	}
	return func(s string) bool { return len(rs.Scan(s)) > 0 }
}

// CorpusRates is one measured rate pair (FR-19.5).
type CorpusRates struct {
	RuleSet, Version             string
	Positives, Negatives, FP, FN int
}

func (c CorpusRates) FPRate() float64 { return ratio(c.FP, c.Negatives) }
func (c CorpusRates) FNRate() float64 { return ratio(c.FN, c.Positives) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func measure(t *testing.T, in *Inspector, rs *RuleSet) (CorpusRates, []string) {
	t.Helper()
	if rs.Corpus == "" {
		t.Fatalf("rule set %s %s has no corpus", rs.ID, rs.Version)
	}
	detect := detector(in, rs)
	r := CorpusRates{RuleSet: rs.ID, Version: rs.Version}
	var misses []string
	for _, s := range loadCorpus(t, rs.Corpus) {
		hit := detect(s.Text)
		switch s.Label {
		case "positive":
			r.Positives++
			if !hit {
				r.FN++
				misses = append(misses, "missed positive: "+s.Note)
			}
		default:
			r.Negatives++
			if hit {
				r.FP++
				misses = append(misses, "false positive: "+s.Note)
			}
		}
	}
	return r, misses
}

// TestCorpusRates measures the false-positive and false-negative rate of
// every rule-set version in the index against its labelled corpus and
// fails when a rate exceeds the target recorded in the index, which is how
// a rule change that raises a rate is reported. The CORPUS lines are the
// published result: tools/reqreport collects them from the CI test run
// into the "corpora" array of status.json, which the status job publishes
// (FR-19.5; tools/reqreport TestCorpusRatesPublished).
func TestCorpusRates(t *testing.T) {
	reqtest.Verifies(t, "FR-19.5")
	reqtest.Partial(t, "FR-4.16")
	in := newTestInspector(t, Options{})
	for _, rs := range in.Library().All() {
		r, misses := measure(t, in, rs)
		t.Logf("CORPUS rule_set=%s version=%s positives=%d negatives=%d fp_rate=%.4f fn_rate=%.4f target_fp=%.4f target_fn=%.4f",
			r.RuleSet, r.Version, r.Positives, r.Negatives, r.FPRate(), r.FNRate(), rs.Targets.FalsePositiveRate, rs.Targets.FalseNegativeRate)
		for _, m := range misses {
			t.Logf("  %s %s: %s", rs.ID, rs.Version, m)
		}
		if r.Positives < 10 || r.Negatives < 10 {
			t.Errorf("%s %s: corpus too small (%d positive, %d negative)", rs.ID, rs.Version, r.Positives, r.Negatives)
		}
		if r.FPRate() > rs.Targets.FalsePositiveRate+1e-9 || r.FNRate() > rs.Targets.FalseNegativeRate+1e-9 {
			t.Errorf("%s %s: rates fp=%.4f fn=%.4f exceed targets fp=%.4f fn=%.4f", rs.ID, rs.Version, r.FPRate(), r.FNRate(),
				rs.Targets.FalsePositiveRate, rs.Targets.FalseNegativeRate)
		}
	}
}

// TestUnicodeCorpus is SR-5.14-1: zero false positives on the legitimate
// multilingual and source-code samples and detection of every hostile
// sample, for bidi overrides, zero-width joiners outside permitted scripts
// and tag characters.
func TestUnicodeCorpus(t *testing.T) {
	reqtest.Verifies(t, "SR-5.14-1")
	in := newTestInspector(t, Options{})
	r, misses := measure(t, in, in.RuleSet(RuleSetUnicode))
	if r.FP != 0 || r.FN != 0 {
		t.Fatalf("unicode corpus: %d false positives, %d false negatives: %s", r.FP, r.FN, strings.Join(misses, "; "))
	}
	for _, rule := range []string{"bidi-control", "zero-width", "tag-characters"} {
		found := false
		for _, s := range loadCorpus(t, in.RuleSet(RuleSetUnicode).Corpus) {
			for _, m := range in.RuleSet(RuleSetUnicode).Scan(s.Text) {
				found = found || m.Rule.ID == rule
			}
		}
		if !found {
			t.Errorf("no hostile sample exercises %s", rule)
		}
	}
}
