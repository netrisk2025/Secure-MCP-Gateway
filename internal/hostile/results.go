package hostile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Result is one Appendix L row as published in build/hostile.json and in
// the hostile array of the status data (FR-19.2). Profile and Requirements
// are additions to the five published fields (fixture, attack, expected,
// observed, pass).
type Result struct {
	Fixture      string   `json:"fixture"`
	Attack       string   `json:"attack"`
	Expected     string   `json:"expected"`
	Observed     string   `json:"observed"`
	Pass         bool     `json:"pass"`
	Profile      string   `json:"profile"`
	Requirements []string `json:"requirements"`
}

// Profiles are the suite's profiles in report order.
var Profiles = []string{"standalone", "enforced"}

// HarnessError is the observed text of a row whose check could not run.
const HarnessError = "harness error (see the test log)"

// WriteResults writes <dir>/hostile-<profile>.json, then merges every
// profile file present in dir into <dir>/hostile.json and <dir>/hostile.md,
// and returns the merged rows.
func WriteResults(dir, profile string, results []Result) ([]Result, error) {
	results = slices.Clone(results)
	slices.SortFunc(results, func(a, b Result) int { return strings.Compare(a.Fixture, b.Fixture) })
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := writeJSONFile(filepath.Join(dir, "hostile-"+profile+".json"), results); err != nil {
		return nil, err
	}
	byProfile := map[string][]Result{}
	for _, p := range Profiles {
		b, err := os.ReadFile(filepath.Join(dir, "hostile-"+p+".json"))
		if err != nil {
			continue
		}
		var rs []Result
		if err := json.Unmarshal(b, &rs); err != nil {
			return nil, fmt.Errorf("hostile-%s.json: %w", p, err)
		}
		byProfile[p] = rs
	}
	merged := Merge(byProfile)
	if err := writeJSONFile(filepath.Join(dir, "hostile.json"), merged); err != nil {
		return nil, err
	}
	return merged, os.WriteFile(filepath.Join(dir, "hostile.md"), []byte(Markdown(merged)), 0o644)
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Merge combines per-profile results into one entry per Appendix L row.
// The observed text lists every profile that ran. A row asserted in "Both"
// profiles passes when it passed in every profile whose check ran; an
// Enforced row passes only on an Enforced result. A harness error is shown
// but counts as not run.
func Merge(by map[string][]Result) []Result {
	out := make([]Result, 0, len(Rows))
	for _, row := range Rows {
		m := Result{Fixture: row.ID, Attack: row.Attack, Expected: row.Expected, Requirements: row.Requirements}
		var parts, profiles []string
		pass, counted := true, 0
		enforcedRan := false
		for _, p := range Profiles {
			for _, r := range by[p] {
				if r.Fixture != row.ID {
					continue
				}
				profiles = append(profiles, p)
				parts = append(parts, p+": "+r.Observed)
				if r.Observed == HarnessError || (row.EnforcedOnly() && p != "enforced") {
					continue
				}
				enforcedRan = enforcedRan || p == "enforced"
				counted++
				pass = pass && r.Pass
			}
		}
		m.Pass = counted > 0 && pass && (!row.EnforcedOnly() || enforcedRan)
		m.Profile = strings.Join(profiles, "+")
		m.Observed = strings.Join(parts, " | ")
		if len(parts) == 0 {
			m.Observed = "not run"
		}
		out = append(out, m)
	}
	return out
}

// Markdown renders merged results as a table for the CI job summary.
func Markdown(rs []Result) string {
	var sb strings.Builder
	n := 0
	for _, r := range rs {
		if r.Pass {
			n++
		}
	}
	fmt.Fprintf(&sb, "## Hostile fixtures (SRS Appendix L)\n\n%d of %d rows behaved as expected.\n\n", n, len(rs))
	sb.WriteString("| Row | Attack | Pass | Profiles | Observed |\n|---|---|---|---|---|\n")
	for _, r := range rs {
		mark := "no"
		if r.Pass {
			mark = "yes"
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n", r.Fixture, mdCell(r.Attack), mark, r.Profile, mdCell(r.Observed))
	}
	return sb.String()
}

func mdCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
