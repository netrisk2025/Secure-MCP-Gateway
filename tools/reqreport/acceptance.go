package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Acceptance scenarios and the release label (FR-19.3, FR-19.4).
//
// The scenarios AT-01 to AT-21 are read from the Appendix M table of
// srs_build/appendix2.md. A test claims a scenario with reqtest.Scenario,
// which logs "SCENARIO: AT-nn profile=<standalone|enforced>"; a person's
// execution is a record docs/verification/AT-nn.md (records.go). For each
// profile a scenario is
//
//   - fail: a claiming test in that profile failed (or never finished), or
//     the latest record for this commit and profile says fail;
//   - pass: at least one claiming test or record for this commit passed and
//     nothing failed;
//   - not-run: otherwise (a skipped test is not a result).
//
// The release is labelled "enforced" only when every Appendix M scenario
// passed in the Enforced profile for the commit of the status document, and
// "not enforced" otherwise.

const (
	profileStandalone = "standalone"
	profileEnforced   = "enforced"

	resultPass   = "pass"
	resultFail   = "fail"
	resultNotRun = "not-run"

	LabelEnforced    = "enforced"
	LabelNotEnforced = "not enforced"
)

var scenarioPattern = regexp.MustCompile(`^AT-(0[1-9]|1[0-9]|2[01])$`)

// Scenario is one row of SRS Appendix M.
type Scenario struct {
	ID           string
	Title        string
	Realization  string
	Requirements []string
	Evidence     string
}

// ScenarioTest is one test claiming a scenario.
type ScenarioTest struct {
	Test    string `json:"test"`
	Result  string `json:"result"`
	Profile string `json:"profile"`
}

// ScenarioRecord is one recorded execution docs/verification/AT-nn.md.
type ScenarioRecord struct {
	Record  string `json:"record"`
	Commit  string `json:"commit"`
	Profile string `json:"profile"`
	Date    string `json:"date"`
	Result  string `json:"result"`
	// Counted is false when the record is for another commit or is
	// incomplete; it is listed but does not decide the result.
	Counted bool   `json:"counted"`
	Note    string `json:"note,omitempty"`
}

// ScenarioResult is the computed state of one scenario.
type ScenarioResult struct {
	ID           string           `json:"id"`
	Title        string           `json:"title"`
	Evidence     string           `json:"evidence"`
	Requirements []string         `json:"requirements"`
	Enforced     string           `json:"enforced"`
	Standalone   string           `json:"standalone"`
	Tests        []ScenarioTest   `json:"tests"`
	Records      []ScenarioRecord `json:"records"`
}

// Acceptance is the "acceptance" member of the status document.
type Acceptance struct {
	Commit string `json:"commit"`
	// Label is "enforced" or "not enforced" (FR-19.3).
	Label string `json:"label"`
	// Reasons lists, for "not enforced", each scenario without an Enforced
	// pass and why.
	Reasons []string `json:"reasons"`
	Total   int      `json:"total"`
	// EnforcedPassed and StandalonePassed count scenarios that passed in
	// each profile.
	EnforcedPassed   int              `json:"enforcedPassed"`
	StandalonePassed int              `json:"standalonePassed"`
	Scenarios        []ScenarioResult `json:"scenarios"`
}

// loadScenarios reads the Appendix M table: rows "| AT-nn Title | realization
// | requirements | evidence |".
func loadScenarios(path string) ([]Scenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Scenario
	in := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "## ") {
			in = strings.Contains(line, "Appendix M")
			continue
		}
		if !in || !strings.HasPrefix(line, "| AT-") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 4 {
			continue
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		id, title, _ := strings.Cut(cells[0], " ")
		if !scenarioPattern.MatchString(id) {
			continue
		}
		s := Scenario{ID: id, Title: title, Realization: cells[1], Evidence: cells[3], Requirements: []string{}}
		for _, r := range strings.Split(cells[2], ",") {
			r = strings.TrimSpace(strings.SplitN(r, ";", 2)[0])
			if idPattern.MatchString(r) {
				s.Requirements = append(s.Requirements, r)
			}
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no Appendix M scenario rows", path)
	}
	return out, nil
}

// recordProfile maps the record field "Profile and platform" to a profile.
func recordProfile(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(l, profileEnforced):
		return profileEnforced
	case strings.HasPrefix(l, profileStandalone):
		return profileStandalone
	}
	return ""
}

// buildAcceptance computes every scenario's results for commit.
func buildAcceptance(scenarios []Scenario, log *TestLog, recs []Record, recordsDir, commit, module string) Acceptance {
	a := Acceptance{Commit: commit, Reasons: []string{}, Total: len(scenarios), Scenarios: []ScenarioResult{}}
	tests := map[string][]ScenarioTest{}
	for _, t := range log.Tests {
		seen := map[ScenarioClaim]bool{}
		for _, c := range t.Scenarios {
			if seen[c] {
				continue
			}
			seen[c] = true
			res := t.Result
			if res == "" {
				res = resultFail
			}
			tests[c.ID] = append(tests[c.ID], ScenarioTest{Test: testLabel(t, module), Result: res, Profile: c.Profile})
		}
	}
	records := map[string][]ScenarioRecord{}
	for _, r := range recs {
		for _, id := range r.Scenarios {
			sr := ScenarioRecord{Record: r.Label(recordsDir), Commit: r.Fields["Commit"], Profile: recordProfile(r.Fields["Profile and platform"]),
				Date: r.Fields["Date"], Result: r.Fields["Result"]}
			switch {
			case len(r.Problems) > 0:
				sr.Note = "incomplete: " + strings.Join(r.Problems, "; ")
			case sr.Profile == "":
				sr.Note = "profile is neither Enforced nor Standalone"
			case commit == "" || sr.Commit != commit:
				sr.Note = "recorded for another commit"
			default:
				sr.Counted = true
			}
			records[id] = append(records[id], sr)
		}
	}
	for _, s := range scenarios {
		ts := tests[s.ID]
		if ts == nil {
			ts = []ScenarioTest{}
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i].Test < ts[j].Test })
		rs := records[s.ID]
		if rs == nil {
			rs = []ScenarioRecord{}
		}
		res := ScenarioResult{ID: s.ID, Title: s.Title, Evidence: s.Evidence, Requirements: s.Requirements, Tests: ts, Records: rs,
			Enforced: profileResult(ts, rs, profileEnforced), Standalone: profileResult(ts, rs, profileStandalone)}
		if res.Enforced == resultPass {
			a.EnforcedPassed++
		} else {
			why := "no automated or recorded result in the Enforced profile"
			if res.Enforced == resultFail {
				why = "failed in the Enforced profile"
			}
			a.Reasons = append(a.Reasons, s.ID+" "+s.Title+": "+why)
		}
		if res.Standalone == resultPass {
			a.StandalonePassed++
		}
		a.Scenarios = append(a.Scenarios, res)
	}
	a.Label = LabelNotEnforced
	if a.Total == 21 && a.EnforcedPassed == a.Total {
		a.Label = LabelEnforced
	}
	if a.Total != 21 {
		a.Reasons = append(a.Reasons, fmt.Sprintf("Appendix M lists %d scenarios, not 21", a.Total))
	}
	return a
}

// profileResult applies the rules in the file comment. For records, the
// latest counted record of the profile decides.
func profileResult(ts []ScenarioTest, rs []ScenarioRecord, profile string) string {
	pass, fail := false, false
	for _, t := range ts {
		if t.Profile != profile {
			continue
		}
		switch t.Result {
		case "pass":
			pass = true
		case "fail":
			fail = true
		}
	}
	var latest *ScenarioRecord
	for i := range rs {
		r := &rs[i]
		if r.Counted && r.Profile == profile && (latest == nil || r.Date >= latest.Date) {
			latest = r
		}
	}
	if latest != nil {
		switch latest.Result {
		case "pass":
			pass = true
		case "fail":
			fail = true
		}
	}
	switch {
	case fail:
		return resultFail
	case pass:
		return resultPass
	}
	return resultNotRun
}

// renderAcceptance is the Markdown section of the report and the release
// notes.
func renderAcceptance(a Acceptance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Release label: **%s**. Scenarios passed in the Enforced profile: %d of %d; in the Standalone profile: %d of %d.\n\n",
		a.Label, a.EnforcedPassed, a.Total, a.StandalonePassed, a.Total)
	b.WriteString("| Scenario | Evidence | Enforced | Standalone | Claimed by |\n|---|---|---|---|---|\n")
	for _, s := range a.Scenarios {
		var by []string
		for _, t := range s.Tests {
			n := "`" + t.Test + "` (" + t.Profile
			if t.Result != "pass" {
				n += ", " + t.Result
			}
			by = append(by, n+")")
		}
		for _, r := range s.Records {
			n := "`" + r.Record + "` (" + r.Result
			if !r.Counted {
				n += ", not counted: " + r.Note
			}
			by = append(by, n+")")
		}
		if len(by) == 0 {
			by = []string{"none"}
		}
		fmt.Fprintf(&b, "| %s %s | %s | %s | %s | %s |\n", s.ID, s.Title, s.Evidence, s.Enforced, s.Standalone, strings.Join(by, ", "))
	}
	return b.String()
}
