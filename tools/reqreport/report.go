package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Requirement statuses (STATUS CONTRACT).
const (
	StatusVerified   = "verified"
	StatusPartial    = "partial"
	StatusFailing    = "failing"
	StatusUnverified = "unverified"
)

// ClaimRef is one test claiming one requirement.
type ClaimRef struct {
	Test    string `json:"test"`
	Result  string `json:"result"`
	Partial bool   `json:"partial"`
}

// ReqResult is the computed status of one requirement.
type ReqResult struct {
	ID       string     `json:"id"`
	Title    string     `json:"title,omitempty"`
	Element  string     `json:"element"`
	Elements []string   `json:"elements,omitempty"`
	Status   string     `json:"status"`
	InSRS    bool       `json:"inSrs"`
	Claims   []ClaimRef `json:"claims"`
}

// computeStatus applies the contract rules: failing when any claiming test
// failed; verified when at least one full claim passed; partial when only
// partial claims passed; unverified otherwise. A skipped test does not
// verify anything.
func computeStatus(claims []ClaimRef) string {
	full, part := false, false
	for _, c := range claims {
		switch c.Result {
		case "fail":
			return StatusFailing
		case "pass":
			if c.Partial {
				part = true
			} else {
				full = true
			}
		}
	}
	switch {
	case full:
		return StatusVerified
	case part:
		return StatusPartial
	default:
		return StatusUnverified
	}
}

// buildResults joins the SRS requirement list with the claims in the log.
// IDs claimed by tests but absent from the SRS are reported with InSRS false
// so a stale or mistyped claim is visible.
func buildResults(reqs []Requirement, log *TestLog, module string) []*ReqResult {
	byID := map[string]*ReqResult{}
	var out []*ReqResult
	for _, r := range reqs {
		rr := &ReqResult{ID: r.ID, Title: r.Title, Element: r.Element(), Elements: r.Elements, InSRS: true, Claims: []ClaimRef{}}
		byID[r.ID] = rr
		out = append(out, rr)
	}
	for _, t := range log.Tests {
		seen := map[Claim]bool{}
		for _, c := range t.Claims {
			if seen[c] {
				continue
			}
			seen[c] = true
			rr := byID[c.ID]
			if rr == nil {
				rr = &ReqResult{ID: c.ID, Claims: []ClaimRef{}}
				byID[c.ID] = rr
				out = append(out, rr)
			}
			res := t.Result
			if res == "" {
				res = "fail"
			}
			rr.Claims = append(rr.Claims, ClaimRef{Test: testLabel(t, module), Result: res, Partial: c.Partial})
		}
	}
	for _, rr := range out {
		sort.Slice(rr.Claims, func(i, j int) bool { return rr.Claims[i].Test < rr.Claims[j].Test })
		rr.Status = computeStatus(rr.Claims)
	}
	sort.SliceStable(out, func(i, j int) bool { return lessID(out[i].ID, out[j].ID) })
	return out
}

// testLabel is the package path relative to the module plus the full test
// name, subtest path included: "internal/e2e.TestQueue/case_1".
func testLabel(t *TestRun, module string) string {
	return shortPackage(t.Package, module) + "." + t.Name
}

// Status is the published status.json document (STATUS CONTRACT, schema 1).
type Status struct {
	Schema       int           `json:"schema"`
	GeneratedAt  string        `json:"generatedAt"`
	Commit       string        `json:"commit"`
	CommitURL    string        `json:"commitUrl"`
	RunURL       string        `json:"runUrl"`
	Tests        TestsSummary  `json:"tests"`
	Coverage     Coverage      `json:"coverage"`
	Requirements ReqSummary    `json:"requirements"`
	Elements     []ElementInfo `json:"elements"`
	Agents       []any         `json:"agents"`
	Hostile      []any         `json:"hostile"`
	// Corpora holds the false-positive and false-negative rate of each
	// detection rule-set version against its labelled corpus (FR-19.5).
	Corpora []CorpusRate `json:"corpora"`
	// Acceptance holds the AT-01 to AT-21 results and the release label
	// (FR-19.3, FR-19.4).
	Acceptance *Acceptance `json:"acceptance,omitempty"`
	// Performance holds the FR-11 measurements of the perf job; the status
	// job adds it (tools/perfrun).
	Performance any    `json:"performance,omitempty"`
	CI          CIInfo `json:"ci"`
}

type TestsSummary struct {
	Total       int          `json:"total"`
	Passed      int          `json:"passed"`
	Failed      int          `json:"failed"`
	Skipped     int          `json:"skipped"`
	DurationSec float64      `json:"durationSec"`
	Packages    []PackageSum `json:"packages"`
}

type PackageSum struct {
	Name    string `json:"name"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Skipped int    `json:"skipped"`
}

type ReqSummary struct {
	Total      int           `json:"total"`
	Verified   int           `json:"verified"`
	Partial    int           `json:"partial"`
	Failing    int           `json:"failing"`
	Unverified int           `json:"unverified"`
	ByElement  []ElementRoll `json:"byElement"`
	Items      []ReqItem     `json:"items"`
}

type ElementRoll struct {
	Element  string `json:"element"`
	Name     string `json:"name"`
	Total    int    `json:"total"`
	Verified int    `json:"verified"`
	Partial  int    `json:"partial"`
	Failing  int    `json:"failing"`
}

type ReqItem struct {
	ID      string   `json:"id"`
	Element string   `json:"element"`
	Status  string   `json:"status"`
	Tests   []string `json:"tests"`
}

type CIInfo struct {
	Workflow   string `json:"workflow"`
	Conclusion string `json:"conclusion"`
}

// Meta is run metadata, normally from the GitHub Actions environment.
type Meta struct {
	Commit     string
	Repo       string // owner/name
	ServerURL  string
	RunID      string
	Workflow   string
	Conclusion string
	Now        time.Time
}

func summarizeTests(log *TestLog) TestsSummary {
	s := TestsSummary{Packages: []PackageSum{}}
	for _, p := range log.Packages {
		if p.Passed+p.Failed+p.Skipped == 0 {
			continue // no test files
		}
		s.Passed += p.Passed
		s.Failed += p.Failed
		s.Skipped += p.Skipped
		s.Packages = append(s.Packages, PackageSum{Name: p.Name, Passed: p.Passed, Failed: p.Failed, Skipped: p.Skipped})
	}
	s.Total = s.Passed + s.Failed + s.Skipped
	if !log.Start.IsZero() && log.End.After(log.Start) {
		s.DurationSec = math.Round(log.End.Sub(log.Start).Seconds()*10) / 10
	}
	return s
}

func summarizeRequirements(results []*ReqResult, els []ElementInfo) ReqSummary {
	s := ReqSummary{ByElement: []ElementRoll{}, Items: []ReqItem{}}
	rolls := map[string]*ElementRoll{}
	for _, e := range els {
		rolls[e.ID] = &ElementRoll{Element: e.ID, Name: e.Name}
	}
	for _, r := range results {
		if !r.InSRS {
			continue
		}
		s.Total++
		tests := make([]string, 0, len(r.Claims))
		for _, c := range r.Claims {
			tests = append(tests, c.Test)
		}
		s.Items = append(s.Items, ReqItem{ID: r.ID, Element: r.Element, Status: r.Status, Tests: tests})
		roll := rolls[r.Element]
		if roll == nil && r.Element != "" {
			roll = &ElementRoll{Element: r.Element}
			rolls[r.Element] = roll
		}
		if roll != nil {
			roll.Total++
		}
		switch r.Status {
		case StatusVerified:
			s.Verified++
			if roll != nil {
				roll.Verified++
			}
		case StatusPartial:
			s.Partial++
			if roll != nil {
				roll.Partial++
			}
		case StatusFailing:
			s.Failing++
			if roll != nil {
				roll.Failing++
			}
		default:
			s.Unverified++
		}
	}
	for _, roll := range rolls {
		if roll.Total > 0 {
			s.ByElement = append(s.ByElement, *roll)
		}
	}
	sort.Slice(s.ByElement, func(i, j int) bool { return s.ByElement[i].Element < s.ByElement[j].Element })
	return s
}

func buildStatus(meta Meta, log *TestLog, cov *Coverage, results []*ReqResult, els []ElementInfo, agents, hostile []any) Status {
	st := Status{
		Schema:       1,
		GeneratedAt:  meta.Now.UTC().Format(time.RFC3339),
		Commit:       meta.Commit,
		Tests:        summarizeTests(log),
		Requirements: summarizeRequirements(results, els),
		Elements:     els,
		Agents:       agents,
		Hostile:      hostile,
		CI:           CIInfo{Workflow: meta.Workflow, Conclusion: meta.Conclusion},
	}
	server := meta.ServerURL
	if server == "" {
		server = "https://github.com"
	}
	if meta.Repo != "" && meta.Commit != "" {
		st.CommitURL = server + "/" + meta.Repo + "/commit/" + meta.Commit
	}
	if meta.Repo != "" && meta.RunID != "" {
		st.RunURL = server + "/" + meta.Repo + "/actions/runs/" + meta.RunID
	}
	if cov != nil {
		st.Coverage = *cov
	} else {
		st.Coverage = Coverage{Packages: []PackageCov{}}
	}
	if st.Agents == nil {
		st.Agents = []any{}
	}
	if st.Hostile == nil {
		st.Hostile = []any{}
	}
	st.Corpora = corpusRates(log)
	if st.Elements == nil {
		st.Elements = []ElementInfo{}
	}
	return st
}

// corpusRates collects the corpus measurements of every test, one per
// rule set and version (the last run wins), sorted by rule set and version.
func corpusRates(log *TestLog) []CorpusRate {
	byKey := map[string]CorpusRate{}
	if log != nil {
		for _, t := range log.Tests {
			for _, c := range t.Corpora {
				c.Test, c.Passed = t.Package+"."+t.Name, t.Result == "pass"
				byKey[c.RuleSet+"\x00"+c.Version] = c
			}
		}
	}
	out := make([]CorpusRate, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleSet != out[j].RuleSet {
			return out[i].RuleSet < out[j].RuleSet
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// renderMarkdown writes the human-readable report.
func renderMarkdown(st Status, results []*ReqResult) string {
	var b strings.Builder
	rs := st.Requirements
	b.WriteString("# Requirement verification report\n\n")
	if st.Commit != "" {
		fmt.Fprintf(&b, "Commit `%s`, generated %s.\n\n", short(st.Commit), st.GeneratedAt)
	}
	fmt.Fprintf(&b, "| Requirements | Verified | Partial | Failing | Unverified |\n|---|---|---|---|---|\n| %d | %d | %d | %d | %d |\n\n",
		rs.Total, rs.Verified, rs.Partial, rs.Failing, rs.Unverified)
	t := st.Tests
	fmt.Fprintf(&b, "Tests: %d passed, %d failed, %d skipped (%d total, %.1f s). Statement coverage: %.1f%%.\n\n",
		t.Passed, t.Failed, t.Skipped, t.Total, t.DurationSec, st.Coverage.TotalPct)

	var failing, stray []*ReqResult
	for _, r := range results {
		if r.Status == StatusFailing {
			failing = append(failing, r)
		}
		if !r.InSRS {
			stray = append(stray, r)
		}
	}
	if len(failing) > 0 {
		b.WriteString("## Failing\n\n| Requirement | Element | Failing tests |\n|---|---|---|\n")
		for _, r := range failing {
			var names []string
			for _, c := range r.Claims {
				if c.Result == "fail" {
					names = append(names, "`"+c.Test+"`")
				}
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", r.ID, r.Element, strings.Join(names, ", "))
		}
		b.WriteString("\n")
	}
	if len(stray) > 0 {
		b.WriteString("## Claimed IDs not in the SRS\n\n")
		for _, r := range stray {
			var names []string
			for _, c := range r.Claims {
				names = append(names, "`"+c.Test+"`")
			}
			fmt.Fprintf(&b, "- %s: %s\n", r.ID, strings.Join(names, ", "))
		}
		b.WriteString("\n")
	}

	b.WriteString("## By element\n\n| Element | Name | Total | Verified | Partial | Failing | Unverified |\n|---|---|---|---|---|---|---|\n")
	for _, e := range rs.ByElement {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %d |\n", e.Element, e.Name, e.Total, e.Verified, e.Partial, e.Failing, e.Total-e.Verified-e.Partial-e.Failing)
	}
	b.WriteString("\n## Claimed requirements\n\n| Requirement | Element | Status | Tests |\n|---|---|---|---|\n")
	for _, r := range results {
		if !r.InSRS || len(r.Claims) == 0 {
			continue
		}
		var names []string
		for _, c := range r.Claims {
			n := "`" + c.Test + "`"
			if c.Partial {
				n += " (partial)"
			}
			if c.Result != "pass" {
				n += " " + c.Result
			}
			names = append(names, n)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.ID, r.Element, r.Status, strings.Join(names, ", "))
	}

	b.WriteString("\n## Unverified requirements\n\n")
	byEl := map[string][]string{}
	var order []string
	for _, r := range results {
		if r.InSRS && r.Status == StatusUnverified {
			if _, ok := byEl[r.Element]; !ok {
				order = append(order, r.Element)
			}
			byEl[r.Element] = append(byEl[r.Element], r.ID)
		}
	}
	sort.Strings(order)
	if len(order) == 0 {
		b.WriteString("None.\n")
	}
	for _, e := range order {
		label := e
		if label == "" {
			label = "(no element)"
		}
		fmt.Fprintf(&b, "- %s (%d): %s\n", label, len(byEl[e]), strings.Join(byEl[e], ", "))
	}
	return b.String()
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
