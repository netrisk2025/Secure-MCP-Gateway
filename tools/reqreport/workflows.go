package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Workflow results: some Test-method requirements are verified by a GitHub
// Actions workflow that is not part of the CI run whose `go test -json`
// output reqreport reads, for example the reference-package job (FR-14.9)
// and the Homebrew tap installation (FR-13.3). Each such workflow publishes
// its latest result to site-data/workflows.json
// (scripts/publish-workflow-result.sh); the CI status job fetches the file
// and passes it with -workflows.
//
// A result is a claim on each requirement it names. A run that succeeded is
// a full claim when it ran on a release tag (the verification statements
// ask for the release commit) and a partial claim otherwise; a run that
// failed is a failing claim. Other conclusions (cancelled, skipped) claim
// nothing and are reported as warnings.

// WorkflowResult is one entry of workflows.json.
type WorkflowResult struct {
	Workflow     string   `json:"workflow"`
	Requirements []string `json:"requirements"`
	Ref          string   `json:"ref"`
	Commit       string   `json:"commit"`
	Conclusion   string   `json:"conclusion"`
	Date         string   `json:"date"`
	RunURL       string   `json:"runUrl"`
}

var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// loadWorkflowResults reads a workflows.json array; a missing file or an
// empty path yields no results.
func loadWorkflowResults(path string) ([]WorkflowResult, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []WorkflowResult
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// label is how a workflow result appears as a claim in the reports.
func (w WorkflowResult) label() string {
	c := w.Commit
	if len(c) > 12 {
		c = c[:12]
	}
	s := fmt.Sprintf("workflow %s at %s (%s, %s)", w.Workflow, w.Ref, c, w.Date)
	if w.RunURL != "" {
		s += " " + w.RunURL
	}
	return s
}

// applyWorkflowResults adds the claims of workflow results to results. For
// each workflow only the entry with the latest date counts. It returns
// warnings for entries that claim nothing.
func applyWorkflowResults(results []*ReqResult, wfs []WorkflowResult) []string {
	byID := map[string]*ReqResult{}
	for _, rr := range results {
		byID[rr.ID] = rr
	}
	latest := map[string]WorkflowResult{}
	for _, w := range wfs {
		if prev, ok := latest[w.Workflow]; !ok || w.Date >= prev.Date {
			latest[w.Workflow] = w
		}
	}
	names := make([]string, 0, len(latest))
	for n := range latest {
		names = append(names, n)
	}
	sort.Strings(names)
	var warnings []string
	for _, n := range names {
		w := latest[n]
		var res string
		switch w.Conclusion {
		case "success":
			res = "pass"
		case "failure":
			res = "fail"
		default:
			warnings = append(warnings, fmt.Sprintf("%s: conclusion %q claims nothing", w.label(), w.Conclusion))
			continue
		}
		if w.Workflow == "" || w.Ref == "" || !commitSHA.MatchString(w.Commit) {
			warnings = append(warnings, fmt.Sprintf("%s: result needs a workflow name, a ref and a full commit SHA", w.label()))
			continue
		}
		partial := !releaseTag.MatchString(w.Ref)
		for _, id := range w.Requirements {
			rr := byID[strings.TrimSpace(id)]
			if rr == nil {
				warnings = append(warnings, fmt.Sprintf("%s: %s is not an SRS requirement", w.label(), id))
				continue
			}
			rr.Claims = append(rr.Claims, ClaimRef{Test: w.label(), Result: res, Partial: partial})
			rr.Status = computeStatus(rr.Claims)
		}
	}
	return warnings
}
