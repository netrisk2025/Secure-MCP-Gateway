package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Verification records (SRS Section 2.6): a requirement whose verification
// method is Inspection, Analysis or Demonstration is verified when a
// complete record with result "pass" is checked in under docs/verification/.
// The record format is described in docs/verification/README.md. A record
// is a field table that starts with the row "| Requirement or scenario |
// ... |"; everything up to the next record's first row belongs to it,
// including its evidence references.

// recordFields are the fields every record must fill in.
var recordFields = []string{"Requirement or scenario", "Commit", "Profile and platform", "Date", "Executor", "Method", "Result"}

var (
	fieldRow     = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|\s*$`)
	commitSHA    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	isoDate      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	evidenceRef  = regexp.MustCompile("`([A-Za-z0-9_.][A-Za-z0-9_./-]*\\.[A-Za-z][A-Za-z0-9]*):(\\d+)(?:-(\\d+))?`")
	recordIDList = regexp.MustCompile(`(FR-\d+(?:\.\d+)?|SR-\d+(?:\.\d+)?-\d+)`)
	recordATList = regexp.MustCompile(`\bAT-\d\d\b`)
)

// evidenceRef matches `path/file.ext:line` (or `:line-line`); the file
// name must end in an extension starting with a letter, so addresses such
// as `127.0.0.1:8443` are not taken for evidence.

// recordMethods are the methods a record can verify; Test-method
// requirements are verified only by automated tests.
var recordMethods = map[string]bool{"Inspection": true, "Analysis": true, "Demonstration": true}

// supportingMethod marks a record of a manual step that the SRS asks to
// file next to the automated tests of a Test-method requirement (for
// example the manual focus-order, target-size and contrast check of
// FR-8.32). It is validated like any record and must name a Test-method
// requirement, but it never counts as verification.
const supportingMethod = "Test"

// Record is one parsed verification record.
type Record struct {
	File   string            // path relative to the records directory
	Line   int               // line of the first field row
	Fields map[string]string // field name -> content
	IDs    []string          // requirement IDs named by the record
	// Scenarios are the acceptance scenario IDs (AT-nn) named by the
	// record (FR-19.4); acceptance.go counts them.
	Scenarios []string
	Evidence  []string // `path:line` references in the record
	Problems  []string // why the record cannot count (empty when valid)
}

// Label is how the record appears as a claim in the reports.
func (r Record) Label(dir string) string {
	return filepath.ToSlash(filepath.Join(dir, r.File)) + fmt.Sprintf(":%d", r.Line)
}

// loadRecords parses every Markdown file under dir except README.md files. A
// missing directory yields no records. Evidence paths are checked against
// root: a reference to a file that does not exist makes the record invalid.
func loadRecords(dir, root string) ([]Record, error) {
	if dir == "" {
		return nil, nil
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	// Records may sit in subdirectories, for example the runbook
	// executions under runbooks/.
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []Record
	for _, fn := range files {
		if filepath.Base(fn) == "README.md" {
			continue
		}
		recs, err := parseRecords(fn)
		if err != nil {
			return nil, err
		}
		for i := range recs {
			recs[i].File, _ = filepath.Rel(dir, fn)
			recs[i].validate(root)
		}
		out = append(out, recs...)
	}
	return out, nil
}

func parseRecords(fn string) ([]Record, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	var cur *Record
	inTable := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		m := fieldRow.FindStringSubmatch(line)
		if m != nil && m[1] == "Requirement or scenario" {
			out = append(out, Record{Line: n, Fields: map[string]string{}})
			cur = &out[len(out)-1]
			inTable = true
		}
		if cur == nil {
			continue
		}
		if inTable {
			if m == nil {
				inTable = false
			} else if _, seen := cur.Fields[m[1]]; !seen {
				cur.Fields[m[1]] = strings.Trim(m[2], "` ")
			}
		}
		for _, ref := range evidenceRef.FindAllStringSubmatch(line, -1) {
			cur.Evidence = append(cur.Evidence, ref[1]+":"+ref[2])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", fn, err)
	}
	for i := range out {
		out[i].IDs = recordIDList.FindAllString(out[i].Fields["Requirement or scenario"], -1)
		for _, id := range recordATList.FindAllString(out[i].Fields["Requirement or scenario"], -1) {
			if scenarioPattern.MatchString(id) {
				out[i].Scenarios = append(out[i].Scenarios, id)
			}
		}
	}
	return out, nil
}

// validate fills Problems: missing fields, malformed commit or date, an
// unknown method or result, no requirement ID, an Inspection without
// evidence, or evidence naming a file that does not exist under root.
func (r *Record) validate(root string) {
	for _, k := range recordFields {
		if r.Fields[k] == "" {
			r.Problems = append(r.Problems, "missing field "+k)
		}
	}
	if c := r.Fields["Commit"]; c != "" && !commitSHA.MatchString(c) {
		r.Problems = append(r.Problems, "commit is not a full SHA")
	}
	if d := r.Fields["Date"]; d != "" && !isoDate.MatchString(d) {
		r.Problems = append(r.Problems, "date is not ISO 8601")
	}
	if m := r.Fields["Method"]; m != "" && !recordMethods[m] && m != supportingMethod {
		r.Problems = append(r.Problems, "method "+m+" cannot be verified by a record")
	}
	if res := r.Fields["Result"]; res != "" && res != "pass" && res != "fail" {
		r.Problems = append(r.Problems, "result is not pass or fail")
	}
	if len(r.IDs) == 0 && len(r.Scenarios) == 0 {
		r.Problems = append(r.Problems, "no requirement ID")
	}
	if r.Fields["Method"] == "Inspection" && len(r.Evidence) == 0 {
		r.Problems = append(r.Problems, "inspection without file:line evidence")
	}
	for _, ev := range r.Evidence {
		path, _, _ := strings.Cut(ev, ":")
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); err != nil {
			r.Problems = append(r.Problems, "evidence file "+path+" does not exist")
		}
	}
}

// applyRecords adds record claims to results. A valid record counts for a
// requirement only when its method equals the SRS verification method; for
// each requirement the record with the latest date decides (a later passing
// run supersedes a failed one, and a later failure supersedes a pass).
// It returns warnings for records that were not counted.
func applyRecords(results []*ReqResult, reqs []Requirement, recs []Record, dir string) []string {
	method := map[string]string{}
	for _, r := range reqs {
		method[r.ID] = r.Method
	}
	byID := map[string]*ReqResult{}
	for _, rr := range results {
		byID[rr.ID] = rr
	}
	var warnings []string
	latest := map[string]Record{}
	for _, rec := range recs {
		if len(rec.Problems) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: record not counted: %s", rec.Label(dir), strings.Join(rec.Problems, "; ")))
			continue
		}
		for _, id := range rec.IDs {
			m, ok := method[id]
			switch {
			case !ok:
				warnings = append(warnings, fmt.Sprintf("%s: %s is not an SRS requirement", rec.Label(dir), id))
				continue
			case m != rec.Fields["Method"]:
				warnings = append(warnings, fmt.Sprintf("%s: %s is verified by %s, not %s", rec.Label(dir), id, m, rec.Fields["Method"]))
				continue
			case m == supportingMethod:
				continue // supporting record of a Test-method requirement
			}
			if prev, ok := latest[id]; !ok || rec.Fields["Date"] >= prev.Fields["Date"] {
				latest[id] = rec
			}
		}
	}
	for id, rec := range latest {
		rr := byID[id]
		rr.Claims = append(rr.Claims, ClaimRef{Test: rec.Label(dir), Result: rec.Fields["Result"]})
		rr.Status = computeStatus(rr.Claims)
	}
	sort.Strings(warnings)
	return warnings
}

// childAnalysisPrefix starts the verification statement of a parent
// requirement whose Analysis is the review of its children's results.
const childAnalysisPrefix = "Review the verification results of every"

// applyChildAnalysis verifies a parent requirement whose verification is
// the Analysis "Review the verification results of every <ID> child
// requirement; confirm each has passed" when every child requirement is
// verified. It runs to a fixed point so nested parents resolve. The claim
// names the number of children reviewed.
//
// A parent that stays unverified, has no claim of its own, and has no
// failing child but at least one verified or partly verified child is
// reported partial, with a partial claim naming how many children are
// verified. A partial parent is never verified by this rule; it becomes
// verified only when every child is, or through evidence for its own
// statement.
func applyChildAnalysis(results []*ReqResult, reqs []Requirement) {
	children := map[string][]string{}
	for _, r := range reqs {
		if r.Parent != "" {
			children[r.Parent] = append(children[r.Parent], r.ID)
		}
	}
	byID := map[string]*ReqResult{}
	for _, rr := range results {
		byID[rr.ID] = rr
	}
	for changed := true; changed; {
		changed = false
		for _, r := range reqs {
			kids := children[r.ID]
			rr := byID[r.ID]
			if r.Method != "Analysis" || !strings.HasPrefix(r.Verify, childAnalysisPrefix) || len(kids) == 0 || rr.Status == StatusVerified || rr.Status == StatusFailing {
				continue
			}
			all := true
			for _, k := range kids {
				if byID[k] == nil || byID[k].Status != StatusVerified {
					all = false
					break
				}
			}
			if all {
				rr.Claims = append(rr.Claims, ClaimRef{Test: fmt.Sprintf("analysis: all %d child requirements verified", len(kids)), Result: "pass"})
				rr.Status = computeStatus(rr.Claims)
				changed = true
			}
		}
	}
	// Partial roll-up, also to a fixed point so a partial nested parent
	// makes its own parent partial.
	for changed := true; changed; {
		changed = false
		for _, r := range reqs {
			kids := children[r.ID]
			rr := byID[r.ID]
			if r.Method != "Analysis" || !strings.HasPrefix(r.Verify, childAnalysisPrefix) || len(kids) == 0 || rr.Status != StatusUnverified || len(rr.Claims) > 0 {
				continue
			}
			verified, evidenced, failing := 0, 0, false
			for _, k := range kids {
				switch st := byID[k]; {
				case st == nil:
				case st.Status == StatusFailing:
					failing = true
				case st.Status == StatusVerified:
					verified++
					evidenced++
				case st.Status == StatusPartial:
					evidenced++
				}
			}
			if failing || evidenced == 0 {
				continue
			}
			rr.Claims = append(rr.Claims, ClaimRef{Test: fmt.Sprintf("analysis: %d of %d child requirements verified", verified, len(kids)), Result: "pass", Partial: true})
			rr.Status = computeStatus(rr.Claims)
			changed = true
		}
	}
}
