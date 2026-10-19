package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Requirement is one SRS requirement read from srs_build/req*.txt.
type Requirement struct {
	ID       string
	Title    string
	Elements []string // E-xx IDs from the A: allocation line, in source order
	Parent   string   // the P: line ("" for "—" or a SEC parent)
	Method   string   // verification method from the V: line (Test, Inspection, Analysis, Demonstration)
	Verify   string   // verification statement from the V: line
	// Deferred is set by a DEFER: line: the requirement is deferred from
	// release 1.0 (SRS Section 2.7, Appendix N) and is not part of the
	// requirement set the report covers.
	Deferred bool
}

// Element returns the primary element: the first E-xx in the allocation.
func (r Requirement) Element() string {
	if len(r.Elements) == 0 {
		return ""
	}
	return r.Elements[0]
}

var (
	idPattern      = regexp.MustCompile(`^(FR-\d+(\.\d+)?|SR-\d+(\.\d+)?-\d+)$`)
	elementPattern = regexp.MustCompile(`^E-\d\d$`)
)

// loadRequirements parses every req*.txt in dir. The record format is
// documented in srs_build/README.md: "@ID | Title", then KEY: value lines,
// ending at a blank line. "@DISP" lines are SEC dispositions, not
// requirements. Records with a DEFER: line are deferred and left out.
func loadRequirements(dir string) ([]Requirement, error) {
	files, err := filepath.Glob(filepath.Join(dir, "req*.txt"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no req*.txt files in %s", dir)
	}
	sort.Strings(files)
	var out []Requirement
	seen := map[string]bool{}
	for _, fn := range files {
		f, err := os.Open(fn)
		if err != nil {
			return nil, err
		}
		var cur *Requirement
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<16), 1<<22)
		flush := func() {
			if cur != nil && !cur.Deferred && !seen[cur.ID] {
				seen[cur.ID] = true
				out = append(out, *cur)
			}
			cur = nil
		}
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), " \t\r")
			switch {
			case strings.HasPrefix(line, "@DISP "):
				continue
			case strings.HasPrefix(line, "@"):
				flush()
				id, title, _ := strings.Cut(line[1:], " | ")
				cur = &Requirement{ID: strings.TrimSpace(id), Title: strings.TrimSpace(title)}
			case line == "":
				flush()
			case cur != nil && strings.HasPrefix(line, "DEFER: "):
				cur.Deferred = true
			case cur != nil && strings.HasPrefix(line, "P: "):
				if p := strings.TrimSpace(line[3:]); idPattern.MatchString(p) {
					cur.Parent = p
				}
			case cur != nil && strings.HasPrefix(line, "V: "):
				m, stmt, _ := strings.Cut(line[3:], "|")
				cur.Method, cur.Verify = strings.TrimSpace(m), strings.TrimSpace(stmt)
			case cur != nil && strings.HasPrefix(line, "A: "):
				for _, tok := range strings.Split(line[3:], ";") {
					tok = strings.TrimSpace(tok)
					if elementPattern.MatchString(tok) {
						cur.Elements = append(cur.Elements, tok)
					}
				}
			}
		}
		flush()
		_ = f.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", fn, err)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return lessID(out[i].ID, out[j].ID) })
	return out, nil
}

// ElementInfo is one architecture element with its implementation status.
type ElementInfo struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Subsystem      string   `json:"subsystem"`
	Implementation string   `json:"implementation"`
	Packages       []string `json:"packages"`
	// Note is the free-text summary from docs/status/elements.json; the
	// site shows it on element pages.
	Note string `json:"note,omitempty"`
}

var (
	subsystemHeading = regexp.MustCompile(`^### (SS-\d+) `)
	elementHeading   = regexp.MustCompile(`^#### (E-\d\d) (.+?) — T`)
)

// loadElements reads element names and subsystems from the "#### E-xx Name —
// Tn" headings under "### SS-n" headings of ArchitectureV2.md.
func loadElements(archPath string) ([]ElementInfo, error) {
	b, err := os.ReadFile(archPath)
	if err != nil {
		return nil, err
	}
	var out []ElementInfo
	seen := map[string]bool{}
	ss := ""
	for _, line := range strings.Split(string(b), "\n") {
		if m := subsystemHeading.FindStringSubmatch(line); m != nil {
			ss = m[1]
			continue
		}
		if m := elementHeading.FindStringSubmatch(line); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, ElementInfo{ID: m[1], Name: strings.TrimSpace(m[2]), Subsystem: ss, Implementation: "not-started", Packages: []string{}})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no element headings found", archPath)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// elementStatus is one entry of docs/status/elements.json.
type elementStatus struct {
	ID             string   `json:"id"`
	Implementation string   `json:"implementation"`
	Packages       []string `json:"packages"`
	Note           string   `json:"note"`
}

var implementationValues = map[string]bool{"implemented": true, "partial": true, "not-started": true}

// mergeElementStatus overlays the checked-in implementation status onto the
// architecture element list. A missing file is not an error.
func mergeElementStatus(els []ElementInfo, path string) ([]ElementInfo, error) {
	if path == "" {
		return els, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return els, nil
	}
	if err != nil {
		return nil, err
	}
	var st []elementStatus
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	idx := map[string]int{}
	for i, e := range els {
		idx[e.ID] = i
	}
	for _, s := range st {
		i, ok := idx[s.ID]
		if !ok {
			return nil, fmt.Errorf("%s: unknown element %q", path, s.ID)
		}
		if s.Implementation != "" {
			if !implementationValues[s.Implementation] {
				return nil, fmt.Errorf("%s: element %s: implementation %q is not implemented, partial or not-started", path, s.ID, s.Implementation)
			}
			els[i].Implementation = s.Implementation
		}
		if s.Packages != nil {
			els[i].Packages = s.Packages
		}
		els[i].Note = s.Note
	}
	return els, nil
}

// lessID orders requirement IDs: FR before SR, then numerically by component.
func lessID(a, b string) bool {
	pa, pb := idParts(a), idParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	if len(pa) != len(pb) {
		return len(pa) < len(pb)
	}
	return a < b
}

func idParts(id string) []int {
	kind := 2
	switch {
	case strings.HasPrefix(id, "FR-"):
		kind = 0
	case strings.HasPrefix(id, "SR-"):
		kind = 1
	}
	out := []int{kind}
	if len(id) < 3 {
		return out
	}
	for _, f := range strings.FieldsFunc(id[3:], func(r rune) bool { return r == '.' || r == '-' }) {
		n := 0
		_, _ = fmt.Sscanf(f, "%d", &n)
		out = append(out, n)
	}
	return out
}
