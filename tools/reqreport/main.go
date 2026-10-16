// Command reqreport reads `go test -json` output on standard input and writes
// a report mapping each requirement ID claimed through internal/reqtest to the
// tests that verify it and their results (FR-12.10).
//
// Usage: go test -json ./... | go run ./tools/reqreport -out build/reqreport
//
// It writes <out>.json and <out>.md. The exit status is 1 when any claiming
// test failed, so CI fails on a regression of a verified requirement.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

const marker = "VERIFIES:"

type event struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

type testResult struct {
	Name   string `json:"test"`
	Result string `json:"result"`
}

type requirement struct {
	ID     string       `json:"id"`
	Result string       `json:"result"` // pass, fail, or mixed
	Tests  []testResult `json:"tests"`
}

func main() {
	out := flag.String("out", "reqreport", "output path without extension")
	flag.Parse()

	claims := map[string][]string{} // test key -> requirement IDs
	results := map[string]string{}  // test key -> pass/fail/skip
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var ev event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil || ev.Test == "" {
			continue
		}
		key := ev.Package + "." + ev.Test
		switch ev.Action {
		case "output":
			line := strings.TrimSpace(ev.Output)
			if i := strings.Index(line, marker); i >= 0 {
				for _, id := range strings.Fields(line[i+len(marker):]) {
					claims[key] = append(claims[key], id)
				}
			}
		case "pass", "fail", "skip":
			results[key] = ev.Action
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reqreport:", err)
		os.Exit(2)
	}

	byReq := map[string]*requirement{}
	for key, ids := range claims {
		res := results[key]
		if res == "" {
			res = "unknown"
		}
		for _, id := range ids {
			r := byReq[id]
			if r == nil {
				r = &requirement{ID: id}
				byReq[id] = r
			}
			r.Tests = append(r.Tests, testResult{Name: key, Result: res})
		}
	}
	reqs := make([]*requirement, 0, len(byReq))
	failed := false
	for _, r := range byReq {
		sort.Slice(r.Tests, func(i, j int) bool { return r.Tests[i].Name < r.Tests[j].Name })
		pass, fail := 0, 0
		for _, t := range r.Tests {
			if t.Result == "pass" {
				pass++
			} else if t.Result == "fail" {
				fail++
			}
		}
		switch {
		case fail > 0 && pass > 0:
			r.Result = "mixed"
			failed = true
		case fail > 0:
			r.Result = "fail"
			failed = true
		case pass > 0:
			r.Result = "pass"
		default:
			r.Result = "unknown"
		}
		reqs = append(reqs, r)
	}
	sort.Slice(reqs, func(i, j int) bool { return less(reqs[i].ID, reqs[j].ID) })

	js, _ := json.MarshalIndent(reqs, "", "  ")
	if err := os.WriteFile(*out+".json", js, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "reqreport:", err)
		os.Exit(2)
	}
	var md strings.Builder
	md.WriteString("# Requirement verification report\n\n| Requirement | Result | Tests |\n|---|---|---|\n")
	for _, r := range reqs {
		names := make([]string, 0, len(r.Tests))
		for _, t := range r.Tests {
			names = append(names, "`"+t.Name[strings.LastIndex(t.Name, "/")+1:]+"`")
		}
		fmt.Fprintf(&md, "| %s | %s | %s |\n", r.ID, r.Result, strings.Join(names, ", "))
	}
	fmt.Fprintf(&md, "\n%d requirements claimed by tests.\n", len(reqs))
	if err := os.WriteFile(*out+".md", []byte(md.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "reqreport:", err)
		os.Exit(2)
	}
	fmt.Printf("reqreport: %d requirements, written to %s.json and %s.md\n", len(reqs), *out, *out)
	if failed {
		os.Exit(1)
	}
}

// less orders requirement IDs numerically by their components.
func less(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

func parts(id string) []int {
	kind := 0
	if strings.HasPrefix(id, "SR-") {
		kind = 1
	}
	out := []int{kind}
	for _, f := range strings.FieldsFunc(id[3:], func(r rune) bool { return r == '.' || r == '-' }) {
		n := 0
		fmt.Sscanf(f, "%d", &n)
		out = append(out, n)
	}
	return out
}
