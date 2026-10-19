package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// runLabel is "reqreport label": it reads a status document and prints the
// release label of FR-19.3 for a release commit. The label is "enforced"
// only when the document is for that commit and every Appendix M scenario
// passed in the Enforced profile; otherwise it is "not enforced" and the
// reasons are listed. With -out it writes the release-notes section
// (Markdown). The exit status is 0 for either label and 2 when the document
// cannot be read.
//
//	go run ./tools/reqreport label -status status.json -commit "$GITHUB_SHA" -out build/release-label.md
func runLabel(args []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet("label", flag.ContinueOnError)
	status := flags.String("status", "build/status.json", "status document (status.json of the release commit)")
	commit := flags.String("commit", os.Getenv("GITHUB_SHA"), "release commit SHA (default $GITHUB_SHA)")
	out := flags.String("out", "", "write the release-notes section here (optional)")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	b, err := os.ReadFile(*status)
	if err != nil {
		return 2, err
	}
	var st struct {
		Commit     string      `json:"commit"`
		Acceptance *Acceptance `json:"acceptance"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return 2, fmt.Errorf("%s: %w", *status, err)
	}
	label, reasons, table := releaseLabel(st.Commit, st.Acceptance, *commit)
	fmt.Fprintf(stdout, "release label: %s\n", label)
	for _, r := range reasons {
		fmt.Fprintf(stdout, "  %s\n", r)
	}
	if *out != "" {
		var md strings.Builder
		md.WriteString("## Acceptance (FR-19.3)\n\n")
		if table {
			md.WriteString(renderAcceptance(*st.Acceptance))
		} else {
			fmt.Fprintf(&md, "Release label: **%s**.\n\n", label)
		}
		if len(reasons) > 0 {
			md.WriteString("\nWhy the release is not labelled enforced:\n\n")
			for _, r := range reasons {
				md.WriteString("- " + r + "\n")
			}
		}
		if err := os.WriteFile(*out, []byte(md.String()), 0o644); err != nil {
			return 2, err
		}
	}
	return 0, nil
}

// releaseLabel decides the FR-19.3 label of commit from a status document.
// table reports whether the document's scenario table applies to commit.
func releaseLabel(statusCommit string, a *Acceptance, commit string) (label string, reasons []string, table bool) {
	switch {
	case a == nil:
		return LabelNotEnforced, []string{"the status document has no acceptance results"}, false
	case commit == "":
		return LabelNotEnforced, []string{"no release commit given"}, false
	case statusCommit != commit || a.Commit != commit:
		return LabelNotEnforced, []string{fmt.Sprintf("the status document is for commit %s, not the release commit %s", short(statusCommit), short(commit))}, false
	case a.Label == LabelEnforced && a.Total == 21 && a.EnforcedPassed == 21:
		return LabelEnforced, nil, true
	}
	reasons = a.Reasons
	if len(reasons) == 0 {
		reasons = []string{"not every scenario passed in the Enforced profile"}
	}
	return LabelNotEnforced, reasons, true
}
