// Package reqtest tags automated tests with the requirement IDs they verify
// (FR-12.10). A test calls Verifies with one or more IDs; the line it logs is
// parsed from `go test -json` output by tools/reqreport, which maps every
// requirement ID to the result of the tests that claim it.
package reqtest

import (
	"regexp"
	"strings"
	"testing"
)

// Marker is the prefix of the log line that tools/reqreport looks for.
const Marker = "VERIFIES:"

var idPattern = regexp.MustCompile(`^(FR-\d+(\.\d+)?|SR-\d+(\.\d+)?-\d+)$`)

// Verifies declares that the calling test verifies the given requirement IDs.
// An ID that does not look like an SRS requirement ID fails the test, so a
// typo cannot silently produce an untracked claim.
func Verifies(t testing.TB, ids ...string) {
	t.Helper()
	if len(ids) == 0 {
		t.Fatal("reqtest.Verifies: no requirement IDs given")
	}
	for _, id := range ids {
		if !idPattern.MatchString(id) {
			t.Fatalf("reqtest.Verifies: %q is not a requirement ID", id)
		}
	}
	t.Log(Marker + " " + strings.Join(ids, " "))
}
