package edge

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestReasonMessagesMatchAppendixB: the data.message table the mediator
// uses is SRS Appendix B Table B.2, row for row and word for word (FR-1.51);
// a row added to the SRS without a message here, or a message here for a
// reason code the table does not list, fails the build.
func TestReasonMessagesMatchAppendixB(t *testing.T) {
	reqtest.Partial(t, "FR-1.51")
	raw, err := os.ReadFile(filepath.Join("..", "..", "srs_build", "appendix.md"))
	if err != nil {
		t.Fatal(err)
	}
	sec := string(raw)
	sec = sec[strings.Index(sec, "### B.2"):]
	sec = sec[:strings.Index(sec, "\n### B.3")] // Table B.2 only
	row := regexp.MustCompile("^\\| `([A-Z_]+)` \\|")
	table := map[string]string{}
	for _, line := range strings.Split(sec, "\n") {
		if m := row.FindStringSubmatch(line); m != nil {
			cells := strings.Split(strings.Trim(line, "|"), "|")
			table[m[1]] = strings.TrimSpace(cells[len(cells)-1])
		}
	}
	if len(table) < 50 {
		t.Fatalf("Table B.2 has %d rows", len(table))
	}
	for reason, msg := range table {
		if reasonMessages[reason] != msg {
			t.Errorf("%s: message %q, Table B.2 %q", reason, reasonMessages[reason], msg)
		}
	}
	for reason := range reasonMessages {
		if _, ok := table[reason]; !ok {
			t.Errorf("%s has a message but no Table B.2 row", reason)
		}
	}
	// The reason codes the edge produces itself are table rows.
	for _, reason := range []string{ReasonJournalUnavailable, ReasonFailClosed, ReasonEmergencyStop, ReasonCapability, ReasonSessionState,
		ReasonSessionEnded, ReasonApprovalDenied, ReasonApprovalNoSvc, ReasonRevisionChanged, ReasonListenLimit, ReasonReleaseRefused, ReasonOutcomeUnrecorded} {
		if _, ok := table[reason]; !ok {
			t.Errorf("edge reason %s is not in Table B.2", reason)
		}
	}
}
