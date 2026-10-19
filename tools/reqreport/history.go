package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// maxHistory is the number of entries history.json keeps (STATUS CONTRACT).
const maxHistory = 200

// HistoryEntry is one element of history.json.
type HistoryEntry struct {
	Commit      string  `json:"commit"`
	GeneratedAt string  `json:"generatedAt"`
	TestsPassed int     `json:"testsPassed"`
	TestsFailed int     `json:"testsFailed"`
	CoveragePct float64 `json:"coveragePct"`
	Verified    int     `json:"verified"`
	Partial     int     `json:"partial"`
	Unverified  int     `json:"unverified"`
}

func historyEntry(st Status) HistoryEntry {
	return HistoryEntry{
		Commit:      st.Commit,
		GeneratedAt: st.GeneratedAt,
		TestsPassed: st.Tests.Passed,
		TestsFailed: st.Tests.Failed,
		CoveragePct: st.Coverage.TotalPct,
		Verified:    st.Requirements.Verified,
		Partial:     st.Requirements.Partial,
		Unverified:  st.Requirements.Unverified,
	}
}

// appendHistory adds the entry, newest last. A re-run for the same commit
// replaces that commit's entry instead of adding a second one. The result is
// capped at maxHistory entries.
func appendHistory(h []HistoryEntry, e HistoryEntry) []HistoryEntry {
	out := make([]HistoryEntry, 0, len(h)+1)
	for _, x := range h {
		if x.Commit != e.Commit || e.Commit == "" {
			out = append(out, x)
		}
	}
	out = append(out, e)
	if len(out) > maxHistory {
		out = out[len(out)-maxHistory:]
	}
	return out
}

// runHistory implements `reqreport history -status s.json -history h.json`:
// it appends the status summary to the history file, creating it if absent.
func runHistory(statusPath, historyPath string) error {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return err
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%s: %w", statusPath, err)
	}
	if st.Schema != 1 {
		return fmt.Errorf("%s: schema %d, want 1", statusPath, st.Schema)
	}
	var h []HistoryEntry
	hb, err := os.ReadFile(historyPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(hb, &h); err != nil {
			// A corrupt history must not block publishing; start over.
			fmt.Fprintf(os.Stderr, "reqreport: warning: %s is not a history array (%v); starting a new history\n", historyPath, err)
			h = nil
		}
	}
	h = appendHistory(h, historyEntry(st))
	return writeJSON(historyPath, h)
}
