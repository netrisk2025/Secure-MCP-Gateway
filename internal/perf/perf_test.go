package perf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestReferenceDataset is FR-11.1's inspection as a test: the generator's
// policy has 10,000 rule and registry nodes and 256 candidate rules for
// each decision of the decision template, and its journal has 100,000
// signed events spanning 30 days. The eight concurrent callers are
// RunOptions' default (RefCallers); cmd/smcp-workload ships in the release
// archives (.goreleaser.yaml).
func TestReferenceDataset(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 100,000-event journal")
	}
	reqtest.Verifies(t, "FR-11.1")
	doc, err := ReferencePolicy("workload-r1", RefRules, RefCandidates)
	if err != nil {
		t.Fatal(err)
	}
	rules, candidates, err := CountRules(doc, "read-only", "ref")
	if err != nil {
		t.Fatal(err)
	}
	if rules+RefRegistryNodes != 10000 || candidates != 256 {
		t.Fatalf("%d rules + %d registry nodes, %d candidates", rules, RefRegistryNodes, candidates)
	}
	var o RunOptions
	o.defaults()
	if o.Callers != 8 || RefCallers != 8 {
		t.Fatalf("callers %d", o.Callers)
	}

	state := filepath.Join(t.TempDir(), "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	n, err := WriteJournal(state, RefEvents, RefDays, now)
	if err != nil || n != 100000 {
		t.Fatalf("wrote %d events: %v", n, err)
	}
	root, err := keys.LoadEvidenceTrustRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := audit.Verify(filepath.Join(state, "journal"), root)
	if err != nil {
		t.Fatalf("generated journal does not verify: %v", err)
	}
	if rep.Events != 100000 {
		t.Fatalf("journal verifies with %d events", rep.Events)
	}
	evs, err := audit.ReadEvents(filepath.Join(state, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := time.Parse(time.RFC3339Nano, evs[0].Time)
	last, _ := time.Parse(time.RFC3339Nano, evs[len(evs)-1].Time)
	if span := last.Sub(first); span < 29*24*time.Hour || last.After(now) {
		t.Fatalf("events span %s, last at %s", span, last)
	}
}

func TestReferencePolicyRejectsImpossibleSizes(t *testing.T) {
	if _, err := ReferencePolicy("r", 100, 256); err == nil {
		t.Fatal("100 rules cannot hold 256 candidates")
	}
	doc, err := ReferencePolicy("r", 600, 256)
	if err != nil {
		t.Fatal(err)
	}
	if n, c, _ := CountRules(doc, "read-only", "ref"); n != 600 || c != 256 {
		t.Fatalf("%d rules %d candidates", n, c)
	}
}

func TestMeasureDecisionsUsesEveryCandidate(t *testing.T) {
	doc, err := ReferencePolicy("r", 600, RefCandidates)
	if err != nil {
		t.Fatal(err)
	}
	lat, err := MeasureDecisions(doc, 800, 8)
	if err != nil || len(lat) != 800 {
		t.Fatalf("%d latencies: %v", len(lat), err)
	}
	for _, l := range lat {
		if l <= 0 {
			t.Fatalf("latency %v", l)
		}
	}
}

func TestQuantile(t *testing.T) {
	xs := []float64{}
	for i := 1; i <= 100; i++ {
		xs = append(xs, float64(i))
	}
	if q := Quantile(xs, 0.95); q != 95 {
		t.Fatalf("p95 of 1..100 = %v", q)
	}
	if Quantile(nil, 0.95) != 0 || Quantile([]float64{7}, 0.5) != 7 {
		t.Fatal("edge cases")
	}
}

// TestWriteTestJSON: a measurement within budget becomes a passing test
// with a partial claim; one over budget a failing test, and the package
// fails.
func TestWriteTestJSON(t *testing.T) {
	var b bytes.Buffer
	ms := []Measurement{{Requirement: "FR-11.2", Name: "x", Pass: true}, {Requirement: "FR-11.8", Name: "y", Pass: false}}
	if err := WriteTestJSON(&b, "example.com/m/internal/perf/run", ms, time.Now()); err != nil {
		t.Fatal(err)
	}
	results := map[string]string{}
	claims := map[string]bool{}
	sc := bufio.NewScanner(&b)
	for sc.Scan() {
		var ev struct{ Action, Test, Output string }
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		switch ev.Action {
		case "pass", "fail":
			results[ev.Test] = ev.Action
		case "output":
			if strings.Contains(ev.Output, "PARTIAL: ") {
				claims[strings.TrimSpace(strings.SplitN(ev.Output, "PARTIAL: ", 2)[1])] = true
			}
		}
	}
	if results["TestPerfFR_11_2"] != "pass" || results["TestPerfFR_11_8"] != "fail" || results[""] != "fail" || !claims["FR-11.2"] || !claims["FR-11.8"] {
		t.Fatalf("results %v claims %v", results, claims)
	}
}

// TestCaptureMeasurement: FR-11.4 is the mean p95 of the enabled runs minus
// that of the disabled runs, in a balanced order.
func TestCaptureMeasurement(t *testing.T) {
	on, off := 0, 0
	for i, e := range CaptureOrder {
		if e {
			on++
		} else {
			off++
		}
		// Balanced: every four runs have two of each condition.
		if (i+1)%4 == 0 && (on != (i+1)/2 || off != (i+1)/2) {
			t.Fatalf("after %d runs %d enabled, %d disabled", i+1, on, off)
		}
	}
	if on != 8 || off != 8 {
		t.Fatalf("%d enabled and %d disabled runs", on, off)
	}
	var runs []captureRun
	p95 := []float64{12, 10, 11, 13, 10, 12.5, 11.5, 11}
	for i, e := range captureBlock {
		runs = append(runs, captureRun{enabled: e, p95: p95[i], n: 2000})
	}
	m := captureMeasurement(runs, true)
	// Enabled 12, 13, 12.5, 11.5 (mean 12.25); disabled 10, 11, 10, 11 (10.5).
	if m.Requirement != "FR-11.4" || m.Value != 1.75 || m.Pass || m.Samples != 8000 || m.Budget != BudgetCaptureMs {
		t.Fatalf("measurement %+v", m)
	}
	if !strings.Contains(m.Method, "12.250 ms, mean of 12.000, 13.000, 12.500, 11.500") || !strings.Contains(m.Method, "8 fresh instances") || !strings.Contains(m.Method, "after sync(2), state on a memory file system") {
		t.Fatalf("method %q", m.Method)
	}
	runs[0].p95, runs[3].p95, runs[5].p95, runs[6].p95 = 11, 11, 10.5, 10.5
	if m := captureMeasurement(runs, false); !m.Pass || !strings.HasSuffix(m.Method, "state on disk") || m.Value != 0.25 {
		t.Fatalf("measurement %+v", m)
	}
	if m := captureMeasurement(runs[:1], true); m.Pass || m.Note == "" {
		t.Fatalf("one condition only: %+v", m)
	}
}

// TestOverheadsFromReceiptToDeliveryWithoutServerTime: P-213 runs from the
// request's receipt to delivery minus server execution, which ends at the
// backend's response (responded_at), not at the completed event that
// follows response inspection.
func TestOverheadsFromReceiptToDeliveryWithoutServerTime(t *testing.T) {
	state := t.TempDir()
	at := func(ms int) string {
		return time.Unix(1700000000, 0).UTC().Add(time.Duration(ms) * time.Millisecond).Format(time.RFC3339Nano)
	}
	lines := []string{
		`{"type":"event","class":"call","phase":"requested","correlation_id":"c1","time":"` + at(2) + `","detail":{"received_at":"` + at(0) + `"}}`,
		`{"type":"event","class":"call","phase":"dispatched","correlation_id":"c1","time":"` + at(5) + `"}`,
		`{"type":"event","class":"call","phase":"completed","correlation_id":"c1","time":"` + at(30) + `","detail":{"responded_at":"` + at(15) + `"}}`,
		`{"type":"event","class":"call","phase":"delivered","correlation_id":"c1","time":"` + at(32) + `"}`,
		`{"type":"event","class":"call","phase":"requested","correlation_id":"c2","time":"` + at(2) + `"}`,
	}
	dir := filepath.Join(state, "journal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "segment-000001.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (&instance{state: state}).overheads()
	if err != nil {
		t.Fatal(err)
	}
	// 32 ms end to end minus 10 ms of server execution; c2 is incomplete.
	if len(got) != 1 || got[0] != 22 {
		t.Fatalf("overheads %v, want [22]", got)
	}
}

// TestCaptureWork: the FR-11.4 instances get a new directory on the memory
// file system when the host has one, and the work directory otherwise.
func TestCaptureWork(t *testing.T) {
	saved := memFS
	t.Cleanup(func() { memFS = saved })
	work := t.TempDir()
	memFS = t.TempDir()
	d, onMemory := CaptureWork(work)
	if !onMemory || filepath.Dir(d) != memFS {
		t.Fatalf("with a memory file system: %q %v", d, onMemory)
	}
	memFS = filepath.Join(work, "absent")
	if d, onMemory := CaptureWork(work); onMemory || d != work {
		t.Fatalf("without one: %q %v", d, onMemory)
	}
}
