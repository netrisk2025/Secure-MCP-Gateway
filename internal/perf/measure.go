package perf

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// Budgets of CP-32 (SRS Appendix A), in the unit of each measurement.
const (
	BudgetDecisionMs   = 10.0  // FR-11.2, p95
	CeilingDecisionMs  = 100.0 // SEC ceiling
	BudgetCaptureMs    = 1.0   // FR-11.4, p95 difference
	BudgetOverheadMs   = 50.0  // FR-11.5, p95
	CeilingOverheadMs  = 250.0 // SEC ceiling
	BudgetQueryMs      = 2000.0
	BudgetIdleRSSBytes = 4 << 30 // FR-11.9
)

// Measurement is one FR-11 result.
type Measurement struct {
	Requirement string  `json:"requirement"`
	Name        string  `json:"name"`
	Metric      string  `json:"metric"`
	Unit        string  `json:"unit"`
	Value       float64 `json:"value"`
	Budget      float64 `json:"budget"`
	Ceiling     float64 `json:"ceiling,omitempty"`
	Samples     int     `json:"samples"`
	Pass        bool    `json:"pass"`
	Method      string  `json:"method"`
	Note        string  `json:"note,omitempty"`
}

// Host describes the machine the measurements ran on.
type Host struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	CPUs      int    `json:"cpus"`
	CPU       string `json:"cpu,omitempty"`
	GoVersion string `json:"goVersion"`
	Runner    string `json:"runner,omitempty"`
}

// Results is the perf.json document the status data publishes as
// "performance".
type Results struct {
	Schema      int    `json:"schema"`
	Commit      string `json:"commit"`
	GeneratedAt string `json:"generatedAt"`
	Host        Host   `json:"host"`
	// ReferenceHardware is false unless the run was on the recorded
	// reference hardware of FR-11; CI runners are not.
	ReferenceHardware bool          `json:"referenceHardware"`
	Dataset           Dataset       `json:"dataset"`
	Measurements      []Measurement `json:"measurements"`
}

// CurrentHost describes this machine.
func CurrentHost() Host {
	h := Host{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), GoVersion: runtime.Version(), Runner: os.Getenv("RUNNER_NAME")}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
				h.CPU = strings.TrimSpace(v)
				break
			}
		}
	}
	return h
}

// Quantile returns the q quantile (0 < q <= 1) of xs by the nearest-rank
// method.
func Quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	i := int(float64(len(s))*q+0.999999) - 1
	return s[min(max(i, 0), len(s)-1)]
}

// MeasureDecisions makes n decisions with callers concurrent callers
// against the compiled reference policy, as the Policy Decision Service
// (E-06) does for each call, and returns each decision's latency in
// milliseconds as the caller sees it (including waiting for the decider).
// Each caller is its own principal; sessions change every 500 calls.
func MeasureDecisions(doc []byte, n, callers int) ([]float64, error) {
	snap, err := policy.Compile(doc)
	if err != nil {
		return nil, err
	}
	d := policy.NewDecider(snap, 1<<30)
	lat := make([]float64, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	per := n / callers
	for c := range callers {
		lo, hi := c*per, (c+1)*per
		if c == callers-1 {
			hi = n
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				req := policy.Request{PrincipalID: fmt.Sprintf("workload-%d", c), SessionID: fmt.Sprintf("s-%d-%d", c, i/500), Profile: "dev",
					Template: "read-only", Server: "ref", Tool: RefTools[i%len(RefTools)], Arguments: json.RawMessage(`{"text":"x","path":"a.txt"}`)}
				t0 := time.Now()
				dec := d.Decide(req)
				lat[i] = float64(time.Since(t0).Nanoseconds()) / 1e6
				if dec.Outcome != policy.Permit {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("perf: decision %s (%s), want permit", dec.Outcome, dec.ReasonCode)
					}
					mu.Unlock()
					return
				}
				if len(dec.ConsideredRules) < RefCandidates {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("perf: decision considered %d rules, want %d", len(dec.ConsideredRules), RefCandidates)
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	return lat, firstErr
}

// WriteTestJSON writes the measurements as `go test -json` events, one
// test per measurement under package pkg, so tools/reqreport counts them:
// a measurement within its budget is a partial claim of its requirement
// (the run is not on the recorded reference hardware), one over its budget
// is a failing test. The status job merges this file with the Go results.
func WriteTestJSON(w io.Writer, pkg string, ms []Measurement, at time.Time) error {
	enc := json.NewEncoder(w)
	ts := at.UTC().Format(time.RFC3339Nano)
	failed := false
	for _, m := range ms {
		name := "TestPerf" + strings.NewReplacer("-", "_", ".", "_").Replace(m.Requirement)
		action := "pass"
		if !m.Pass {
			action, failed = "fail", true
		}
		out := fmt.Sprintf("    perf: %s %s %s = %.3f %s (budget %.3f %s, %d samples): %s\n", m.Requirement, m.Name, m.Metric, m.Value, m.Unit, m.Budget, m.Unit, m.Samples, m.Method)
		for _, ev := range []map[string]any{
			{"Time": ts, "Action": "run", "Package": pkg, "Test": name},
			{"Time": ts, "Action": "output", "Package": pkg, "Test": name, "Output": out},
			{"Time": ts, "Action": "output", "Package": pkg, "Test": name, "Output": "    PARTIAL: " + m.Requirement + "\n"},
			{"Time": ts, "Action": action, "Package": pkg, "Test": name, "Elapsed": 0},
		} {
			if err := enc.Encode(ev); err != nil {
				return err
			}
		}
	}
	end := "pass"
	if failed {
		end = "fail"
	}
	return enc.Encode(map[string]any{"Time": ts, "Action": end, "Package": pkg})
}
