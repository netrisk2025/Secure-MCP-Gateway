package perf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RunOptions configure a measurement run.
type RunOptions struct {
	BinDir    string        // smcpd, smcpctl and smcp-refserver
	Work      string        // empty directory for the instances
	Calls     int           // tool calls per load measurement (default 2000)
	Callers   int           // concurrent callers (default RefCallers)
	Decisions int           // decisions for FR-11.2 (default 100,000)
	Queries   int           // repetitions of the console query set (default 100)
	Idle      time.Duration // wait before the idle memory sample (default 10 minutes)
	Commit    string
	Log       io.Writer
}

func (o *RunOptions) defaults() {
	if o.Calls <= 0 {
		o.Calls = 2000
	}
	if o.Callers <= 0 {
		o.Callers = RefCallers
	}
	if o.Decisions <= 0 {
		o.Decisions = 100000
	}
	if o.Queries <= 0 {
		o.Queries = 100
	}
	if o.Idle <= 0 {
		o.Idle = 10 * time.Minute
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
}

// Run measures FR-11.2, FR-11.4, FR-11.5, FR-11.8 and FR-11.9 with the
// reference workload against real smcpd instances.
func Run(ctx context.Context, o RunOptions) (*Results, error) {
	o.defaults()
	say := func(f string, a ...any) { fmt.Fprintf(o.Log, "smcp-workload: "+f+"\n", a...) }
	doc, err := ReferencePolicy("workload-r1", RefRules, RefCandidates)
	if err != nil {
		return nil, err
	}
	res := &Results{Schema: 1, Commit: o.Commit, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Host: CurrentHost(),
		Dataset: Dataset{Rules: RefRules, RegistryNodes: RefRegistryNodes, Candidates: RefCandidates, Events: RefEvents, Days: RefDays, Callers: o.Callers}}

	// FR-11.9: an idle instance, started first and sampled last.
	idle, err := newInstance(o.BinDir, filepath.Join(o.Work, "idle"), "", doc)
	if err != nil {
		return nil, err
	}
	if err := idle.start(); err != nil {
		return nil, err
	}
	defer idle.stop()
	idleSince := time.Now()
	say("idle instance started; memory is sampled after %s", o.Idle)

	// FR-11.2: decisions against the reference policy.
	say("FR-11.2: %d decisions, %d callers, %d candidate rules", o.Decisions, o.Callers, RefCandidates)
	lat, err := MeasureDecisions(doc, o.Decisions, o.Callers)
	if err != nil {
		return nil, err
	}
	p95 := Quantile(lat, 0.95)
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.2", Name: "Decision latency", Metric: "p95", Unit: "ms",
		Value: p95, Budget: BudgetDecisionMs, Ceiling: CeilingDecisionMs, Samples: len(lat), Pass: p95 <= BudgetDecisionMs,
		Method: fmt.Sprintf("policy.Decider.Decide on the compiled reference policy (%d rules, %d candidates per decision), %d concurrent callers, latency as the caller sees it", RefRules, RefCandidates, o.Callers)})

	// FR-11.4 and FR-11.5: load against three instances.
	load := func(work, name, extra string) ([]float64, error) {
		in, err := newInstance(o.BinDir, filepath.Join(work, name), extra, doc)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(in.sandbox, "64k.txt"), []byte(strings.Repeat("0123456789abcdef", 64<<10/16)), 0o644); err != nil {
			return nil, err
		}
		if err := in.start(); err != nil {
			return nil, err
		}
		defer in.stop()
		// Start the load on a quiet disk: P-213 includes the journal's
		// flush before launch, and dirty pages left by earlier work (the
		// build before the CI job, the previous instances) are otherwise
		// written back during this run's flushes.
		flushDisk()
		say("%s: %d calls of read_file (64 KiB result), %d callers", name, o.Calls, o.Callers)
		if err := drive(ctx, in, o.Calls, o.Callers); err != nil {
			return nil, err
		}
		in.stop()
		return in.overheads()
	}
	syncScoring, err := load(o.Work, "sync-scoring", "\n[observation]\nscoring = \"sync\"\n")
	if err != nil {
		return nil, err
	}
	p95 = Quantile(syncScoring, 0.95)
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.5", Name: "Gateway-added overhead (P-213)", Metric: "p95", Unit: "ms",
		Value: p95, Budget: BudgetOverheadMs, Ceiling: CeilingOverheadMs, Samples: len(syncScoring), Pass: p95 <= BudgetOverheadMs,
		Method: fmt.Sprintf("real smcpd with synchronous scoring, %d concurrent callers reading a 64 KiB file through the reference server; P-213 from journal timestamps (request receipt to delivered, minus dispatched to the backend's response)", o.Callers)})
	// Eight instances of each condition in the order of CaptureOrder, so
	// that warm-up and drift on the runner affect both conditions alike;
	// the p95 of each condition is the mean of its runs' p95. With two runs
	// of each, the spread between runs of one condition on a CI runner
	// (about 5 ms) was larger than the 1 ms being measured.
	//
	// The instances keep their state on a memory file system where the
	// host has one (CaptureWork). Their journals' flushes before launch
	// are in P-213, and on some CI runners a few percent of those flushes
	// stalled for about 190 ms, in enabled and disabled runs alike (0.56%
	// and 0.60% of 208,000 calls each): each run's p95 then fell anywhere
	// between 13 and 130 ms, and the difference between conditions said
	// nothing about observation. Flush latency is the disk's and the same
	// with observation on or off; FR-11.5 measures it, on disk.
	capWork, onMemory := CaptureWork(o.Work)
	if onMemory {
		defer os.RemoveAll(capWork)
	}
	var runs []captureRun
	for i, enabled := range CaptureOrder {
		extra := ""
		if !enabled {
			extra = "\n[observation]\nenabled = false\n"
		}
		name := fmt.Sprintf("capture-%d", i)
		lat, err := load(capWork, name, extra)
		if onMemory {
			os.RemoveAll(filepath.Join(capWork, name))
		}
		if err != nil {
			return nil, err
		}
		runs = append(runs, captureRun{enabled: enabled, p95: Quantile(lat, 0.95), n: len(lat)})
	}
	res.Measurements = append(res.Measurements, captureMeasurement(runs, onMemory))

	// FR-11.8: the console's audit queries over 30 days of reference data.
	qi, err := newInstance(o.BinDir, filepath.Join(o.Work, "queries"), "", doc)
	if err != nil {
		return nil, err
	}
	say("FR-11.8: writing %d journal events over %d days", RefEvents, RefDays)
	n, err := WriteJournal(qi.state, RefEvents, RefDays, time.Now())
	if err != nil {
		return nil, err
	}
	if err := qi.start(); err != nil {
		return nil, err
	}
	qlat, err := queries(qi, o.Queries)
	qi.stop()
	if err != nil {
		return nil, err
	}
	p95 = Quantile(qlat, 0.95)
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.8", Name: "Console query latency", Metric: "p95", Unit: "ms",
		Value: p95, Budget: BudgetQueryMs, Samples: len(qlat), Pass: p95 <= BudgetQueryMs,
		Method: fmt.Sprintf("the console's audit queries (latest page, by class, by reason, by correlation, by time window, text search) over a journal of %d events spanning %d days, %d repetitions", n, RefDays, o.Queries),
		Note:   "audit queries only; analytics queries over 30 days of observation data are not in the reference dataset yet"})

	// FR-11.9: wait out the idle period, then sample.
	if wait := o.Idle - time.Since(idleSince); wait > 0 {
		say("FR-11.9: waiting %s for the idle sample", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	rss, err := idle.rssBytes()
	if err != nil {
		return nil, err
	}
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.9", Name: "Idle resident memory", Metric: "RSS", Unit: "MiB",
		Value: float64(rss) / (1 << 20), Budget: float64(BudgetIdleRSSBytes) / (1 << 20), Samples: 1, Pass: rss <= BudgetIdleRSSBytes,
		Method: fmt.Sprintf("resident set size of smcpd %s after start with no traffic, Data Server off (no Neo4j); server instances excluded", time.Since(idleSince).Round(time.Second))})
	return res, nil
}

// drive makes calls tool calls with callers concurrent sessions.
func drive(ctx context.Context, in *instance, calls, callers int) error {
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	sessions := make([]*mcp.ClientSession, callers)
	for i := range sessions {
		cs, err := in.session(ctx)
		if err != nil {
			return err
		}
		defer cs.Close()
		sessions[i] = cs
	}
	for i, cs := range sessions {
		n := calls / callers
		if i < calls%callers {
			n++
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range n {
				cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				r, err := cs.CallTool(cctx, &mcp.CallToolParams{Name: "ref_read_file", Arguments: map[string]any{"path": "64k.txt"}})
				cancel()
				if err != nil {
					errs <- fmt.Errorf("read_file: %w", err)
					return
				}
				if r.IsError {
					errs <- errors.New("read_file returned a tool error")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	return <-errs
}

// queries runs the console's audit query set reps times and returns each
// request's latency in milliseconds.
func queries(in *instance, reps int) ([]float64, error) {
	hc, err := in.httpClient()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	window := url.Values{"since": {now.Add(-15 * 24 * time.Hour).Format(time.RFC3339)}, "until": {now.Add(-14 * 24 * time.Hour).Format(time.RFC3339)}, "limit": {"100"}}
	set := []string{
		"/api/v1/audit/events?limit=100",
		"/api/v1/audit/events?class=decision&limit=100",
		"/api/v1/audit/events?reason_code=NO_PERMIT&limit=100",
		"/api/v1/audit/events?correlation_id=corr-0012345",
		"/api/v1/audit/events?" + window.Encode(),
		"/api/v1/audit/events?q=read_file&limit=50",
	}
	var out []float64
	for range reps {
		for _, p := range set {
			code, d, err := in.api(hc, p)
			if err != nil {
				return nil, err
			}
			if code != 200 {
				return nil, fmt.Errorf("GET %s: %d", p, code)
			}
			out = append(out, float64(d.Nanoseconds())/1e6)
		}
	}
	return out, nil
}

// captureBlock is two enabled-disabled-disabled-enabled blocks, the second
// mirrored, so that a linear or quadratic drift over its runs affects both
// conditions alike (true for observation enabled).
var captureBlock = []bool{true, false, false, true, false, true, true, false}

// CaptureOrder is the order of the FR-11.4 runs: captureBlock twice,
// sixteen runs. With eight, the mean p95 of a condition still moved by
// 0.2 to 0.3 ms between repetitions on one CI runner, which put a
// difference of 0.7 ms over the 1 ms budget in about one repetition in
// six; sixteen halve the variance of the estimate.
var CaptureOrder = append(append([]bool{}, captureBlock...), captureBlock...)

type captureRun struct {
	enabled bool
	p95     float64
	n       int
}

// captureMeasurement is FR-11.4: the mean p95 P-213 of the enabled runs
// minus that of the disabled runs. onMemory reports whether the instances
// kept their state on a memory file system (CaptureWork).
func captureMeasurement(runs []captureRun, onMemory bool) Measurement {
	var on, off []string
	var sumOn, sumOff float64
	var nOn, nOff, samplesOn, samplesOff int
	for _, r := range runs {
		v := fmt.Sprintf("%.3f", r.p95)
		if r.enabled {
			on, sumOn, nOn, samplesOn = append(on, v), sumOn+r.p95, nOn+1, samplesOn+r.n
		} else {
			off, sumOff, nOff, samplesOff = append(off, v), sumOff+r.p95, nOff+1, samplesOff+r.n
		}
	}
	m := Measurement{Requirement: "FR-11.4", Name: "Observation capture overhead", Metric: "p95 difference", Unit: "ms", Budget: BudgetCaptureMs}
	if nOn == 0 || nOff == 0 {
		m.Note = "no runs of one condition"
		return m
	}
	where := "state on disk"
	if onMemory {
		where = "state on a memory file system"
	}
	pOn, pOff := sumOn/float64(nOn), sumOff/float64(nOff)
	m.Value, m.Samples, m.Pass = pOn-pOff, min(samplesOn, samplesOff), pOn-pOff <= BudgetCaptureMs
	m.Method = fmt.Sprintf("p95 P-213 with observation enabled (%.3f ms, mean of %s) minus disabled (%.3f ms, mean of %s), %d fresh instances run in the order %s, each load started after sync(2), %s",
		pOn, strings.Join(on, ", "), pOff, strings.Join(off, ", "), len(runs), orderText(runs), where)
	return m
}

// memFS is the memory file system CaptureWork uses when it exists.
var memFS = "/dev/shm"

// CaptureWork returns the directory for the FR-11.4 instances: a new
// directory on the memory file system memFS when the host has one and it
// is writable (Linux), which the caller removes, otherwise work.
func CaptureWork(work string) (dir string, onMemory bool) {
	if fi, err := os.Stat(memFS); err == nil && fi.IsDir() {
		if d, err := os.MkdirTemp(memFS, "smcp-capture-"); err == nil {
			return d, true
		}
	}
	return work, false
}

func orderText(runs []captureRun) string {
	parts := make([]string, len(runs))
	for i, r := range runs {
		parts[i] = "disabled"
		if r.enabled {
			parts[i] = "enabled"
		}
	}
	return strings.Join(parts, ", ")
}
