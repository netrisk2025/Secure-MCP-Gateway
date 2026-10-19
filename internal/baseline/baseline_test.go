package baseline

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func relErr(a, b float64) float64 {
	if a == b {
		return 0
	}
	return math.Abs(a-b) / math.Max(math.Abs(a), math.Abs(b))
}

func TestWelfordMatchesTwoPass(t *testing.T) {
	reqtest.Verifies(t, "FR-10.13")
	r := rand.New(rand.NewPCG(1, 2))
	const n = 1_000_000
	xs := make([]float64, n)
	var w Welford
	for i := range xs {
		// Large offset and small spread: the case where naive sums lose
		// precision.
		xs[i] = 1e6 + r.NormFloat64()*3 + float64(i%7)
		w.Add(xs[i], t0, 0)
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	mean := sum / n
	ss := 0.0
	for _, x := range xs {
		ss += (x - mean) * (x - mean)
	}
	variance := ss / (n - 1)
	if relErr(w.Mean, mean) > 1e-9 || relErr(w.Variance(), variance) > 1e-9 {
		t.Fatalf("Welford mean %v var %v, two-pass %v %v", w.Mean, w.Variance(), mean, variance)
	}
	if w.N != n || w.W != n {
		t.Fatalf("count %d weight %v", w.N, w.W)
	}

	// Decay: with a half-life, an observation one half-life old weighs 1/2.
	var d Welford
	d.Add(10, t0, time.Hour)
	d.Add(20, t0.Add(time.Hour), time.Hour)
	// weights 0.5 and 1: mean = (5 + 20) / 1.5
	if relErr(d.Mean, 25/1.5) > 1e-12 || relErr(d.W, 1.5) > 1e-12 {
		t.Fatalf("decayed mean %v weight %v", d.Mean, d.W)
	}
	// A level shift is followed: after many half-lives the mean is the new level.
	var f Welford
	ts := t0
	for i := 0; i < 200; i++ {
		f.Add(1, ts, time.Hour)
		ts = ts.Add(10 * time.Minute)
	}
	for i := 0; i < 200; i++ {
		f.Add(5, ts, time.Hour)
		ts = ts.Add(10 * time.Minute)
	}
	if math.Abs(f.Mean-5) > 0.01 {
		t.Fatalf("decayed baseline did not follow the shift: %v", f.Mean)
	}
}

func TestTransforms(t *testing.T) {
	reqtest.Verifies(t, "FR-10.14")
	for _, tc := range []struct {
		spec string
		x    float64
		want float64
		ok   bool
	}{
		{"none", 7, 7, true},
		{"log1p", 7, math.Log1p(7), true},
		{"log1p", -1, 0, false},
		{"box-cox(0.5)", 9, (3 - 1) / 0.5, true},
		{"box-cox(0)", math.E, 1, true},
		{"box-cox(1)", 0, 0, false},
	} {
		tr, err := ParseTransform(tc.spec)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := tr.Apply(tc.x)
		if ok != tc.ok || (ok && relErr(got, tc.want) > 1e-12) {
			t.Fatalf("%s(%v) = %v %v, want %v %v", tc.spec, tc.x, got, ok, tc.want, tc.ok)
		}
		if back, _ := ParseTransform(tr.String()); back != tr {
			t.Fatalf("round trip %v", tr)
		}
	}
	for _, bad := range []string{"log", "box-cox()", "box-cox(x)", "box-cox(9)"} {
		if _, err := ParseTransform(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// The stored statistics are of transformed values.
	for _, spec := range []string{"none", "log1p", "box-cox(0.25)"} {
		tr, _ := ParseTransform(spec)
		e := newEngine(t, Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "request_bytes", Transform: tr}}})
		vals := []float64{10, 100, 1000, 50}
		var ref Welford
		for _, v := range vals {
			e.Learn(sample("s", "read", map[string]float64{"request_bytes": v}), LearnInfo{})
			y, _ := tr.Apply(v)
			ref.Add(y, t0, 0)
		}
		snap, err := e.Build("operator")
		if err != nil {
			t.Fatal(err)
		}
		fs := snap.Contexts["tool=read"].Features["request_bytes"]
		if relErr(fs.Mean, ref.Mean) > 1e-12 || relErr(fs.Variance, ref.Variance()) > 1e-12 || fs.Transform != tr.String() {
			t.Fatalf("%s: stored %+v, want mean %v var %v", spec, fs, ref.Mean, ref.Variance())
		}
	}
}

func TestTDigestMedianMAD(t *testing.T) {
	reqtest.Verifies(t, "FR-10.15")
	r := rand.New(rand.NewPCG(3, 4))
	for name, gen := range map[string]func() float64{
		"normal":    func() float64 { return 100 + 15*r.NormFloat64() },
		"lognormal": func() float64 { return math.Exp(r.NormFloat64()) * 50 },
		"uniform":   func() float64 { return r.Float64() * 1000 },
	} {
		d := NewTDigest(200)
		xs := make([]float64, 100_000)
		for i := range xs {
			xs[i] = gen()
			d.Add(xs[i])
		}
		sort.Float64s(xs)
		med := exactMedian(xs)
		dev := make([]float64, len(xs))
		for i, x := range xs {
			dev[i] = math.Abs(x - med)
		}
		sort.Float64s(dev)
		mad := exactMedian(dev)
		gm, gmad := d.MedianMAD()
		if relErr(gm, med) > 0.01 || relErr(gmad, mad) > 0.01 {
			t.Fatalf("%s: sketch median %v MAD %v, exact %v %v", name, gm, gmad, med, mad)
		}
		t.Logf("%s: median %.4f vs %.4f, MAD %.4f vs %.4f, %d centroids", name, gm, med, gmad, mad, len(d.Centroids))
		if q := d.Quantile(0.99); relErr(q, xs[int(0.99*float64(len(xs)-1))]) > 0.01 {
			t.Fatalf("%s: p99 %v vs %v", name, q, xs[int(0.99*float64(len(xs)-1))])
		}
	}
}

func exactMedian(s []float64) float64 {
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func newEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	e, err := NewEngine(cfg, func() time.Time { return t0.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func sample(session, tool string, num map[string]float64) Sample {
	return Sample{Time: t0, Session: session, Tool: tool, Dims: map[string]string{"principal": "p1", "tool": tool}, Numeric: num}
}

func TestContextPerObservedPair(t *testing.T) {
	reqtest.Verifies(t, "FR-10.12")
	e := newEngine(t, Config{Dimensions: []string{"principal", "tool"}, Features: []FeatureSpec{{Name: "x"}}})
	pairs := map[string]bool{}
	for _, p := range []string{"a", "b", "c"} {
		for _, tool := range []string{"read", "write"} {
			if p == "c" && tool == "write" {
				continue
			}
			for i := 0; i < 3; i++ {
				e.Learn(Sample{Time: t0, Dims: map[string]string{"principal": p, "tool": tool, "hour": "12"}, Numeric: map[string]float64{"x": 1}}, LearnInfo{})
			}
			pairs[ContextKey([]string{"principal", "tool"}, map[string]string{"principal": p, "tool": tool})] = true
		}
	}
	snap, _ := e.Build("operator")
	if len(snap.Contexts) != len(pairs) {
		t.Fatalf("%d contexts, want %d", len(snap.Contexts), len(pairs))
	}
	for k := range pairs {
		if snap.Contexts[k].Count != 3 {
			t.Fatalf("context %s: %+v", k, snap.Contexts[k])
		}
	}
	// Separators in values cannot collide.
	a := ContextKey([]string{"principal", "tool"}, map[string]string{"principal": "x|tool=y", "tool": "z"})
	b := ContextKey([]string{"principal", "tool"}, map[string]string{"principal": "x", "tool": "y|tool=z"})
	if a == b {
		t.Fatal("context keys collide")
	}
	if err := (&Config{Dimensions: []string{"color"}}).Validate(); err == nil {
		t.Fatal("unknown dimension accepted")
	}
}

func TestCategoricalAndTransitionFrequencies(t *testing.T) {
	reqtest.Verifies(t, "FR-10.16")
	e := newEngine(t, Config{Dimensions: []string{"principal", "tool"}, Features: []FeatureSpec{{Name: "decision_outcome", Kind: "categorical"}}})
	seq := []string{"list", "read", "read", "write", "list", "read"}
	prev := ""
	var surprises []float64
	for _, tool := range seq {
		s := Sample{Time: t0, Session: "s1", Tool: tool, PrevTool: prev, Dims: map[string]string{"principal": "p1", "tool": tool},
			Categorical: map[string]string{"decision_outcome": "permit"}}
		if sv, ok := e.TransitionSurprise(s); ok {
			surprises = append(surprises, sv)
		}
		e.Learn(s, LearnInfo{})
		prev = tool
	}
	snap, _ := e.Build("operator")
	want := map[string]map[string]int64{"list": {"read": 2}, "read": {"read": 1, "write": 1}, "write": {"list": 1}}
	got := snap.Transitions["principal=p1"]
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if string(gb) != string(wb) {
		t.Fatalf("transitions %s, want %s", gb, wb)
	}
	// Surprise before each update, with add-one smoothing:
	// list->read: unseen, c(list)=0, V=0: -ln(1/1) = 0
	// read->read: unseen, c(read)=0: 0
	// read->write: c=0, c(read)=1, V=1: -ln(1/3)
	// write->list: 0
	// list->read: c=1, c(list)=1, V=1: -ln(2/3)
	wantS := []float64{0, 0, math.Log(3), 0, -math.Log(2.0 / 3)}
	if len(surprises) != len(wantS) {
		t.Fatalf("surprises %v", surprises)
	}
	for i := range wantS {
		if math.Abs(surprises[i]-wantS[i]) > 1e-12 {
			t.Fatalf("surprise %d = %v, want %v", i, surprises[i], wantS[i])
		}
	}
	// Category counts and the baselined surprise statistic.
	cs := snap.Contexts["principal=p1|tool=read"]
	if cs.Categories["decision_outcome"]["permit"] != 3 {
		t.Fatalf("category counts %v", cs.Categories)
	}
	// Surprise of "permit" for the three read calls: c=0,1,2 of total 0,1,2
	// with V=0,1,1: -ln(1/1), -ln(2/3), -ln(3/4).
	ref := Welford{}
	for _, v := range []float64{0, -math.Log(2.0 / 3), -math.Log(3.0 / 4)} {
		ref.Add(v, t0, 0)
	}
	fs := cs.Features["decision_outcome:surprise"]
	if fs.N != 3 || math.Abs(fs.Mean-ref.Mean) > 1e-12 || math.Abs(fs.Variance-ref.Variance()) > 1e-12 {
		t.Fatalf("surprise stats %+v, want mean %v var %v", fs, ref.Mean, ref.Variance())
	}
}

func TestLearningExclusions(t *testing.T) {
	reqtest.Verifies(t, "FR-10.17")
	e := newEngine(t, Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "x"}}, Window: 24 * time.Hour})
	e.Flag("flagged")
	in := func(v float64) Sample {
		return Sample{Time: t0, Session: "ok", Dims: map[string]string{"tool": "t"}, Numeric: map[string]float64{"x": v}}
	}
	cases := []struct {
		s    Sample
		info LearnInfo
		why  string
	}{
		{in(1000), LearnInfo{Denied: true}, ExcludedDenied},
		{in(1000), LearnInfo{Band: "abnormal"}, ExcludedBand},
		{in(1000), LearnInfo{Band: "critical"}, ExcludedBand},
		{func() Sample { s := in(1000); s.Session = "flagged"; return s }(), LearnInfo{}, ExcludedFlagged},
		{func() Sample { s := in(1000); s.Time = t0.Add(-48 * time.Hour); return s }(), LearnInfo{}, ExcludedWindow},
	}
	for _, c := range cases {
		if ok, why := e.Learn(c.s, c.info); ok || why != c.why {
			t.Fatalf("learned=%v why=%q, want excluded %q", ok, why, c.why)
		}
	}
	for _, v := range []float64{1, 2, 3} {
		if ok, _ := e.Learn(in(v), LearnInfo{Band: "elevated"}); !ok {
			t.Fatal("included record not learned")
		}
	}
	snap, _ := e.Build("operator")
	fs := snap.Contexts["tool=t"].Features["x"]
	if fs.N != 3 || fs.Mean != 2 {
		t.Fatalf("excluded records changed the statistics: %+v", fs)
	}
	st := e.Status()
	if st.Excluded[ExcludedBand] != 2 || st.Excluded[ExcludedDenied] != 1 || st.Learned != 3 {
		t.Fatalf("status %+v", st)
	}
}

type memLoader struct {
	mu  sync.Mutex
	ids []string
	err error
}

func (l *memLoader) Load(s *Snapshot) error {
	if err := s.Verify(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.ids = append(l.ids, s.ID)
	return nil
}

func (l *memLoader) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ids) == 0 {
		return ""
	}
	return l.ids[len(l.ids)-1]
}

func newManager(t *testing.T, dir string, o ManagerOptions, cfg Config) (*Manager, *audit.Memory) {
	t.Helper()
	e, err := NewEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	o.Dir = dir
	m, err := NewManager(e, o)
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	m.SetRecorder(mem)
	return m, mem
}

func feed(m *Manager, n int, mean, sd float64, seed uint64) {
	r := rand.New(rand.NewPCG(seed, 9))
	for i := 0; i < n; i++ {
		m.Learn(Sample{Time: time.Now(), Session: "s", Dims: map[string]string{"tool": "t"}, Numeric: map[string]float64{"x": mean + sd*r.NormFloat64()}}, LearnInfo{})
	}
}

func TestSnapshotTriggersAndImmutability(t *testing.T) {
	reqtest.Verifies(t, "FR-10.18")
	dir := t.TempDir()
	cfg := Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "x", SigmaFloor: 0.1}}}
	loader := &memLoader{}
	m, mem := newManager(t, dir, ManagerOptions{Records: 100, Interval: 50 * time.Millisecond, Loader: loader}, cfg)

	built := func() int {
		n := 0
		for _, ev := range mem.Events() {
			if ev.Outcome == "snapshot_built" {
				n++
			}
		}
		return n
	}
	// Record count. The build runs in the background; Wait returns when its
	// snapshot is stored and its event recorded.
	feed(m, 100, 10, 1, 1)
	m.Wait()
	if l, _ := m.Store().List(); len(l) != 1 || built() != 1 {
		t.Fatalf("after the record-count build: %d snapshots, %d events", len(l), built())
	}
	// Interval. Run is stopped, and has returned (it saves the state on
	// the way out), before the next step.
	// The records are learned before Run starts, so that one tick builds
	// them all.
	feed(m, 10, 10, 1, 2)
	ctx, cancel := contextWithCancel()
	runDone := make(chan struct{})
	go func() { defer close(runDone); m.Run(ctx) }()
	waitFor(t, func() bool { return built() == 2 })
	cancel()
	<-runDone
	// Operator command.
	res, err := m.BuildSnapshot("operator", "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	list, _ := m.Store().List()
	triggers := map[string]bool{}
	for _, s := range list {
		triggers[s.Trigger] = true
	}
	if len(list) != 3 || !triggers["records"] || !triggers["interval"] || !triggers["operator"] {
		t.Fatalf("snapshots %+v", list)
	}
	snap, err := m.Store().Load(res.Snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ID == "" || snap.Digest == "" || len(snap.Contexts) != 1 || snap.Records != 110 || snap.Window.From.IsZero() ||
		snap.Contexts["tool=t"].Features["x"].N != 110 {
		t.Fatalf("snapshot content %+v", snap)
	}
	// Immutability: more learning does not change a stored snapshot, the
	// file is read-only and a snapshot with the same ID cannot be saved.
	before, _ := os.ReadFile(filepath.Join(dir, snap.ID+".json"))
	feed(m, 50, 99, 1, 3)
	after, _ := os.ReadFile(filepath.Join(dir, snap.ID+".json"))
	if string(before) != string(after) {
		t.Fatal("stored snapshot changed")
	}
	info, _ := os.Stat(filepath.Join(dir, snap.ID+".json"))
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("snapshot file mode %v", info.Mode().Perm())
	}
	if err := m.Store().Save(snap); err == nil {
		t.Fatal("snapshot overwritten")
	}
	m.Wait()
	if n := built(); n != 3 {
		t.Fatalf("%d snapshot_built events", n)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDriftReport(t *testing.T) {
	reqtest.Verifies(t, "FR-10.19")
	cfg := Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "x"}}, NMin: 30}
	mk := func(tools map[string][2]float64) *Snapshot {
		e := newEngine(t, cfg)
		for tool, ms := range tools {
			// Exactly mean ± sd alternating: sample sd = sd*sqrt(n/(n-1)).
			for i := 0; i < 1000; i++ {
				v := ms[0] + ms[1]*float64(1-2*(i%2))
				e.Learn(Sample{Time: t0, Dims: map[string]string{"tool": tool}, Numeric: map[string]float64{"x": v}}, LearnInfo{})
			}
		}
		s, _ := e.Build("operator")
		return s
	}
	prom := mk(map[string][2]float64{"a": {10, 2}})
	cand := mk(map[string][2]float64{"a": {13, 4}, "b": {1, 1}})
	r := Drift(cand, prom)
	if len(r.NewContexts) != 1 || r.NewContexts[0] != "tool=b" {
		t.Fatalf("new contexts %v", r.NewContexts)
	}
	if len(r.Contexts) != 1 || len(r.Contexts[0].Features) != 1 {
		t.Fatalf("contexts %+v", r.Contexts)
	}
	fd := r.Contexts[0].Features[0]
	sp := prom.Contexts["tool=a"].Features["x"].Std
	if math.Abs(fd.MeanShift-3/sp) > 1e-9 || math.Abs(fd.SigmaRatio-2) > 1e-9 {
		t.Fatalf("drift %+v (promoted σ %v)", fd, sp)
	}
	if math.Abs(r.MaxAbsShift-3/sp) > 1e-9 || math.Abs(r.MaxSigmaFactor-2) > 1e-9 {
		t.Fatalf("summary %+v", r)
	}
	if first := Drift(cand, nil); len(first.NewContexts) != 2 {
		t.Fatalf("against no promoted snapshot: %+v", first)
	}
}

func TestPromotionManualAndAutomatic(t *testing.T) {
	reqtest.Partial(t, "FR-10.20") // authorization of the operator: analytics HTTP tests
	cfg := Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "x", SigmaFloor: 0.01}}}
	loader := &memLoader{}
	m, mem := newManager(t, t.TempDir(), ManagerOptions{Loader: loader, Auto: AutoLimits{MaxMeanShift: 0.5, MaxSigmaFactor: 1.5}}, cfg)
	feed(m, 500, 10, 1, 1)
	r1, err := m.BuildSnapshot("operator", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Promoted {
		t.Fatal("first snapshot promoted without an operator")
	}
	if _, err := m.Promote(r1.Snapshot.ID, "admin:alice"); err != nil {
		t.Fatal(err)
	}
	if loader.last() != r1.Snapshot.ID {
		t.Fatal("scorer did not receive the promoted snapshot")
	}
	if _, err := m.Promote(r1.Snapshot.ID, "admin:alice"); !errors.Is(err, ErrAlreadyPromoted) {
		t.Fatalf("re-promotion: %v", err)
	}
	// Same distribution: within the limits, promoted automatically.
	feed(m, 500, 10, 1, 2)
	r2, err := m.BuildSnapshot("records", "E-30")
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Promoted || loader.last() != r2.Snapshot.ID {
		t.Fatalf("within limits not promoted: %+v", r2.Drift)
	}
	// Shifted distribution: beyond the limits, not promoted.
	feed(m, 3000, 14, 1, 3)
	r3, err := m.BuildSnapshot("records", "E-30")
	if err != nil {
		t.Fatal(err)
	}
	if r3.Promoted || loader.last() != r2.Snapshot.ID {
		t.Fatalf("beyond limits promoted: %+v", r3.Drift)
	}
	h, _ := m.Store().History()
	if len(h) != 2 || h[0].Mode != "operator" || h[0].By != "admin:alice" || h[1].Mode != "automatic" {
		t.Fatalf("history %+v", h)
	}
	n := 0
	for _, ev := range mem.Events() {
		if ev.Outcome == "promoted" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d promotion events", n)
	}
}

func TestRollbackAndIntegrity(t *testing.T) {
	reqtest.Partial(t, "FR-10.21", "SR-7-1")
	dir := t.TempDir()
	cfg := Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "x"}}}
	loader := &memLoader{}
	m, mem := newManager(t, dir, ManagerOptions{Loader: loader}, cfg)
	feed(m, 100, 10, 1, 1)
	a, _ := m.BuildSnapshot("operator", "admin")
	feed(m, 100, 10, 1, 2)
	b, _ := m.BuildSnapshot("operator", "admin")
	if _, err := m.Promote(b.Snapshot.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	p, err := m.Promote(a.Snapshot.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "rollback" || loader.last() != a.Snapshot.ID {
		t.Fatalf("rollback %+v loaded %s", p, loader.last())
	}
	// Tamper with snapshot b: promotion is refused and an integrity event
	// recorded.
	path := filepath.Join(dir, b.Snapshot.ID+".json")
	raw, _ := os.ReadFile(path)
	var s map[string]any
	json.Unmarshal(raw, &s)
	s["records"] = 1
	raw, _ = json.Marshal(s)
	os.Chmod(path, 0o600)
	os.WriteFile(path, raw, 0o600)
	if _, err := m.Promote(b.Snapshot.ID, "admin"); !errors.Is(err, ErrDigest) {
		t.Fatalf("tampered snapshot promoted: %v", err)
	}
	found := false
	for _, ev := range mem.Events() {
		if ev.Class == "integrity" && ev.ReasonCode == "BASELINE_DIGEST_MISMATCH" {
			found = true
		}
	}
	if !found {
		t.Fatal("no integrity event")
	}
	if loader.last() != a.Snapshot.ID {
		t.Fatal("tampered snapshot reached the scorer")
	}
	// At restart, a tampered promoted snapshot is refused.
	m.Store().SetPromoted(Promotion{ID: b.Snapshot.ID, Mode: "test"})
	loader2 := &memLoader{}
	m2, mem2 := newManager(t, dir, ManagerOptions{Loader: loader2}, cfg)
	if loader2.last() != "" || m2.LifecycleStatus().PromotedError == "" {
		t.Fatal("tampered promoted snapshot loaded at start")
	}
	if len(mem2.Events()) != 1 || mem2.Events()[0].Class != "integrity" {
		t.Fatalf("start events %+v", mem2.Events())
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "x", Robust: true}}}
	m, _ := newManager(t, dir, ManagerOptions{}, cfg)
	feed(m, 1000, 5, 2, 1)
	m.Flag("bad")
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m2, _ := newManager(t, dir, ManagerOptions{}, cfg)
	if m2.Learned() != 1000 || len(m2.Flagged()) != 1 {
		t.Fatalf("restored learned=%d flagged=%v", m2.Learned(), m2.Flagged())
	}
	s1, _ := m.Build("operator")
	s2, _ := m2.Build("operator")
	a, b := s1.Contexts["tool=t"].Features["x"], s2.Contexts["tool=t"].Features["x"]
	if a.Mean != b.Mean || a.Variance != b.Variance || relErr(a.Median, b.Median) > 1e-9 {
		t.Fatalf("restored stats %+v vs %+v", b, a)
	}
	cfg.Features[0].Name = "y"
	e3, _ := NewEngine(cfg, nil)
	if err := e3.LoadState(filepath.Join(dir, "candidate-state.json")); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("state of another configuration loaded: %v", err)
	}
}

func TestSnapshotBuildTime(t *testing.T) {
	reqtest.Verifies(t, "FR-11.7")
	if testing.Short() {
		t.Skip("10,000-context build")
	}
	cfg := Config{Dimensions: []string{"principal", "tool"}, Features: []FeatureSpec{{Name: "a"}, {Name: "b", Robust: true}, {Name: "c", Transform: Transform{Kind: "log1p"}}}}
	e := newEngine(t, cfg)
	r := rand.New(rand.NewPCG(5, 6))
	for c := 0; c < 10_000; c++ {
		dims := map[string]string{"principal": "p" + itoa(c/100), "tool": "t" + itoa(c%100)}
		for i := 0; i < 30; i++ {
			e.Learn(Sample{Time: t0, Dims: dims, Numeric: map[string]float64{"a": r.Float64(), "b": r.NormFloat64(), "c": r.Float64() * 100}}, LearnInfo{})
		}
	}
	start := time.Now()
	snap, err := e.Build("operator")
	if err != nil {
		t.Fatal(err)
	}
	d := time.Since(start)
	t.Logf("10,000 contexts built and sealed in %v", d)
	if len(snap.Contexts) != 10_000 || d > 60*time.Second {
		t.Fatalf("%d contexts in %v", len(snap.Contexts), d)
	}
}

func itoa(i int) string {
	return string(rune('a'+i/26%26)) + string(rune('a'+i%26)) + string(rune('0'+i/676%10))
}

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
