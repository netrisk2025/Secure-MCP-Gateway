package anomaly

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func engine(t *testing.T, cfg baseline.Config) *baseline.Engine {
	t.Helper()
	e, err := baseline.NewEngine(cfg, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func scorer(t *testing.T) *Scorer {
	t.Helper()
	s, err := New(DefaultThresholds)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// knownSnapshot learns a series with known mean and sample sd per feature.
func knownSnapshot(t *testing.T, features []baseline.FeatureSpec, vals map[string][]float64, n int) *baseline.Snapshot {
	e := engine(t, baseline.Config{Dimensions: []string{"principal", "tool"}, Features: features})
	for i := 0; i < n; i++ {
		num := map[string]float64{}
		for f, vs := range vals {
			num[f] = vs[i%len(vs)]
		}
		e.Learn(baseline.Sample{Time: t0, Dims: map[string]string{"principal": "p1", "tool": "read"}, Numeric: num}, baseline.LearnInfo{})
	}
	s, err := e.Build("operator")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const ctxKey = "principal=p1|tool=read"

func TestZScoreAgainstReference(t *testing.T) {
	reqtest.Verifies(t, "FR-10.23")
	logT, _ := baseline.ParseTransform("log1p")
	snap := knownSnapshot(t, []baseline.FeatureSpec{{Name: "a", SigmaFloor: 0.5}, {Name: "b", Transform: logT, SigmaFloor: 1e-6}, {Name: "c", SigmaFloor: 3}},
		map[string][]float64{"a": {8, 12}, "b": {10, 100, 1000}, "c": {5, 5}}, 300)
	s := scorer(t)
	if err := s.Load(snap); err != nil {
		t.Fatal(err)
	}
	r := s.Score(Input{Context: ctxKey, Numeric: map[string]float64{"a": 20, "b": 5000, "c": 11}})
	byName := map[string]FeatureScore{}
	for _, f := range r.Features {
		byName[f.Feature] = f
	}
	ref := func(name string, x float64, tr baseline.Transform, floor float64) float64 {
		st := snap.Contexts[ctxKey].Features[name]
		y, _ := tr.Apply(x)
		return (y - st.Mean) / math.Max(math.Sqrt(st.Variance), floor)
	}
	for _, c := range []struct {
		name  string
		x     float64
		tr    baseline.Transform
		floor float64
	}{{"a", 20, baseline.Transform{Kind: "none"}, 0.5}, {"b", 5000, logT, 1e-6}, {"c", 11, baseline.Transform{Kind: "none"}, 3}} {
		want := ref(c.name, c.x, c.tr, c.floor)
		got := byName[c.name].Z
		if math.Abs(got-want) > 1e-9*math.Max(1, math.Abs(want)) {
			t.Fatalf("%s: z %v, reference %v", c.name, got, want)
		}
	}
	// σ_floor applies to a constant feature: c has σ 0, floor 3: (11-5)/3.
	if math.Abs(byName["c"].Z-2) > 1e-12 {
		t.Fatalf("floored z %v", byName["c"].Z)
	}
	if r.SnapshotID != snap.ID || r.Context != ctxKey {
		t.Fatalf("result %+v", r)
	}
}

func TestRobustZ(t *testing.T) {
	reqtest.Verifies(t, "FR-10.24")
	vals := []float64{}
	r := rand.New(rand.NewPCG(1, 1))
	for i := 0; i < 20000; i++ {
		vals = append(vals, 50+10*r.NormFloat64())
	}
	snap := knownSnapshot(t, []baseline.FeatureSpec{{Name: "x", Robust: true, SigmaFloor: 0.1}}, map[string][]float64{"x": vals}, len(vals))
	st := snap.Contexts[ctxKey].Features["x"]
	s := scorer(t)
	s.Load(snap)
	for _, x := range []float64{50, 70, 10, 200} {
		res := s.Score(Input{Context: ctxKey, Numeric: map[string]float64{"x": x}})
		want := 0.6745 * (x - st.Median) / math.Max(st.MAD, 0.1)
		if len(res.Features) != 1 || math.Abs(res.Features[0].Z-want) > 1e-12 || !res.Features[0].Robust {
			t.Fatalf("x=%v: %+v, want z %v", x, res.Features, want)
		}
	}
	// For normal data 0.6745·(x−median)/MAD approximates the standard z.
	z := s.Score(Input{Context: ctxKey, Numeric: map[string]float64{"x": 80}}).Features[0].Z
	if math.Abs(z-3) > 0.1 {
		t.Fatalf("robust z of +3σ = %v", z)
	}
	if RobustZ(5, 5, 0, 0) != 0 || RobustZ(6, 5, 0, 0) != math.MaxFloat64 {
		t.Fatal("zero MAD and floor")
	}
}

func TestCombinationAndBands(t *testing.T) {
	reqtest.Verifies(t, "FR-10.25", "FR-10.26")
	snap := knownSnapshot(t, []baseline.FeatureSpec{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		map[string][]float64{"a": {9, 11}, "b": {9, 11}, "c": {9, 11}}, 1000)
	sd := snap.Contexts[ctxKey].Features["a"].Std
	s := scorer(t)
	s.Load(snap)
	// a +2.5σ, b −3.5σ, c +1σ: combined is b's −3.5, abnormal.
	r := s.Score(Input{Context: ctxKey, Numeric: map[string]float64{"a": 10 + 2.5*sd, "b": 10 - 3.5*sd, "c": 10 + sd}})
	if r.Contributor != "b" || math.Abs(r.Combined+3.5) > 1e-9 || r.Band != Abnormal || len(r.Features) != 3 {
		t.Fatalf("combination %+v", r)
	}
	th := DefaultThresholds
	for _, c := range []struct {
		z    float64
		band string
	}{
		{0, Normal}, {1.999999, Normal}, {2, Elevated}, {-2, Elevated}, {2.999999, Elevated}, {3, Abnormal},
		{-3.5, Abnormal}, {3.999999, Abnormal}, {4, Critical}, {-40, Critical}, {math.MaxFloat64, Critical},
	} {
		if got := th.Classify(c.z); got != c.band {
			t.Fatalf("|z|=%v: %s, want %s", c.z, got, c.band)
		}
	}
	custom := Thresholds{Elevated: 1, Abnormal: 1.5, Critical: 2.5}
	if custom.Classify(1.6) != Abnormal || custom.Classify(0.99) != Normal {
		t.Fatal("policy thresholds ignored")
	}
	if (Thresholds{Elevated: 3, Abnormal: 2, Critical: 4}).Validate() == nil {
		t.Fatal("unordered thresholds accepted")
	}
}

func TestUncharacterizedContext(t *testing.T) {
	reqtest.Verifies(t, "FR-10.27")
	s := scorer(t)
	in := Input{Context: ctxKey, Numeric: map[string]float64{"x": 1000}}
	if r := s.Score(in); r.Band != Uncharacterized || r.SnapshotID != "" {
		t.Fatalf("no snapshot: %+v", r)
	}
	e := engine(t, baseline.Config{Dimensions: []string{"principal", "tool"}, Features: []baseline.FeatureSpec{{Name: "x"}}, NMin: 30})
	for i := 1; i <= 30; i++ {
		e.Learn(baseline.Sample{Time: t0, Dims: map[string]string{"principal": "p1", "tool": "read"}, Numeric: map[string]float64{"x": float64(i % 3)}}, baseline.LearnInfo{})
		snap, _ := e.Build("operator")
		s.Load(snap)
		r := s.Score(in)
		if i < 30 && r.Band != Uncharacterized {
			t.Fatalf("n=%d: band %s", i, r.Band)
		}
		if i == 30 && r.Band != Critical {
			t.Fatalf("n=30: band %s", r.Band)
		}
	}
	// Another context stays uncharacterized.
	if r := s.Score(Input{Context: "principal=p2|tool=read", Numeric: map[string]float64{"x": 1}}); r.Band != Uncharacterized {
		t.Fatalf("new context: %s", r.Band)
	}
}

func TestSnapshotLoadAtomicAndVerified(t *testing.T) {
	reqtest.Verifies(t, "FR-10.22")
	a := knownSnapshot(t, []baseline.FeatureSpec{{Name: "x"}}, map[string][]float64{"x": {9, 11}}, 100)
	b := knownSnapshot(t, []baseline.FeatureSpec{{Name: "x"}}, map[string][]float64{"x": {99, 101}}, 100)
	s := scorer(t)
	s.Load(a)
	// Concurrent scoring during repeated promotions: every result is
	// consistent with exactly one snapshot.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 8)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := s.Score(Input{Context: ctxKey, Numeric: map[string]float64{"x": 10}})
				want := map[string]float64{a.ID: 0, b.ID: (10 - 100) / b.Contexts[ctxKey].Features["x"].Std}[r.SnapshotID]
				if len(r.Features) != 1 || math.Abs(r.Features[0].Z-want) > 1e-9 {
					errs <- fmt.Errorf("mixed snapshot: %+v", r)
					return
				}
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		if i%2 == 0 {
			s.Load(b)
		} else {
			s.Load(a)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
	// A corrupted snapshot is rejected and the previous one stays.
	bad := *b
	bad.Contexts = map[string]baseline.ContextStats{}
	for k, v := range b.Contexts {
		v.Count += 1
		bad.Contexts[k] = v
	}
	before := s.SnapshotID()
	if err := s.Load(&bad); !errors.Is(err, baseline.ErrDigest) {
		t.Fatalf("corrupted snapshot: %v", err)
	}
	if s.SnapshotID() != before {
		t.Fatal("corrupted snapshot replaced the loaded one")
	}
}

func TestRollbackScoresRecordSnapshot(t *testing.T) {
	reqtest.Partial(t, "FR-10.21")
	dir := t.TempDir()
	s := scorer(t)
	e, _ := baseline.NewEngine(baseline.Config{Dimensions: []string{"principal", "tool"}, Features: []baseline.FeatureSpec{{Name: "x"}}}, nil)
	m, err := baseline.NewManager(e, baseline.ManagerOptions{Dir: dir, Loader: s})
	if err != nil {
		t.Fatal(err)
	}
	learn := func(v float64) {
		for i := 0; i < 50; i++ {
			m.Learn(baseline.Sample{Time: time.Now(), Dims: map[string]string{"principal": "p1", "tool": "read"}, Numeric: map[string]float64{"x": v + float64(i%2)}}, baseline.LearnInfo{})
		}
	}
	learn(1)
	r1, _ := m.BuildSnapshot("operator", "admin")
	learn(50)
	r2, _ := m.BuildSnapshot("operator", "admin")
	m.Promote(r2.Snapshot.ID, "admin")
	if got := s.Score(Input{Context: ctxKey, Numeric: map[string]float64{"x": 1}}).SnapshotID; got != r2.Snapshot.ID {
		t.Fatalf("score recorded %s", got)
	}
	if _, err := m.Promote(r1.Snapshot.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := s.Score(Input{Context: ctxKey, Numeric: map[string]float64{"x": 1}}).SnapshotID; got != r1.Snapshot.ID {
		t.Fatalf("after rollback score recorded %s", got)
	}
}

// TestConvergenceAndInjectedOutliers feeds a synthetic call stream with
// known per-context distributions, checks that the learned baseline
// converges to them, then scores a held-out stream with injected outliers.
func TestConvergenceAndInjectedOutliers(t *testing.T) {
	reqtest.Partial(t, "FR-10", "FR-10.28")
	logT, _ := baseline.ParseTransform("log1p")
	cfg := baseline.Config{Dimensions: []string{"principal", "tool"}, Features: []baseline.FeatureSpec{
		{Name: "latency", SigmaFloor: 0.1},
		{Name: "bytes", Transform: logT, SigmaFloor: 0.01},
		{Name: "entropy", Robust: true, SigmaFloor: 0.01},
	}}
	e := engine(t, cfg)
	r := rand.New(rand.NewPCG(11, 12))
	type truth struct{ latMean, latSD, bytesMu, bytesSigma float64 }
	ctxs := map[string]truth{
		"read":  {20, 4, 6, 0.3},
		"write": {80, 10, 8, 0.5},
	}
	gen := func(tool string) map[string]float64 {
		tr := ctxs[tool]
		return map[string]float64{"latency": tr.latMean + tr.latSD*r.NormFloat64(), "bytes": math.Expm1(tr.bytesMu + tr.bytesSigma*r.NormFloat64()),
			"entropy": 4 + 0.2*r.NormFloat64()}
	}
	for i := 0; i < 20000; i++ {
		tool := []string{"read", "write"}[i%2]
		e.Learn(baseline.Sample{Time: t0, Dims: map[string]string{"principal": "p1", "tool": tool}, Numeric: gen(tool)}, baseline.LearnInfo{})
	}
	snap, err := e.Build("operator")
	if err != nil {
		t.Fatal(err)
	}
	for tool, tr := range ctxs {
		cs := snap.Contexts["principal=p1|tool="+tool]
		lat, by := cs.Features["latency"], cs.Features["bytes"]
		if math.Abs(lat.Mean-tr.latMean) > 0.05*tr.latSD*4 || math.Abs(lat.Std-tr.latSD)/tr.latSD > 0.05 {
			t.Fatalf("%s latency did not converge: %+v", tool, lat)
		}
		if math.Abs(by.Mean-tr.bytesMu) > 0.02 || math.Abs(by.Std-tr.bytesSigma)/tr.bytesSigma > 0.05 {
			t.Fatalf("%s log1p(bytes) did not converge: %+v", tool, by)
		}
	}
	s := scorer(t)
	if err := s.Load(snap); err != nil {
		t.Fatal(err)
	}
	// Held-out stream: 2,000 normal calls, 40 injected outliers.
	falsePos, detected := 0, 0
	for i := 0; i < 2000; i++ {
		tool := []string{"read", "write"}[i%2]
		res := s.Score(Input{Context: "principal=p1|tool=" + tool, Numeric: gen(tool)})
		if Rank(res.Band) >= Rank(Abnormal) {
			falsePos++
		}
	}
	for i := 0; i < 40; i++ {
		tool := []string{"read", "write"}[i%2]
		f := gen(tool)
		switch i % 4 {
		case 0:
			f["latency"] = ctxs[tool].latMean + 8*ctxs[tool].latSD
		case 1:
			f["bytes"] *= 1000 // exfiltration-sized result
		case 2:
			f["entropy"] = 7.5 // random-looking payload
		case 3:
			f["latency"] = ctxs[tool].latMean - 6*ctxs[tool].latSD
		}
		res := s.Score(Input{Context: "principal=p1|tool=" + tool, Numeric: f})
		if Rank(res.Band) >= Rank(Abnormal) {
			detected++
		}
	}
	// Three features at ≥3σ: the expected normal-data false-positive rate
	// is about 1 − (0.9973)^3 ≈ 0.8%.
	if detected != 40 || falsePos > 40 {
		t.Fatalf("detected %d/40 outliers, %d/2000 false positives", detected, falsePos)
	}
	t.Logf("detected %d/40 injected outliers; %d/2000 normal calls at abnormal or worse", detected, falsePos)
}

func TestScoringLatency(t *testing.T) {
	reqtest.Verifies(t, "FR-11.3")
	var feats []baseline.FeatureSpec
	vals := map[string][]float64{}
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("f%02d", i)
		feats = append(feats, baseline.FeatureSpec{Name: name, Robust: i%4 == 0, SigmaFloor: 0.01})
		vals[name] = []float64{1, 2, 3, 4}
	}
	snap := knownSnapshot(t, feats, vals, 200)
	s := scorer(t)
	s.Load(snap)
	in := Input{Context: ctxKey, Numeric: map[string]float64{}}
	for i := 0; i < 64; i++ {
		in.Numeric[fmt.Sprintf("f%02d", i)] = float64(i % 5)
	}
	const n = 100_000
	d := make([]time.Duration, n)
	for i := range d {
		st := time.Now()
		r := s.Score(in)
		d[i] = time.Since(st)
		if len(r.Features) != 64 {
			t.Fatal("not all features scored")
		}
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	p95 := d[n*95/100]
	t.Logf("64-feature score p50 %v p95 %v p99 %v", d[n/2], p95, d[n*99/100])
	if p95 > 2*time.Millisecond {
		t.Fatalf("p95 %v > 2 ms", p95)
	}
}
