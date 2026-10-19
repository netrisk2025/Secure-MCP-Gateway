package analytics

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// enabledConfig is an enabled observation configuration with its state in
// a temporary directory and the JSON Lines store.
func enabledConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := parse(t, `store = "jsonl"`)
	cfg.State.Dir = t.TempDir()
	return cfg
}

// batchStore records the batches the writer appends.
type batchStore struct {
	obsstore.Store // nil: only Append is used
	mu             sync.Mutex
	sizes          []int
	at             []time.Time
}

func (b *batchStore) Append(_ string, rows []obsstore.Row) error {
	b.mu.Lock()
	b.sizes = append(b.sizes, len(rows))
	b.at = append(b.at, time.Now())
	b.mu.Unlock()
	return nil
}

// TestObservationBatching: at 5,000 records per second the writer appends
// batches of at most 1,000 records, and no record waits more than about
// 200 ms for its batch (FR-9.5; defaults of Resolve).
func TestObservationBatching(t *testing.T) {
	reqtest.Verifies(t, "FR-9.5")
	st, err := Resolve(enabledConfig(t), observe.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if st.FlushRecords != 1000 || st.FlushInterval != 200*time.Millisecond {
		t.Fatalf("defaults: %d rows, %s", st.FlushRecords, st.FlushInterval)
	}
	bs := &batchStore{}
	w := newWriter(bs, st.FlushRecords, st.FlushInterval, 20000, diag.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.run(ctx); close(done) }()
	// 5,000 records per second for two seconds, in 1 ms steps of 5.
	var offered []time.Time
	start := time.Now()
	for i := 0; i < 2000; i++ {
		for j := 0; j < 5; j++ {
			w.offer("records", obsstore.Row{"ts": time.Now()})
		}
		offered = append(offered, time.Now())
		if d := time.Until(start.Add(time.Duration(i+1) * time.Millisecond)); d > 0 {
			time.Sleep(d)
		}
	}
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	bs.mu.Lock()
	defer bs.mu.Unlock()
	total := 0
	for _, n := range bs.sizes {
		if n > 1000 {
			t.Fatalf("batch of %d records", n)
		}
		total += n
	}
	if total != 10000 {
		t.Fatalf("%d of 10000 records written", total)
	}
	// The longest gap between consecutive batches bounds how long a record
	// waited (it was offered after the previous batch).
	var worst time.Duration
	for i := 1; i < len(bs.at); i++ {
		if g := bs.at[i].Sub(bs.at[i-1]); g > worst && bs.at[i].Before(offered[len(offered)-1]) {
			worst = g
		}
	}
	if worst > 350*time.Millisecond { // 200 ms plus scheduling jitter
		t.Fatalf("a batch waited %s", worst)
	}
}

// TestBackpressureSignal: with the Observation Store stalled, the writer's
// queue fills; at 80% occupancy the backpressure signal is raised and the
// degrader moves the Observation Collector to reduced sampling (FR-9.6).
func TestBackpressureSignal(t *testing.T) {
	reqtest.Verifies(t, "FR-9.6")
	w := newWriter(&batchStore{}, 1000, time.Hour, 10, diag.Discard()) // not running: the store is stalled
	d := newDegrader(0, w.underPressure, diag.Discard())
	d.hostFree = func() (float64, bool) { return 0.5, true }
	for i := 0; i < 7; i++ {
		w.offer("records", obsstore.Row{})
	}
	if w.underPressure() {
		t.Fatal("pressure at 70% occupancy")
	}
	if st, _ := d.step(); st != StageNormal {
		t.Fatalf("stage %d without pressure", st)
	}
	w.offer("records", obsstore.Row{})
	if !w.underPressure() {
		t.Fatal("no pressure at 80% occupancy")
	}
	if st, changed := d.step(); st != StageReducedSampling || !changed || !strings.Contains(d.Reason(), "backpressure") {
		t.Fatalf("stage %d (%v) reason %q", st, changed, d.Reason())
	}
}

// TestDegradationStagesInOrder: under memory pressure (heap above 90% of
// the observation budget, or less than 10% of host memory available) the
// stages are applied one at a time in the order reduced sampling, S3
// capture suspended, campaigns paused, caches shrunk, and lifted in reverse
// once the pressure ends; the stage is reported in the observation status
// and to the Health & Safety Monitor (FR-9.12; the collector's behavior at
// each stage is TestCaptureFollowsDegradationStage in internal/observe).
func TestDegradationStagesInOrder(t *testing.T) {
	reqtest.Verifies(t, "FR-9.12")
	s, err := New(Options{Config: enabledConfig(t), Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	heap := int64(100 << 20)
	var mu sync.Mutex
	s.degrade.budget = 512 << 20
	s.degrade.heap = func() int64 { mu.Lock(); defer mu.Unlock(); return heap }
	s.degrade.hostFree = func() (float64, bool) { return 0.5, true }
	setHeap := func(v int64) { mu.Lock(); heap = v; mu.Unlock() }
	if st, _ := s.degrade.step(); st != StageNormal || len(s.HealthCheck()(time.Now())) != 0 {
		t.Fatal("degraded without pressure")
	}
	setHeap(470 << 20) // above 90% of 512 MiB
	var seen []string
	for i := 0; i < 6; i++ {
		st, _ := s.degrade.step()
		seen = append(seen, StageNames[st])
	}
	if strings.Join(seen, ",") != "reduced_sampling,s3_capture_suspended,campaigns_paused,caches_shrunk,caches_shrunk,caches_shrunk" {
		t.Fatalf("stages %v", seen)
	}
	causes := s.HealthCheck()(time.Now())
	if len(causes) != 1 || causes[0].Name != CauseObservationDegraded || causes[0].Critical || !strings.Contains(causes[0].Detail, "caches_shrunk") {
		t.Fatalf("health %+v", causes)
	}
	if st, name := s.Degradation(); st != StageCachesShrunk || name != "caches_shrunk" {
		t.Fatalf("reported %d %s", st, name)
	}
	if s.Collector.Stats().Sessions != 0 {
		t.Fatal("unexpected sessions")
	}
	// Host memory below 10% keeps the pressure on after the heap recovers.
	setHeap(100 << 20)
	s.degrade.hostFree = func() (float64, bool) { return 0.05, true }
	if st, _ := s.degrade.step(); st != StageCachesShrunk {
		t.Fatalf("host pressure: stage %d", st)
	}
	s.degrade.hostFree = func() (float64, bool) { return 0.5, true }
	seen = nil
	for i := 0; i < 5; i++ {
		st, _ := s.degrade.step()
		seen = append(seen, StageNames[st])
	}
	if strings.Join(seen, ",") != "campaigns_paused,s3_capture_suspended,reduced_sampling,normal,normal" {
		t.Fatalf("recovery %v", seen)
	}
	if len(s.HealthCheck()(time.Now())) != 0 {
		t.Fatal("health still degraded")
	}
}
