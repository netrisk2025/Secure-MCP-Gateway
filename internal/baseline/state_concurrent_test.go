package baseline

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Concurrent saves of the candidate state (the record-count build, the
// interval loop and Close can overlap) leave a complete state file that
// loads, and no temporary file behind.
func TestSaveStateConcurrent(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dimensions: []string{"tool"}, Features: []FeatureSpec{{Name: "x"}}}
	e, err := NewEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 200 {
		e.Learn(Sample{Time: time.Now(), Session: "s", Dims: map[string]string{"tool": "t"}, Numeric: map[string]float64{"x": float64(i)}}, LearnInfo{})
	}
	path := filepath.Join(dir, "candidate-state.json")
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 64 {
		wg.Go(func() {
			if err := e.SaveState(path); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent save: %v", err)
	}
	e2, err := NewEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.LoadState(path); err != nil {
		t.Fatalf("state after concurrent saves: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		names := []string{}
		for _, d := range entries {
			names = append(names, d.Name())
		}
		t.Fatalf("files left: %v", names)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v", info.Mode().Perm())
	}
}
