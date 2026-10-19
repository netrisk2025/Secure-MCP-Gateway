package analytics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestObservationHealthCheck: an enabled service whose store failed to
// open makes the Gateway degraded, never fail-closed.
func TestObservationHealthCheck(t *testing.T) {
	reqtest.Partial(t, "FR-7.12")
	var off *Service
	if c := off.HealthCheck()(time.Now()); len(c) != 0 || off.StoreError() != nil {
		t.Fatalf("nil service: %v", c)
	}
	s := &Service{S: Settings{Enabled: true}}
	if c := s.HealthCheck()(time.Now()); len(c) != 0 {
		t.Fatalf("healthy store: %v", c)
	}
	s.storeErr = errors.New("duckdb: disk full")
	c := s.HealthCheck()(time.Now())
	if len(c) != 1 || c[0].Name != health.CauseObservationUnavailable || c[0].Critical || s.StoreError() == nil {
		t.Fatalf("%+v", c)
	}
	mon := health.New(health.Options{Log: diag.Discard()})
	mon.Register("observation", s.HealthCheck())
	mon.Evaluate()
	if mon.State() != health.Degraded || len(mon.Gate()) != 0 {
		t.Fatalf("state %s gate %v", mon.State(), mon.Gate())
	}
}

// TestObservationStoreReachability (FR-7.11): an opened store is reported
// unreachable while its directory no longer accepts files, and while its
// last batch write failed; both clear once the store works again.
func TestObservationStoreReachability(t *testing.T) {
	reqtest.Partial(t, "FR-7.11")
	s, err := New(Options{Config: enabledConfig(t), Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	check := s.HealthCheck()
	if c := check(time.Now()); len(c) != 0 {
		t.Fatalf("healthy store: %v", c)
	}
	dir := filepath.Join(s.S.Dir, "store")
	if err := os.Rename(dir, dir+".x"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(dir, nil, 0o600)
	if c := check(time.Now()); len(c) != 1 || c[0].Name != health.CauseObservationUnavailable || c[0].Critical {
		t.Fatalf("unreachable store: %+v", c)
	}
	_ = os.Remove(dir)
	_ = os.Rename(dir+".x", dir)
	if c := check(time.Now()); len(c) != 0 {
		t.Fatalf("store back: %v", c)
	}
	msg := "disk full"
	s.writer.failing.Store(&msg)
	if c := check(time.Now()); len(c) != 1 || !strings.Contains(c[0].Detail, "disk full") {
		t.Fatalf("failed write: %+v", c)
	}
	s.writer.failing.Store(nil)
	if c := check(time.Now()); len(c) != 0 {
		t.Fatalf("after a good write: %v", c)
	}
}

// TestWriterRecordsLastWriteError: a failed batch sets the writer's last
// error and the next successful batch clears it.
func TestWriterRecordsLastWriteError(t *testing.T) {
	st := &failingStore{err: errors.New("no space left on device")}
	w := newWriter(st, 1, time.Hour, 16, diag.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)
	w.offer("t", obsstore.Row{"a": 1})
	w.sync(ctx)
	if !strings.Contains(w.lastError(), "no space") {
		t.Fatalf("last error %q", w.lastError())
	}
	st.set(nil)
	w.offer("t", obsstore.Row{"a": 2})
	w.sync(ctx)
	if e := w.lastError(); e != "" {
		t.Fatalf("last error after a good write %q", e)
	}
}

type failingStore struct {
	obsstore.Store // nil: only Append is used
	mu             sync.Mutex
	err            error
}

func (f *failingStore) set(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

func (f *failingStore) Append(string, []obsstore.Row) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}
