package analytics

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
)

type tableRow struct {
	table string
	row   obsstore.Row
}

// writer batches rows into the store: a batch is written at maxRows rows or
// after interval, whichever comes first. offer never blocks; a full queue
// drops the row and counts it. The writer takes queued rows when its
// interval ends or when maxRows are queued, not one at a time, so that an
// offer does not wake it (and run its low-priority thread) once per row.
type writer struct {
	store    obsstore.Store
	maxRows  int
	interval time.Duration
	ch       chan tableRow
	full     chan struct{} // maxRows rows are queued
	syncCh   chan chan struct{}
	log      *slog.Logger

	mu        sync.Mutex
	dropCount map[string]uint64
	pressure  atomic.Uint64 // offers seen at ≥ 80% occupancy
	written   atomic.Int64
	failing   atomic.Pointer[string] // error of the last batch write, nil after a success
}

// lastError returns the error of the most recent batch write, or "" when
// it succeeded (or nothing was written yet).
func (w *writer) lastError() string {
	if w == nil {
		return ""
	}
	if e := w.failing.Load(); e != nil {
		return *e
	}
	return ""
}

func newWriter(s obsstore.Store, maxRows int, interval time.Duration, queue int, log *slog.Logger) *writer {
	return &writer{store: s, maxRows: maxRows, interval: interval, ch: make(chan tableRow, queue), full: make(chan struct{}, 1),
		syncCh: make(chan chan struct{}), log: log, dropCount: map[string]uint64{}}
}

// sync writes every row offered before the call, or returns when ctx ends
// (the writer stopped or never ran).
func (w *writer) sync(ctx context.Context) {
	done := make(chan struct{})
	select {
	case w.syncCh <- done:
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (w *writer) offer(table string, r obsstore.Row) {
	if len(w.ch)*5 >= cap(w.ch)*4 {
		w.pressure.Add(1)
	}
	select {
	case w.ch <- tableRow{table, r}:
	default:
		w.drop(observe.DropStoreQueue, 1)
	}
	if len(w.ch) >= w.maxRows {
		select {
		case w.full <- struct{}{}:
		default:
		}
	}
}

// underPressure reports the P2 backpressure signal (FR-9.6): the queue is
// at 80% or more of its capacity.
func (w *writer) underPressure() bool {
	return w != nil && len(w.ch)*5 >= cap(w.ch)*4
}

func (w *writer) drop(reason string, n uint64) {
	w.mu.Lock()
	w.dropCount[reason] += n
	w.mu.Unlock()
}

func (w *writer) drops() map[string]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range w.dropCount {
		out[k] = v
	}
	return out
}

// run writes batches until ctx ends, on a thread of lowered priority
// (idlePriority), and writes what is queued before it returns.
func (w *writer) run(ctx context.Context) {
	idlePriority() // the goroutine keeps its thread until it returns
	t := time.NewTicker(w.interval)
	defer t.Stop()
	buf := map[string][]obsstore.Row{}
	n := 0
	flush := func() {
		for table, rows := range buf {
			if len(rows) == 0 {
				continue
			}
			if err := w.store.Append(table, rows); err != nil {
				w.log.Warn("observation store write failed", "table", table, "rows", len(rows), "err", err)
				w.drop(observe.DropStoreError, uint64(len(rows)))
				msg := err.Error()
				w.failing.Store(&msg)
			} else {
				w.written.Add(int64(len(rows)))
				w.failing.Store(nil)
			}
			buf[table] = nil
		}
		n = 0
	}
	// take moves the queued rows into batches of at most maxRows.
	take := func() {
		for {
			select {
			case tr := <-w.ch:
				buf[tr.table] = append(buf[tr.table], tr.row)
				if n++; n >= w.maxRows {
					flush()
				}
			default:
				return
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			take()
			flush()
			return
		case <-t.C:
			take()
			flush()
		case <-w.full:
			take()
			flush()
		case done := <-w.syncCh:
			// Rows offered before the request are queued; take them all.
			take()
			flush()
			close(done)
		}
	}
}
