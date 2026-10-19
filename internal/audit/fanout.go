package audit

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
)

// Observer receives events after the authoritative journal has accepted
// them. Observers feed non-authoritative mirrors: the Observation Collector
// (E-29), the graph mirror (E-26 into E-25) and analytics (E-27). They run on
// their own goroutine behind a bounded queue; when the queue is full the
// event is dropped for that observer and counted. An observer can never
// block, slow or fail a call.
type Observer interface {
	Observe(Event)
}

// NonBlocking marks an Observer whose Observe never blocks and bounds its
// own work (a non-blocking offer to a bounded queue of its own, which
// counts its drops). The fan-out calls such an observer directly on the
// writing goroutine instead of through a queue and goroutine of its own:
// a queued observer's goroutine is woken for every event, and on a busy
// host those wake-ups delay the calls that write the events (FR-11.4).
type NonBlocking interface {
	Observer
	NonBlockingObserver()
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(Event)

// Observe calls f.
func (f ObserverFunc) Observe(e Event) { f(e) }

// Appender is the authoritative store behind a Fanout. *Journal implements
// it; tests use *Memory.
type Appender interface {
	Append(ev Event, durable bool) (Event, error)
}

// Fanout is the EvidenceSink: it writes each event to the authoritative
// journal first and then offers it to every registered observer.
type Fanout struct {
	store Appender
	log   *slog.Logger

	mu        sync.RWMutex
	observers []*observerQueue
	direct    []directObserver
	closed    bool
}

type directObserver struct {
	name string
	obs  Observer
}

type observerQueue struct {
	name    string
	obs     Observer
	ch      chan Event
	dropped atomic.Uint64
	done    chan struct{}
}

// NewFanout returns a fan-out over the authoritative store.
func NewFanout(store Appender, log *slog.Logger) *Fanout {
	if log == nil {
		log = slog.Default()
	}
	return &Fanout{store: store, log: log}
}

// AddObserver registers a non-authoritative observer with a queue of the
// given size (default 1024). A NonBlocking observer is called directly
// instead, and queue is ignored.
func (f *Fanout) AddObserver(name string, o Observer, queue int) {
	if _, ok := o.(NonBlocking); ok {
		f.mu.Lock()
		f.direct = append(f.direct, directObserver{name, o})
		f.mu.Unlock()
		return
	}
	if queue <= 0 {
		queue = 1024
	}
	q := &observerQueue{name: name, obs: o, ch: make(chan Event, queue), done: make(chan struct{})}
	go q.run(f.log)
	f.mu.Lock()
	f.observers = append(f.observers, q)
	f.mu.Unlock()
}

func (q *observerQueue) run(log *slog.Logger) {
	defer close(q.done)
	for ev := range q.ch {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error("evidence observer panicked", "observer", q.name, "panic", fmt.Sprint(r))
				}
			}()
			q.obs.Observe(ev)
		}()
	}
}

// Record appends to the journal and notifies observers.
func (f *Fanout) Record(ev Event) error { return f.append(ev, false) }

// Commit appends durably and notifies observers.
func (f *Fanout) Commit(ev Event) error { return f.append(ev, true) }

func (f *Fanout) append(ev Event, durable bool) error {
	written, err := f.store.Append(ev, durable)
	if err != nil {
		return err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return nil
	}
	for _, q := range f.observers {
		select {
		case q.ch <- written:
		default:
			q.dropped.Add(1)
		}
	}
	for _, d := range f.direct {
		f.observeDirect(d, written)
	}
	return nil
}

// observeDirect calls a NonBlocking observer; a panic is logged, as on an
// observer's own goroutine, and never reaches the call.
func (f *Fanout) observeDirect(d directObserver, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			f.log.Error("evidence observer panicked", "observer", d.name, "panic", fmt.Sprint(r))
		}
	}()
	d.obs.Observe(ev)
}

// Dropped reports, per observer, how many events were dropped because its
// queue was full.
func (f *Fanout) Dropped() map[string]uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := map[string]uint64{}
	for _, q := range f.observers {
		out[q.name] = q.dropped.Load()
	}
	for _, d := range f.direct {
		out[d.name] = 0 // a direct observer counts its own drops
	}
	return out
}

// Close stops delivery and waits for observers to drain their queues.
func (f *Fanout) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	obs := f.observers
	f.mu.Unlock()
	for _, q := range obs {
		close(q.ch)
		<-q.done
	}
}

// Memory is an in-memory Appender and Recorder for tests. Fail makes every
// later append fail, to exercise fail-closed paths.
type Memory struct {
	mu     sync.Mutex
	events []Event
	err    error
	n      int
}

// Append implements Appender.
func (m *Memory) Append(ev Event, durable bool) (Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return ev, m.err
	}
	m.n++
	if ev.EventID == "" {
		ev.EventID = fmt.Sprintf("ev-%d", m.n)
	}
	m.events = append(m.events, ev)
	return ev, nil
}

// Record implements Recorder.
func (m *Memory) Record(ev Event) error { _, err := m.Append(ev, false); return err }

// Commit implements Recorder.
func (m *Memory) Commit(ev Event) error { _, err := m.Append(ev, true); return err }

// Fail makes later appends return err (nil restores).
func (m *Memory) Fail(err error) { m.mu.Lock(); m.err = err; m.mu.Unlock() }

// Events returns a copy of the recorded events.
func (m *Memory) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}
