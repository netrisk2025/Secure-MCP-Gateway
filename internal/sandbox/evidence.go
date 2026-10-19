package sandbox

import (
	"log/slog"
	"sync"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// maxPending bounds the evidence buffered before the journal is attached.
const maxPending = 1024

type pendingEvent struct {
	ev      audit.Event
	durable bool
}

// lazyRecorder holds runtime evidence produced while the Gateway starts
// (server instances launch before the journal is handed to the launcher)
// and writes it in order once a Recorder is attached.
type lazyRecorder struct {
	mu      sync.Mutex
	r       audit.Recorder
	pending []pendingEvent
	dropped int
	log     *slog.Logger
}

func newLazyRecorder(log *slog.Logger) *lazyRecorder { return &lazyRecorder{log: log} }

func (l *lazyRecorder) write(ev audit.Event, durable bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.r == nil {
		if len(l.pending) >= maxPending {
			l.dropped++
			return nil
		}
		l.pending = append(l.pending, pendingEvent{ev, durable})
		return nil
	}
	if durable {
		return l.r.Commit(ev)
	}
	return l.r.Record(ev)
}

func (l *lazyRecorder) attach(r audit.Recorder) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.r = r
	for i, p := range l.pending {
		var err error
		if p.durable || i == len(l.pending)-1 {
			err = r.Commit(p.ev)
		} else {
			err = r.Record(p.ev)
		}
		if err != nil {
			l.log.Error("runtime evidence write failed", "outcome", p.ev.Outcome, "err", err)
		}
	}
	l.pending = nil
	if l.dropped > 0 {
		l.log.Warn("runtime evidence dropped before the journal was attached", "events", l.dropped)
		if err := r.Commit(audit.Event{Class: EvidenceClass, Origin: OriginRuntime, Outcome: "evidence_dropped", PolicyStatus: "not_evaluated",
			Detail: map[string]any{"events": l.dropped}}); err != nil {
			l.log.Error("runtime evidence write failed", "err", err)
		}
		l.dropped = 0
	}
}
