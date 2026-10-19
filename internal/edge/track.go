package edge

import (
	"errors"
	"sync"
	"time"
)

// Kinds of tracked activity.
const (
	kindRequest = iota // an HTTP request on the MCP endpoint
	kindListen         // a subscriptions/listen stream
	kindCall           // a tool call inside a request
)

// Causes with which the Gateway ends a listen stream itself; a listen
// stream ended with one of them is closed with an empty complete response
// (FR-1.37).
var (
	errSessionEnded  = errors.New("session ended")
	errShutdown      = errors.New("gateway shutting down")
	errEmergencyStop = errors.New("emergency stop")
)

type activity struct {
	kind   int
	cancel func(error)
	done   chan struct{}
}

// tracker records what each session has in progress, so that ending a
// session can cancel its calls, end its listen streams and wait for its
// requests to finish writing their responses (FR-2.11). It also holds the
// IDs of each session's in-flight requests (FR-1.21).
type tracker struct {
	mu        sync.Mutex
	seq       uint64
	bySession map[string]map[uint64]*activity
	ids       map[string]map[string]bool
}

func newTracker() *tracker {
	return &tracker{bySession: map[string]map[uint64]*activity{}, ids: map[string]map[string]bool{}}
}

// add registers an activity and returns the function that marks it done.
func (t *tracker) add(sessionID string, kind int, cancel func(error)) func() {
	done, _ := t.addLimited(sessionID, kind, 0, 0, cancel)
	return done
}

// addLimited registers an activity unless the session already has
// perSession activities of that kind, or all sessions together have total
// (0 means no limit). It reports false, and registers nothing, when a
// limit is reached. The check and the registration happen under one lock.
func (t *tracker) addLimited(sessionID string, kind, perSession, total int, cancel func(error)) (func(), bool) {
	a := &activity{kind: kind, cancel: cancel, done: make(chan struct{})}
	t.mu.Lock()
	m := t.bySession[sessionID]
	if perSession > 0 || total > 0 {
		mine, all := 0, 0
		for sid, sm := range t.bySession {
			for _, b := range sm {
				if b.kind == kind {
					all++
					if sid == sessionID {
						mine++
					}
				}
			}
		}
		if (perSession > 0 && mine >= perSession) || (total > 0 && all >= total) {
			t.mu.Unlock()
			return nil, false
		}
	}
	t.seq++
	id := t.seq
	if m == nil {
		m = map[uint64]*activity{}
		t.bySession[sessionID] = m
	}
	m[id] = a
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(a.done)
			t.mu.Lock()
			if m := t.bySession[sessionID]; m != nil {
				delete(m, id)
				if len(m) == 0 {
					delete(t.bySession, sessionID)
				}
			}
			t.mu.Unlock()
		})
	}, true
}

// claimID records a request ID as in flight for the session. It reports
// false when the same ID is already in flight (FR-1.21).
func (t *tracker) claimID(sessionID, id string) (func(), bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.ids[sessionID]
	if m[id] {
		return nil, false
	}
	if m == nil {
		m = map[string]bool{}
		t.ids[sessionID] = m
	}
	m[id] = true
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if m := t.ids[sessionID]; m != nil {
				delete(m, id)
				if len(m) == 0 {
					delete(t.ids, sessionID)
				}
			}
		})
	}, true
}

// take removes and returns every activity of a session.
func (t *tracker) take(sessionID string) []*activity {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.bySession[sessionID]
	delete(t.bySession, sessionID)
	out := make([]*activity, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	return out
}

func (t *tracker) count(kind int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, m := range t.bySession {
		for _, a := range m {
			if a.kind == kind {
				n++
			}
		}
	}
	return n
}

// cancelKind cancels every activity of one kind with cause, without
// removing it; each one unregisters when its request returns.
func (t *tracker) cancelKind(kind int, cause error) {
	t.mu.Lock()
	var acts []*activity
	for _, m := range t.bySession {
		for _, a := range m {
			if a.kind == kind {
				acts = append(acts, a)
			}
		}
	}
	t.mu.Unlock()
	for _, a := range acts {
		a.cancel(cause)
	}
}

// endSession cancels calls and listen streams, then waits up to grace for
// the session's requests to finish writing. It returns the number of calls
// cancelled.
func (t *tracker) endSession(sessionID string, grace time.Duration) int {
	acts := t.take(sessionID)
	calls := 0
	for _, a := range acts {
		if a.kind == kindCall || a.kind == kindListen {
			a.cancel(errSessionEnded)
		}
		if a.kind == kindCall {
			calls++
		}
	}
	deadline := time.NewTimer(grace)
	defer deadline.Stop()
	for _, a := range acts {
		select {
		case <-a.done:
		case <-deadline.C:
			for _, b := range acts {
				b.cancel(errSessionEnded)
			}
			return calls
		}
	}
	return calls
}
