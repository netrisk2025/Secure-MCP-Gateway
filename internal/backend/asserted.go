package backend

import (
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Kinds of server-asserted text (SR-6.18-1).
const (
	AssertStderr       = "stderr"
	AssertError        = "error"
	AssertNotification = "notification"
)

// Assertion is text a server instance asserted: a stretch of its stderr,
// the message of a JSON-RPC error it returned, or a notification it sent
// (SR-6.18-1). The Gateway records it as evidence attributed to the
// instance and never treats it as a fact about the call.
type Assertion struct {
	Server         string // alias
	ServerRevision string
	Instance       string // "<alias>#<n>", unique for the process lifetime
	Kind           string // AssertStderr, AssertError or AssertNotification
	Method         string // notification method
	Code           int64  // JSON-RPC error code
	Text           string // at most MaxAssertedText bytes, secrets redacted
	// Truncated counts the bytes cut from Text, and Skipped the stderr
	// bytes that were overwritten in the ring before they were read.
	Truncated, Skipped uint64
	// Dropped counts the assertions of the interval not delivered because
	// more than maxAssertionsPerInterval arrived.
	Dropped int
}

const (
	// MaxAssertedText bounds the text of one assertion.
	MaxAssertedText = 4 << 10
	// maxAssertionsPerInterval bounds the assertions delivered per
	// instance and interval, so a noisy server cannot flood the journal.
	maxAssertionsPerInterval = 16
)

// asserter collects an instance's assertions and delivers them in
// batches. Its methods are safe on a nil receiver, which does nothing.
type asserter struct {
	server, instance string
	proc             pipeline.Process
	secrets          []string
	deliver          func(Assertion)

	mu       sync.Mutex
	revision string
	pending  []Assertion
	dropped  int
	off      uint64
	stopped  bool
	done     chan struct{}
	finished chan struct{}
}

func newAsserter(server, instance string, proc pipeline.Process, secrets map[string]string, deliver func(Assertion)) *asserter {
	a := &asserter{server: server, instance: instance, proc: proc, deliver: deliver, done: make(chan struct{}), finished: make(chan struct{})}
	for _, v := range secrets {
		if v != "" {
			a.secrets = append(a.secrets, v)
		}
	}
	return a
}

// add queues one assertion, bounding and redacting its text.
func (a *asserter) add(x Assertion) {
	if a == nil {
		return
	}
	for _, v := range a.secrets {
		x.Text = strings.ReplaceAll(x.Text, v, "[REDACTED]")
	}
	if len(x.Text) > MaxAssertedText {
		x.Truncated += uint64(len(x.Text) - MaxAssertedText) //nolint:gosec // positive: len exceeds MaxAssertedText
		x.Text = strings.ToValidUTF8(x.Text[:MaxAssertedText], "")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pending) >= maxAssertionsPerInterval {
		a.dropped++
		return
	}
	a.pending = append(a.pending, x)
}

// notification is the frame filter's hook for every notification.
func (a *asserter) notification(method string, params []byte) {
	a.add(Assertion{Kind: AssertNotification, Method: method, Text: string(params)})
}

// run starts delivery once the instance's revision is known. Assertions
// made during the handshake are delivered with the first batch.
func (a *asserter) run(revision string, every time.Duration) {
	if a == nil {
		return
	}
	if every <= 0 {
		every = time.Second
	}
	a.mu.Lock()
	a.revision = revision
	a.mu.Unlock()
	go func() {
		defer close(a.finished)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				a.flush()
			case <-a.done:
				a.flush()
				return
			}
		}
	}()
}

// stop delivers what is left and ends delivery. It is safe to call more
// than once and before run.
func (a *asserter) stop() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
	a.stopped = true
	started := a.revision != ""
	a.mu.Unlock()
	close(a.done)
	if started {
		<-a.finished
	}
}

// flush reads the new stderr output and delivers the queued assertions.
func (a *asserter) flush() {
	if sr, ok := a.proc.(pipeline.StderrReader); ok {
		a.mu.Lock()
		off := a.off
		a.mu.Unlock()
		text, next, skipped := sr.StderrSince(off)
		a.mu.Lock()
		a.off = next
		a.mu.Unlock()
		if text != "" || skipped > 0 {
			a.add(Assertion{Kind: AssertStderr, Text: text, Skipped: skipped})
		}
	}
	a.mu.Lock()
	batch, dropped, rev := a.pending, a.dropped, a.revision
	a.pending, a.dropped = nil, 0
	a.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	batch[len(batch)-1].Dropped = dropped
	for _, x := range batch {
		x.Server, x.ServerRevision, x.Instance = a.server, rev, a.instance
		a.deliver(x)
	}
}
