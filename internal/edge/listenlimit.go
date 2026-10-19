package edge

import (
	"errors"
	"net/http"
	"time"
)

// maxListenTotal bounds the listen streams the listener holds open at once
// over all sessions, in addition to the CP-20 listen_streams_per_session
// bound of each session (FR-1.38). A listen stream lives until the client
// or the session ends it, so this bounds what many session holders
// together can keep open.
const maxListenTotal = 256

// listenWriteTimeout bounds one write (and flush) on a listen stream. A
// reader that does not take the data in time loses the stream. A variable
// for tests.
var listenWriteTimeout = 10 * time.Second

// errListenStalled is the cause with which a listen stream whose reader
// stopped taking data is ended.
var errListenStalled = errors.New("listen stream reader stopped taking data")

// deadlineWriter bounds each write and flush on a listen stream with a write
// deadline, cleared again when the write completes so that an idle stream
// is not reset. A write that fails (the deadline passed: the reader stopped
// taking data) cancels the stream's context, which ends the stream.
type deadlineWriter struct {
	http.ResponseWriter
	rc     *http.ResponseController
	cancel func(error)
}

func newDeadlineWriter(w http.ResponseWriter, cancel func(error)) *deadlineWriter {
	return &deadlineWriter{ResponseWriter: w, rc: http.NewResponseController(w), cancel: cancel}
}

func (l *deadlineWriter) Write(b []byte) (int, error) {
	_ = l.rc.SetWriteDeadline(time.Now().Add(listenWriteTimeout))
	n, err := l.ResponseWriter.Write(b)
	if err != nil {
		l.cancel(errListenStalled)
		return n, err
	}
	_ = l.rc.SetWriteDeadline(time.Time{})
	return n, nil
}

// Flush implements http.Flusher, which the SDK uses to push each event.
func (l *deadlineWriter) Flush() {
	_ = l.rc.SetWriteDeadline(time.Now().Add(listenWriteTimeout))
	if err := l.rc.Flush(); err != nil {
		l.cancel(errListenStalled)
		return
	}
	_ = l.rc.SetWriteDeadline(time.Time{})
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (l *deadlineWriter) Unwrap() http.ResponseWriter { return l.ResponseWriter }
