package edge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
)

// Held calls (FR-3.19). The MCP endpoint answers in JSON (FR-1.6), but a
// call parked for an approval needs keep-alives, which only an event
// stream can carry. A tools/call request is therefore served by an SDK
// handler in event-stream mode behind a heldWriter that buffers the
// output: when the call finishes without having been held, the single
// response event is re-encoded as an application/json body, so the
// harness sees exactly what JSON mode would have produced; when the
// Approval Service sends the first keep-alive, the writer commits to
// text/event-stream and every later event and keep-alive goes out as it
// is written.

const ctxHeld ctxKey = 100

// serveMCP routes one authenticated, mediated MCP POST: a listen request
// to the JSON handler (which streams it) behind a listenWriter; a
// tools/call, or any request that carries a progress token, to the
// event-stream handler behind a heldWriter; anything else to the JSON
// handler. A request with a progress token is answered as an event stream
// from its first message (FR-1.6). Plain-text SDK errors become JSON-RPC
// errors (rpcWriter).
func (g *Gateway) serveMCP(w http.ResponseWriter, r *http.Request) {
	msg := messageFrom(r.Context())
	rw := &rpcWriter{w: w, id: msg.ID}
	defer rw.finish()
	switch {
	case msg.Method == "subscriptions/listen":
		lw := newListenWriter(rw, g.listenInterval)
		g.handler.ServeHTTP(lw, r)
		cause := context.Cause(r.Context())
		lw.finish(msg.ID, errors.Is(cause, errSessionEnded) || errors.Is(cause, errShutdown))
	case msg.Method == "tools/call" || msg.Progress:
		hw := &heldWriter{w: rw, hdr: http.Header{}, eager: msg.Progress}
		g.streamHandler.ServeHTTP(hw, r.WithContext(context.WithValue(r.Context(), ctxHeld, hw)))
		hw.finish()
	default:
		g.handler.ServeHTTP(rw, r)
	}
}

// heldWriter buffers an event-stream response until the call is held
// (startStream) or finishes (finish). It serializes the SDK's writes with
// keep-alive comments; the SDK writes each event with one Write, so a
// comment never splits an event.
type heldWriter struct {
	mu        sync.Mutex
	w         http.ResponseWriter
	hdr       http.Header
	status    int
	buf       bytes.Buffer
	streaming bool
	done      bool
	// eager commits the response to an event stream at its first write
	// (a request with a progress token, FR-1.6).
	eager bool
}

func (h *heldWriter) Header() http.Header { return h.hdr }

func (h *heldWriter) WriteHeader(code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streaming {
		return // already sent
	}
	if h.status == 0 {
		h.status = code
	}
}

func (h *heldWriter) Write(b []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streaming {
		return h.w.Write(b)
	}
	n, err := h.buf.Write(b)
	if h.eager {
		h.startStreamLocked()
	}
	return n, err
}

// Flush implements http.Flusher; it is a no-op until the stream starts.
func (h *heldWriter) Flush() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streaming {
		_ = http.NewResponseController(h.w).Flush()
	}
}

func isEventStream(hdr http.Header) bool {
	mt, _, _ := mime.ParseMediaType(hdr.Get("Content-Type"))
	return mt == "text/event-stream"
}

func (h *heldWriter) copyHeaders() {
	for k, v := range h.hdr {
		h.w.Header()[k] = v
	}
	if isEventStream(h.w.Header()) { // FR-1.7
		h.w.Header().Set("X-Accel-Buffering", "no")
	}
}

// startStream commits the response to text/event-stream and writes what
// was buffered. It reports false when the response is not an event stream
// (for example an HTTP error) or has already been sent.
func (h *heldWriter) startStream() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.startStreamLocked()
}

func (h *heldWriter) startStreamLocked() bool {
	if h.streaming {
		return true
	}
	if h.done || !isEventStream(h.hdr) || (h.status != 0 && h.status != http.StatusOK) {
		return false
	}
	h.copyHeaders()
	h.w.WriteHeader(http.StatusOK)
	_, _ = h.w.Write(h.buf.Bytes())
	h.buf.Reset()
	h.streaming = true
	_ = http.NewResponseController(h.w).Flush()
	return true
}

// comment writes an SSE comment line (a keep-alive that clients ignore).
func (h *heldWriter) comment(text string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.streaming {
		return
	}
	_, _ = io.WriteString(h.w, ": "+strings.ReplaceAll(text, "\n", " ")+"\n\n")
	_ = http.NewResponseController(h.w).Flush()
}

// finish sends a response that was never streamed: a single event-stream
// message becomes the JSON body JSON mode would have sent; anything else is
// sent as written.
func (h *heldWriter) finish() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.done = true
	if h.streaming {
		return
	}
	status := h.status
	if status == 0 {
		status = http.StatusOK
	}
	if isEventStream(h.hdr) && status == http.StatusOK {
		if data, ok := singleEventData(h.buf.Bytes()); ok {
			h.copyHeaders()
			hdr := h.w.Header()
			hdr.Set("Content-Type", "application/json")
			hdr.Del("Connection")
			hdr.Del("X-Accel-Buffering")
			h.w.WriteHeader(status)
			_, _ = h.w.Write(data)
			return
		}
	}
	h.copyHeaders()
	h.w.WriteHeader(status)
	_, _ = h.w.Write(h.buf.Bytes())
}

// singleEventData returns the data of the only event in an SSE body.
func singleEventData(b []byte) ([]byte, bool) {
	var data []byte
	events := 0
	for block := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n\n") {
		var lines []string
		for line := range strings.SplitSeq(block, "\n") {
			if v, ok := strings.CutPrefix(line, "data:"); ok {
				lines = append(lines, strings.TrimPrefix(v, " "))
			}
		}
		if len(lines) > 0 {
			events++
			data = []byte(strings.Join(lines, "\n"))
		}
	}
	return data, events == 1
}

// keepAlive returns the Progress function of an approval request: it
// commits the held call to an event stream and sends a
// notifications/progress message when the request carries a progress token,
// or an SSE comment line otherwise (FR-3.19).
//
// The progress values continue in the call's progressRelay, so backend
// progress relayed after the approval keeps increasing (FR-1.39).
func (g *Gateway) keepAlive(ctx context.Context, prog *progressRelay) func(string) {
	hw, _ := ctx.Value(ctxHeld).(*heldWriter)
	return func(msg string) {
		streaming := hw != nil && hw.startStream()
		if prog.keepAlive(msg) {
			return
		}
		if streaming {
			hw.comment("keep-alive " + msg)
		}
	}
}
