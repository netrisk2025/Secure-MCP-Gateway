package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Message mediation in front of the MCP SDK (E-02). The SDK's
// StreamableHTTPHandler answers some malformed or unusual POST bodies with
// plain-text HTTP errors, accepts what the 2026-07-28 Streamable HTTP
// rules reject, and refuses a Last-Event-ID header that FR-1.16 says to
// ignore. The edge therefore reads and checks each POST body before the
// SDK sees it:
//
//   - a body that is not valid UTF-8 JSON is refused with 400 and -32700
//     (FR-1.22);
//   - a body that is not exactly one JSON-RPC request or notification
//     object (a batch, a response object, a scalar) is refused with 400
//     and -32600 (FR-1.4);
//   - a well-formed notification is answered 202 with an empty body and
//     discarded (FR-1.5);
//   - Last-Event-ID is removed from 2026-07-28 requests (FR-1.16);
//   - a request whose ID is already in flight in the session is refused
//     with 400 and -32600 (FR-1.21);
//   - a listen request beyond CP-20 is refused with -31005 (FR-1.38).
//
// Every error the SDK still writes as plain text is rewritten as a
// JSON-RPC error that echoes the request ID (rpcWriter, FR-1.18).

// Reserved JSON-RPC codes the edge writes itself.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInternalError  = -32603
	codeMethodNotFound = -32601
)

// ctxMessage carries the mediated message of a request.
const ctxMessage ctxKey = 101

// rpcMessage is what the edge learned from a POST body.
type rpcMessage struct {
	// ID is the raw request ID, or nil for a notification or a body
	// without a usable ID.
	ID json.RawMessage
	// Method is the JSON-RPC method.
	Method string
	// Version is _meta["io.modelcontextprotocol/protocolVersion"].
	Version string
	// Progress reports that the request carries a progress token.
	Progress bool
	// Notification reports a well-formed notification.
	Notification bool
	// Err is the JSON-RPC error that refuses the body, with Status its
	// HTTP status; nil when the body is one well-formed message.
	Err    *jsonrpc.Error
	Status int
	// Unread reports that the body could not be read to its end (the
	// CP-07 body deadline passed or the client went away); the request is
	// answered without authenticating it.
	Unread bool
}

func messageFrom(ctx context.Context) rpcMessage {
	m, _ := ctx.Value(ctxMessage).(rpcMessage)
	return m
}

// readMessage reads the body within limit, restores it for the SDK and
// classifies it. A body over the limit is refused with 413.
func readMessage(r *http.Request, limit int64) rpcMessage {
	if r.Body == nil {
		r.Body = http.NoBody
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		return rpcMessage{Status: http.StatusRequestEntityTooLarge, Err: &jsonrpc.Error{Code: codeInvalidRequest, Message: fmt.Sprintf("request body exceeds %d bytes", mbe.Limit)}}
	case err != nil:
		return rpcMessage{Status: http.StatusBadRequest, Err: &jsonrpc.Error{Code: codeParseError, Message: "request body could not be read"}, Unread: true}
	case int64(len(body)) > limit:
		return rpcMessage{Status: http.StatusRequestEntityTooLarge, Err: &jsonrpc.Error{Code: codeInvalidRequest, Message: fmt.Sprintf("request body exceeds %d bytes", limit)}}
	}
	return classify(body)
}

// classify checks one POST body against FR-1.4, FR-1.5 and FR-1.22.
func classify(body []byte) rpcMessage {
	bad := func(code int64, msg string, id json.RawMessage) rpcMessage {
		return rpcMessage{ID: id, Status: http.StatusBadRequest, Err: &jsonrpc.Error{Code: code, Message: msg}}
	}
	if !utf8.Valid(body) { // FR-1.22: encoding/json would replace the bytes silently
		return bad(codeParseError, "parse error: body is not valid UTF-8", nil)
	}
	if !json.Valid(body) {
		return bad(codeParseError, "parse error: body is not valid JSON", nil)
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' { // FR-1.4: batch or scalar
		if len(trimmed) > 0 && trimmed[0] == '[' {
			return bad(codeInvalidRequest, "invalid request: JSON-RPC batches are not supported", nil)
		}
		return bad(codeInvalidRequest, "invalid request: the body must be one JSON-RPC object", nil)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return bad(codeParseError, "parse error: "+err.Error(), nil)
	}
	var id json.RawMessage
	rawID, hasID := obj["id"]
	if hasID {
		if !validID(rawID) {
			return bad(codeInvalidRequest, "invalid request: id must be a string or a number", nil)
		}
		id = compactJSON(rawID)
	}
	var version string
	if err := json.Unmarshal(obj["jsonrpc"], &version); err != nil || version != "2.0" {
		return bad(codeInvalidRequest, `invalid request: jsonrpc must be "2.0"`, id)
	}
	_, hasResult := obj["result"]
	_, hasError := obj["error"]
	rawMethod, hasMethod := obj["method"]
	if !hasMethod && (hasResult || hasError) { // FR-1.4: clients must not send responses
		return bad(codeInvalidRequest, "invalid request: JSON-RPC responses are not accepted", id)
	}
	var method string
	if err := json.Unmarshal(rawMethod, &method); err != nil || method == "" {
		return bad(codeInvalidRequest, "invalid request: method must be a non-empty string", id)
	}
	if hasResult || hasError {
		return bad(codeInvalidRequest, "invalid request: a request cannot carry result or error", id)
	}
	m := rpcMessage{ID: id, Method: method, Notification: !hasID}
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if p, ok := obj["params"]; ok && json.Unmarshal(p, &params) == nil {
		_ = json.Unmarshal(params.Meta["io.modelcontextprotocol/protocolVersion"], &m.Version)
		if tok, ok := params.Meta["progressToken"]; ok && validID(tok) {
			m.Progress = true
		}
	}
	return m
}

// validID reports whether raw is a JSON string or number.
func validID(raw json.RawMessage) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	switch v.(type) {
	case string, float64:
		return true
	}
	return false
}

func compactJSON(raw json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return nil
	}
	return b.Bytes()
}

// writeRPCErrorID writes a JSON-RPC error response that echoes id (null
// when id is nil).
func writeRPCErrorID(w http.ResponseWriter, status int, id json.RawMessage, e *jsonrpc.Error) {
	if id == nil {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
}

// rpcWriter rewrites a plain-text HTTP error written by the SDK as a
// JSON-RPC error carrying the request ID (FR-1.18). Every other response
// passes through unchanged.
type rpcWriter struct {
	w       http.ResponseWriter
	id      json.RawMessage
	status  int
	capture bool // a plain-text error is being collected
	buf     bytes.Buffer
}

func (p *rpcWriter) Header() http.Header { return p.w.Header() }

func (p *rpcWriter) WriteHeader(code int) {
	if p.status != 0 {
		return
	}
	p.status = code
	mt, _, _ := mime.ParseMediaType(p.w.Header().Get("Content-Type"))
	if code >= 400 && (mt == "text/plain" || mt == "") {
		p.capture = true
		return
	}
	p.w.WriteHeader(code)
}

func (p *rpcWriter) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.WriteHeader(http.StatusOK)
	}
	if p.capture {
		return p.buf.Write(b)
	}
	return p.w.Write(b)
}

// Flush implements http.Flusher.
func (p *rpcWriter) Flush() {
	if !p.capture {
		_ = http.NewResponseController(p.w).Flush()
	}
}

// finish writes a captured plain-text error as a JSON-RPC error.
func (p *rpcWriter) finish() {
	if !p.capture {
		return
	}
	code := int64(codeInvalidRequest)
	text := strings.TrimSpace(p.buf.String())
	switch {
	// The SDK refuses an unknown legacy-era method with its
	// jsonrpc2.ErrNotHandled text.
	case p.status == http.StatusNotFound || strings.Contains(text, "JSON RPC not handled"):
		code = codeMethodNotFound
	case p.status >= 500:
		code = codeInternalError
	}
	hdr := p.w.Header()
	hdr.Del("X-Content-Type-Options")
	writeRPCErrorID(p.w, p.status, p.id, &jsonrpc.Error{Code: code, Message: text})
}

// listenKeepAlive is the CP-20 keep-alive interval of idle listen streams.
const listenKeepAlive = 15 * time.Second

// listenWriter serializes a listen stream's writes with SSE comment
// keep-alives sent whenever the stream has been idle for the keep-alive
// interval (FR-1.36), sets X-Accel-Buffering (FR-1.7), and closes a stream
// the Gateway ends with an empty complete response (FR-1.37). The SDK
// writes each event with one Write, so a comment never splits an event.
type listenWriter struct {
	mu       sync.Mutex
	w        http.ResponseWriter
	interval time.Duration
	status   int
	started  bool // the event stream has been committed
	closed   bool
	last     time.Time
	stop     chan struct{}
	stopped  chan struct{}
}

func newListenWriter(w http.ResponseWriter, interval time.Duration) *listenWriter {
	l := &listenWriter{w: w, interval: interval, stop: make(chan struct{}), stopped: make(chan struct{})}
	go l.keepAlive()
	return l
}

func (l *listenWriter) Header() http.Header { return l.w.Header() }

func (l *listenWriter) WriteHeader(code int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writeHeaderLocked(code)
}

func (l *listenWriter) writeHeaderLocked(code int) {
	if l.status != 0 {
		return
	}
	l.status = code
	if code == http.StatusOK && isEventStream(l.w.Header()) {
		l.w.Header().Set("X-Accel-Buffering", "no")
		l.started = true
		l.last = time.Now()
	}
	l.w.WriteHeader(code)
}

func (l *listenWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.status == 0 {
		l.writeHeaderLocked(http.StatusOK)
	}
	if l.closed {
		return 0, http.ErrHandlerTimeout
	}
	l.last = time.Now()
	return l.w.Write(b)
}

// Flush implements http.Flusher.
func (l *listenWriter) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = http.NewResponseController(l.w).Flush()
}

func (l *listenWriter) keepAlive() {
	defer close(l.stopped)
	t := time.NewTimer(l.interval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
		}
		l.mu.Lock()
		next := l.interval
		if l.started && !l.closed {
			if idle := time.Since(l.last); idle >= l.interval {
				_, _ = io.WriteString(l.w, ": keep-alive\n\n")
				_ = http.NewResponseController(l.w).Flush()
				l.last = time.Now()
			} else {
				next = l.interval - idle
			}
		}
		l.mu.Unlock()
		t.Reset(next)
	}
}

// finish stops the keep-alives. When the Gateway ended the stream
// (complete), it sends the empty complete response carrying the
// subscription ID, which is the listen request's ID (FR-1.37).
func (l *listenWriter) finish(id json.RawMessage, complete bool) {
	close(l.stop)
	<-l.stopped
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if !complete || !l.started || id == nil {
		return
	}
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
		"resultType": "complete", "_meta": map[string]any{"io.modelcontextprotocol/subscriptionId": id, // FR-1.14
			mcp.MetaKeyServerInfo: serverInfo}}}) // FR-1.15
	_, _ = fmt.Fprintf(l.w, "data: %s\n\n", msg)
	_ = http.NewResponseController(l.w).Flush()
}
