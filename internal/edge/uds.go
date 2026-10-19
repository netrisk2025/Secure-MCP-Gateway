package edge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// UDS Harness Profile (CP-02, FR-1.47, FR-2.15, SR-2.8-3).
//
// The socket carries MCP as newline-delimited JSON-RPC, as the stdio
// binding defines it: one message per line, no embedded newlines. A
// connection is accepted only from a peer UID registered in [[uds.peer]];
// its first message must be
//
//	{"jsonrpc":"2.0","id":0,"method":"local.smcpgw/authenticate","params":{"key":"<bearer key>"}}
//
// carrying the bearer key registered for that UID. Both checks pass, or
// the connection gets -31006 and is closed (FR-2.15). A session is then
// created for the peer's principal on the "uds" listener and lasts as
// long as the connection: closing the socket ends it.
//
// Every later message is served by the same chain as the TLS endpoint
// (mcpChain, serveMCP): the bridge turns the line into an internal POST
// with the session's bearer token and the Mcp-Method, Mcp-Name and
// MCP-Protocol-Version headers the body implies, and writes each JSON-RPC
// message of the answer (the JSON body or each event of an event stream)
// back as one line. Requests run concurrently. A notifications/cancelled
// for an in-flight request ID cancels that request exactly as closing its
// HTTP response stream does (FR-1.41), and the bridge writes nothing more
// for it. Listen streams carry their subscriptionId in _meta as on HTTP.

// MethodUDSAuthenticate is the first message on a UDS connection.
const MethodUDSAuthenticate = "local.smcpgw/authenticate"

// udsMaxInFlight bounds the concurrent requests of one connection.
const udsMaxInFlight = 64

// ListenUDS creates the UDS harness socket with mode 0660 owned by the
// configured group (SR-2.8-3). A stale socket file at the path is
// replaced; any other file there is an error.
func (g *Gateway) ListenUDS() (net.Listener, error) {
	u := g.cfg.UDS
	if !u.Enabled {
		return nil, errors.New("edge: the UDS Harness Profile is not enabled")
	}
	grp, err := user.LookupGroup(u.Group)
	if err != nil {
		return nil, fmt.Errorf("uds: group %q: %w", u.Group, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return nil, fmt.Errorf("uds: group %q: %w", u.Group, err)
	}
	if fi, err := os.Lstat(u.Path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("uds: %s exists and is not a socket", u.Path)
		}
		if err := os.Remove(u.Path); err != nil {
			return nil, err
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: u.Path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chown(u.Path, -1, gid); err != nil {
		ln.Close()
		return nil, fmt.Errorf("uds: chown %s to group %s: %w", u.Path, u.Group, err)
	}
	if err := os.Chmod(u.Path, 0o660); err != nil { //nolint:gosec // SR-2.8-3: the smcp-harness group connects
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// ServeUDS accepts UDS harness connections on ln until ctx ends.
func (g *Gateway) ServeUDS(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.serveUDSConn(ctx, uc)
		}()
	}
}

// udsConn is one authenticated UDS connection.
type udsConn struct {
	g       *Gateway
	c       *net.UnixConn
	wmu     sync.Mutex
	mu      sync.Mutex
	sess    *session.Session
	token   string
	legacy  string // protocol version negotiated by a legacy initialize
	cancels map[string]context.CancelFunc
	slots   chan struct{}
}

// writeLine writes one JSON-RPC message as one line.
func (u *udsConn) writeLine(msg []byte) {
	var b bytes.Buffer
	if err := json.Compact(&b, msg); err != nil {
		return
	}
	b.WriteByte('\n')
	u.wmu.Lock()
	defer u.wmu.Unlock()
	_, _ = u.c.Write(b.Bytes())
}

func (u *udsConn) writeError(id json.RawMessage, e *jsonrpc.Error) {
	if id == nil {
		id = json.RawMessage("null")
	}
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
	u.writeLine(msg)
}

func (g *Gateway) serveUDSConn(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	u := &udsConn{g: g, c: c, cancels: map[string]context.CancelFunc{}, slots: make(chan struct{}, udsMaxInFlight)}
	ctx, cancel := context.WithCancel(channel.With(ctx, channel.Origin{Channel: channel.UDS}))
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		if u.sess != nil {
			g.store.Terminate(u.sess.ID) // the session lasts as long as the connection
		}
	}()
	limit := int(g.cfg.Limits.RequestBodyBytes)
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64<<10), limit+1)
	sc.Split(scanLines)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second)) // the authenticate message (CP-06)
	if !sc.Scan() {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if !u.authenticate(sc.Bytes()) {
		return
	}
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		msg := classify(line)
		if msg.Err != nil {
			u.writeError(msg.ID, msg.Err)
			continue
		}
		if msg.Method == "notifications/cancelled" {
			u.cancel(line)
			continue
		}
		if msg.Notification {
			continue // FR-1.5: accepted and discarded, as on HTTP
		}
		body := append([]byte(nil), line...)
		rctx, rcancel := context.WithCancel(ctx)
		key := string(msg.ID)
		u.mu.Lock()
		if _, dup := u.cancels[key]; dup {
			u.mu.Unlock()
			rcancel()
			u.writeError(msg.ID, &jsonrpc.Error{Code: codeInvalidRequest, Message: "invalid request: a request with this id is already in flight on this connection"})
			continue
		}
		u.cancels[key] = rcancel
		u.mu.Unlock()
		select {
		case u.slots <- struct{}{}:
		case <-ctx.Done():
			rcancel()
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-u.slots }()
			defer rcancel()
			u.serve(rctx, msg, body)
			u.mu.Lock()
			delete(u.cancels, key)
			u.mu.Unlock()
		}()
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		u.writeError(nil, &jsonrpc.Error{Code: codeInvalidRequest, Message: fmt.Sprintf("message exceeds %d bytes", limit)})
	}
	// End of input: the harness closed the connection, which cancels its
	// requests in flight and ends the session (deferred above).
}

// scanLines splits on '\n' and keeps no line terminator.
func scanLines(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, bytes.TrimSuffix(data[:i], []byte("\r")), nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// authenticate checks the peer UID and the bearer key of the first
// message and creates the connection's session (FR-2.15).
func (u *udsConn) authenticate(line []byte) bool {
	g := u.g
	corr := ids.New()
	msg := classify(bytes.TrimSpace(line))
	var req struct {
		Params struct {
			Key string `json:"key"`
		} `json:"params"`
	}
	_ = json.Unmarshal(line, &req)
	uid, uidErr := peerUID(u.c)
	peer, registered := g.cfg.UDS.Peer(uid)
	// The key is verified even for an unregistered UID, so both failures
	// cost the same (SR-2.3-1).
	hash := peer.KeyHash
	if !registered {
		hash = udsDummyHash()
	}
	keyOK := req.Params.Key != "" && keys.VerifyPassword(hash, req.Params.Key)
	reason := ""
	switch {
	case msg.Err != nil || msg.Method != MethodUDSAuthenticate || msg.Notification:
		reason = "UDS_AUTH_REQUIRED"
	case uidErr != nil || !registered:
		reason = "UDS_PEER_UNREGISTERED"
	case !keyOK:
		reason = "UDS_KEY_INVALID"
	}
	if reason != "" {
		detail := map[string]any{"listener": channel.UDS}
		if uidErr == nil {
			detail["peer_uid"] = uid
		}
		if err := g.evidence.Commit(audit.Event{Class: "auth_failure", Origin: "E-03", CorrelationID: corr, Outcome: "deny", ReasonCode: reason,
			PolicyStatus: "not_evaluated", Detail: detail}); err != nil {
			g.log.Error("evidence write failed", "err", err)
		}
		u.writeError(msg.ID, gatewayError(CodeSessionInvalid, "session invalid", "SESSION_INVALID", corr, "", nil))
		return false
	}
	if reason := g.failClosed(); reason != "" {
		u.writeError(msg.ID, gatewayError(CodeGatewayFailClosed, "gateway fail-closed", reason, corr, "", nil))
		return false
	}
	sess, tok, err := g.store.Create(session.CreateParams{PrincipalID: peer.Principal, ClientID: fmt.Sprintf("uds:%d", uid),
		Claims: session.Claims{Template: peer.Template}, Listener: channel.UDS})
	if err != nil {
		u.writeError(msg.ID, gatewayError(CodeSessionInvalid, "session not created: "+err.Error(), "SESSION_INVALID", corr, "", nil))
		return false
	}
	if err := g.evidence.Commit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, PolicyRevision: sess.PolicyRevision,
		Outcome: "created", ReasonCode: "UDS_PEER", PolicyStatus: "evaluated", Detail: map[string]any{"template": sess.Template, "listener": channel.UDS, "peer_uid": uid,
			"observation_policy": sess.ObservationPolicy, "context_key": sess.ContextKey}}); err != nil {
		g.store.Terminate(sess.ID)
		u.writeError(msg.ID, gatewayError(CodeGatewayFailClosed, "gateway fail-closed", ReasonJournalUnavailable, corr, "", nil))
		return false
	}
	u.sess, u.token = sess, tok.Access
	res, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{
		"sessionId": sess.ID, "principal": sess.PrincipalID, "template": sess.Template, "resultType": "complete",
		"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": serverInfo}}})
	u.writeLine(res)
	return true
}

// udsDummyHash is verified for an unregistered peer; it is made on first
// use so that processes without the profile never pay for it.
var udsDummyHash = sync.OnceValue(func() string {
	h, err := keys.HashPassword(ids.Secret())
	if err != nil {
		panic(err)
	}
	return h
})

// cancel handles notifications/cancelled: the in-flight request with the
// named ID is cancelled.
func (u *udsConn) cancel(line []byte) {
	var n struct {
		Params struct {
			RequestID json.RawMessage `json:"requestId"`
		} `json:"params"`
	}
	if json.Unmarshal(line, &n) != nil || !validID(n.Params.RequestID) {
		return
	}
	u.mu.Lock()
	cancel := u.cancels[string(compactJSON(n.Params.RequestID))]
	u.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// serve runs one request through the MCP endpoint chain and writes its
// messages back as lines.
func (u *udsConn) serve(ctx context.Context, msg rpcMessage, body []byte) {
	g := u.g
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.Listener.MCPPath, bytes.NewReader(body))
	if err != nil {
		u.writeError(msg.ID, &jsonrpc.Error{Code: codeInternalError, Message: "internal error"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+u.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.RemoteAddr = "uds"
	version := msg.Version
	if version == "" && msg.Method != "initialize" {
		u.mu.Lock()
		version = u.legacy
		u.mu.Unlock()
	}
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	if msg.Version != "" { // 2026-07-28 request headers (SR-5.2-2)
		req.Header.Set("Mcp-Method", msg.Method)
		if msg.Method == "tools/call" {
			var p struct {
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &p) == nil && p.Params.Name != "" {
				req.Header.Set("Mcp-Name", p.Params.Name)
			}
		}
	}
	w := &udsResponse{hdr: http.Header{}, out: func(m []byte) {
		if ctx.Err() != nil {
			return // cancelled: nothing more is written for this request
		}
		if msg.Method == "initialize" {
			u.noteLegacy(m)
		}
		u.writeLine(m)
	}}
	g.udsHandler.ServeHTTP(w, req)
	w.finish()
}

// noteLegacy records the protocol version a legacy initialize negotiated,
// which later requests on the connection carry as MCP-Protocol-Version.
func (u *udsConn) noteLegacy(m []byte) {
	var r struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(m, &r) == nil && r.Result.ProtocolVersion != "" {
		u.mu.Lock()
		u.legacy = r.Result.ProtocolVersion
		u.mu.Unlock()
	}
}

// udsResponse is the http.ResponseWriter of one bridged request. A JSON
// body is written as one line when the handler returns; each event of an
// event stream is written as one line when it is complete. Comments
// (keep-alives) are dropped: the socket has no proxy to keep open.
type udsResponse struct {
	mu     sync.Mutex
	hdr    http.Header
	status int
	stream bool
	buf    bytes.Buffer
	out    func([]byte)
}

func (r *udsResponse) Header() http.Header { return r.hdr }

func (r *udsResponse) WriteHeader(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status != 0 {
		return
	}
	r.status = code
	r.stream = isEventStream(r.hdr)
}

func (r *udsResponse) Write(b []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Write(b)
	if r.stream {
		r.drainEvents()
	}
	return len(b), nil
}

// Flush implements http.Flusher.
func (r *udsResponse) Flush() {}

// drainEvents writes every complete event in the buffer. r.mu is held.
func (r *udsResponse) drainEvents() {
	for {
		data := r.buf.Bytes()
		i := bytes.Index(data, []byte("\n\n"))
		if i < 0 {
			return
		}
		event := string(data[:i])
		r.buf.Next(i + 2)
		var parts []string
		for _, line := range strings.Split(event, "\n") {
			if d, ok := strings.CutPrefix(line, "data:"); ok {
				parts = append(parts, strings.TrimPrefix(d, " "))
			}
		}
		if len(parts) > 0 {
			r.out([]byte(strings.Join(parts, "\n")))
		}
	}
}

// finish writes a JSON body.
func (r *udsResponse) finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stream {
		r.drainEvents()
		return
	}
	if body := bytes.TrimSpace(r.buf.Bytes()); len(body) > 0 && json.Valid(body) {
		r.out(body)
	}
}
