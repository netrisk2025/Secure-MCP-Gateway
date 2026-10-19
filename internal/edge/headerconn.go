package edge

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
)

// Header characters (SR-5.2-2). net/http refuses a request whose header
// block it cannot parse, a header name or value with invalid characters
// among them, before any handler runs: it writes a fixed plain-text 400
// to the connection and closes it. On the harness listener such a
// response is rewritten into the JSON-RPC answer the requirement asks
// for: HTTP 400 with error -32020 and a null ID (the body was never
// read). The rewrite works on the plaintext side of TLS, so the harness
// listener terminates TLS in headerListener and serves HTTP/1.1 over the
// result; a client that offers HTTP/2 falls back to HTTP/1.1 by ALPN.

// codeHeaderMismatch is the MCP 2026-07-28 header error code.
const codeHeaderMismatch = -32020

// net/http's canned responses for an unparseable header block.
var (
	cannedHeaderError = []byte("HTTP/1.1 400 Bad Request: invalid header ")
	cannedBadRequest  = []byte("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request")
)

// headerErrorResponse is the HTTP response that replaces them.
var headerErrorResponse = func() []byte {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{
		"code": codeHeaderMismatch, "message": "invalid request headers: a header name or value has invalid characters, or the header block is malformed"}})
	return fmt.Appendf(nil, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}()

// headerListener terminates TLS and wraps each connection in a
// headerConn.
type headerListener struct {
	net.Listener
	tc *tls.Config
}

func newHeaderListener(ln net.Listener, tc *tls.Config) net.Listener {
	tc = tc.Clone()
	tc.NextProtos = []string{"http/1.1"}
	return headerListener{Listener: ln, tc: tc}
}

func (l headerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &headerConn{Conn: tls.Server(c, l.tc)}, nil
}

// headerConn rewrites net/http's canned header-error response. net/http
// writes it with one Write straight to the connection when it cannot read
// a request; a handler's response never has the same bytes (its status
// line has no ": reason" and its header block carries a Date).
type headerConn struct {
	net.Conn
}

func (c *headerConn) Write(b []byte) (int, error) {
	if bytes.HasPrefix(b, cannedHeaderError) || bytes.Equal(b, cannedBadRequest) {
		if _, err := c.Conn.Write(headerErrorResponse); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}
