package egress

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const chunk = 32 << 10

// meteredReader counts bytes, refuses more than limit bytes and charges
// the server's byte-rate limiter. Its error is a *refusal so the caller
// can report the reason.
type meteredReader struct {
	r        io.Reader
	limit    int64
	n        *atomic.Int64
	lim      *rate.Limiter
	now      func() time.Time
	tooLarge string
}

func (m *meteredReader) Read(p []byte) (int, error) {
	if len(p) > chunk {
		p = p[:chunk]
	}
	n, err := m.r.Read(p)
	if n > 0 {
		total := m.n.Add(int64(n))
		if total > m.limit {
			return 0, refused(m.tooLarge, "more than %d bytes", m.limit)
		}
		if !m.lim.AllowN(m.now(), n) {
			return 0, refused(ReasonByteRate, "byte rate limit of the server reached")
		}
	}
	return n, err
}

// splice copies both directions of a tunnel until either side ends, the
// deadline passes or a limit is hit. It returns the first limit refusal,
// if any.
func splice(client, upstream net.Conn, up, down *meteredReader, deadline time.Time) *refusal {
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	type result struct {
		upward bool
		err    error
	}
	done := make(chan result, 2)
	go func() {
		_, err := io.Copy(upstream, up)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok && err == nil {
			_ = cw.CloseWrite()
		}
		done <- result{true, err}
	}()
	go func() {
		_, err := io.Copy(client, down)
		done <- result{false, err}
	}()
	first := <-done
	var r *refusal
	if first.err != nil && !errors.Is(first.err, net.ErrClosed) {
		r = classifyCopy(first.err)
	}
	// The client closing its side half-closes the upstream and the answer
	// still flows; anything else ends the tunnel.
	if r != nil || !first.upward || first.err != nil {
		client.Close()
		upstream.Close()
	}
	second := <-done
	client.Close()
	upstream.Close()
	if r == nil && second.err != nil && !errors.Is(second.err, net.ErrClosed) {
		r = classifyCopy(second.err)
	}
	return r
}

// classifyCopy maps a copy error to a refusal; an ordinary connection end
// returns nil.
func classifyCopy(err error) *refusal {
	var rf *refusal
	if errors.As(err, &rf) {
		return rf
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &refusal{ReasonTimeout, "tunnel duration limit reached"}
	}
	return nil
}

// recordingConn feeds the TLS stack a ClientHello from r while keeping
// every byte read, and discards what the stack writes (the alert sent when
// the handshake is aborted). The broker never answers the handshake.
type recordingConn struct {
	net.Conn
	r   io.Reader
	buf bytes.Buffer
	max int
}

func (c *recordingConn) Read(p []byte) (int, error) {
	if c.buf.Len() >= c.max {
		return 0, errors.New("ClientHello too large")
	}
	if room := c.max - c.buf.Len(); len(p) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) { return len(p), nil }

var errHelloSeen = errors.New("client hello read")

// readClientHello reads the TLS ClientHello from r and returns its server
// name and the raw bytes read, which the caller forwards unchanged. The
// broker does not terminate or inspect the TLS session beyond this.
func readClientHello(conn net.Conn, r io.Reader) (string, []byte, error) {
	rc := &recordingConn{Conn: conn, r: r, max: 64 << 10}
	var sni string
	seen := false
	err := tls.Server(rc, &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni, seen = h.ServerName, true
		return nil, errHelloSeen
	}}).Handshake()
	if !seen {
		return "", rc.buf.Bytes(), fmt.Errorf("no TLS ClientHello: %w", err)
	}
	return sni, rc.buf.Bytes(), nil
}
