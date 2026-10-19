package edge

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// listenerBounds are the pre-parse bounds of the harness listener
// (SR-7.11-1): the CP-06 header limit and deadline, the CP-07 body deadline
// (the CP-07 size limit is config.Limits.RequestBodyBytes), and the CP-09
// connection and unauthenticated-work limits.
type listenerBounds struct {
	HeaderBytes     int           // CP-06
	HeaderTimeout   time.Duration // CP-06
	BodyTimeout     time.Duration // CP-07: the whole request, headers and body
	Connections     int           // CP-09: open connections on the listener
	Unauthenticated int           // CP-09: requests being read or authenticated at once
}

// defaultBounds are the Appendix A values.
var defaultBounds = listenerBounds{
	HeaderBytes:     16 << 10,
	HeaderTimeout:   5 * time.Second,
	BodyTimeout:     15 * time.Second,
	Connections:     128,
	Unauthenticated: 32,
}

// connLimitListener closes, without reading from it, every accepted
// connection beyond max open ones (CP-09). Closing at once rather than
// leaving the connection in the accept backlog keeps a flood from holding
// connections that the server would serve later.
type connLimitListener struct {
	net.Listener
	max     int64
	open    atomic.Int64
	refused atomic.Int64
}

func newConnLimitListener(ln net.Listener, max int) *connLimitListener {
	return &connLimitListener{Listener: ln, max: int64(max)}
}

func (l *connLimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Add(1) > l.max {
			l.open.Add(-1)
			l.refused.Add(1)
			_ = c.Close()
			continue
		}
		return &limitedConn{Conn: c, release: func() { l.open.Add(-1) }}, nil
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// workLimit bounds the requests whose body is being read or whose bearer
// token is being checked (CP-09 unauthenticated work). A request takes a
// slot before the body is read and gives it back once authentication is
// done.
type workLimit chan struct{}

func newWorkLimit(n int) workLimit { return make(workLimit, n) }

func (w workLimit) tryAcquire() bool {
	select {
	case w <- struct{}{}:
		return true
	default:
		return false
	}
}

func (w workLimit) release() { <-w }
