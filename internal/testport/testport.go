// Package testport hands out loopback TCP ports for tests that must write
// a listener address into a configuration before the listener opens.
//
// A port taken from a "127.0.0.1:0" listener and released is in the
// operating system's ephemeral range, which outgoing connections and
// listeners on port 0 also draw from. Under load (go test ./... runs
// packages in parallel, each making many connections), such a port is often
// in use by the time the configured listener binds it, and the bind fails
// with "address already in use". Free picks a random port below the
// ephemeral range instead and checks that it can be bound. It never returns
// the same port twice in one process, and on Unix it reserves the port for
// the life of the process with a lock on one byte of a shared file, so two
// test processes running at once never hand out the same port either.
package testport

import (
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Ports below the ephemeral range: Linux defaults to 32768-60999, macOS and
// Windows to 49152-65535. A narrower range read from the system is honored.
const (
	low  = 20000
	high = 32768
)

var (
	mu     sync.Mutex
	issued = map[int]bool{}
)

// Free returns a loopback port that was bindable when checked and that no
// earlier call in this process, or in another process using this package
// at the same time, returned.
func Free(t testing.TB) int {
	t.Helper()
	p, err := Port()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// SocketDir returns a new directory for Unix domain sockets, removed when
// the test ends. A socket path is limited to 104 bytes on macOS and 108 on
// Linux (sun_path), and $TMPDIR, where t.TempDir and os.MkdirTemp("", ...)
// put directories, can be long (macOS's per-user /var/folders/... or a
// sandbox's own), so the directory is made directly under /tmp, with a
// one-letter prefix, wherever /tmp is writable.
func SocketDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "s")
	if err != nil {
		dir, err = os.MkdirTemp("", "s")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// Port is Free for programs that are not tests (the agent conformance
// runner): it returns an error instead of failing a test.
func Port() (int, error) {
	top := high
	if l := ephemeralLow(); l > low+1000 && l < top {
		top = l
	}
	mu.Lock()
	defer mu.Unlock()
	for range 500 {
		p := low + rand.IntN(top-low) // #nosec G404 -- test port choice, not security relevant
		if issued[p] {
			continue
		}
		if !reserve(p) {
			issued[p] = true // held by another process; do not try it again
			continue
		}
		issued[p] = true
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		_ = l.Close()
		return p, nil
	}
	return 0, errors.New("testport: no free loopback port below the ephemeral range")
}

// ephemeralLow returns the low end of the Linux ephemeral port range, or 0.
func ephemeralLow() int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}
