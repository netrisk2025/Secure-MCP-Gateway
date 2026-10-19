package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// container is a running instance: the attached `podman run` client
// process carries the server's stdio. It implements pipeline.Process.
type container struct {
	l      *Launcher
	inst   *Instance
	cmd    *exec.Cmd
	stdout *os.File
	stdin  *os.File
	stderr *pipeline.Ring
	after  time.Duration
	done   chan struct{}

	waitErr error
	eof     atomic.Bool // stdout ended before Close: the server exited on its own
	once    sync.Once
	err     error
	release func()
	// issue mints the egress capabilities of a call (SR-5.16-1) or, when
	// they are not required, records its egress-limit obligation
	// (FR-5.38); nil without an egress attachment.
	issue func(pipeline.Binding) (*pipeline.EgressAuth, func())
}

// IssueEgress implements pipeline.EgressIssuer.
func (c *container) IssueEgress(b pipeline.Binding) (*pipeline.EgressAuth, func()) {
	if c.issue == nil {
		return nil, func() {}
	}
	return c.issue(b)
}

func (c *container) Read(b []byte) (int, error) {
	n, err := c.stdout.Read(b)
	if errors.Is(err, io.EOF) {
		c.eof.Store(true)
	}
	return n, err
}

func (c *container) Write(b []byte) (int, error) { return c.stdin.Write(b) }
func (c *container) Stderr() string              { return c.stderr.Tail() }

// StderrSince implements pipeline.StderrReader (SR-6.18-1).
func (c *container) StderrSince(off uint64) (string, uint64, uint64) { return c.stderr.Since(off) }

// exited reports whether the podman client process has ended.
func (c *container) exited() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *container) wait(d time.Duration) bool {
	select {
	case <-c.done:
		return true
	case <-time.After(d):
		return false
	}
}

// Close runs the FR-5.27 shutdown sequence against the container: close
// stdin, wait, SIGTERM inside the container, wait, SIGKILL; then remove the
// container. It is safe to call more than once.
func (c *container) Close() error {
	c.once.Do(func() {
		// A Close that follows the end of the server's output (the MCP
		// client closes on EOF) is not a requested shutdown.
		c.inst.setClosing(!c.eof.Load() && !c.exited())
		c.stdin.Close()
		if !c.wait(c.after) {
			c.l.signal(c.inst.Name, "TERM")
			if !c.wait(c.after) {
				c.l.signal(c.inst.Name, "KILL")
				if !c.wait(c.after) {
					if c.cmd.Process != nil {
						_ = c.cmd.Process.Kill()
					}
					if !c.wait(c.after) {
						c.err = errors.New("server container did not exit")
					}
				}
			}
		}
		c.stdout.Close()
		c.l.finish(c.inst, c.waitErr)
		if c.release != nil {
			c.release()
		}
	})
	return c.err
}

// kill stops the container immediately (containment action). The process
// is then reaped by the monitor and by Close.
func (c *container) kill() {
	c.l.signal(c.inst.Name, "KILL")
	go func() {
		if !c.wait(5 * time.Second) {
			if c.cmd.Process != nil {
				_ = c.cmd.Process.Kill()
			}
		}
	}()
}

// signal sends sig to the container's main process through Podman.
func (l *Launcher) signal(name, sig string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := l.podman(ctx, "kill", "--signal", sig, name).CombinedOutput(); err != nil {
		l.log.Debug("podman kill", "name", name, "signal", sig, "err", err, "out", string(out))
	}
}
