package hostile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// children holds the HF-20 child processes and the write ends of their
// standard input pipes. Closing a pipe (or the fixture exiting, which
// closes it) ends the child.
var children struct {
	mu    sync.Mutex
	pipes []io.Closer
	procs []*exec.Cmd
}

// releaseChildren closes every child's standard input and waits for the
// children to exit.
func releaseChildren() {
	children.mu.Lock()
	pipes, procs := children.pipes, children.procs
	children.pipes, children.procs = nil, nil
	children.mu.Unlock()
	for _, p := range pipes {
		_ = p.Close()
	}
	for _, c := range procs {
		_ = c.Wait()
	}
}

// spawn starts helper processes up to Config.Children, at most MaxChildren,
// then reports how many started and holds them (HF-20). Each child is this
// binary with -hold and waits for its standard input to close.
func spawn(s *server, id json.RawMessage, _ callParams) {
	want := min(max(s.cfg.Children, 1), MaxChildren)
	self := s.cfg.Self
	if len(self) == 0 {
		exe, err := os.Executable()
		if err != nil {
			s.reply(id, text("spawned 0: "+err.Error()))
			return
		}
		self = []string{exe}
	}
	started := 0
	var firstErr error
	for started < want {
		cmd := exec.Command(self[0], append(append([]string(nil), self[1:]...), "-hold")...) // #nosec G204 -- re-executes this fixture binary
		w, err := cmd.StdinPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			if w != nil {
				_ = w.Close()
			}
			firstErr = err
			break
		}
		children.mu.Lock()
		children.pipes = append(children.pipes, w)
		children.procs = append(children.procs, cmd)
		children.mu.Unlock()
		started++
	}
	msg := fmt.Sprintf("spawned %d of %d", started, want)
	if firstErr != nil {
		msg += "; stopped: " + firstErr.Error()
	}
	s.reply(id, text(msg))
}

// held keeps HF-21 allocations reachable until the process exits.
var held [][]byte

// alloc allocates and touches memory in 16 MiB steps up to Config.AllocMiB,
// at most MaxAllocMiB, then reports and holds it (HF-21).
func alloc(s *server, id json.RawMessage, _ callParams) {
	want := min(max(s.cfg.AllocMiB, 1), MaxAllocMiB)
	const step = 16
	got := 0
	for got < want {
		n := min(step, want-got)
		b := make([]byte, n<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		held = append(held, b)
		got += n
	}
	s.reply(id, text(fmt.Sprintf("allocated %d MiB", got)))
}
