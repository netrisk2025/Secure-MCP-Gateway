package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ServerSpec is what a Launcher needs to start one backend server
// instance. Env is the complete environment: the Launcher adds nothing
// except what its confinement requires.
type ServerSpec struct {
	Alias       string
	Command     string
	Args        []string
	Env         map[string]string
	Dir         string
	RiskClasses []string
	HighRisk    bool
	// SecretDir is the host directory of the instance's secret files (S2,
	// S3) whose paths appear in Env, or "". A launcher whose instances
	// cannot see the host file system (the sandbox) makes it available
	// read-only and rewrites those paths.
	SecretDir string
	// NegotiatedEra is the protocol version the instance negotiated in the
	// handshake. The dispatcher sets it after the launch, before asking the
	// ManifestSource for the tool set, so a verified source can refuse an
	// instance whose era differs from the manifest's (FR-5.40).
	NegotiatedEra string
	// SpawnsProcesses is the process-creation behavior the verified
	// manifest declares (capabilities.spawns_processes), or nil when the
	// server has no manifest. The Runtime Monitor treats a process created
	// by an instance that does not declare it as a deviation (FR-5.34).
	SpawnsProcesses *bool
	// Runtime is the launch runtime of a packaged server's manifest
	// ("native", "node", "python" or "oci"), or "" for a configured
	// command. A sandbox runs node and python servers with the interpreter
	// of the server's image.
	Runtime string
	// ArtifactRoot is the unpacked, digest-verified artifact tree of a
	// packaged server, or "". A sandbox mounts it read-only for node and
	// python servers, whose arguments name files in it.
	ArtifactRoot string
	// Roots are the filesystem slots the verified manifest declares, bound
	// to host paths: nil when the server has no manifest, empty when the
	// manifest declares none. A sandbox mounts only the parts of its
	// mount grants that lie within these roots (SR-4.6-1).
	Roots []Root
}

// Root is one manifest-declared filesystem slot bound to a host path.
// Write is true when the manifest declares the slot read-write.
type Root struct {
	Slot  string
	Path  string
	Write bool
}

// Process is a running server instance speaking newline-delimited JSON-RPC:
// Read returns the server's stdout and Write feeds its stdin. Close runs the
// shutdown sequence (close stdin, wait, terminate, kill) and is safe to call
// more than once.
type Process interface {
	io.Reader
	io.Writer
	Close() error
	// Stderr returns the bounded tail of the server's diagnostic output.
	Stderr() string
}

// StderrReader is implemented by a Process whose diagnostic output can be
// read incrementally (Ring.Since), for server-asserted evidence (SR-6.18-1).
type StderrReader interface {
	StderrSince(off uint64) (text string, next, skipped uint64)
}

// Launcher starts server instances (E-15 Server Runtime Manager, E-16
// Execution Sandbox). Confined reports whether instances run inside a
// sandbox; the standalone profile has an unconfined launcher.
type Launcher interface {
	Name() string
	Confined() bool
	Launch(ctx context.Context, spec ServerSpec) (Process, error)
}

// resolverCommands install or resolve packages at run time and are refused
// as server commands (SR-3.6-1).
var resolverCommands = []string{
	"npx", "npm", "pnpm", "pnpx", "yarn", "bun", "bunx", "uv", "uvx", "pip", "pip3", "pipx",
	"poetry", "deno", "go", "cargo", "gem", "bundle", "composer", "dotnet",
}

// ErrUnpinnedLaunch is returned by CheckLaunchSpec.
var ErrUnpinnedLaunch = errors.New("launch specification is not a pinned local artifact (SR-3.6-1)")

// CheckLaunchSpec refuses launch specifications that resolve or install
// packages at run time: a command that is not an absolute path (PATH lookup
// can change what runs), a package runner or installer, an interpreter
// running pip, and a container run without an image digest. It does not
// prove the artifact is content-addressed; signed packages (E-13) do.
func CheckLaunchSpec(spec ServerSpec) error {
	if !filepath.IsAbs(spec.Command) {
		return fmt.Errorf("%w: command %q must be an absolute path", ErrUnpinnedLaunch, spec.Command)
	}
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(spec.Command)), ".exe")
	if slices.Contains(resolverCommands, base) {
		return fmt.Errorf("%w: %s resolves or installs packages at run time; package the server with `smcpctl package build`", ErrUnpinnedLaunch, base)
	}
	if strings.HasPrefix(base, "python") {
		for i, a := range spec.Args {
			if a == "-m" && i+1 < len(spec.Args) && slices.Contains([]string{"pip", "pipx", "uv", "ensurepip"}, spec.Args[i+1]) {
				return fmt.Errorf("%w: python -m %s installs packages", ErrUnpinnedLaunch, spec.Args[i+1])
			}
		}
	}
	if base == "docker" || base == "podman" {
		run := slices.Contains(spec.Args, "run") || slices.Contains(spec.Args, "pull")
		// An image by digest, or a local OCI archive whose digest the
		// Library Trust Verifier checks before launch (SR-3-2).
		pinned := slices.ContainsFunc(spec.Args, func(a string) bool {
			return strings.Contains(a, "@sha256:") || strings.HasPrefix(a, "oci-archive:/")
		})
		if run && !pinned {
			return fmt.Errorf("%w: container image must be referenced by digest", ErrUnpinnedLaunch)
		}
	}
	return nil
}

// SubprocessLauncher runs servers as plain child processes with a minimal
// environment. It provides no confinement: the standalone profile.
type SubprocessLauncher struct {
	// TerminateAfter is how long Close waits after closing stdin before
	// signalling (default 5s).
	TerminateAfter time.Duration
	// StderrBytes bounds the retained diagnostic output (default 1 MiB, CP-37).
	StderrBytes int
}

// Name implements Launcher.
func (SubprocessLauncher) Name() string { return "subprocess" }

// Confined implements Launcher.
func (SubprocessLauncher) Confined() bool { return false }

// Launch implements Launcher.
func (l SubprocessLauncher) Launch(_ context.Context, spec ServerSpec) (Process, error) {
	if err := CheckLaunchSpec(spec); err != nil {
		return nil, err
	}
	if l.TerminateAfter <= 0 {
		l.TerminateAfter = 5 * time.Second
	}
	if l.StderrBytes <= 0 {
		l.StderrBytes = 1 << 20
	}
	cmd := exec.Command(spec.Command, spec.Args...)
	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}
	slices.Sort(env)
	cmd.Env = env
	cmd.Dir = spec.Dir
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		return nil, err
	}
	rb := &Ring{Max: l.StderrBytes}
	cmd.Stdout, cmd.Stdin, cmd.Stderr = stdoutW, stdinR, rb
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{stdoutR, stdoutW, stdinR, stdinW} {
			f.Close()
		}
		return nil, fmt.Errorf("start %s: %w", spec.Command, err)
	}
	// The child holds its own copies; close the parent's ends it does not use.
	stdoutW.Close()
	stdinR.Close()
	p := &subprocess{cmd: cmd, stdout: stdoutR, stdin: stdinW, stderr: rb, after: l.TerminateAfter, done: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

type subprocess struct {
	cmd     *exec.Cmd
	stdout  *os.File
	stdin   *os.File
	stderr  *Ring
	after   time.Duration
	done    chan struct{}
	waitErr error
	once    sync.Once
	err     error
}

func (p *subprocess) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *subprocess) Write(b []byte) (int, error) { return p.stdin.Write(b) }
func (p *subprocess) Stderr() string              { return p.stderr.Tail() }

// Close closes stdin, waits for exit, then sends SIGTERM and finally
// SIGKILL (the stdio shutdown sequence of the MCP specification, FR-5.27).
func (p *subprocess) Close() error {
	p.once.Do(func() {
		p.stdin.Close()
		wait := func(d time.Duration) bool {
			select {
			case <-p.done:
				return true
			case <-time.After(d):
				return false
			}
		}
		if !wait(p.after) {
			if p.cmd.Process.Signal(syscall.SIGTERM) != nil || !wait(p.after) {
				_ = p.cmd.Process.Kill()
				if !wait(p.after) {
					p.err = errors.New("server process did not exit")
				}
			}
		}
		p.stdout.Close()
		if p.err == nil {
			var ee *exec.ExitError
			if p.waitErr != nil && !errors.As(p.waitErr, &ee) {
				p.err = p.waitErr
			}
		}
	})
	return p.err
}

// Ring is a bounded byte buffer that keeps the most recent output (CP-37).
type Ring struct {
	Max int
	mu  sync.Mutex
	buf []byte
	n   uint64 // bytes written in total
}

// Write implements io.Writer and never fails.
func (b *Ring) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n += uint64(len(p))
	if len(p) >= b.Max {
		b.buf = append(b.buf[:0], p[len(p)-b.Max:]...)
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	// Compact only when the buffer exceeds the bound by a quarter, so a
	// stream of small writes costs a copy of the bound per quarter-bound
	// written instead of per write (FR-5.15: 10 MiB of stderr must not
	// stall the instance).
	if len(b.buf) > b.Max+b.Max/4 {
		b.buf = append(b.buf[:0], b.buf[len(b.buf)-b.Max:]...)
	}
	return len(p), nil
}

// Since returns the retained output written after offset off (a value
// returned by an earlier call, or 0) and the offset to pass next. Output
// written after off that the ring no longer holds is skipped; skipped
// reports how many bytes that was.
func (b *Ring) Since(off uint64) (text string, next, skipped uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.buf
	if len(t) > b.Max {
		t = t[len(t)-b.Max:]
	}
	start := b.n - uint64(len(t)) // offset of t[0]
	if off < start {
		skipped, off = start-off, start
	}
	if off > b.n {
		off = b.n
	}
	return string(t[off-start:]), b.n, skipped
}

// StderrSince implements StderrReader.
func (p *subprocess) StderrSince(off uint64) (string, uint64, uint64) { return p.stderr.Since(off) }

// Tail returns the retained output (at most Max bytes, the most recent),
// trimmed.
func (b *Ring) Tail() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.buf
	if len(t) > b.Max {
		t = t[len(t)-b.Max:]
	}
	return strings.TrimSpace(string(t))
}
