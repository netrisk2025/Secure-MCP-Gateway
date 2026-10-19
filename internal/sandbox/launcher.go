package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/posixacl"
)

// Origins of the evidence this package writes.
const (
	OriginRuntime = "E-15"
	OriginSandbox = "E-16"
	OriginMonitor = "E-17"
)

// EvidenceClass is the audit class of runtime evidence.
const EvidenceClass = "runtime"

// Options configure a Launcher.
type Options struct {
	// Runtime is the [runtime] configuration (defaults applied).
	Runtime config.Runtime
	// StateDir is the Gateway state directory; the Gateway-built root
	// directory lives in <StateDir>/runtime/rootfs and mounts that overlap
	// the state directory are refused.
	StateDir string
	Log      *slog.Logger
	// PodmanEnv adds variables to the Podman process environment (for
	// example CONTAINERS_CONF). They are not passed to instances.
	PodmanEnv map[string]string
	// TerminateAfter is each wait of the shutdown sequence (default 5s,
	// FR-5.27).
	TerminateAfter time.Duration
	// StderrBytes bounds retained diagnostic output per instance (default
	// 1 MiB, CP-37).
	StderrBytes int
	// CgroupRoot is the cgroup v2 mount (default /sys/fs/cgroup).
	CgroupRoot string
	// Now is the clock (tests).
	Now func() time.Time
	// Nsenter and Nft are the host tools that install an egress instance's
	// confinement rules; default: found in PATH or the system directories.
	Nsenter, Nft string
	// LookupUser resolves runtime.run_as (tests; default user.Lookup).
	LookupUser func(string) (*user.User, error)
	// ProcRoot is the proc file system (default /proc); the launcher
	// reads a created container's UID map there.
	ProcRoot string
	// GrantReader gives uid the permission bits perm on path (tests;
	// default posixacl.AddUser).
	GrantReader func(path string, uid int, perm uint16) error
	// GrantDeclaredSlots mounts every filesystem slot a launch
	// specification declares (its Roots), with the slot's mode, in place
	// of the runtime.server mount grants. smcpctl package build uses it
	// for its probe, whose slots are empty throwaway directories (SR-3.5-1).
	GrantDeclaredSlots bool
}

// Launcher is the confining pipeline.Launcher of the enforced profile.
type Launcher struct {
	o       Options
	run     runner
	podPath string
	gateway string
	rootfs  string
	log     *slog.Logger
	ev      *lazyRecorder
	mon     *Monitor

	mu        sync.Mutex
	egress    pipeline.EgressAttacher // set by the Egress Broker (SetEgress)
	instances map[string]*Instance
	order     []string
	closed    bool
}

// passEnv are variables of the Gateway's environment that the Podman
// process needs; nothing else is inherited.
var passEnv = []string{"PATH", "HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
	"DBUS_SESSION_BUS_ADDRESS", "CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF", "CONTAINERS_REGISTRIES_CONF", "TMPDIR"}

// New builds a Launcher. It does not touch the host until Start or Launch.
func New(o Options) (*Launcher, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.TerminateAfter <= 0 {
		o.TerminateAfter = 5 * time.Second
	}
	if o.StderrBytes <= 0 {
		o.StderrBytes = 1 << 20
	}
	if o.CgroupRoot == "" {
		o.CgroupRoot = "/sys/fs/cgroup"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.StateDir == "" || !filepath.IsAbs(o.StateDir) {
		return nil, errors.New("sandbox: an absolute state directory is required")
	}
	pod := o.Runtime.Podman
	if pod == "" {
		p, err := exec.LookPath("podman")
		if err != nil {
			return nil, errors.New("sandbox: podman not found on PATH; install rootless Podman or set runtime.podman")
		}
		if pod, err = filepath.Abs(p); err != nil {
			return nil, err
		}
	}
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.GrantReader == nil {
		o.GrantReader = posixacl.AddUser
	}
	rootfs := filepath.Join(o.StateDir, "runtime", "rootfs")
	run := runner{podman: pod, extra: o.PodmanEnv}
	if o.Runtime.RunAs != "" {
		u, err := lookupRunAs(o.Runtime.RunAs, o.Runtime.Sudo, o.LookupUser)
		if err != nil {
			return nil, err
		}
		if o.Runtime.SharedDir == "" || !filepath.IsAbs(o.Runtime.SharedDir) {
			return nil, errors.New("sandbox: runtime.run_as needs an absolute runtime.shared_dir")
		}
		run.runAs = u
		// The state directory is closed to run_as; the root directory of
		// image-less servers lives where it can read it.
		rootfs = filepath.Join(o.Runtime.SharedDir, "rootfs")
	}
	l := &Launcher{o: o, run: run, podPath: pod, gateway: ids.New(), rootfs: rootfs,
		log: o.Log, ev: newLazyRecorder(o.Log), instances: map[string]*Instance{}}
	l.mon = newMonitor(l)
	return l, nil
}

// Name implements pipeline.Launcher.
func (l *Launcher) Name() string { return "podman" }

// Confined implements pipeline.Launcher: instances run in the E-16 sandbox.
func (l *Launcher) Confined() bool { return true }

// SetEgress implements pipeline.EgressAware: the Egress Broker (E-18)
// hands the launcher its attacher instead of wrapping it, because a
// sandboxed instance must be attached through its own network namespace.
func (l *Launcher) SetEgress(a pipeline.EgressAttacher) {
	l.mu.Lock()
	l.egress = a
	l.mu.Unlock()
}

// GatewayID is the value of the smcp.gateway label on this Launcher's
// containers.
func (l *Launcher) GatewayID() string { return l.gateway }

// SetEvidence connects the evidence journal. Evidence produced before this
// call (instances launched while the Gateway starts) is buffered and
// written now.
func (l *Launcher) SetEvidence(r audit.Recorder) { l.ev.attach(r) }

// Start removes containers left by an earlier Gateway process and starts
// the Runtime Monitor's event stream. It runs until ctx ends.
func (l *Launcher) Start(ctx context.Context) {
	l.Reap(ctx)
	go l.mon.runEvents(ctx)
}

// Reap removes every Gateway-managed container that is not one of this
// Launcher's instances.
func (l *Launcher) Reap(ctx context.Context) {
	out, err := l.podman(ctx, "ps", "--all", "--filter", "label="+LabelManaged+"=1", "--format", "{{.Names}} {{.Labels."+LabelGateway+"}}").Output()
	if err != nil {
		l.log.Warn("podman ps failed; leftover containers were not removed", "err", err)
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || (len(f) > 1 && f[1] == l.gateway) {
			continue
		}
		if err := l.podman(ctx, "rm", "--force", "--time", "0", f[0]).Run(); err == nil {
			l.log.Info("removed leftover server container", "name", f[0])
		}
	}
}

// podman builds a Podman command with the minimal Podman environment, run
// as runtime.run_as when that is set (runner).
func (l *Launcher) podman(ctx context.Context, args ...string) *exec.Cmd {
	return l.run.command(ctx, nil, args...)
}

// RunAs is the identity that owns the server containers: runtime.run_as,
// or "" for the Gateway's own identity.
func (l *Launcher) RunAs() string {
	if l.run.runAs == nil {
		return ""
	}
	return l.run.runAs.Name
}

// Launch implements pipeline.Launcher.
func (l *Launcher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return nil, errors.New("sandbox: launcher closed")
	}
	srv := l.o.Runtime.FindServer(spec.Alias)
	if srv.Scope == "" {
		srv.Scope = "shared"
	}
	if srv.OnDeviation == "" {
		srv.OnDeviation = "alert"
	}
	if l.o.GrantDeclaredSlots {
		srv.Mounts = nil
		for _, r := range spec.Roots {
			srv.Mounts = append(srv.Mounts, config.RuntimeMount{Source: r.Path, Write: r.Write})
		}
	}
	id := ids.New()
	network := NetworkNone
	var att *pipeline.EgressAttachment
	var egressEnv map[string]string
	releaseEgress := func() {}
	if srv.Network == "egress" {
		l.mu.Lock()
		broker := l.egress
		l.mu.Unlock()
		if broker == nil {
			return nil, fmt.Errorf("runtime.server %q requests egress but no Egress Broker is enabled ([egress] enabled = true)", spec.Alias)
		}
		var err error
		att, err = broker.Attach(ctx, pipeline.EgressRequest{Alias: spec.Alias, Network: &pipeline.EgressNetwork{
			ListenAddr: egressListenAddr, GuestAddr: egressGuestAddr, LauncherConfines: true}})
		if err != nil {
			return nil, fmt.Errorf("runtime.server %q: egress: %w", spec.Alias, err)
		}
		network, egressEnv = EgressNetworkMode, att.Env
		releaseEgress = func() {
			if err := att.Close(); err != nil {
				l.log.Warn("egress detach failed", "alias", spec.Alias, "err", err)
			}
		}
	}
	spec = SecretPaths(spec)
	ls, err := Build(BuildInput{Runtime: l.o.Runtime, Server: srv, Spec: spec, Network: network, EgressEnv: egressEnv,
		InstanceID: id, Gateway: l.gateway, Rootfs: l.rootfs, StateDir: l.o.StateDir})
	if err != nil {
		releaseEgress()
		return nil, err
	}
	if err := l.stageArtifact(&ls); err != nil {
		releaseEgress()
		return nil, err
	}
	if ls.Artifact.Image == "" {
		if err := PrepareRootfs(l.rootfs, ls.Mounts); err != nil {
			releaseEgress()
			return nil, fmt.Errorf("prepare root directory: %w", err)
		}
	}
	values := Env(spec, nil, ls.EnvNames)
	var cmd *exec.Cmd
	netns := ""
	// Secret files are owner-only files of the Gateway identity. An
	// instance under another UID (userns = "auto", or runtime.run_as)
	// reads them through ACL entries that need the instance's host UID,
	// which exists only once the container is created (secretacl.go).
	secretReaders := spec.SecretDir != "" && (l.run.runAs != nil || srv.UserNS != "keep-id")
	if att != nil || secretReaders {
		// Create, confine the network namespace (egress.go) and grant the
		// secret files, then start.
		var allow []netip.AddrPort
		if att != nil {
			allow = att.Allow
		}
		if netns, err = l.createPrepared(ls, values, att != nil, allow, spec.SecretDir); err != nil {
			releaseEgress()
			return nil, fmt.Errorf("runtime.server %q: %w", spec.Alias, err)
		}
		cmd = l.run.instanceCommand(nil, "start", "--attach", "--interactive", ls.Name)
		release := releaseEgress
		releaseEgress = func() {
			// Until the start command runs, the created container is ours
			// to remove; afterwards finish removes it.
			if cmd.Process == nil {
				rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_ = l.podman(rctx, "rm", "--force", "--time", "0", ls.Name).Run()
				cancel()
			}
			release()
		}
	} else {
		cmd = l.run.instanceCommand(values, ls.PodmanArgs()...)
	}
	setParentDeath(cmd)
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		releaseEgress()
		return nil, err
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		releaseEgress()
		return nil, err
	}
	rb := &pipeline.Ring{Max: l.o.StderrBytes}
	cmd.Stdout, cmd.Stdin, cmd.Stderr = stdoutW, stdinR, rb
	inst := &Instance{ID: id, Alias: spec.Alias, Name: ls.Name, Spec: ls, Started: l.o.Now().UTC(), State: StateStarting, stderr: rb}
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{stdoutR, stdoutW, stdinR, stdinW} {
			f.Close()
		}
		releaseEgress()
		return nil, fmt.Errorf("start podman: %w", err)
	}
	stdoutW.Close()
	stdinR.Close()
	c := &container{l: l, inst: inst, cmd: cmd, stdout: stdoutR, stdin: stdinW, stderr: rb, after: l.o.TerminateAfter,
		done: make(chan struct{}), release: releaseEgress}
	if att != nil {
		c.issue = att.Issue
	}
	inst.proc = c
	go func() {
		c.waitErr = cmd.Wait()
		close(c.done)
		l.mon.exited(inst)
	}()
	// Locate the container's cgroup before the server receives its first
	// message, so that the monitor observes the instance from the start.
	l.mon.locate(inst, c.done, 10*time.Second)
	l.mu.Lock()
	l.instances[id] = inst
	l.order = append(l.order, id)
	l.mu.Unlock()
	l.record(audit.Event{Class: EvidenceClass, Origin: OriginRuntime, Outcome: "instance_launched", PolicyStatus: "not_evaluated",
		Detail: launchDetail(spec.Alias, id, ls, att, netns)}, true)
	go l.mon.watch(inst)
	return c, nil
}

// finish runs after an instance's shutdown sequence.
func (l *Launcher) finish(inst *Instance, waitErr error) {
	l.mon.exited(inst)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := l.podman(ctx, "rm", "--force", "--time", "0", inst.Name).CombinedOutput(); err != nil {
		l.log.Debug("podman rm", "name", inst.Name, "err", err, "out", string(out))
	}
	inst.mu.Lock()
	inst.removed = true
	if inst.State == StateStarting || inst.State == StateRunning {
		inst.State = StateExited
	}
	inst.mu.Unlock()
	_ = waitErr
}

// record writes runtime evidence. A failure is logged: runtime evidence
// cannot fail a call that has already been decided, and the journal's
// sticky error fails the endpoint closed on its own.
func (l *Launcher) record(ev audit.Event, durable bool) {
	if err := l.ev.write(ev, durable); err != nil {
		l.log.Error("runtime evidence write failed", "outcome", ev.Outcome, "err", err)
	}
}

// Instances returns a snapshot of the instance table, oldest first.
func (l *Launcher) Instances() []InstanceView {
	l.mu.Lock()
	ids := slices.Clone(l.order)
	insts := make([]*Instance, 0, len(ids))
	for _, id := range ids {
		insts = append(insts, l.instances[id])
	}
	l.mu.Unlock()
	out := make([]InstanceView, 0, len(insts))
	for _, in := range insts {
		out = append(out, in.View())
	}
	return out
}

// Instance returns one instance by ID.
func (l *Launcher) Instance(id string) (*Instance, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	in, ok := l.instances[id]
	return in, ok
}

// ErrNoInstance is returned by Kill for an unknown or finished instance.
var ErrNoInstance = errors.New("no running instance with that ID")

// Kill stops a running instance immediately on an operator's request and
// records who asked and why.
func (l *Launcher) Kill(id, actor, reason string) error {
	in, ok := l.Instance(id)
	if !ok || !in.running() {
		return ErrNoInstance
	}
	l.mon.contain(in, ActionKill, "OPERATOR_KILL", map[string]any{"actor": actor, "reason": reason})
	return nil
}

// Close stops the monitor. Instances are closed by their owners (the
// backend registry) before this.
func (l *Launcher) Close() {
	l.mu.Lock()
	l.closed = true
	insts := make([]*Instance, 0, len(l.instances))
	for _, in := range l.instances {
		insts = append(insts, in)
	}
	l.mu.Unlock()
	for _, in := range insts {
		if in.running() && in.proc != nil {
			_ = in.proc.Close()
		}
	}
	l.mon.stop()
}

// launchDetail is the detail of an instance_launched event. An egress
// instance names its broker attachment and the endpoints its namespace
// may reach.
func launchDetail(alias, id string, ls LaunchSpec, att *pipeline.EgressAttachment, netns string) map[string]any {
	d := map[string]any{"alias": alias, "instance_id": id, "container": ls.Name, "launch_spec": ls}
	if att != nil {
		allow := make([]string, 0, len(att.Allow))
		for _, ap := range att.Allow {
			allow = append(allow, ap.String())
		}
		d["egress"] = map[string]any{"attachment": att.ID, "confined": true, "netns": netns, "allow": allow, "table": "inet " + EgressTable}
	}
	return d
}
