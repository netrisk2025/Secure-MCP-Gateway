package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testRuntime() config.Runtime {
	cfg, err := config.Parse([]byte(`
[admin]
username = "admin"
password_hash = "$argon2id$x"
[profile]
mode = "auto"
[runtime]
sandbox = "podman"
monitor_interval = "50ms"
`))
	if err != nil {
		panic(err)
	}
	return cfg.Runtime
}

type harness struct {
	t     *testing.T
	l     *Launcher
	dir   string
	state string
	mem   *audit.Memory
	exe   string
}

func newHarness(t *testing.T, rt config.Runtime, adjust ...func(*Options)) *harness {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	state := t.TempDir()
	rt.Podman = exe
	o := Options{Runtime: rt, StateDir: state, Log: quiet(), TerminateAfter: 300 * time.Millisecond,
		CgroupRoot: filepath.Join(dir, "cgroup"), PodmanEnv: map[string]string{"SMCP_FAKE_PODMAN": "1", "SMCP_FAKE_DIR": dir,
			// The race detector's runtime sleeps 1 s at exit by default; a
			// fake podman call would then take a second longer than podman.
			"GORACE": "atexit_sleep_ms=0"}}
	for _, f := range adjust {
		f(&o)
	}
	l, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	l.SetEvidence(mem)
	t.Cleanup(l.Close)
	return &harness{t: t, l: l, dir: dir, state: state, mem: mem, exe: exe}
}

func (h *harness) spec(alias string) pipeline.ServerSpec {
	return pipeline.ServerSpec{Alias: alias, Command: h.exe, Env: map[string]string{"SMCP_FAKE_SERVER": "1", "PATH": "/usr/bin", "HOME": "/home/x"}}
}

func (h *harness) run(name string) fakeRun {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, name+".run.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	var r fakeRun
	if err := json.Unmarshal(b, &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *harness) cg(name, file, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, "cgroup", name, file), []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) kills(name string) string {
	b, _ := os.ReadFile(filepath.Join(h.dir, name+".kills"))
	return string(b)
}

// eventually waits up to d for cond.
func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func findEvent(evs []audit.Event, outcome, reason string) *audit.Event {
	for i := range evs {
		if evs[i].Outcome == outcome && (reason == "" || evs[i].ReasonCode == reason) {
			return &evs[i]
		}
	}
	return nil
}

func hasArg(args []string, a string) bool { return slices.Contains(args, a) }

// connect speaks MCP to a launched process.
func connect(t *testing.T, p pipeline.Process) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := c.Connect(ctx, &mcp.IOTransport{Reader: io.NopCloser(p), Writer: closer{p}}, nil)
	if err != nil {
		t.Fatalf("connect: %v (stderr %s)", err, p.Stderr())
	}
	return s
}

type closer struct{ p pipeline.Process }

func (c closer) Write(b []byte) (int, error) { return c.p.Write(b) }
func (c closer) Close() error                { return c.p.Close() }

func callText(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any) string {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestPodmanArgsCarryTheSandboxProfile(t *testing.T) {
	// SR-4.7-1 asks for inspection of the effective container
	// configuration; this checks the configuration the Gateway requests.
	// The Linux integration test inspects a real container.
	reqtest.Partial(t, "SR-4.7-1", "SR-4.7-2", "SR-4.5-1", "SR-4.1-2", "FR-5.9")
	exe, _ := os.Executable()
	ro, rw := t.TempDir(), t.TempDir()
	rt := testRuntime()
	srv := config.RuntimeServer{Alias: "fs", Mounts: []config.RuntimeMount{{Source: ro, Target: "/ro"}, {Source: rw, Target: "/data", Write: true}}}
	ls, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "fs", Command: exe, Args: []string{"--root", "/data"},
		Env: map[string]string{"TOKEN": "s3cret-value", "PATH": "/usr/bin"}}, Network: NetworkNone,
		InstanceID: "0192-abcd-ef01-2345", Gateway: "gw", Rootfs: "/state/runtime/rootfs", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	args := ls.PodmanArgs()
	for _, want := range []string{"run", "--interactive", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
		"--userns=auto:size=2048", "--network=none", "--pid=private", "--ipc=private", "--uts=private", "--pull=never",
		"--memory=536870912", "--memory-swap=536870912", "--cpus=1", "--pids-limit=128", "--user=1000:1000", "--no-hosts",
		"--mount=type=bind,src=" + ro + ",dst=/ro,ro,bind-propagation=rprivate",
		"--mount=type=bind,src=" + rw + ",dst=/data,rw,bind-propagation=rprivate",
		"--mount=type=bind,src=" + exe + ",dst=/smcp/bin/" + filepath.Base(exe) + ",ro,bind-propagation=rprivate",
		"--env=TOKEN", "--rootfs"} {
		if !hasArg(args, want) {
			t.Errorf("podman args lack %q\n%v", want, args)
		}
	}
	joined := strings.Join(args, " ")
	for _, bad := range []string{"--privileged", "--device", "--cap-add", "seccomp=unconfined", "--pid=host", "--network=host",
		"--ipc=host", "--uts=host", "--userns=host", "docker.sock", "podman.sock", "s3cret-value", "--env=PATH", "label=disable"} {
		if strings.Contains(joined, bad) {
			t.Errorf("podman args contain %q", bad)
		}
	}
	// Flags, then --rootfs <dir>, then the server's own argument vector.
	i := slices.Index(args, "--rootfs")
	if got := args[i+1:]; !slices.Equal(got, []string{"/state/runtime/rootfs", "/smcp/bin/" + filepath.Base(exe), "--root", "/data"}) {
		t.Fatalf("positional args = %v", got)
	}
	if !strings.HasPrefix(ls.Artifact.Digest, "sha256:") || len(ls.Artifact.Digest) != 71 {
		t.Fatalf("artifact digest %q", ls.Artifact.Digest)
	}
	if !slices.Equal(ls.EnvNames, []string{"TOKEN"}) {
		t.Fatalf("env names %v", ls.EnvNames)
	}
}

func TestBuildWithImageAndEgress(t *testing.T) {
	reqtest.Partial(t, "FR-5.37", "FR-5.9")
	rt := testRuntime()
	img := "registry.local/fs@sha256:" + strings.Repeat("a", 64)
	srv := config.RuntimeServer{Alias: "web", Image: img, Network: "egress", UserNS: "keep-id"}
	ls, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "web", Command: "/usr/local/bin/server"},
		Network: "smcp-egress-web", EgressEnv: map[string]string{"FETCH_BASE_URL": "http://10.89.0.1:8080"},
		InstanceID: "i", Gateway: "gw", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	args := ls.PodmanArgs()
	if !hasArg(args, "--network=smcp-egress-web") || !hasArg(args, "--env=FETCH_BASE_URL=http://10.89.0.1:8080") || !hasArg(args, "--userns=keep-id") || slices.Contains(ls.EnvNames, "FETCH_BASE_URL") {
		t.Fatalf("args %v", args)
	}
	if args[len(args)-2] != img || args[len(args)-1] != "/usr/local/bin/server" || ls.Artifact.Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("image positional: %v digest %s", args[len(args)-2:], ls.Artifact.Digest)
	}
	// A network the server did not ask for is refused.
	srv.Network = "none"
	if _, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "web", Command: "/usr/local/bin/server"},
		Network: "bridge", StateDir: t.TempDir()}); err == nil {
		t.Fatal("unrequested network accepted")
	}
}

// TestSecretFilesReachTheSandbox: the broker's S2/S3 files live in a host
// directory the instance cannot otherwise see; Build mounts it read-only at
// SecretDir and the file-path variables are rewritten to match (Appendix L
// HF-08 in the enforced profile).
func TestSecretFilesReachTheSandbox(t *testing.T) {
	reqtest.Partial(t, "FR-6.8")
	rt := testRuntime()
	img := "registry.local/fs@sha256:" + strings.Repeat("a", 64)
	host := filepath.Join(t.TempDir(), "h-123")
	spec := SecretPaths(pipeline.ServerSpec{Alias: "h", Command: "/usr/local/bin/server", SecretDir: host,
		Env: map[string]string{"TOKEN_FILE": host + "/token", "OTHER": "/data/x", "DIR": host}})
	if spec.Env["TOKEN_FILE"] != SecretDir+"/token" || spec.Env["DIR"] != SecretDir || spec.Env["OTHER"] != "/data/x" {
		t.Fatalf("env %v", spec.Env)
	}
	// An auto user namespace gets the same mount; the launcher grants the
	// instance's UID read access (TestSecretFilesForAnotherUID).
	auto, err := Build(BuildInput{Runtime: rt, Server: config.RuntimeServer{Alias: "h", Image: img}, Spec: spec, InstanceID: "i", Gateway: "gw", StateDir: t.TempDir()})
	if err != nil || !hasArg(auto.PodmanArgs(), "--mount=type=bind,src="+host+",dst="+SecretDir+",ro,bind-propagation=rprivate") {
		t.Fatalf("auto user namespace with secret files: %v %v", err, auto.PodmanArgs())
	}
	ls, err := Build(BuildInput{Runtime: rt, Server: config.RuntimeServer{Alias: "h", Image: img, UserNS: "keep-id"}, Spec: spec, InstanceID: "i", Gateway: "gw", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !hasArg(ls.PodmanArgs(), "--mount=type=bind,src="+host+",dst="+SecretDir+",ro,bind-propagation=rprivate") {
		t.Fatalf("args %v", ls.PodmanArgs())
	}
	if v := Env(spec, nil, ls.EnvNames); v["TOKEN_FILE"] != SecretDir+"/token" {
		t.Fatalf("instance value %v", v)
	}
	// No secret directory: no mount, values unchanged.
	plain := SecretPaths(pipeline.ServerSpec{Alias: "h", Command: "/usr/local/bin/server", Env: map[string]string{"A": host}})
	ls, err = Build(BuildInput{Runtime: rt, Server: config.RuntimeServer{Alias: "h", Image: img}, Spec: plain, InstanceID: "i", Gateway: "gw", StateDir: t.TempDir()})
	if err != nil || plain.Env["A"] != host || slices.ContainsFunc(ls.Mounts, func(m Mount) bool { return m.Target == SecretDir }) {
		t.Fatalf("plain: %v %v %v", err, plain.Env, ls.Mounts)
	}
	// A directory name that would break the mount option list is refused.
	bad := pipeline.ServerSpec{Alias: "h", Command: "/usr/local/bin/server", SecretDir: "/run/a,b"}
	if _, err := Build(BuildInput{Runtime: rt, Server: config.RuntimeServer{Alias: "h", Image: img, UserNS: "keep-id"}, Spec: bad, InstanceID: "i", Gateway: "gw", StateDir: t.TempDir()}); !errors.Is(err, ErrMountRefused) {
		t.Fatalf("comma in secret directory: %v", err)
	}
}

func TestLaunchRefusesUnsafeInput(t *testing.T) {
	reqtest.Partial(t, "SR-4.6-1", "SR-4.7-1", "SR-3.6-1")
	rt := testRuntime()
	exe, _ := os.Executable()
	state := t.TempDir()
	sock := filepath.Join(t.TempDir(), "x.sock")
	if ln, err := net.Listen("unix", sock); err == nil {
		defer ln.Close()
	}
	inside := filepath.Join(state, "keys")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	comma := filepath.Join(t.TempDir(), "a,b")
	if err := os.MkdirAll(comma, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"/", "/etc", "/proc", "/var/run", "/run/user", "relative/path", state, inside, filepath.Dir(state), sock, comma, "/does/not/exist"} {
		srv := config.RuntimeServer{Alias: "x", Mounts: []config.RuntimeMount{{Source: src}}}
		_, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "x", Command: exe}, InstanceID: "i", Rootfs: "/r", StateDir: state})
		if !errors.Is(err, ErrMountRefused) {
			t.Errorf("mount of %q: err = %v, want ErrMountRefused", src, err)
		}
	}
	ok := t.TempDir()
	for _, target := range []string{"/work", "/tmp", "/tmp/x/y", "/work/a", "/smcp/bin", "/smcp/bin/x", "/proc/x", "/dev/shm", "/run/x", "/etc/x", "/", "rel"} {
		srv := config.RuntimeServer{Alias: "x", Mounts: []config.RuntimeMount{{Source: ok, Target: target}}}
		if _, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "x", Command: exe}, Rootfs: "/r", StateDir: state}); !errors.Is(err, ErrMountRefused) {
			t.Errorf("target %q accepted", target)
		}
	}
	for _, name := range []string{"LD_PRELOAD", "CONTAINERS_CONF", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HTTPS_PROXY"} {
		_, err := Build(BuildInput{Runtime: rt, Spec: pipeline.ServerSpec{Alias: "x", Command: exe, Env: map[string]string{name: "v"}}, Rootfs: "/r", StateDir: state})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("env %s: err = %v", name, err)
		}
	}
	for _, cmd := range []string{"npx", "/usr/bin/npx", "/usr/bin/uvx"} {
		if _, err := Build(BuildInput{Runtime: rt, Spec: pipeline.ServerSpec{Alias: "x", Command: cmd}, Rootfs: "/r", StateDir: state}); !errors.Is(err, pipeline.ErrUnpinnedLaunch) {
			t.Errorf("command %q: err = %v", cmd, err)
		}
	}
	if _, err := Build(BuildInput{Runtime: rt, Spec: pipeline.ServerSpec{Alias: "x", Command: "/no/such/binary"}, Rootfs: "/r", StateDir: state}); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("missing artifact: %v", err)
	}
}

func TestLaunchRunsServerThroughPodmanWithoutShell(t *testing.T) {
	// SR-4.8-1: launch input reaches the server as an argument vector; the
	// environment travels by name. Both launchers use exec, never a shell.
	reqtest.Verifies(t, "SR-4.8-1")
	reqtest.Partial(t, "FR-5.9", "SR-2.14-1")
	h := newHarness(t, testRuntime())
	spec := h.spec("ref")
	spec.Args = []string{"$(touch /tmp/pwned); echo `id` | sh", "a b"}
	spec.Env["API_TOKEN"] = "tok-123"
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	insts := h.l.Instances()
	if len(insts) != 1 {
		t.Fatalf("instances %d", len(insts))
	}
	name := insts[0].Container
	sess := connect(t, p)
	if got := callText(t, sess, "echo", map[string]any{"text": "hi"}); got != "hi" {
		t.Fatalf("echo = %q", got)
	}
	r := h.run(name)
	if got := r.Command[1:]; !slices.Equal(got, spec.Args) {
		t.Fatalf("server argv %v, want %v verbatim", got, spec.Args)
	}
	if strings.Contains(strings.Join(r.Argv, " "), "tok-123") {
		t.Fatal("environment value on the podman command line")
	}
	if !r.EnvSet["API_TOKEN"] || !r.EnvSet["SMCP_FAKE_SERVER"] || slices.Contains(r.EnvNames, "SMCP_FAKE_PODMAN") || slices.Contains(r.EnvNames, "PATH") {
		t.Fatalf("env names %v set %v", r.EnvNames, r.EnvSet)
	}
	if !hasArg(r.Argv, "--label") || r.Rootfs != filepath.Join(h.state, "runtime", "rootfs") {
		t.Fatalf("run %+v", r)
	}
	for _, f := range []string{"proc", "dev", "work", "etc/hosts", "etc/passwd", "smcp/bin/" + filepath.Base(h.exe)} {
		if _, err := os.Stat(filepath.Join(r.Rootfs, f)); err != nil {
			t.Errorf("root directory lacks %s", f)
		}
	}
	// The subprocess launcher passes the same vector without a shell.
	sp, err := pipeline.SubprocessLauncher{TerminateAfter: time.Second}.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	s2 := connect(t, sp)
	if got := callText(t, s2, "echo", map[string]any{"text": "ok"}); got != "ok" {
		t.Fatal(got)
	}
	s2.Close()
	if _, err := os.Stat("/tmp/pwned"); err == nil {
		t.Fatal("argument was interpreted by a shell")
	}
	sess.Close()
	eventually(t, 5*time.Second, "instance removed", func() bool { _, err := os.Stat(filepath.Join(h.dir, name+".rm")); return err == nil })
	evs := h.mem.Events()
	if e := findEvent(evs, "instance_launched", ""); e == nil || e.Origin != OriginRuntime || e.Class != EvidenceClass {
		t.Fatalf("no launch evidence: %+v", evs)
	} else if b, _ := json.Marshal(e.Detail); strings.Contains(string(b), "tok-123") {
		t.Fatal("secret value in launch evidence")
	}
	e := findEvent(evs, "instance_exited", "")
	if e == nil {
		t.Fatal("no exit evidence")
	}
	if d := e.Detail.(map[string]any); d["expected"] != true || e.ReasonCode != "" {
		t.Fatalf("exit evidence %+v", e)
	}
}

func TestBackendRegistryUsesConfinedLauncher(t *testing.T) {
	reqtest.Partial(t, "FR-5.9", "SR-4-1")
	h := newHarness(t, testRuntime())
	caps := pipeline.NewCapabilities(time.Minute)
	reg, err := backend.Start(context.Background(), []config.Server{{Alias: "probe", Command: h.exe, Env: map[string]string{"SMCP_FAKE_SERVER": "1"},
		RiskClasses: []string{"code-execution"}}}, backend.Options{Launcher: h.l, Capabilities: caps, Log: quiet(),
		Limits: backend.Limits{PerPrincipal: 1, Total: 1, UpstreamTimeout: 10 * time.Second, ResultBytes: 1 << 20}})
	if err != nil {
		t.Fatalf("a high-risk server must start under the confined launcher: %v", err)
	}
	ref := reg.Resolve("probe_echo")
	if ref == nil {
		t.Fatalf("tools %v", reg.PublicNames())
	}
	b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: "probe_echo"}
	res, err := reg.Call(context.Background(), backend.Dispatch{Principal: "p", Ref: ref, Arguments: json.RawMessage(`{"text":"via registry"}`), Capability: caps.Issue(b), Binding: b})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != "via registry" {
		t.Fatalf("call: %v %+v", err, res)
	}
	reg.Close()
}

func TestMonitorKillsOnMemoryBreachWithinOneSecond(t *testing.T) {
	// The kernel enforces the cgroup limit; the monitor sees the OOM kill
	// counter and kills the instance. Measured from the counter change.
	reqtest.Partial(t, "FR-5.35", "FR-5.33", "SR-4.7-2")
	h := newHarness(t, testRuntime())
	p, err := h.l.Launch(context.Background(), h.spec("mem"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	name := h.l.Instances()[0].Container
	eventually(t, 3*time.Second, "running", func() bool { return h.l.Instances()[0].State == StateRunning })
	start := time.Now()
	h.cg(name, "memory.events", "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n")
	eventually(t, time.Second, "kill within 1 s", func() bool { return strings.Contains(h.kills(name), "KILL") })
	if el := time.Since(start); el > time.Second {
		t.Fatalf("containment took %v", el)
	}
	eventually(t, 3*time.Second, "breach evidence", func() bool { return findEvent(h.mem.Events(), "limit_breach", ReasonMemoryLimit) != nil })
	e := findEvent(h.mem.Events(), "limit_breach", ReasonMemoryLimit)
	if d := e.Detail.(map[string]any); d["action"] != ActionKill || e.Origin != OriginMonitor {
		t.Fatalf("evidence %+v", e)
	}
	eventually(t, 3*time.Second, "exit evidence", func() bool { return findEvent(h.mem.Events(), "instance_exited", "") != nil })
	v := h.l.Instances()[0]
	if v.State != StateKilled || v.KillReason != ReasonMemoryLimit || v.Deviations != 1 {
		t.Fatalf("view %+v", v)
	}
}

func TestMonitorKillsOnPidsBreach(t *testing.T) {
	reqtest.Partial(t, "FR-5.35", "SR-4.7-2")
	h := newHarness(t, testRuntime())
	p, err := h.l.Launch(context.Background(), h.spec("pids"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	name := h.l.Instances()[0].Container
	eventually(t, 3*time.Second, "running", func() bool { return h.l.Instances()[0].State == StateRunning })
	h.cg(name, "pids.events", "max 2\n")
	eventually(t, time.Second, "kill", func() bool { return strings.Contains(h.kills(name), "KILL") })
	eventually(t, 3*time.Second, "evidence", func() bool { return findEvent(h.mem.Events(), "limit_breach", ReasonPidsLimit) != nil })
}

// A pids limit hit before the monitor's first sample (a fork bomb at
// startup) is a breach: the counters of the instance's fresh cgroup start
// at zero, so the first sample is not taken as the baseline.
func TestMonitorKillsOnPidsBreachBeforeFirstSample(t *testing.T) {
	reqtest.Partial(t, "FR-5.35", "SR-4.7-2")
	h := newHarness(t, testRuntime(), func(o *Options) { o.PodmanEnv["SMCP_FAKE_PIDS_MAX"] = "1" })
	p, err := h.l.Launch(context.Background(), h.spec("pids"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	name := h.l.Instances()[0].Container
	eventually(t, 3*time.Second, "kill", func() bool { return strings.Contains(h.kills(name), "KILL") })
	eventually(t, 3*time.Second, "evidence", func() bool { return findEvent(h.mem.Events(), "limit_breach", ReasonPidsLimit) != nil })
}

func TestMonitorUndeclaredProcessAlertsOrKills(t *testing.T) {
	reqtest.Partial(t, "FR-5.33", "FR-5.34", "FR-5.35")
	for _, rule := range []string{ActionAlert, ActionKill} {
		t.Run(rule, func(t *testing.T) {
			rt := testRuntime()
			rt.Servers = []config.RuntimeServer{{Alias: "sp", OnDeviation: rule}}
			h := newHarness(t, rt)
			p, err := h.l.Launch(context.Background(), h.spec("sp"))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			sess := connect(t, p)
			name := h.l.Instances()[0].Container
			eventually(t, 3*time.Second, "first sample", func() bool { return findEvent(h.mem.Events(), "process_created", "") != nil })
			main := h.l.Instances()[0]
			_ = main
			pid, _ := os.ReadFile(filepath.Join(h.dir, name+".pid"))
			h.cg(name, "cgroup.procs", strings.TrimSpace(string(pid))+"\n999999\n")
			eventually(t, 2*time.Second, "deviation", func() bool { return findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess) != nil })
			e := findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess)
			if e.Detail.(map[string]any)["action"] != rule {
				t.Fatalf("action %v", e.Detail)
			}
			if rule == ActionAlert {
				if got := callText(t, sess, "echo", map[string]any{"text": "alive"}); got != "alive" || strings.Contains(h.kills(name), "KILL") {
					t.Fatal("alert must not stop the instance")
				}
			} else {
				eventually(t, time.Second, "kill", func() bool { return strings.Contains(h.kills(name), "KILL") })
			}
		})
	}
}

func TestMonitorExecEventIsDeviation(t *testing.T) {
	reqtest.Partial(t, "FR-5.33", "FR-5.34")
	rt := testRuntime()
	rt.Servers = []config.RuntimeServer{{Alias: "ex", OnDeviation: ActionKill}}
	h := newHarness(t, rt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.l.Start(ctx)
	p, err := h.l.Launch(context.Background(), h.spec("ex"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	in := h.l.Instances()[0]
	line, _ := json.Marshal(PodmanEvent{ID: "x", Name: in.Container, Status: "exec", Type: "container",
		Attributes: map[string]string{LabelGateway: h.l.GatewayID(), LabelInstance: in.ID}})
	// An event of another Gateway is ignored.
	other, _ := json.Marshal(PodmanEvent{Name: in.Container, Status: "exec", Attributes: map[string]string{LabelGateway: "other", LabelInstance: in.ID}})
	if err := os.WriteFile(filepath.Join(h.dir, "events.jsonl"), append(append(other, '\n'), append(line, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "exec deviation", func() bool { return findEvent(h.mem.Events(), "deviation", ReasonExecIntoInstance) != nil })
	eventually(t, time.Second, "kill", func() bool { return strings.Contains(h.kills(in.Container), "KILL") })
	if n := strings.Count(h.kills(in.Container), "KILL"); n != 1 {
		t.Fatalf("killed %d times", n)
	}
}

func TestUnexpectedExitIsRecorded(t *testing.T) {
	// The exit evidence of FR-5.12; the restart and the suspension after
	// three exits in five minutes are internal/backend TestCrashRestartAndSuspension.
	reqtest.Partial(t, "FR-5.12")
	h := newHarness(t, testRuntime())
	p, err := h.l.Launch(context.Background(), h.spec("crash"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	name := h.l.Instances()[0].Container
	if err := os.WriteFile(filepath.Join(h.dir, name+".exit"), []byte("137"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, name+".oom"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pid, _ := os.ReadFile(filepath.Join(h.dir, name+".pid"))
	pr, _ := os.FindProcess(atoi(string(pid)))
	_ = pr.Kill()
	eventually(t, 3*time.Second, "exit evidence", func() bool { return findEvent(h.mem.Events(), "instance_exited", ReasonMemoryLimit) != nil })
	e := findEvent(h.mem.Events(), "instance_exited", ReasonMemoryLimit)
	d := e.Detail.(map[string]any)
	if d["expected"] != false || d["exit_code"] != 137 || d["oom_killed"] != true {
		t.Fatalf("detail %+v", d)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestShutdownSequenceEscalates(t *testing.T) {
	// FR-5.27 at a scaled interval (300 ms instead of 5 s); the default is
	// checked below.
	reqtest.Partial(t, "FR-5.27")
	h := newHarness(t, testRuntime())
	spec := h.spec("stub")
	spec.Env["SMCP_FAKE_SERVER"] = "ignore-eof"
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	name := h.l.Instances()[0].Container
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	el := time.Since(start)
	k := h.kills(name)
	if !strings.Contains(k, "TERM") || !strings.Contains(k, "KILL") || strings.Index(k, "TERM") > strings.Index(k, "KILL") {
		t.Fatalf("kill sequence %q", k)
	}
	// Each fake podman invocation starts the test binary, which adds time.
	if el < 600*time.Millisecond || el > 15*time.Second {
		t.Fatalf("shutdown took %v; want two 300 ms waits before SIGKILL", el)
	}
	l, _ := New(Options{Runtime: testRuntime(), StateDir: t.TempDir(), Log: quiet()})
	if l != nil && l.o.TerminateAfter != 5*time.Second {
		t.Fatalf("default wait %v", l.o.TerminateAfter)
	}
}

func TestReapRemovesOtherGatewaysContainers(t *testing.T) {
	h := newHarness(t, testRuntime())
	ps := "smcp-old-1 gw-old\nsmcp-mine-2 " + h.l.GatewayID() + "\n"
	if err := os.WriteFile(filepath.Join(h.dir, "ps.txt"), []byte(ps), 0o600); err != nil {
		t.Fatal(err)
	}
	h.l.Reap(context.Background())
	if _, err := os.Stat(filepath.Join(h.dir, "smcp-old-1.rm")); err != nil {
		t.Fatal("leftover container not removed")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "smcp-mine-2.rm")); err == nil {
		t.Fatal("own container removed")
	}
}

type recordingEgress struct {
	calls  int
	reqs   []pipeline.EgressRequest
	closed int
}

func (r *recordingEgress) Attach(_ context.Context, req pipeline.EgressRequest) (*pipeline.EgressAttachment, error) {
	r.calls++
	r.reqs = append(r.reqs, req)
	return &pipeline.EgressAttachment{ID: "att-1", Enforced: true,
		Env:   map[string]string{"HTTPS_PROXY": "http://10.0.2.2:41000", "HTTP_PROXY": "http://10.0.2.2:41000", "NO_PROXY": "", "API_BASE_URL": "http://10.0.2.2:41001"},
		Allow: []netip.AddrPort{netip.MustParseAddrPort("10.0.2.2:41000"), netip.MustParseAddrPort("10.0.2.2:41001")},
		Close: func() error { r.closed++; return nil }}, nil
}

// TestEgressAttachesSandboxNetwork: a server with network = "egress" is
// attached to the broker as a launcher-confined network, created on a
// slirp4netns network, confined with the nftables script in its own
// network namespace (through podman unshare) and only then started. The
// broker variables reach the container; servers without egress keep
// network none and are never attached.
func TestEgressAttachesSandboxNetwork(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-1", "FR-5.37")
	var _ pipeline.EgressAware = (*Launcher)(nil)
	rt := testRuntime()
	rt.Servers = []config.RuntimeServer{{Alias: "web", Network: "egress"}}
	h := newHarness(t, rt)
	h.l.o.Nsenter, h.l.o.Nft = "/usr/bin/nsenter", "/usr/sbin/nft"
	if _, err := h.l.Launch(context.Background(), h.spec("web")); err == nil || !strings.Contains(err.Error(), "no Egress Broker is enabled") {
		t.Fatalf("egress without a broker: %v", err)
	}
	eg := &recordingEgress{}
	h.l.SetEgress(eg)
	p, err := h.l.Launch(context.Background(), h.spec("web"))
	if err != nil {
		t.Fatal(err)
	}
	connect(t, p)
	inst := h.l.Instances()[0]
	if eg.calls != 1 || eg.reqs[0].Alias != "web" || eg.reqs[0].Network == nil || !eg.reqs[0].Network.LauncherConfines ||
		eg.reqs[0].Network.GuestAddr != netip.MustParseAddr("10.0.2.2") || eg.reqs[0].Network.ListenAddr != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("attach requests %+v", eg.reqs)
	}
	r := h.run(inst.Container)
	for _, want := range []string{"--network=" + EgressNetworkMode, "--http-proxy=false", "--env=HTTPS_PROXY=http://10.0.2.2:41000",
		"--env=API_BASE_URL=http://10.0.2.2:41001", "--cap-drop=all"} {
		if !hasArg(r.Argv, want) {
			t.Fatalf("create arguments lack %s: %v", want, r.Argv)
		}
	}
	if !r.EnvSet["HTTPS_PROXY"] || !r.EnvSet["SMCP_FAKE_SERVER"] {
		t.Fatalf("instance environment %v", r.EnvSet)
	}
	calls, _ := os.ReadFile(filepath.Join(h.dir, "calls.log"))
	order := []string{"create ", "init " + inst.Container, "unshare /usr/bin/nsenter --net=/run/user/1000/netns/netns-" + inst.Container + " /usr/sbin/nft -f -",
		"unshare /usr/bin/nsenter --net=/run/user/1000/netns/netns-" + inst.Container + " /usr/sbin/nft list table inet smcp_egress",
		"start --attach --interactive " + inst.Container}
	pos := 0
	for _, want := range order {
		i := strings.Index(string(calls)[pos:], want)
		if i < 0 {
			t.Fatalf("podman calls out of order or missing %q:\n%s", want, calls)
		}
		pos += i + len(want)
	}
	rules, _ := os.ReadFile(filepath.Join(h.dir, "rules.nft"))
	for _, want := range []string{"policy drop;", "ip daddr 10.0.2.2 tcp dport 41000 accept", "ip daddr 10.0.2.2 tcp dport 41001 accept", "reject with icmpx admin-prohibited"} {
		if !strings.Contains(string(rules), want) {
			t.Fatalf("rules lack %q:\n%s", want, rules)
		}
	}
	ev := findEvent(h.mem.Events(), "instance_launched", "")
	if ev == nil {
		t.Fatal("no instance_launched evidence")
	}
	if eg, _ := ev.Detail.(map[string]any)["egress"].(map[string]any); eg == nil || eg["attachment"] != "att-1" || eg["confined"] != true {
		t.Fatalf("launch evidence %+v", ev.Detail)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if eg.closed != 1 {
		t.Fatalf("attachment closed %d times after the instance closed", eg.closed)
	}

	plain, err := h.l.Launch(context.Background(), h.spec("plain"))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	connect(t, plain)
	views := h.l.Instances()
	if r := h.run(views[len(views)-1].Container); !hasArg(r.Argv, "--network=none") || eg.calls != 1 {
		t.Fatalf("server without egress: %v (attach calls %d)", r.Argv, eg.calls)
	}
}

// TestEgressConfinementFailsClosed: when the rules cannot be installed the
// container is removed before it starts and the attachment is closed.
func TestEgressConfinementFailsClosed(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-1")
	rt := testRuntime()
	rt.Servers = []config.RuntimeServer{{Alias: "web", Network: "egress"}}
	h := newHarness(t, rt)
	eg := &recordingEgress{}
	h.l.SetEgress(eg)
	for _, f := range []string{"unshare.fail", "create.fail"} {
		if err := os.WriteFile(filepath.Join(h.dir, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := h.l.Launch(context.Background(), h.spec("web"))
		if err == nil || !strings.Contains(err.Error(), "egress confinement") {
			t.Fatalf("%s: launch error %v", f, err)
		}
		_ = os.Remove(filepath.Join(h.dir, f))
	}
	if eg.closed != 2 || len(h.l.Instances()) != 0 {
		t.Fatalf("attachments closed %d, instances %d", eg.closed, len(h.l.Instances()))
	}
	calls, _ := os.ReadFile(filepath.Join(h.dir, "calls.log"))
	if strings.Contains(string(calls), "start ") {
		t.Fatalf("a container started without confinement:\n%s", calls)
	}
	if n := strings.Count(string(calls), "rm --force --time 0 smcp-web-"); n != 2 {
		t.Fatalf("containers removed %d times:\n%s", n, calls)
	}
}

func TestEgressRules(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-1")
	got, err := EgressRules([]netip.AddrPort{netip.MustParseAddrPort("10.0.2.2:8080"), netip.MustParseAddrPort("[fd00::2]:9090")})
	if err != nil {
		t.Fatal(err)
	}
	want := `table inet smcp_egress {
	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		ct state established,related accept
		ip daddr 10.0.2.2 tcp dport 8080 accept
		ip6 daddr fd00::2 tcp dport 9090 accept
		reject with icmpx admin-prohibited
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state established,related accept
	}
}
`
	if got != want {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, want)
	}
	if _, err := EgressRules([]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("10.0.2.2"), 0)}); err == nil {
		t.Fatal("port 0 accepted")
	}
}

func TestBuildEgressEnvNames(t *testing.T) {
	reqtest.Partial(t, "FR-5.37")
	rt := testRuntime()
	srv := config.RuntimeServer{Alias: "web", Image: "registry.local/fs@sha256:" + strings.Repeat("a", 64), Network: "egress"}
	build := func(env map[string]string) error {
		_, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "web", Command: "/srv"}, Network: EgressNetworkMode,
			EgressEnv: env, InstanceID: "i", Gateway: "gw", StateDir: t.TempDir()})
		return err
	}
	if err := build(map[string]string{"HTTPS_PROXY": "http://10.0.2.2:1", "NO_PROXY": ""}); err != nil {
		t.Fatalf("proxy variables refused: %v", err)
	}
	for _, bad := range []map[string]string{{"LD_PRELOAD": "x"}, {"CONTAINERS_CONF": "x"}, {"API_URL": "a\nb"}} {
		if err := build(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestLazyRecorderBuffersUntilAttached(t *testing.T) {
	lr := newLazyRecorder(quiet())
	_ = lr.write(audit.Event{Outcome: "a"}, false)
	_ = lr.write(audit.Event{Outcome: "b"}, true)
	mem := &audit.Memory{}
	lr.attach(mem)
	_ = lr.write(audit.Event{Outcome: "c"}, false)
	evs := mem.Events()
	if len(evs) != 3 || evs[0].Outcome != "a" || evs[2].Outcome != "c" {
		t.Fatalf("%+v", evs)
	}
	lr2 := newLazyRecorder(quiet())
	for range maxPending + 5 {
		_ = lr2.write(audit.Event{Outcome: "x"}, false)
	}
	mem2 := &audit.Memory{}
	lr2.attach(mem2)
	if e := findEvent(mem2.Events(), "evidence_dropped", ""); e == nil || e.Detail.(map[string]any)["events"] != 5 {
		t.Fatal("dropped evidence not reported")
	}
}

func TestReadCgroup(t *testing.T) {
	reqtest.Partial(t, "FR-5.33")
	dir := t.TempDir()
	sub := filepath.Join(dir, "container")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"memory.current": "100\n", "memory.peak": "200\n", "pids.current": "3", "pids.peak": "4",
		"memory.events": "oom 2\noom_kill 1\n", "pids.events": "max 7\n", "cpu.stat": "usage_usec 99\n", "cgroup.procs": "10\n"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600)
	}
	_ = os.WriteFile(filepath.Join(sub, "cgroup.procs"), []byte("12\n11\n"), 0o600)
	s, err := ReadCgroup(dir, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if s.MemoryCurrent != 100 || s.MemoryPeak != 200 || s.Pids != 3 || s.PidsPeak != 4 || s.OOMEvents != 2 || s.OOMKills != 1 ||
		s.PidsMaxEvents != 7 || s.CPUUsageUsec != 99 || !slices.Equal(s.Procs, []int{10, 11, 12}) {
		t.Fatalf("%+v", s)
	}
	if _, err := ReadCgroup(filepath.Join(dir, "gone"), time.Now()); err == nil {
		t.Fatal("missing cgroup read")
	}
}
