//go:build linux

package sandbox

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// These tests run real rootless Podman. They run when SMCP_SANDBOX_IT=1
// (the linux-integration CI job sets it) and need a statically linked test
// binary, because the binary itself is the server inside an empty root
// filesystem:
//
//	CGO_ENABLED=0 SMCP_SANDBOX_IT=1 go test -run Integration ./internal/sandbox/
func realHarness(t *testing.T, rt config.Runtime) *harness {
	t.Helper()
	if os.Getenv("SMCP_SANDBOX_IT") != "1" {
		t.Skip("set SMCP_SANDBOX_IT=1 to run against real rootless Podman")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if f, err := elf.Open(exe); err == nil {
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				t.Fatal("the test binary is dynamically linked; run with CGO_ENABLED=0")
			}
		}
		f.Close()
	}
	if failed := Failed(Doctor(context.Background(), DoctorOptions{})); len(failed) > 0 {
		var names []string
		for _, c := range failed {
			names = append(names, c.ID)
		}
		if os.Getenv("SMCP_SANDBOX_IT_STRICT") == "1" {
			t.Fatalf("enforced-profile prerequisites missing: %v", names)
		}
		t.Logf("prerequisites missing (continuing): %v", names)
	}
	state := t.TempDir() // 0700, as the real state directory
	l, err := New(Options{Runtime: rt, StateDir: state, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	l.SetEvidence(mem)
	ctx, cancel := context.WithCancel(context.Background())
	l.Start(ctx)
	t.Cleanup(func() {
		l.Close()
		cancel()
		if t.Failed() {
			for _, e := range mem.Events() {
				b, _ := json.Marshal(e.Detail)
				t.Logf("evidence: %s %s %s", e.Outcome, e.ReasonCode, b)
			}
			for _, v := range l.Instances() {
				t.Logf("instance %s %s usage %+v", v.Alias, v.State, v.Usage)
			}
		}
	})
	return &harness{t: t, l: l, state: state, mem: mem, exe: exe}
}

func itRuntime(t *testing.T, servers ...config.RuntimeServer) config.Runtime {
	rt := testRuntime()
	rt.Servers = servers
	rt.MonitorInterval.Duration = 100 * time.Millisecond
	if m := os.Getenv("SMCP_SANDBOX_IT_CGROUP_MANAGER"); m != "" {
		rt.CgroupManager = m
	}
	return rt
}

func shareDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, mode); err != nil { // #nosec G302 -- instance UIDs must reach it
		t.Fatal(err)
	}
	return d
}

func podmanInspect(t *testing.T, l *Launcher, name string) map[string]any {
	t.Helper()
	out, err := l.podman(context.Background(), "inspect", "--type", "container", name).Output()
	if err != nil {
		t.Fatalf("podman inspect: %v", err)
	}
	var v []map[string]any
	if err := json.Unmarshal(out, &v); err != nil || len(v) != 1 {
		t.Fatalf("inspect output: %v", err)
	}
	return v[0]
}

func mcpCall(name string, args map[string]any) *mcp.CallToolParams {
	return &mcp.CallToolParams{Name: name, Arguments: args}
}

// TestIntegrationSandboxConfinesServer inspects a real instance and its
// effective container configuration. It verifies SR-4.7-1 (all
// capabilities dropped, no_new_privs, a seccomp filter with Podman's
// default profile, a read-only root, no host PID, network or IPC
// namespace, no devices, no host socket mounted) and SR-4.1-2 (two
// concurrent instances map container root to different host UID ranges,
// neither of them host root).
func TestIntegrationSandboxConfinesServer(t *testing.T) {
	reqtest.Verifies(t, "SR-4.7-1", "SR-4.1-2")
	reqtest.Partial(t, "SR-4.5-1", "SR-4.6-1", "FR-5.9", "FR-5.33")
	ro, rw := shareDir(t, 0o755), shareDir(t, 0o777)
	if err := os.WriteFile(filepath.Join(ro, "granted.txt"), []byte("granted-content"), 0o644); err != nil { // #nosec G306 -- read by the instance
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "host-secret.txt")
	_ = os.WriteFile(secret, []byte("must-not-leak"), 0o644) // #nosec G306 -- the point is that it is readable on the host
	h := realHarness(t, itRuntime(t, config.RuntimeServer{Alias: "probe", Mounts: []config.RuntimeMount{{Source: ro, Target: "/ro"}, {Source: rw, Target: "/rw", Write: true}}}))
	p, err := h.l.Launch(context.Background(), h.spec("probe"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := connect(t, p)

	id := callText(t, s, "identity", nil)
	t.Log(id)
	for _, want := range []string{"uid=1000 ", "CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "NoNewPrivs:\t1", "Seccomp:\t2"} {
		if !strings.Contains(id, want) {
			t.Errorf("identity lacks %q", want)
		}
	}
	if m := regexp.MustCompile(`uid_map=\s*0\s+(\d+)\s+(\d+)`).FindStringSubmatch(id); m == nil || m[1] == "0" {
		t.Errorf("container root must not map to host root or the Gateway's own UID: %q", id)
	}

	// Network: no route anywhere, including the host's loopback services.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// The Internet, LAN addresses and the host's loopback services.
	for _, addr := range []string{"1.1.1.1:53", "8.8.8.8:443", "192.168.1.1:80", "172.16.0.1:5432", ln.Addr().String(), "10.0.2.2:22"} {
		if got := callText(t, s, "net_connect", map[string]any{"address": addr}); !strings.HasPrefix(got, "blocked:") {
			t.Errorf("connect %s: %s", addr, got)
		}
	}
	// Filesystem: read-only root, read-only grant, writable grant, nothing else of the host.
	for path, wantBlocked := range map[string]bool{"/etc/evil": true, "/smcp/bin/evil": true, "/ro/evil": true, "/evil": true,
		"/rw/ok.txt": false, "/work/ok.txt": false} {
		got := callText(t, s, "write_file", map[string]any{"path": path, "text": "x"})
		if strings.HasPrefix(got, "blocked:") != wantBlocked {
			t.Errorf("write %s: %s", path, got)
		}
	}
	// The file belongs to the instance's subordinate UID on the host.
	if st, err := os.Stat(filepath.Join(rw, "ok.txt")); err != nil || st.Size() != 1 {
		t.Errorf("write grant did not reach the host: %v", err)
	}
	if got := callText(t, s, "read_file", map[string]any{"path": "/ro/granted.txt"}); got != "granted-content" {
		t.Errorf("read grant: %s", got)
	}
	for _, path := range []string{secret, h.state, "/etc/shadow", "/etc/passwd-", "/var/lib/containers"} {
		if got := callText(t, s, "read_file", map[string]any{"path": path}); !strings.HasPrefix(got, "blocked:") {
			t.Errorf("read %s: %q", path, got)
		}
	}

	// Effective container configuration (SR-4.7-1 inspection).
	name := h.l.Instances()[0].Container
	ins := podmanInspect(t, h.l, name)
	hc := ins["HostConfig"].(map[string]any)
	if hc["ReadonlyRootfs"] != true || hc["NetworkMode"] != "none" || hc["Privileged"] != false || fmt.Sprint(hc["PidMode"]) == "host" ||
		fmt.Sprint(hc["IpcMode"]) == "host" || hc["Memory"].(float64) != 512<<20 || hc["PidsLimit"].(float64) != 128 || fmt.Sprint(hc["NanoCpus"]) != "1e+09" {
		t.Errorf("host config: ReadonlyRootfs=%v NetworkMode=%v Privileged=%v PidMode=%v IpcMode=%v Memory=%v PidsLimit=%v NanoCpus=%v",
			hc["ReadonlyRootfs"], hc["NetworkMode"], hc["Privileged"], hc["PidMode"], hc["IpcMode"], hc["Memory"], hc["PidsLimit"], hc["NanoCpus"])
	}
	if devs, _ := hc["Devices"].([]any); len(devs) != 0 {
		t.Errorf("devices %v", devs)
	}
	so := fmt.Sprint(hc["SecurityOpt"])
	if !strings.Contains(so, "no-new-privileges") || strings.Contains(so, "unconfined") {
		t.Errorf("security options %v", so)
	}
	if b, _ := json.Marshal(ins["Mounts"]); strings.Contains(string(b), ".sock") {
		t.Errorf("a socket is mounted: %s", b)
	}

	// SR-4.1-2: a second instance gets a different host UID range.
	p2, err := h.l.Launch(context.Background(), h.spec("probe"))
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2 := connect(t, p2)
	id2 := callText(t, s2, "identity", nil)
	re := regexp.MustCompile(`uid_map=\s*0\s+(\d+)`)
	if a, b := re.FindStringSubmatch(id), re.FindStringSubmatch(id2); a == nil || b == nil || a[1] == b[1] {
		t.Errorf("two instances share a UID mapping:\n%s\n%s", id, id2)
	}

	// Monitor: resource observables are sampled.
	eventually(t, 5*time.Second, "cgroup sample", func() bool { return h.l.Instances()[0].Usage.MemoryCurrent > 0 })
}

// TestIntegrationMonitorContainment exceeds each cgroup limit from the
// probe (SR-4.7-2): memory (the kernel kills at the limit), CPU (busy
// goroutines get no more than the CPU quota), PIDs (forking past the limit
// is refused and the monitor kills the instance). The CP-24 defaults are
// checked on a real container by TestIntegrationSandboxConfinesServer.
func TestIntegrationMonitorContainment(t *testing.T) {
	reqtest.Verifies(t, "SR-4.7-2")
	reqtest.Partial(t, "FR-5.33", "FR-5.34", "FR-5.35")
	h := realHarness(t, itRuntime(t,
		config.RuntimeServer{Alias: "cpu", CPUs: 0.25},
		config.RuntimeServer{Alias: "oom", MemoryBytes: 64 << 20},
		config.RuntimeServer{Alias: "spawn"},
		config.RuntimeServer{Alias: "fork", Pids: 40, AllowSpawn: true},
	))

	// CPU: four busy goroutines for two seconds get at most the quota of a
	// quarter CPU (with slack for scheduling); unconfined they would use
	// several CPU-seconds.
	p, err := h.l.Launch(context.Background(), h.spec("cpu"))
	if err != nil {
		t.Fatal(err)
	}
	s := connect(t, p)
	var cpuMS, wallMS int
	if got := callText(t, s, "burn", map[string]any{"workers": 4, "ms": 2000}); func() bool {
		_, err := fmt.Sscanf(got, "cpu_ms=%d wall_ms=%d", &cpuMS, &wallMS)
		return err != nil
	}() {
		t.Fatalf("burn: %q", got)
	}
	t.Logf("cpus=0.25: %d ms CPU in %d ms wall", cpuMS, wallMS)
	if wallMS < 1900 || float64(cpuMS) > 0.4*float64(wallMS) {
		t.Errorf("CPU limit of 0.25 not enforced: %d ms CPU in %d ms wall", cpuMS, wallMS)
	}
	p.Close()

	// Memory: the kernel kills at the cgroup limit; the instance ends and
	// the evidence names the limit.
	p, err = h.l.Launch(context.Background(), h.spec("oom"))
	if err != nil {
		t.Fatal(err)
	}
	s = connect(t, p)
	_, _ = s.CallTool(context.Background(), mcpCall("alloc", map[string]any{"mib": 256}))
	eventually(t, 10*time.Second, "memory evidence", func() bool {
		return findEvent(h.mem.Events(), "limit_breach", ReasonMemoryLimit) != nil || findEvent(h.mem.Events(), "instance_exited", ReasonMemoryLimit) != nil
	})
	p.Close()

	// Process creation: observed and reported as an undeclared deviation.
	p, err = h.l.Launch(context.Background(), h.spec("spawn"))
	if err != nil {
		t.Fatal(err)
	}
	s = connect(t, p)
	if got := callText(t, s, "spawn", nil); !strings.HasPrefix(got, "spawned") {
		t.Fatalf("spawn: %s", got)
	}
	eventually(t, 5*time.Second, "deviation", func() bool { return findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess) != nil })
	p.Close()

	// PIDs: forking past the limit is refused by the kernel and the monitor
	// kills the instance.
	p, err = h.l.Launch(context.Background(), h.spec("fork"))
	if err != nil {
		t.Fatal(err)
	}
	s = connect(t, p)
	for range 30 {
		if _, err := s.CallTool(context.Background(), mcpCall("spawn", nil)); err != nil {
			break
		}
	}
	eventually(t, 10*time.Second, "pids breach", func() bool { return findEvent(h.mem.Events(), "limit_breach", ReasonPidsLimit) != nil })
	p.Close()
}

func TestIntegrationLeftoverContainersAreReaped(t *testing.T) {
	h := realHarness(t, itRuntime(t))
	ctx := context.Background()
	name := "smcp-leftover-" + strings.ReplaceAll(h.l.GatewayID(), "-", "")[20:]
	cmd := exec.Command(h.l.podPath, "create", "--label", LabelManaged+"=1", "--label", LabelGateway+"=old", "--name", name, "--rootfs", "/", "/bin/true") // #nosec G204 -- test
	cmd.Env = h.l.run.env(nil)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot create a test container: %v %s", err, out)
	}
	h.l.Reap(ctx)
	if err := h.l.podman(ctx, "container", "exists", name).Run(); err == nil {
		t.Fatal("leftover container still exists")
	}
}

// TestIntegrationEgressBroker: a sandboxed server with network = "egress"
// reaches a granted local HTTP server only through its Egress Broker
// proxy. Direct connections, to the granted server itself, to other host
// loopback services, to the slirp4netns DNS forwarder and to the Internet,
// are refused by the nftables table in the container's namespace; a
// proxied request to an ungranted destination is refused by the broker.
func TestIntegrationEgressBroker(t *testing.T) {
	// SR-4.5-1: from an instance in its network namespace, connections to
	// the Internet, the LAN, host loopback services (the canary, as a local
	// database would be) and the DNS forwarder fail; only the broker
	// endpoint carries traffic. TestIntegrationSandboxConfinesServer checks
	// the same for an instance without egress (network none).
	reqtest.Verifies(t, "SR-4.5-1")
	reqtest.Partial(t, "FR-5.37", "SR-5.15-1")
	allowed := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("egress-ok"))
	})}
	aln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = allowed.Serve(aln) }()
	defer allowed.Close()
	canary, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer canary.Close()
	hits := make(chan struct{}, 16)
	go func() {
		for {
			c, err := canary.Accept()
			if err != nil {
				return
			}
			hits <- struct{}{}
			c.Close()
		}
	}()
	aport, cport := aln.Addr().(*net.TCPAddr).Port, canary.Addr().(*net.TCPAddr).Port

	h := realHarness(t, itRuntime(t, config.RuntimeServer{Alias: "web", Network: "egress"}))
	ev := &audit.Memory{}
	b, err := egress.New(egress.Options{Evidence: ev, ProxyEnv: true, Servers: []string{"web"},
		Grants: egress.NewStaticGrants([]egress.Grant{{Server: "web", Host: "127.0.0.1", Ports: []int{aport}, Methods: []string{"GET"},
			Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}})})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	h.l.SetEgress(b)
	p, err := h.l.Launch(context.Background(), h.spec("web"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := connect(t, p)

	// The granted server itself, a host loopback service standing in for
	// the database (the canary), the slirp4netns DNS forwarder, the
	// Internet, LAN addresses and host SSH: only the broker is reachable.
	for _, addr := range []string{fmt.Sprintf("10.0.2.2:%d", aport), fmt.Sprintf("10.0.2.2:%d", cport), "10.0.2.3:53", "1.1.1.1:443",
		"192.168.1.1:80", "172.16.0.1:5432", "10.0.2.2:22"} {
		if got := callText(t, s, "net_connect", map[string]any{"address": addr}); !strings.HasPrefix(got, "blocked:") {
			t.Errorf("direct connect %s: %s", addr, got)
		}
	}
	if got := callText(t, s, "http_get", map[string]any{"url": fmt.Sprintf("http://127.0.0.1:%d/", aport)}); got != "status 200: egress-ok" {
		t.Errorf("brokered request to the granted server: %q", got)
	}
	if got := callText(t, s, "http_get", map[string]any{"url": fmt.Sprintf("http://127.0.0.1:%d/", cport)}); !strings.HasPrefix(got, "status 403") {
		t.Errorf("brokered request to an ungranted destination: %q", got)
	}
	select {
	case <-hits:
		t.Error("the ungranted canary was reached")
	case <-time.After(200 * time.Millisecond):
	}
	name := h.l.Instances()[0].Container
	hc := podmanInspect(t, h.l, name)["HostConfig"].(map[string]any)
	if nm := fmt.Sprint(hc["NetworkMode"]); !strings.HasPrefix(nm, "slirp4netns") {
		t.Errorf("network mode %s", nm)
	}
	var allowedOp, deniedOp bool
	for _, e := range ev.Events() {
		if e.Class == "egress" && e.Outcome == "allow" {
			allowedOp = true
		}
		if e.Class == "egress" && e.Outcome == "deny" {
			deniedOp = true
		}
	}
	if !allowedOp || !deniedOp {
		t.Errorf("egress evidence: allow %v deny %v", allowedOp, deniedOp)
	}
	if e := findEvent(h.mem.Events(), "instance_launched", ""); e == nil || e.Detail.(map[string]any)["egress"] == nil {
		t.Error("launch evidence lacks the egress attachment")
	}
}
