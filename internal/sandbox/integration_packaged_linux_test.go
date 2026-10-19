//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestIntegrationPackagedServerSlotsAndEnvironment runs the probe server as
// a packaged server (a manifest resolved by packaging.ResolveLaunch, as the
// package library does) in real rootless Podman, attached to the Egress
// Broker, and inspects the launched instance from inside and with podman
// inspect:
//
//   - SR-4.6-1: the manifest declares the slots "docs" (read-only) and
//     "out" (read-write); the Runtime Profile grants their parent directory
//     with write. The instance reads a file in docs, cannot write to docs,
//     writes to out, and cannot see the parent's other directory, which
//     the grant covers but no slot declares. Nothing of the host outside
//     the slots is readable.
//   - FR-5.37 and SR-2.14-1: the instance environment (/proc/self/environ
//     of the server process, and the container configuration) holds the
//     manifest's env_fixed variables, the allowlisted operator value, the
//     approved S4 secret, the Egress Broker's endpoint base-URL variable
//     (named in the grant, pointing at the broker) and proxy variables, and
//     otherwise only what the container runtime itself sets (PATH, HOME,
//     HOSTNAME, container, TERM) with values that are not the Gateway's. A
//     variable of the Gateway's own environment is absent.
func TestIntegrationPackagedServerSlotsAndEnvironment(t *testing.T) {
	reqtest.Verifies(t, "SR-4.6-1", "FR-5.37", "SR-2.14-1")
	t.Setenv("SMCP_HOST_ONLY_CANARY", "host-environment-canary-7c1")
	parent := shareDir(t, 0o755)
	docs, out, other := filepath.Join(parent, "docs"), filepath.Join(parent, "out"), filepath.Join(parent, "other")
	for d, mode := range map[string]os.FileMode{docs: 0o755, out: 0o777, other: 0o755} {
		if err := os.Mkdir(d, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil { // #nosec G302 -- instance UIDs must reach it
			t.Fatal(err)
		}
	}
	for p, s := range map[string]string{filepath.Join(docs, "doc.txt"): "declared-slot-content", filepath.Join(other, "secret.txt"): "undeclared-content"} {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil { // #nosec G306 -- read by the instance
			t.Fatal(err)
		}
	}

	h := realHarness(t, itRuntime(t, config.RuntimeServer{Alias: "pkg", Network: "egress",
		Mounts: []config.RuntimeMount{{Source: parent, Target: "/data", Write: true}}}))

	// The package: the probe binary as a native artifact.
	root := shareDir(t, 0o755)
	exe, err := os.ReadFile(h.exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "probe"), exe, 0o755); err != nil { // #nosec G306 -- an executable
		t.Fatal(err)
	}
	m := &packaging.Manifest{Artifact: packaging.ArtifactInfo{Type: "binary"},
		Launch: packaging.Launch{Runtime: "native", Argv: []string{"probe"}, EnvAllowlist: []string{"APP_MODE"},
			EnvFixed: map[string]string{"SMCP_FAKE_SERVER": "1", "FIXED_VAR": "fixed-value"}},
		Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{{Slot: "docs", Mode: "ro"}, {Slot: "out", Mode: "rw"}}}}
	spec, err := packaging.ResolveLaunch(packaging.LaunchInput{Manifest: m, Alias: "pkg", Root: root, WorkDir: t.TempDir(),
		Slots: map[string]string{"docs": docs, "out": out}, Env: map[string]string{"APP_MODE": "test-mode"}})
	if err != nil {
		t.Fatal(err)
	}
	// As the Server Runtime Manager does (internal/backend): base, then the
	// resolved environment, then the approved S4 secrets.
	if spec.Env, err = pipeline.MergeEnv(pipeline.BaseEnv(), spec.Env, map[string]string{"S4_TOKEN": "approved-s4-value"}); err != nil {
		t.Fatal(err)
	}

	api := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("api-ok")) })}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = api.Serve(ln) }()
	defer api.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	b, err := egress.New(egress.Options{Evidence: &audit.Memory{}, ProxyEnv: true, Servers: []string{"pkg"},
		Grants: egress.NewStaticGrants([]egress.Grant{{Server: "pkg", Host: "127.0.0.1", Ports: []int{port}, Methods: []string{"GET"},
			Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, EndpointEnv: "API_BASE_URL"}})})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	h.l.SetEgress(b)
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := connect(t, p)

	// SR-4.6-1.
	if got := callText(t, s, "read_file", map[string]any{"path": "/data/docs/doc.txt"}); got != "declared-slot-content" {
		t.Errorf("read in the declared slot: %q", got)
	}
	for path, wantBlocked := range map[string]bool{"/data/docs/new.txt": true, "/data/out/new.txt": false, "/data/new.txt": true, "/data/other/new.txt": true} {
		if got := callText(t, s, "write_file", map[string]any{"path": path, "text": "x"}); strings.HasPrefix(got, "blocked:") != wantBlocked {
			t.Errorf("write %s: %s", path, got)
		}
	}
	for _, path := range []string{"/data/other/secret.txt", other + "/secret.txt", parent, h.state} {
		if got := callText(t, s, "read_file", map[string]any{"path": path}); !strings.HasPrefix(got, "blocked:") {
			t.Errorf("read %s outside the declared slots: %q", path, got)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "new.txt")); err != nil {
		t.Errorf("the write to the read-write slot did not reach the host: %v", err)
	}

	// FR-5.37 and SR-2.14-1: the environment of the server process.
	raw := callText(t, s, "read_file", map[string]any{"path": "/proc/self/environ"})
	if strings.HasPrefix(raw, "blocked:") {
		t.Fatalf("environment unreadable: %s", raw)
	}
	env := map[string]string{}
	for _, kv := range strings.Split(strings.TrimRight(raw, "\x00"), "\x00") {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	t.Logf("instance environment names: %v", slices.Sorted(maps.Keys(env)))
	want := map[string]string{"APP_MODE": "test-mode", "FIXED_VAR": "fixed-value", "SMCP_FAKE_SERVER": "1", "S4_TOKEN": "approved-s4-value"}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	if !strings.HasPrefix(env["API_BASE_URL"], "http://10.0.2.2:") {
		t.Errorf("API_BASE_URL = %q, want the broker endpoint", env["API_BASE_URL"])
	}
	// The endpoint is a broker listener the instance can reach (the probe's
	// http_get always goes through HTTP_PROXY, so a plain connect is used).
	if got := callText(t, s, "net_connect", map[string]any{"address": strings.TrimPrefix(env["API_BASE_URL"], "http://")}); got != "connected" {
		t.Errorf("connect to the endpoint base URL: %q", got)
	}
	egressNames := []string{"API_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"}
	runtimeNames := []string{"PATH", "HOME", "HOSTNAME", "container", "TERM"}
	for k, v := range env {
		switch {
		case want[k] != "", slices.Contains(egressNames, k):
		case slices.Contains(runtimeNames, k):
			if (k == "PATH" || k == "HOME") && v == os.Getenv(k) {
				t.Errorf("%s carries the Gateway's value %q", k, v)
			}
		default:
			t.Errorf("variable %s=%q is neither in the manifest allowlist, an egress endpoint, an approved S4 secret nor set by the runtime", k, v)
		}
		if strings.Contains(v, "host-environment-canary") {
			t.Errorf("the Gateway's environment reached the instance in %s", k)
		}
	}

	// The same from the container configuration.
	ins := podmanInspect(t, h.l, h.l.Instances()[0].Container)
	cfg, _ := ins["Config"].(map[string]any)
	cenv, _ := cfg["Env"].([]any)
	names := map[string]bool{}
	for _, e := range cenv {
		k, _, _ := strings.Cut(fmt.Sprint(e), "=")
		names[k] = true
		if strings.Contains(fmt.Sprint(e), "host-environment-canary") {
			t.Errorf("container configuration holds the Gateway's environment: %v", e)
		}
	}
	for k := range want {
		if !names[k] {
			t.Errorf("container configuration lacks %s: %v", k, cenv)
		}
	}
}
