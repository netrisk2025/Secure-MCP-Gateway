package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestEnableDelegatedControllers: smcpd in the "supervisor" leaf of its
// delegated service cgroup enables memory, pids and cpu in the service
// cgroup's subtree_control (so that container cgroups created next to the
// leaf get limits), and changes nothing when they are already there or
// when the parent is not offered them.
func TestEnableDelegatedControllers(t *testing.T) {
	reqtest.Partial(t, "SR-4.7-2", "FR-13.5")
	root := t.TempDir()
	svc := filepath.Join(root, "system.slice", "smcpd.service")
	leaf := filepath.Join(svc, "supervisor")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, v string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(svc, "cgroup.controllers"), "cpuset cpu io memory pids\n")
	write(filepath.Join(svc, "cgroup.subtree_control"), "")
	write(filepath.Join(leaf, "cgroup.controllers"), "")
	self := "0::/system.slice/smcpd.service/supervisor\n"

	on, err := EnableDelegatedControllers(root, self)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(on, []string{"cpu", "memory", "pids"}) {
		t.Fatalf("enabled %v", on)
	}
	if b, _ := os.ReadFile(filepath.Join(svc, "cgroup.subtree_control")); string(b) != "+cpu +memory +pids" {
		t.Fatalf("subtree_control %q", b)
	}

	// Already delegated: nothing is written.
	write(filepath.Join(leaf, "cgroup.controllers"), "cpu memory pids\n")
	write(filepath.Join(svc, "cgroup.subtree_control"), "cpu memory pids")
	if on, err := EnableDelegatedControllers(root, self); err != nil || on != nil {
		t.Fatalf("already delegated: %v %v", on, err)
	}
	// Not offered by the parent, the root cgroup, cgroup v1 lines: nothing.
	write(filepath.Join(leaf, "cgroup.controllers"), "")
	write(filepath.Join(svc, "cgroup.controllers"), "io\n")
	for _, s := range []string{self, "0::/\n", "1:name=systemd:/x\n", ""} {
		if on, err := EnableDelegatedControllers(root, s); err != nil || on != nil {
			t.Fatalf("%q: %v %v", s, on, err)
		}
	}
}

func TestDoctorUsesConfiguredCgroupManager(t *testing.T) {
	reqtest.Partial(t, "FR-12.3")
	var got []string
	o := doctorOpts(fakeHost(t), goodInfo)
	run := o.Run
	o.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = args
		return run(ctx, name, args...)
	}
	o.CgroupManager = "cgroupfs"
	Doctor(context.Background(), o)
	if strings.Join(got, " ") != "--cgroup-manager=cgroupfs info --format json" {
		t.Fatalf("podman info arguments %v", got)
	}
}
