package profile

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	full := Host{OS: "linux", Arch: "amd64", Podman: true, Rootless: true, Nftables: true, CgroupV2: true, Systemd: true}
	mac := Host{OS: "darwin", Arch: "arm64"}

	r, err := Resolve("auto", "subprocess", false, mac)
	if err != nil || r.Profile != Standalone || r.Label != "not enforced" || r.Degraded() != "unconfined" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(strings.Join(r.Reasons, ","), "linux") {
		t.Fatalf("reasons %v", r.Reasons)
	}
	// A capable host with an unconfined launcher is still standalone.
	r, _ = Resolve("auto", "subprocess", false, full)
	if r.Profile != Standalone {
		t.Fatalf("%+v", r)
	}
	r, err = Resolve("auto", "podman", true, full)
	if err != nil || r.Profile != Enforced || r.Degraded() != "" || !r.Confined {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := Resolve("enforced", "subprocess", false, mac); err == nil {
		t.Fatal("enforced mode ran unconfined")
	}
	r, _ = Resolve("standalone", "podman", true, full)
	if r.Profile != Standalone {
		t.Fatalf("%+v", r)
	}
	h := DetectHost()
	if h.OS == "" || h.Arch == "" {
		t.Fatal("host not detected")
	}
}
