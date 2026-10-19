package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDoctorChecksTheServerIdentity: with runtime.run_as the Podman checks
// run as that identity through sudo and the subordinate ID checks read its
// ranges, not the Gateway's; an unknown identity fails the run-as check.
func TestDoctorChecksTheServerIdentity(t *testing.T) {
	reqtest.Partial(t, "FR-13.5", "SR-4.1-2")
	root := fakeHost(t)
	_ = os.WriteFile(filepath.Join(root, "etc/subuid"), []byte("smcp-srv:200000:65536\n"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "etc/subgid"), []byte("smcp-srv:200000:65536\n"), 0o600)
	o := doctorOpts(root, goodInfo)
	var ran []string
	o.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		ran = append([]string{name}, args...)
		return []byte(goodInfo), nil
	}
	o.RunAs, o.Sudo, o.Podman, o.LookupUser = "smcp-srv", "/usr/bin/sudo", "/usr/bin/podman", fakeSrvUser
	checks := Doctor(context.Background(), o)
	if f := Failed(checks); len(f) != 0 {
		t.Fatalf("failed: %+v", f)
	}
	if status(checks)["run-as"] != CheckPass {
		t.Fatalf("run-as check: %+v", checks)
	}
	if strings.Join(ran, " ") != "/usr/bin/sudo -n -E -u smcp-srv -- /usr/bin/podman info --format json" {
		t.Fatalf("podman info ran as %q", ran)
	}
	// The Gateway's own ranges do not count for the server identity.
	_ = os.WriteFile(filepath.Join(root, "etc/subuid"), []byte("smcp-core:100000:65536\n"), 0o600)
	if s := status(Doctor(context.Background(), o)); s["subid-subuid"] != CheckFail {
		t.Fatalf("subuid of smcp-core accepted for smcp-srv: %v", s)
	}
	o.RunAs = "nobody-here"
	if s := status(Doctor(context.Background(), o)); s["run-as"] != CheckFail {
		t.Fatalf("unknown identity: %v", s)
	}
}

// TestDoctorReportsTheServerAppArmorProfile: on an AppArmor host the
// doctor warns (does not fail) until smcp-server is loaded in enforce mode.
func TestDoctorReportsTheServerAppArmorProfile(t *testing.T) {
	reqtest.Partial(t, "FR-13.5")
	root := fakeHost(t)
	o := doctorOpts(root, goodInfo)
	if s := status(Doctor(context.Background(), o)); s["apparmor-server"] != CheckWarn {
		t.Fatalf("profile not loaded: %v", s)
	}
	// The unprivileged view: apparmorfs per-profile directories.
	pd := filepath.Join(root, "sys/kernel/security/apparmor/policy/profiles/smcp-server.7")
	_ = os.MkdirAll(pd, 0o700)
	_ = os.WriteFile(filepath.Join(pd, "name"), []byte("smcp-server\n"), 0o600)
	_ = os.WriteFile(filepath.Join(pd, "mode"), []byte("complain\n"), 0o600)
	if s := status(Doctor(context.Background(), o)); s["apparmor-server"] != CheckWarn {
		t.Fatalf("profile in complain mode: %v", s)
	}
	_ = os.WriteFile(filepath.Join(pd, "mode"), []byte("enforce\n"), 0o600)
	if s := status(Doctor(context.Background(), o)); s["apparmor-server"] != CheckPass {
		t.Fatalf("profile loaded (apparmorfs): %v", s)
	}
	// The root view: the profiles list.
	_ = os.RemoveAll(filepath.Join(root, "sys/kernel/security/apparmor/policy"))
	_ = os.WriteFile(filepath.Join(root, "sys/kernel/security/apparmor/profiles"), []byte("smcpd (enforce)\nsmcp-server (enforce)\n"), 0o600)
	if s := status(Doctor(context.Background(), o)); s["apparmor-server"] != CheckPass {
		t.Fatalf("profile loaded (profiles list): %v", s)
	}
}
