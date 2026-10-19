package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const goodInfo = `{"host":{"cgroupVersion":"v2","cgroupManager":"systemd","cgroupControllers":["cpu","memory","pids","io"],
"ociRuntime":{"name":"crun","version":"1.14"},"security":{"rootless":true,"seccompEnabled":true,"apparmorEnabled":true}},
"version":{"Version":"4.9.3"}}`

// fakeHost writes a host file tree that meets every prerequisite.
func fakeHost(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"proc/sys/kernel/osrelease":          "6.8.0-1017-azure",
		"proc/sys/user/max_user_namespaces":  "63000",
		"sys/fs/cgroup/cgroup.controllers":   "cpu memory pids",
		"etc/subuid":                         "other:1:5\nsmcp-core:100000:65536\n",
		"etc/subgid":                         "smcp-core:100000:65536\n",
		"run/systemd/system/.keep":           "",
		"sys/kernel/security/apparmor/.keep": "",
	}
	for p, v := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func doctorOpts(root string, info string, missing ...string) DoctorOptions {
	uid := 1001
	return DoctorOptions{Root: root, GOOS: "linux", GOARCH: "amd64", Euid: &uid, User: "smcp-core",
		LookPath: func(n string) (string, error) {
			for _, m := range missing {
				if m == n {
					return "", errors.New("not found")
				}
			}
			return "/usr/bin/" + n, nil
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if info == "" {
				return nil, errors.New("exit status 125")
			}
			return []byte(info), nil
		}}
}

func status(checks []Check) map[string]string {
	out := map[string]string{}
	for _, c := range checks {
		out[c.ID] = c.Status
	}
	return out
}

func TestDoctorAllPrerequisitesPresent(t *testing.T) {
	reqtest.Partial(t, "FR-12.3", "FR-13.5")
	checks := Doctor(context.Background(), doctorOpts(fakeHost(t), goodInfo))
	if f := Failed(checks); len(f) != 0 {
		t.Fatalf("failed: %+v", f)
	}
	for _, id := range []string{"os", "arch", "kernel", "rootless", "cgroup-v2", "userns", "subid-subuid", "subid-subgid", "uidmap",
		"nftables", "systemd", "lsm", "podman", "podman-rootless", "crun", "podman-cgroup-v2", "cgroup-delegation", "seccomp"} {
		if status(checks)[id] != CheckPass {
			t.Errorf("check %s missing or not passing: %v", id, status(checks))
		}
	}
}

func TestDoctorNamesEachMissingPrerequisite(t *testing.T) {
	reqtest.Partial(t, "FR-13.9")
	root := fakeHost(t)
	_ = os.WriteFile(filepath.Join(root, "proc/sys/kernel/osrelease"), []byte("5.15.0"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "etc/subuid"), []byte("smcp-core:100000:1000\n"), 0o600)
	_ = os.RemoveAll(filepath.Join(root, "sys/kernel/security"))
	_ = os.WriteFile(filepath.Join(root, "proc/sys/kernel/apparmor_restrict_unprivileged_userns"), []byte("1"), 0o600)
	bad := strings.NewReplacer(`"crun"`, `"runc"`, `"rootless":true`, `"rootless":false`, `"pids",`, ``).Replace(goodInfo)
	st := status(Doctor(context.Background(), doctorOpts(root, bad, "nft", "newuidmap")))
	for id, want := range map[string]string{"kernel": CheckFail, "subid-subuid": CheckFail, "subid-subgid": CheckPass, "lsm": CheckFail,
		"nftables": CheckFail, "uidmap": CheckFail, "crun": CheckFail, "podman-rootless": CheckFail, "cgroup-delegation": CheckFail,
		"userns-apparmor": CheckWarn, "systemd": CheckPass} {
		if st[id] != want {
			t.Errorf("%s = %q, want %q", id, st[id], want)
		}
	}
	// Podman missing or failing.
	if st := status(Doctor(context.Background(), doctorOpts(root, "", "podman"))); st["podman"] != CheckFail {
		t.Errorf("podman missing: %v", st)
	}
	if st := status(Doctor(context.Background(), doctorOpts(root, ""))); st["podman"] != CheckFail {
		t.Errorf("podman info failing: %v", st)
	}
	// Not Linux: only the platform checks.
	o := doctorOpts(root, goodInfo)
	o.GOOS = "darwin"
	if c := Doctor(context.Background(), o); len(c) != 2 || c[0].Status != CheckFail {
		t.Fatalf("darwin: %+v", c)
	}
	root0 := 0
	o = doctorOpts(fakeHost(t), goodInfo)
	o.Euid = &root0
	if st := status(Doctor(context.Background(), o)); st["rootless"] != CheckFail {
		t.Fatal("root accepted")
	}
}

func TestFromConfigRefusesWithoutPrerequisites(t *testing.T) {
	reqtest.Partial(t, "FR-13.9")
	cfg, err := config.Parse([]byte("[admin]\nusername=\"a\"\npassword_hash=\"$argon2id$x\"\n[profile]\nmode=\"enforced\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.Sandbox != "podman" {
		t.Fatalf("enforced profile defaults the sandbox to podman, got %q", cfg.Runtime.Sandbox)
	}
	cfg.State.Dir = t.TempDir()
	_, err = FromConfig(context.Background(), cfg, SetupOptions{Log: quiet(), Doctor: func(context.Context) []Check {
		return []Check{{Name: "Podman runs rootless", Status: CheckFail}, {Name: "nftables (nft)", Status: CheckFail}, {Name: "systemd", Status: CheckPass}}
	}})
	if !errors.Is(err, ErrPrerequisites) || !strings.Contains(err.Error(), "Podman runs rootless") || !strings.Contains(err.Error(), "nftables") || strings.Contains(err.Error(), "systemd") {
		t.Fatalf("err = %v", err)
	}
	// Mode auto: only checks the sandbox needs refuse.
	cfg.Profile.Mode = "auto"
	l, err := FromConfig(context.Background(), cfg, SetupOptions{Log: quiet(), Doctor: func(context.Context) []Check {
		return []Check{{ID: "systemd", Name: "systemd", Status: CheckFail}, {ID: "lsm", Name: "AppArmor or SELinux", Status: CheckFail}}
	}})
	if err != nil && !strings.Contains(err.Error(), "podman not found") {
		t.Fatalf("auto mode refused for non-essential checks: %v", err)
	}
	if l != nil {
		l.Close()
	}
	if _, err := FromConfig(context.Background(), cfg, SetupOptions{Log: quiet(), Doctor: func(context.Context) []Check {
		return []Check{{ID: "podman-rootless", Name: "Podman runs rootless", Status: CheckFail}}
	}}); !errors.Is(err, ErrPrerequisites) {
		t.Fatalf("auto mode accepted a host where the sandbox cannot work: %v", err)
	}
	cfg.Runtime.Sandbox = "none"
	if l, err := FromConfig(context.Background(), cfg, SetupOptions{}); l != nil || err != nil {
		t.Fatal("sandbox none must give no launcher")
	}
}

func TestKernelVersionCompare(t *testing.T) {
	for rel, want := range map[string]bool{"6.8.0-45-generic": true, "6.12.72-linuxkit": true, "7.0": true, "6.7.12": false, "5.15.0": false, "x": false, "6.8rc1": true} {
		if got := kernelAtLeast(rel, MinKernel); got != want {
			t.Errorf("%s: %v", rel, got)
		}
	}
}
