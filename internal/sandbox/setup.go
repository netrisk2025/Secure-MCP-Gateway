package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// ErrPrerequisites is wrapped by FromConfig when the host lacks an
// enforced-profile prerequisite.
var ErrPrerequisites = errors.New("enforced-profile prerequisites missing")

// SetupOptions adjust FromConfig.
type SetupOptions struct {
	Log *slog.Logger
	// Doctor replaces the prerequisite check (tests).
	Doctor func(ctx context.Context) []Check
	// CgroupRoot is the cgroup v2 mount (default /sys/fs/cgroup).
	CgroupRoot string
}

// SandboxEssential names the checks without which the Podman sandbox cannot
// confine an instance at all. The remaining checks (systemd, nftables, an
// LSM) are needed for the enforced profile but not for the container
// itself.
var SandboxEssential = []string{"os", "arch", "kernel", "rootless", "cgroup-v2", "userns", "subid-subuid", "subid-subgid", "uidmap",
	"podman", "podman-rootless", "crun", "podman-cgroup-v2", "cgroup-delegation", "seccomp"}

// FromConfig returns the confining launcher selected by `[runtime] sandbox`,
// or nil when the sandbox is "none". Before it returns a launcher it checks
// the enforced-profile prerequisites. With `[profile] mode = "enforced"`
// every missing prerequisite refuses the start, each one named (FR-13.9),
// so a Gateway configured for enforcement never runs servers unconfined.
// In mode "auto" only the checks the sandbox itself needs refuse; the
// others are logged and the profile resolves to standalone.
func FromConfig(ctx context.Context, cfg *config.Config, o SetupOptions) (*Launcher, error) {
	if cfg.Runtime.Sandbox != "podman" {
		return nil, nil
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if cfg.Runtime.CgroupManager == "cgroupfs" && runtime.GOOS == "linux" {
		// Under smcpd.service (Delegate=yes, DelegateSubgroup=supervisor)
		// the container cgroups need the controllers enabled first.
		if self, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			cgroupRoot := o.CgroupRoot
			if cgroupRoot == "" {
				cgroupRoot = "/sys/fs/cgroup"
			}
			if on, err := EnableDelegatedControllers(cgroupRoot, string(self)); err != nil {
				o.Log.Warn("could not enable cgroup controllers in the delegated subtree", "err", err)
			} else if len(on) > 0 {
				o.Log.Info("enabled cgroup controllers for server containers in the delegated subtree", "controllers", on)
			}
		}
	}
	if o.Doctor == nil {
		do := DoctorOptionsFor(cfg.Runtime)
		o.Doctor = func(ctx context.Context) []Check { return Doctor(ctx, do) }
	}
	var refuse []string
	for _, c := range Failed(o.Doctor(ctx)) {
		n := c.Name
		if c.Detail != "" {
			n += " (" + c.Detail + ")"
		}
		if cfg.Profile.Mode == "enforced" || c.ID == "" || slices.Contains(SandboxEssential, c.ID) {
			refuse = append(refuse, n)
		} else {
			o.Log.Warn("enforced-profile prerequisite missing; servers are sandboxed but the profile is not enforced", "check", n)
		}
	}
	if len(refuse) > 0 {
		return nil, fmt.Errorf("%w: %s; run `smcpctl runtime doctor` for remedies", ErrPrerequisites, strings.Join(refuse, "; "))
	}
	return New(Options{Runtime: cfg.Runtime, StateDir: cfg.State.Dir, Log: o.Log})
}
