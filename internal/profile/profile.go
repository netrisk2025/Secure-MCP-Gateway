// Package profile decides the deployment profile the Gateway runs under.
//
// Enforced profile: Linux (x86_64 or arm64) with rootless Podman, nftables,
// cgroup v2 and systemd, and a confining Launcher (E-16). Server instances
// run in sandboxes and every server class may be enabled.
//
// Standalone (unconfined) profile: any other host, including macOS arm64,
// or a host without a confining Launcher. Instances run as plain child
// processes, high-risk server classes are refused, health reports
// degraded with cause "unconfined", and the release label is
// "not enforced".
package profile

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Profile names.
const (
	Standalone = "standalone"
	Enforced   = "enforced"
)

// Host is what the enforced profile needs from the machine.
type Host struct {
	OS, Arch string
	Podman   bool
	Rootless bool
	Nftables bool
	CgroupV2 bool
	Systemd  bool
}

// Missing lists the enforced-profile prerequisites the host lacks.
func (h Host) Missing() []string {
	var out []string
	if h.OS != "linux" {
		out = append(out, "linux")
	}
	if h.Arch != "amd64" && h.Arch != "arm64" {
		out = append(out, "amd64 or arm64")
	}
	for _, c := range []struct {
		ok   bool
		name string
	}{{h.Podman, "podman"}, {h.Rootless, "rootless (non-root user)"}, {h.Nftables, "nftables"}, {h.CgroupV2, "cgroup v2"}, {h.Systemd, "systemd"}} {
		if !c.ok {
			out = append(out, c.name)
		}
	}
	return out
}

// DetectHost inspects the running machine.
func DetectHost() Host {
	h := Host{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if h.OS != "linux" {
		return h
	}
	_, err := exec.LookPath("podman")
	h.Podman = err == nil
	h.Rootless = os.Geteuid() != 0
	_, err = exec.LookPath("nft")
	h.Nftables = err == nil
	_, err = os.Stat("/sys/fs/cgroup/cgroup.controllers")
	h.CgroupV2 = err == nil
	_, err = os.Stat("/run/systemd/system")
	h.Systemd = err == nil
	return h
}

// Report is the resolved profile.
type Report struct {
	Mode     string // requested: auto, standalone or enforced
	Profile  string // Standalone or Enforced
	Confined bool
	Label    string   // release label: "enforced" or "not enforced"
	Reasons  []string // why the profile is standalone, when it is
	Launcher string
	Host     Host
}

// Resolve applies the configured mode to the host and launcher. Mode
// "enforced" fails when the enforced profile is unavailable, so a Gateway
// configured for enforcement never runs unconfined.
func Resolve(mode string, launcherName string, launcherConfined bool, host Host) (Report, error) {
	r := Report{Mode: mode, Launcher: launcherName, Host: host}
	missing := host.Missing()
	if !launcherConfined {
		missing = append(missing, "confining launcher (launcher "+launcherName+" is unconfined)")
	}
	switch {
	case mode == Standalone || (mode == "auto" && len(missing) > 0):
		r.Profile, r.Label = Standalone, "not enforced"
		if mode == Standalone {
			r.Reasons = []string{"standalone profile configured"}
		} else {
			r.Reasons = missing
		}
		r.Confined = false
	case len(missing) > 0:
		return r, fmt.Errorf("enforced profile requested but unavailable: missing %s", strings.Join(missing, ", "))
	default:
		r.Profile, r.Label, r.Confined = Enforced, "enforced", true
	}
	return r, nil
}

// Degraded reports the health cause of the profile, or "" when none.
func (r Report) Degraded() string {
	if r.Profile == Standalone {
		return "unconfined"
	}
	return ""
}
