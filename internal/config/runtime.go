package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Runtime configures the Server Runtime Manager (E-15), the Execution
// Sandbox (E-16) and the Runtime Monitor (E-17): the `[runtime]` table.
//
// Sandbox selects the launcher: "none" runs servers as plain child
// processes (standalone profile); "podman" runs each instance in a rootless
// Podman container. When the key is absent it defaults to "podman" if
// `[profile] mode = "enforced"` and to "none" otherwise.
//
// The resource keys are the CP-24 instance budget; a [[runtime.server]]
// entry may lower or raise them for one server.
type Runtime struct {
	Sandbox         string          `toml:"sandbox" json:"sandbox"`
	Podman          string          `toml:"podman" json:"podman"`
	Image           string          `toml:"image" json:"image"`
	MemoryBytes     int64           `toml:"memory_bytes" json:"memory_bytes"`
	CPUs            float64         `toml:"cpus" json:"cpus"`
	Pids            int             `toml:"pids" json:"pids"`
	TmpfsBytes      int64           `toml:"tmpfs_bytes" json:"tmpfs_bytes"`
	NoFile          int             `toml:"nofile" json:"nofile"`
	UserNSSize      int             `toml:"userns_size" json:"userns_size"`
	User            string          `toml:"user" json:"user"`
	AppArmorProfile string          `toml:"apparmor_profile" json:"apparmor_profile"`
	SELinuxType     string          `toml:"selinux_type" json:"selinux_type"`
	CgroupManager   string          `toml:"cgroup_manager" json:"cgroup_manager"`
	MonitorInterval Duration        `toml:"monitor_interval" json:"monitor_interval"`
	Servers         []RuntimeServer `toml:"server" json:"server"`

	// RunAs is the CP-46 server-runtime identity (smcp-srv): when set, the
	// Gateway runs every Podman command as this user through Sudo, so
	// server containers belong to that user's rootless Podman and its
	// subordinate ID range, not to the Gateway's own identity.
	RunAs string `toml:"run_as" json:"run_as"`
	// Sudo is the absolute path of sudo (default /usr/bin/sudo); used only
	// with RunAs.
	Sudo string `toml:"sudo" json:"sudo"`
	// SharedDir is a directory the Gateway writes and RunAs can traverse
	// and read; it holds the Gateway-built root directory of servers that
	// run without an image. Required with RunAs.
	SharedDir string `toml:"shared_dir" json:"shared_dir"`
}

// RuntimeServer holds the sandbox settings of one server, matched by alias.
// Zero resource values take the [runtime] value.
type RuntimeServer struct {
	Alias       string  `toml:"alias" json:"alias"`
	Image       string  `toml:"image" json:"image"`
	MemoryBytes int64   `toml:"memory_bytes" json:"memory_bytes"`
	CPUs        float64 `toml:"cpus" json:"cpus"`
	Pids        int     `toml:"pids" json:"pids"`
	// Network is "none" (default, loopback only) or "egress" (attach the
	// instance to the Egress Broker; refused by the sandbox until that
	// attachment is built).
	Network string `toml:"network" json:"network"`
	// Scope is the instance scope (FR-5.10). Only "shared" is implemented.
	Scope string `toml:"scope" json:"scope"`
	// UserNS is "auto" (default: a distinct UID range per instance) or
	// "keep-id" (the host user's UID is mapped into the container so that
	// write grants on the operator's directories work; instances of this
	// server then share one mapping).
	UserNS string `toml:"userns" json:"userns"`
	// AllowSpawn declares that the server may create processes besides its
	// first one. When false, each new process is a deviation (FR-5.34).
	AllowSpawn bool `toml:"allow_spawn" json:"allow_spawn"`
	// OnDeviation is the containment action for a deviation: "alert"
	// (default) or "kill-instance" (FR-5.35). Resource-limit breaches always
	// kill the instance.
	OnDeviation string         `toml:"on_deviation" json:"on_deviation"`
	Mounts      []RuntimeMount `toml:"mount" json:"mount"`
}

// RuntimeMount grants one host path to a server's instances. An empty
// Target mounts the path at its host location. Mounts are read-only unless
// Write is true. A relative Source is resolved against the directory of the
// configuration file.
type RuntimeMount struct {
	Source string `toml:"source" json:"source"`
	Target string `toml:"target" json:"target"`
	Write  bool   `toml:"write" json:"write"`
}

// Runtime defaults (CP-24 and the sandbox profile).
const (
	DefaultRuntimeMemoryBytes = 512 << 20
	DefaultRuntimeCPUs        = 1.0
	DefaultRuntimePids        = 128
	DefaultRuntimeTmpfsBytes  = 64 << 20
	DefaultRuntimeNoFile      = 1024
	DefaultRuntimeUserNSSize  = 2048
	DefaultRuntimeUser        = "1000:1000"
	DefaultMonitorInterval    = 500 * time.Millisecond
)

// FindServer returns the sandbox settings for alias, or the zero value.
func (r *Runtime) FindServer(alias string) RuntimeServer {
	for _, s := range r.Servers {
		if s.Alias == alias {
			return s
		}
	}
	return RuntimeServer{Alias: alias}
}

// DefaultRuntime returns the [runtime] defaults of the Enforced profile
// (the podman sandbox and the CP-24 budget), for tools that run a sandbox
// without a configuration file.
func DefaultRuntime() Runtime {
	var r Runtime
	r.applyDefaults("enforced")
	return r
}

func (r *Runtime) applyDefaults(profileMode string) {
	if r.Sandbox == "" {
		r.Sandbox = "none"
		if profileMode == "enforced" {
			r.Sandbox = "podman"
		}
	}
	if r.MemoryBytes == 0 {
		r.MemoryBytes = DefaultRuntimeMemoryBytes
	}
	if r.CPUs == 0 {
		r.CPUs = DefaultRuntimeCPUs
	}
	if r.Pids == 0 {
		r.Pids = DefaultRuntimePids
	}
	if r.TmpfsBytes == 0 {
		r.TmpfsBytes = DefaultRuntimeTmpfsBytes
	}
	if r.NoFile == 0 {
		r.NoFile = DefaultRuntimeNoFile
	}
	if r.UserNSSize == 0 {
		r.UserNSSize = DefaultRuntimeUserNSSize
	}
	if r.User == "" {
		r.User = DefaultRuntimeUser
	}
	if r.MonitorInterval.Duration == 0 {
		r.MonitorInterval.Duration = DefaultMonitorInterval
	}
	for i := range r.Servers {
		s := &r.Servers[i]
		if s.Network == "" {
			s.Network = "none"
		}
		if s.Scope == "" {
			s.Scope = "shared"
		}
		if s.UserNS == "" {
			s.UserNS = "auto"
		}
		if s.OnDeviation == "" {
			s.OnDeviation = "alert"
		}
	}
}

func (r *Runtime) check(c *Config) error {
	if r.Sandbox == "podman" && c.Profile.Mode == "standalone" {
		return fmt.Errorf(`runtime.sandbox = "podman" contradicts profile.mode = "standalone"`)
	}
	if r.Podman != "" && !filepath.IsAbs(r.Podman) {
		return fmt.Errorf("runtime.podman must be an absolute path")
	}
	if r.Image != "" && !strings.Contains(r.Image, "@sha256:") {
		return fmt.Errorf("runtime.image must be referenced by digest (name@sha256:...) (SR-3.6-1)")
	}
	if err := r.checkRunAs(c); err != nil {
		return err
	}
	if r.MonitorInterval.Duration < 50*time.Millisecond || r.MonitorInterval.Duration > 10*time.Second {
		return fmt.Errorf("runtime.monitor_interval must be between 50ms and 10s")
	}
	aliases := map[string]bool{}
	for _, s := range c.Servers {
		aliases[s.Alias] = true
	}
	seen := map[string]bool{}
	for _, s := range r.Servers {
		if seen[s.Alias] {
			return fmt.Errorf("duplicate runtime.server alias %q", s.Alias)
		}
		seen[s.Alias] = true
		if !aliases[s.Alias] {
			return fmt.Errorf("runtime.server %q names no configured [[server]]", s.Alias)
		}
		if s.Image != "" && !strings.Contains(s.Image, "@sha256:") {
			return fmt.Errorf("runtime.server %q: image must be referenced by digest (SR-3.6-1)", s.Alias)
		}
		if s.Scope != "shared" {
			return fmt.Errorf("runtime.server %q: scope %q is not supported yet; only \"shared\" instances are implemented", s.Alias, s.Scope)
		}
		targets := map[string]bool{}
		for _, m := range s.Mounts {
			if m.Source == "" {
				return fmt.Errorf("runtime.server %q: mount source is empty", s.Alias)
			}
			if m.Target == "" {
				continue // mounted at the (resolved) source path
			}
			if !filepath.IsAbs(m.Target) || filepath.Clean(m.Target) != m.Target {
				return fmt.Errorf("runtime.server %q: mount target %q must be a clean absolute path", s.Alias, m.Target)
			}
			if targets[m.Target] {
				return fmt.Errorf("runtime.server %q: duplicate mount target %q", s.Alias, m.Target)
			}
			targets[m.Target] = true
		}
	}
	return nil
}

var runAsName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (r *Runtime) checkRunAs(c *Config) error {
	if r.RunAs == "" {
		if r.Sudo != "" || r.SharedDir != "" {
			return fmt.Errorf("runtime.sudo and runtime.shared_dir apply only with runtime.run_as")
		}
		return nil
	}
	if r.Sandbox != "podman" {
		return fmt.Errorf(`runtime.run_as needs runtime.sandbox = "podman"`)
	}
	if !runAsName.MatchString(r.RunAs) {
		return fmt.Errorf("runtime.run_as %q is not a valid user name", r.RunAs)
	}
	if r.CgroupManager == "cgroupfs" {
		return fmt.Errorf(`runtime.run_as runs Podman under the server identity's systemd user manager: set cgroup_manager = "systemd" or leave it unset`)
	}
	if r.Sudo != "" && !filepath.IsAbs(r.Sudo) {
		return fmt.Errorf("runtime.sudo must be an absolute path")
	}
	if r.SharedDir == "" {
		return fmt.Errorf("runtime.run_as needs runtime.shared_dir, a directory that %s can read (for example /var/lib/smcp/srv)", r.RunAs)
	}
	if filepath.Clean(r.SharedDir) != r.SharedDir || strings.ContainsAny(r.SharedDir, ",=\n") {
		return fmt.Errorf("runtime.shared_dir must be a clean absolute path without commas, equals signs or newlines")
	}
	if st := c.State.Dir; st != "" {
		if rel, err := filepath.Rel(st, r.SharedDir); err == nil && (rel == "." || !strings.HasPrefix(rel, "..")) {
			return fmt.Errorf("runtime.shared_dir must not be inside the state directory, which only the Gateway identity can traverse")
		}
	}
	return nil
}

func (r *Runtime) resolvePaths(dir string) {
	if r.SharedDir != "" && !filepath.IsAbs(r.SharedDir) {
		r.SharedDir = filepath.Join(dir, r.SharedDir)
	}
	for i := range r.Servers {
		for j := range r.Servers[i].Mounts {
			m := &r.Servers[i].Mounts[j]
			if m.Source != "" && !filepath.IsAbs(m.Source) {
				m.Source = filepath.Join(dir, m.Source)
			}
		}
	}
}
