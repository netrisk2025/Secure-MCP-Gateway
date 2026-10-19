// Package sandbox is the enforced-profile server runtime: the Server
// Runtime Manager (E-15) launches each backend MCP server as a rootless
// Podman container under the Execution Sandbox (E-16) profile, and the
// Runtime Monitor (E-17) watches each instance's cgroup and the Podman
// event stream, records runtime evidence and kills an instance that breaches
// a limit or matches a kill-instance containment rule.
//
// The sandbox profile of every instance (SR-4.7-1, SR-4.7-2, SR-4.5-1,
// SR-4.6-1, SR-4.1-2):
//
//   - read-only root filesystem: a digest-pinned image, or a Gateway-built
//     empty root directory with the server executable bind-mounted read-only
//   - all capabilities dropped, no-new-privileges, Podman's default seccomp
//     profile, the configured AppArmor profile or SELinux type when set
//   - a user namespace with a distinct UID range per instance (userns=auto)
//   - network "none" unless the Egress Broker attaches one
//   - private PID, IPC and UTS namespaces; no devices; no host sockets
//   - cgroup v2 memory (swap disabled), CPU and PID limits, CP-24 by default
//   - a size-bounded tmpfs working directory and /tmp
//   - bind mounts only for the operator-granted roots, read-only unless
//     write is granted
//
// Launch input never passes through a shell (SR-4.8-1): Podman is started
// with an argument vector and environment values are passed through the
// Podman process environment by name, never on its command line.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// NetworkNone is the container network of an instance without egress: a
// loopback interface only (SR-4.5-1).
const NetworkNone = "none"

// Label keys set on every container the Gateway creates.
const (
	LabelManaged  = "smcp.managed"
	LabelGateway  = "smcp.gateway"
	LabelAlias    = "smcp.alias"
	LabelInstance = "smcp.instance"
)

// Paths inside the container.
const (
	ServerBinDir = "/smcp/bin"
	WorkDir      = "/work"
	// SecretDir is where the instance's secret files (S2, S3) appear,
	// read-only (pipeline.ServerSpec.SecretDir).
	SecretDir = "/smcp/secrets"
)

// SecretPaths returns spec with every environment value that names a path
// in spec.SecretDir rewritten to the same path under SecretDir, where Build
// mounts that directory.
func SecretPaths(spec pipeline.ServerSpec) pipeline.ServerSpec {
	if spec.SecretDir == "" {
		return spec
	}
	dir := filepath.Clean(spec.SecretDir)
	env := make(map[string]string, len(spec.Env))
	for k, v := range spec.Env {
		switch {
		case v == dir:
			v = SecretDir
		case strings.HasPrefix(v, dir+"/"):
			v = SecretDir + v[len(dir):]
		}
		env[k] = v
	}
	spec.Env = env
	return spec
}

// Mount is one bind mount of the launch specification.
type Mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Write  bool   `json:"write"`
}

// Limits are the cgroup and rlimit bounds of one instance.
type Limits struct {
	MemoryBytes int64   `json:"memory_bytes"`
	CPUs        float64 `json:"cpus"`
	Pids        int     `json:"pids"`
	TmpfsBytes  int64   `json:"tmpfs_bytes"`
	NoFile      int     `json:"nofile"`
}

// Profile is the sandbox profile (E-16 owned data).
type Profile struct {
	ReadOnlyRoot    bool   `json:"read_only_root"`
	NoNewPrivileges bool   `json:"no_new_privileges"`
	CapDrop         string `json:"cap_drop"`
	Seccomp         string `json:"seccomp"`
	UserNS          string `json:"userns"`
	User            string `json:"user"`
	AppArmor        string `json:"apparmor,omitempty"`
	SELinuxType     string `json:"selinux_type,omitempty"`
	CgroupManager   string `json:"cgroup_manager,omitempty"`
	AllowSpawn      bool   `json:"allow_spawn"`
	OnDeviation     string `json:"on_deviation"`
}

// Artifact identifies what the instance runs. Digest is the SHA-256 of the
// executable file when it is bind-mounted, or the image digest.
type Artifact struct {
	Command string `json:"command"`
	Digest  string `json:"digest"`
	Image   string `json:"image,omitempty"`
	Rootfs  string `json:"rootfs,omitempty"`
}

// LaunchSpec is the complete launch specification of one instance
// (FR-5.9): artifact digest, argument vector, environment allowlist (names
// only), mounts, network attachment, resource limits and sandbox profile.
type LaunchSpec struct {
	Alias      string   `json:"alias"`
	InstanceID string   `json:"instance_id"`
	Name       string   `json:"name"`
	Gateway    string   `json:"gateway"`
	Artifact   Artifact `json:"artifact"`
	Argv       []string `json:"argv"`
	EnvNames   []string `json:"env_names"`
	// EgressEnv holds the Egress Broker's variables (proxy and endpoint
	// URLs). They are addresses, not secrets, and are passed on the Podman
	// command line: proxy variables in the Podman process environment
	// would configure Podman itself.
	EgressEnv map[string]string `json:"egress_env,omitempty"`
	Mounts    []Mount           `json:"mounts"`
	Network   string            `json:"network"`
	Workdir   string            `json:"workdir"`
	Limits    Limits            `json:"limits"`
	Profile   Profile           `json:"profile"`
	Scope     string            `json:"scope"`
}

// Errors returned while building a launch specification.
var (
	ErrMountRefused = errors.New("mount refused")
	ErrNoArtifact   = errors.New("server artifact unavailable")
)

// deniedSources are host paths never mounted into an instance: host
// management sockets, kernel interfaces and system configuration (SR-4.7-1).
var deniedSources = []string{
	"/", "/proc", "/sys", "/dev", "/boot", "/etc", "/root", "/run", "/var/run",
	"/var/lib/containers", "/var/lib/docker", "/var/lib/smcp", "/etc/smcp", "/run/smcp",
}

var deniedSocketNames = []string{"docker.sock", "podman.sock", "containerd.sock", "crio.sock", "dbus", "systemd"}

// CheckMountSource refuses mount sources that are not absolute existing
// paths, that are or contain a denied location, or that lie inside the
// Gateway's own state directory.
func CheckMountSource(src, stateDir string) error {
	if !filepath.IsAbs(src) || filepath.Clean(src) != src {
		return fmt.Errorf("%w: source %q must be a clean absolute path", ErrMountRefused, src)
	}
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		return fmt.Errorf("%w: source %q: %w", ErrMountRefused, src, err)
	}
	if strings.ContainsAny(src, ",=\n") {
		return fmt.Errorf("%w: source %q contains a comma, equals sign or newline", ErrMountRefused, src)
	}
	for _, p := range []string{src, real} {
		for _, d := range deniedSources {
			if p == d || (d != "/" && within(d, p)) {
				return fmt.Errorf("%w: %q is a protected host location", ErrMountRefused, p)
			}
		}
		for _, n := range deniedSocketNames {
			if strings.Contains(filepath.Base(p), n) {
				return fmt.Errorf("%w: %q looks like a host management socket", ErrMountRefused, p)
			}
		}
		if stateDir != "" {
			sd := filepath.Clean(stateDir)
			if rs, err := filepath.EvalSymlinks(sd); err == nil {
				sd = rs
			}
			if p == sd || within(sd, p) || within(p, sd) {
				return fmt.Errorf("%w: %q overlaps the Gateway state directory", ErrMountRefused, p)
			}
		}
	}
	st, err := os.Stat(real)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMountRefused, err)
	}
	if st.Mode()&os.ModeSocket != 0 {
		return fmt.Errorf("%w: %q is a socket", ErrMountRefused, src)
	}
	return nil
}

// reservedTargets are container paths that the sandbox itself mounts
// (tmpfs, kernel filesystems, the server executable). A bind mount at or
// below them is refused: below a tmpfs the runtime would have to create the
// mount point as the instance user, which a user namespace does not allow.
var reservedTargets = []string{"/", WorkDir, "/tmp", "/var/tmp", ServerBinDir, "/smcp", "/proc", "/sys", "/dev", "/run", "/etc"}

func checkTarget(target string) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return fmt.Errorf("%w: target %q must be a clean absolute path", ErrMountRefused, target)
	}
	for _, r := range reservedTargets {
		if target == r || (r != "/" && within(r, target)) {
			return fmt.Errorf("%w: target %q is at or below %s, which the sandbox reserves; set target to another path such as /data", ErrMountRefused, target, r)
		}
	}
	return nil
}

// within reports whether p is strictly inside dir.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../")
}

// FileDigest returns "sha256:<hex>" of the file at path.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- the configured server artifact
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// imageDigest returns the digest part of name@sha256:hex.
func imageDigest(image string) string {
	if i := strings.LastIndex(image, "@"); i >= 0 {
		return image[i+1:]
	}
	return ""
}

// BuildInput is what Build needs besides the server specification.
type BuildInput struct {
	Runtime config.Runtime
	Server  config.RuntimeServer
	Spec    pipeline.ServerSpec
	// Network is the container network: NetworkNone unless the
	// instance is attached to the Egress Broker.
	Network string
	// EgressEnv holds the Egress Broker's variables for the instance.
	EgressEnv  map[string]string
	InstanceID string
	Gateway    string
	Rootfs     string // Gateway-built root directory, used when no image is set
	StateDir   string
}

// Build derives the launch specification of one instance.
func Build(in BuildInput) (LaunchSpec, error) {
	if err := pipeline.CheckLaunchSpec(in.Spec); err != nil {
		return LaunchSpec{}, err
	}
	rt, srv := in.Runtime, in.Server
	ls := LaunchSpec{
		Alias:      in.Spec.Alias,
		InstanceID: in.InstanceID,
		Name:       "smcp-" + in.Spec.Alias + "-" + shortID(in.InstanceID),
		Gateway:    in.Gateway,
		Network:    in.Network,
		Workdir:    WorkDir,
		Scope:      srv.Scope,
		Limits: Limits{
			MemoryBytes: pick64(srv.MemoryBytes, rt.MemoryBytes),
			CPUs:        pickF(srv.CPUs, rt.CPUs),
			Pids:        pickI(srv.Pids, rt.Pids),
			TmpfsBytes:  rt.TmpfsBytes,
			NoFile:      rt.NoFile,
		},
		Profile: Profile{
			ReadOnlyRoot: true, NoNewPrivileges: true, CapDrop: "ALL", Seccomp: "default",
			User: rt.User, AppArmor: rt.AppArmorProfile, SELinuxType: rt.SELinuxType, CgroupManager: rt.CgroupManager,
			AllowSpawn: srv.AllowSpawn || (in.Spec.SpawnsProcesses != nil && *in.Spec.SpawnsProcesses), OnDeviation: srv.OnDeviation,
		},
	}
	if ls.Scope == "" {
		ls.Scope = "shared"
	}
	if ls.Profile.OnDeviation == "" {
		ls.Profile.OnDeviation = "alert"
	}
	if ls.Network == "" {
		ls.Network = NetworkNone
	}
	if srv.Network != "egress" && ls.Network != NetworkNone {
		return LaunchSpec{}, fmt.Errorf("egress broker attached network %q but runtime.server %q does not request egress", ls.Network, srv.Alias)
	}
	switch srv.UserNS {
	case "keep-id":
		ls.Profile.UserNS = "keep-id"
		ls.Profile.User = ""
	default:
		ls.Profile.UserNS = "auto:size=" + strconv.Itoa(rt.UserNSSize)
	}

	image := srv.Image
	if image == "" {
		image = rt.Image
	}
	interpreted := in.Spec.Runtime == "node" || in.Spec.Runtime == "python"
	if image != "" {
		// A packaged node or python server runs on the interpreter of its
		// image (found on the image's PATH), not on the host interpreter
		// its launch specification names.
		argv0 := in.Spec.Command
		switch in.Spec.Runtime {
		case "node":
			argv0 = "node"
		case "python":
			argv0 = "python3"
		}
		ls.Artifact = Artifact{Command: in.Spec.Command, Image: image, Digest: imageDigest(image)}
		ls.Argv = append([]string{argv0}, in.Spec.Args...)
	} else if interpreted {
		return LaunchSpec{}, fmt.Errorf("%w: server %q is a %s package; in the sandbox it needs an image with that interpreter: set image in its runtime.server entry", ErrNoArtifact, in.Spec.Alias, in.Spec.Runtime)
	} else {
		st, err := os.Stat(in.Spec.Command)
		if err != nil || !st.Mode().IsRegular() {
			return LaunchSpec{}, fmt.Errorf("%w: %s is not a regular file", ErrNoArtifact, in.Spec.Command)
		}
		d, err := FileDigest(in.Spec.Command)
		if err != nil {
			return LaunchSpec{}, fmt.Errorf("%w: %w", ErrNoArtifact, err)
		}
		if in.Rootfs == "" {
			return LaunchSpec{}, errors.New("no image configured and no root directory prepared")
		}
		target := ServerBinDir + "/" + filepath.Base(in.Spec.Command)
		ls.Artifact = Artifact{Command: in.Spec.Command, Digest: d, Rootfs: in.Rootfs}
		ls.Mounts = append(ls.Mounts, Mount{Source: in.Spec.Command, Target: target})
		ls.Argv = append([]string{target}, in.Spec.Args...)
	}

	if d := in.Spec.SecretDir; d != "" {
		// The broker's per-instance directory: created by the Gateway for
		// this instance only, so the state-directory overlap rule of
		// CheckMountSource does not apply to it.
		if !filepath.IsAbs(d) || filepath.Clean(d) != d || strings.ContainsAny(d, ",=\n") {
			return LaunchSpec{}, fmt.Errorf("%w: secret directory %q must be a clean absolute path without commas, equals signs or newlines", ErrMountRefused, d)
		}
		// The files are mode 0600 and owned by the Gateway user. Under
		// any other UID the launcher grants the instance's host UID read
		// access before the server starts (secretacl.go).
		ls.Mounts = append(ls.Mounts, Mount{Source: d, Target: SecretDir})
	}

	if interpreted && in.Spec.ArtifactRoot != "" {
		// The verified artifact tree of a node or python package: its
		// arguments name files in it. Created by the Gateway's package
		// library under the state directory, so the state-directory overlap
		// rule of CheckMountSource does not apply to it.
		r := in.Spec.ArtifactRoot
		if !filepath.IsAbs(r) || filepath.Clean(r) != r || strings.ContainsAny(r, ",=\n") {
			return LaunchSpec{}, fmt.Errorf("%w: artifact tree %q must be a clean absolute path without commas, equals signs or newlines", ErrMountRefused, r)
		}
		if err := checkTarget(r); err != nil {
			return LaunchSpec{}, err
		}
		ls.Mounts = append(ls.Mounts, Mount{Source: r, Target: r})
	}

	grants := srv.Mounts
	if in.Spec.Roots != nil {
		var err error
		if grants, err = IntersectRoots(srv.Alias, srv.Mounts, in.Spec.Roots); err != nil {
			return LaunchSpec{}, err
		}
	}
	for _, m := range grants {
		target := m.Target
		if target == "" {
			target = m.Source
		}
		if err := CheckMountSource(m.Source, in.StateDir); err != nil {
			return LaunchSpec{}, err
		}
		if strings.ContainsAny(target, ",=\n") {
			return LaunchSpec{}, fmt.Errorf("%w: target %q contains a comma, equals sign or newline", ErrMountRefused, target)
		}
		if err := checkTarget(target); err != nil {
			return LaunchSpec{}, err
		}
		ls.Mounts = append(ls.Mounts, Mount{Source: m.Source, Target: target, Write: m.Write})
		if in.Spec.Dir != "" && filepath.Clean(in.Spec.Dir) == target {
			ls.Workdir = target
		}
	}

	env := make(map[string]string, len(in.Spec.Env)+len(in.EgressEnv))
	for k, v := range in.Spec.Env {
		env[k] = v
	}
	// Host PATH and HOME make no sense inside the container.
	delete(env, "PATH")
	delete(env, "HOME")
	for k := range env {
		if ReservedEnv(k) {
			return LaunchSpec{}, fmt.Errorf("environment variable %s is reserved: it would configure Podman itself", k)
		}
	}
	for k, v := range in.EgressEnv {
		if ReservedEnv(k) && !slices.Contains(egressProxyVars, k) {
			return LaunchSpec{}, fmt.Errorf("egress endpoint variable %s is reserved", k)
		}
		if _, dup := env[k]; dup {
			return LaunchSpec{}, fmt.Errorf("egress endpoint variable %s collides with a configured variable", k)
		}
		if k == "" || strings.ContainsAny(k, "=\n\x00") || strings.ContainsAny(v, "\n\x00") {
			return LaunchSpec{}, fmt.Errorf("egress endpoint variable %q has an invalid name or value", k)
		}
		if ls.EgressEnv == nil {
			ls.EgressEnv = map[string]string{}
		}
		ls.EgressEnv[k] = v
	}
	for k := range env {
		ls.EnvNames = append(ls.EnvNames, k)
	}
	slices.Sort(ls.EnvNames)
	return ls, nil
}

// IntersectRoots restricts a server's Runtime Profile mount grants to the
// filesystem slots its verified manifest declares (SR-4.6-1): a grant
// within a declared root is mounted as granted; a declared root within a
// grant is mounted alone, at the matching place under the grant's target;
// either way the mount is writable only when the grant asks for write and
// the manifest declares the slot read-write. A grant that meets no
// declared root is refused, so a configuration that would expose more
// than the manifest asks for fails at launch instead of being narrowed
// silently. roots holds the bound slots; nil means the server has no
// manifest (a configured command), and the grants are returned unchanged.
func IntersectRoots(alias string, grants []config.RuntimeMount, roots []pipeline.Root) ([]config.RuntimeMount, error) {
	if roots == nil {
		return grants, nil
	}
	within := func(p, root string) bool {
		return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
	}
	var out []config.RuntimeMount
	seen := map[string]bool{}
	add := func(m config.RuntimeMount) {
		key := m.Source + "\x00" + m.Target
		if !seen[key] {
			seen[key] = true
			out = append(out, m)
		}
	}
	for _, g := range grants {
		src := filepath.Clean(g.Source)
		target := g.Target
		if target == "" {
			target = src
		}
		met := false
		for _, r := range roots {
			root := filepath.Clean(r.Path)
			switch {
			case within(src, root):
				add(config.RuntimeMount{Source: src, Target: target, Write: g.Write && r.Write})
				met = true
			case within(root, src):
				rel, err := filepath.Rel(src, root)
				if err != nil {
					return nil, err
				}
				add(config.RuntimeMount{Source: root, Target: filepath.Join(target, rel), Write: g.Write && r.Write})
				met = true
			}
		}
		if !met {
			names := []string{}
			for _, r := range roots {
				names = append(names, r.Slot+"="+r.Path)
			}
			if len(names) == 0 {
				names = append(names, "none")
			}
			return nil, fmt.Errorf("%w: runtime.server %q grants %q, which is outside every filesystem slot its manifest declares (%s) (SR-4.6-1)",
				ErrMountRefused, alias, g.Source, strings.Join(names, ", "))
		}
	}
	return out, nil
}

// reservedEnvPrefixes are variable names that would change the behavior of
// the Podman process itself, which receives instance values in its own
// environment.
var reservedEnvPrefixes = []string{"CONTAINERS_", "PODMAN_", "BUILDAH_", "XDG_", "DBUS_", "DOCKER_", "LD_", "STORAGE_", "REGISTRY_", "CONTAINER_", "_CONTAINERS_", "NOTIFY_SOCKET", "TMPDIR", "SSL_CERT_", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "GODEBUG", "GOTRACEBACK"}

// egressProxyVars are the reserved names the Egress Broker itself sets for
// an instance; they reach the container on the Podman command line.
var egressProxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"}

// ReservedEnv reports whether name may not be passed to an instance.
func ReservedEnv(name string) bool {
	for _, p := range reservedEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Env returns the values for the spec's environment names from the same
// sources Build used. The values go to the Podman process environment.
func Env(spec pipeline.ServerSpec, egressEnv map[string]string, names []string) map[string]string {
	out := make(map[string]string, len(names))
	for _, n := range names {
		if v, ok := egressEnv[n]; ok {
			out[n] = v
		} else if v, ok := spec.Env[n]; ok {
			out[n] = v
		}
	}
	return out
}

// PodmanArgs is the argument vector for `podman` that creates and attaches
// to the instance. Flags precede the image (or --rootfs directory), which
// precedes the server's own argument vector.
func (s LaunchSpec) PodmanArgs() []string { return s.podmanArgs("run") }

// CreateArgs is the argument vector for `podman create` of the instance,
// used when the network namespace must be confined before the server
// starts (egress instances): the same flags as PodmanArgs.
func (s LaunchSpec) CreateArgs() []string { return s.podmanArgs("create") }

func (s LaunchSpec) podmanArgs(verb string) []string {
	a := []string{verb, "--interactive", "--name", s.Name,
		"--label", LabelManaged + "=1",
		"--label", LabelGateway + "=" + s.Gateway,
		"--label", LabelAlias + "=" + s.Alias,
		"--label", LabelInstance + "=" + s.InstanceID,
		"--pull=never",
		"--log-driver=none",
		"--read-only",
		"--read-only-tmpfs=false",
		"--cap-drop=all",
		"--security-opt=no-new-privileges",
		"--userns=" + s.Profile.UserNS,
		"--network=" + s.Network,
		"--pid=private", "--ipc=private", "--uts=private",
		"--hostname=" + s.Name,
		"--no-hosts",
		"--memory=" + strconv.FormatInt(s.Limits.MemoryBytes, 10),
		"--memory-swap=" + strconv.FormatInt(s.Limits.MemoryBytes, 10),
		"--cpus=" + strconv.FormatFloat(s.Limits.CPUs, 'f', -1, 64),
		"--pids-limit=" + strconv.Itoa(s.Limits.Pids),
		"--ulimit=nofile=" + strconv.Itoa(s.Limits.NoFile) + ":" + strconv.Itoa(s.Limits.NoFile),
		"--ulimit=core=0:0",
		"--tmpfs=" + WorkDir + ":rw,nosuid,nodev,size=" + strconv.FormatInt(s.Limits.TmpfsBytes, 10) + ",mode=1777",
		"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=" + strconv.FormatInt(s.Limits.TmpfsBytes, 10) + ",mode=1777",
		"--workdir=" + s.Workdir,
	}
	if verb == "run" {
		// Podman 4.9 has no --passwd flag on create; the Gateway-built
		// root directory carries the passwd entries itself.
		a = append(a, "--passwd=false")
	}
	if s.Profile.User != "" {
		a = append(a, "--user="+s.Profile.User)
	}
	if s.Profile.AppArmor != "" {
		a = append(a, "--security-opt=apparmor="+s.Profile.AppArmor)
	}
	if s.Profile.SELinuxType != "" {
		a = append(a, "--security-opt=label=type:"+s.Profile.SELinuxType)
	}
	if s.Profile.CgroupManager != "" {
		a = append(a, "--cgroup-manager="+s.Profile.CgroupManager)
	}
	for _, m := range s.Mounts {
		opt := "ro"
		if m.Write {
			opt = "rw"
		}
		a = append(a, "--mount=type=bind,src="+m.Source+",dst="+m.Target+","+opt+",bind-propagation=rprivate")
	}
	for _, n := range s.EnvNames {
		a = append(a, "--env="+n) // value taken from the Podman process environment
	}
	if len(s.EgressEnv) > 0 {
		a = append(a, "--http-proxy=false")
		for _, k := range slices.Sorted(maps.Keys(s.EgressEnv)) {
			a = append(a, "--env="+k+"="+s.EgressEnv[k]) // broker addresses, not secrets
		}
	}
	if s.Artifact.Image != "" {
		a = append(a, s.Artifact.Image)
	} else {
		a = append(a, "--rootfs", s.Artifact.Rootfs)
	}
	return append(a, s.Argv...)
}

func shortID(id string) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > 12 {
		return id[len(id)-12:]
	}
	return id
}

func pick64(a, b int64) int64 {
	if a > 0 {
		return a
	}
	return b
}

func pickF(a, b float64) float64 {
	if a > 0 {
		return a
	}
	return b
}

func pickI(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}
