package packaging

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Interpreters are the absolute paths of the runtimes that run node and
// python artifacts and OCI images. Empty values are looked up on PATH once,
// when the launch specification is built, and made absolute: the command
// the Gateway executes is never resolved again at launch (SR-3.6-1).
type Interpreters struct {
	Node   string
	Python string
	Podman string
}

func lookAbs(configured, name string) (string, error) {
	if configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("%s path %q must be absolute", name, configured)
		}
		return configured, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found on PATH; set it in [packages]", name)
	}
	return filepath.Abs(p)
}

// LaunchInput is what ResolveLaunch needs to turn a manifest's launch
// vector into a concrete launch specification.
type LaunchInput struct {
	Manifest *Manifest
	Alias    string
	Root     string            // unpacked artifact tree (native, node, python)
	Archive  string            // OCI image layout tar (oci)
	Slots    map[string]string // filesystem slot -> absolute host path
	Env      map[string]string // operator-supplied values; names must be in env_allowlist
	WorkDir  string            // working directory of the instance
	Interp   Interpreters
}

// DefaultPath is the PATH of a packaged server instance and of the probe
// unless the manifest's env_fixed sets one.
const DefaultPath = "/usr/bin:/bin"

// SlotMountPrefix is where an OCI instance sees its filesystem slots.
const SlotMountPrefix = "/slots/"

// ResolveLaunch builds the launch specification of a packaged server. The
// environment holds only env_fixed, allowlisted operator values and the
// variables the runtime needs (SR-2.14-1).
func ResolveLaunch(in LaunchInput) (pipeline.ServerSpec, error) {
	m := in.Manifest
	spec := pipeline.ServerSpec{Alias: in.Alias, Dir: in.WorkDir, Env: map[string]string{}}
	if err := CheckArgv(m.Launch.Runtime, m.Launch.Argv); err != nil {
		return spec, err
	}
	for k, v := range in.Env {
		if !slices.Contains(m.Launch.EnvAllowlist, k) {
			return spec, fmt.Errorf("environment variable %s is not in the manifest env_allowlist %v", k, m.Launch.EnvAllowlist)
		}
		spec.Env[k] = v
	}
	declared := map[string]FilesystemSlot{}
	for _, s := range m.Capabilities.Filesystem {
		declared[s.Slot] = s
	}
	for slot, p := range in.Slots {
		if _, ok := declared[slot]; !ok {
			return spec, fmt.Errorf("slot %q is not declared by the manifest", slot)
		}
		if !filepath.IsAbs(p) {
			return spec, fmt.Errorf("slot %q path %q must be absolute", slot, p)
		}
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			return spec, fmt.Errorf("slot %q path %q is not a directory", slot, p)
		}
	}
	oci := m.Launch.Runtime == "oci"
	spec.Runtime = m.Launch.Runtime
	if !oci {
		spec.ArtifactRoot = in.Root
	}
	spec.Roots = []pipeline.Root{}
	for _, fs := range m.Capabilities.Filesystem {
		if p, ok := in.Slots[fs.Slot]; ok {
			spec.Roots = append(spec.Roots, pipeline.Root{Slot: fs.Slot, Path: filepath.Clean(p), Write: fs.Mode == "rw"})
		}
	}
	subst := func(s string) (string, error) {
		var err error
		out := placeholderRE.ReplaceAllStringFunc(s, func(ph string) string {
			for _, fs := range m.Capabilities.Filesystem {
				if fs.ArgvPlaceholder != ph {
					continue
				}
				host, ok := in.Slots[fs.Slot]
				if !ok {
					err = fmt.Errorf("filesystem slot %q (%s) is not bound; set it in the server's slots", fs.Slot, ph)
					return ph
				}
				if oci {
					return SlotMountPrefix + fs.Slot
				}
				return host
			}
			err = fmt.Errorf("unknown placeholder %s", ph)
			return ph
		})
		return out, err
	}
	keys := make([]string, 0, len(m.Launch.EnvFixed))
	for k := range m.Launch.EnvFixed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, err := subst(m.Launch.EnvFixed[k])
		if err != nil {
			return spec, err
		}
		spec.Env[k] = v
	}
	// A packaged server does not inherit the Gateway's PATH or HOME: PATH
	// is the system directories unless env_fixed sets it, and HOME is the
	// instance working directory (SR-2.14-1). Without this, a server that
	// looks for optional helpers on PATH behaves differently at run time
	// than in the probe.
	if _, ok := spec.Env["PATH"]; !ok {
		spec.Env["PATH"] = DefaultPath
	}
	if _, ok := spec.Env["HOME"]; !ok && in.WorkDir != "" {
		spec.Env["HOME"] = in.WorkDir
	}
	args := make([]string, 0, len(m.Launch.Argv))
	for i, a := range m.Launch.Argv {
		v, err := subst(a)
		if err != nil {
			return spec, err
		}
		// A relative path argument that exists in the artifact tree is made
		// absolute, so the working directory can be a scratch directory.
		if i > 0 && !oci && in.Root != "" && v == a && !strings.HasPrefix(v, "-") && !filepath.IsAbs(v) && validRel(v) {
			if _, err := os.Stat(filepath.Join(in.Root, filepath.FromSlash(v))); err == nil {
				v = filepath.Join(in.Root, filepath.FromSlash(v))
			}
		}
		args = append(args, v)
	}
	var err error
	switch m.Launch.Runtime {
	case "native":
		spec.Command = filepath.Join(in.Root, filepath.FromSlash(m.Launch.Argv[0]))
		spec.Args = args[1:]
	case "node":
		if spec.Command, err = lookAbs(in.Interp.Node, "node"); err != nil {
			return spec, err
		}
		spec.Args = args[1:]
	case "python":
		if spec.Command, err = lookAbs(in.Interp.Python, "python3"); err != nil {
			return spec, err
		}
		spec.Args = args[1:]
		spec.Env["PYTHONPATH"] = filepath.Join(in.Root, "site")
		spec.Env["PYTHONDONTWRITEBYTECODE"] = "1" // keep the verified tree unchanged
		spec.Env["PYTHONNOUSERSITE"] = "1"
	case "oci":
		if spec.Command, err = lookAbs(in.Interp.Podman, "podman"); err != nil {
			return spec, err
		}
		run := []string{"run", "--rm", "-i", "--pull=never", "--network=none", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges"}
		slots := make([]string, 0, len(in.Slots))
		for s := range in.Slots {
			slots = append(slots, s)
		}
		sort.Strings(slots)
		for _, s := range slots {
			run = append(run, "-v", in.Slots[s]+":"+SlotMountPrefix+s+":"+declared[s].Mode)
		}
		for _, k := range keys {
			run = append(run, "-e", k+"="+spec.Env[k])
		}
		// podman itself needs the operator's HOME (container storage) and
		// runtime directory, not the instance environment.
		spec.Env = map[string]string{}
		if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
			spec.Env["XDG_RUNTIME_DIR"] = v
		}
		run = append(run, "oci-archive:"+in.Archive)
		spec.Args = append(run, args...)
	default:
		return spec, fmt.Errorf("unknown runtime %q", m.Launch.Runtime)
	}
	return spec, nil
}

func validRel(p string) bool {
	return !strings.Contains(p, "..") && !strings.HasPrefix(p, "/")
}
