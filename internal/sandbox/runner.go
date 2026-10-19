package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
)

// DefaultSudo is the sudo binary used with runtime.run_as when
// runtime.sudo is not set.
const DefaultSudo = "/usr/bin/sudo"

// runner builds Podman commands. Without RunAs it runs Podman directly as
// the Gateway's identity. With RunAs (CP-46 smcp-srv) it runs
//
//	sudo -n -E -u <run_as> -- <podman> <args>
//
// so that containers belong to the server identity's rootless Podman and
// its subordinate ID range. The environment is built here, not inherited:
// HOME, USER, LOGNAME, XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS are
// those of the run_as user (its systemd user manager, started by
// lingering, owns /run/user/<uid>), and -E passes them together with the
// instance values that Podman reads by name (--env=NAME). The sudoers rule
// installed by packaging/linux/install-enforced.sh allows smcp-core to run
// only Podman as smcp-srv, with SETENV for -E.
type runner struct {
	podman string
	runAs  *runAsUser
	extra  map[string]string // Options.PodmanEnv
}

// runAsUser is the resolved runtime.run_as identity.
type runAsUser struct {
	Name string
	UID  int
	GID  int
	Home string
	Sudo string
}

// lookupRunAs resolves name with lookup (default user.Lookup).
func lookupRunAs(name, sudo string, lookup func(string) (*user.User, error)) (*runAsUser, error) {
	if lookup == nil {
		lookup = user.Lookup
	}
	u, err := lookup(name)
	if err != nil {
		return nil, fmt.Errorf("runtime.run_as %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("runtime.run_as %q: UID %q is not numeric", name, u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("runtime.run_as %q: GID %q is not numeric", name, u.Gid)
	}
	if uid == 0 {
		return nil, fmt.Errorf("runtime.run_as %q is root; rootless Podman needs an unprivileged identity", name)
	}
	if sudo == "" {
		sudo = DefaultSudo
	}
	return &runAsUser{Name: name, UID: uid, GID: gid, Home: u.HomeDir, Sudo: sudo}, nil
}

// runtimeDir is XDG_RUNTIME_DIR of the run_as user.
func (u *runAsUser) runtimeDir() string { return "/run/user/" + strconv.Itoa(u.UID) }

// argv returns the program and arguments that run Podman with args.
func (r runner) argv(args []string) (string, []string) {
	if r.runAs == nil {
		return r.podman, args
	}
	a := make([]string, 0, len(args)+7)
	a = append(a, "-n", "-E", "-u", r.runAs.Name, "--", r.podman)
	return r.runAs.Sudo, append(a, args...)
}

// env is the Podman process environment: the passEnv variables of the
// Gateway, Options.PodmanEnv, the run_as identity's variables and then
// the instance values.
func (r runner) env(instance map[string]string) []string {
	env := map[string]string{}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	if u := r.runAs; u != nil {
		// The Gateway's own per-user locations must not reach the other
		// identity's Podman.
		for _, k := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMPDIR"} {
			delete(env, k)
		}
		env["HOME"], env["USER"], env["LOGNAME"] = u.Home, u.Name, u.Name
		env["XDG_RUNTIME_DIR"] = u.runtimeDir()
		env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + u.runtimeDir() + "/bus"
	}
	for k, v := range r.extra {
		env[k] = v
	}
	for k, v := range instance {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// command builds a Podman command bound to ctx.
func (r runner) command(ctx context.Context, instance map[string]string, args ...string) *exec.Cmd {
	name, argv := r.argv(args)
	return r.prepare(exec.CommandContext(ctx, name, argv...), instance) // #nosec G204 -- fixed binary, argument vector, no shell (SR-4.8-1)
}

// instanceCommand builds the Podman command that carries an instance's
// stdio; it lives as long as the instance, not a context.
func (r runner) instanceCommand(instance map[string]string, args ...string) *exec.Cmd {
	name, argv := r.argv(args)
	return r.prepare(exec.Command(name, argv...), instance) // #nosec G204 -- as above
}

func (r runner) prepare(cmd *exec.Cmd, instance map[string]string) *exec.Cmd {
	cmd.Env = r.env(instance)
	if r.runAs != nil {
		// The Gateway's working directory may be closed to run_as.
		cmd.Dir = "/"
	}
	return cmd
}
