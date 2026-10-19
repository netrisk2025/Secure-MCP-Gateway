package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// delegatedControllers are the cgroup v2 controllers the sandbox limits
// need (CP-24): memory, PIDs and CPU.
var delegatedControllers = []string{"cpu", "memory", "pids"}

// EnableDelegatedControllers prepares a cgroup subtree that systemd has
// delegated to smcpd (smcpd.service: Delegate=yes, DelegateSubgroup=
// supervisor). systemd places smcpd in the leaf "supervisor" and leaves the
// service cgroup's subtree_control empty, so containers that rootless
// Podman creates next to the leaf (cgroup manager cgroupfs) would have no
// memory, pids or cpu controller and no limits. When smcpd's own cgroup
// lacks one of them, its parent offers it and the parent belongs to the
// Gateway user (delegated), the controllers are enabled in the parent's
// cgroup.subtree_control. self is the content of /proc/self/cgroup and root
// the cgroup v2 mount. It returns the controllers it enabled; it changes
// nothing in a cgroup the Gateway user does not own.
func EnableDelegatedControllers(root, self string) ([]string, error) {
	var rel string
	for _, line := range strings.Split(self, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			rel = p
		}
	}
	if rel == "" || rel == "/" || !strings.HasPrefix(rel, "/") {
		return nil, nil
	}
	own := filepath.Join(root, filepath.Clean(rel))
	parent := filepath.Dir(own)
	if !within(root, parent) {
		return nil, nil
	}
	have := fields(filepath.Join(own, "cgroup.controllers"))
	offered := fields(filepath.Join(parent, "cgroup.controllers"))
	var want []string
	for _, c := range delegatedControllers {
		if !slices.Contains(have, c) && slices.Contains(offered, c) {
			want = append(want, c)
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	st, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	if !ownedBySelf(st) {
		return nil, nil
	}
	var b strings.Builder
	for i, c := range want {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("+" + c)
	}
	f, err := os.OpenFile(filepath.Join(parent, "cgroup.subtree_control"), os.O_WRONLY, 0) // #nosec G304 -- cgroupfs control file of the delegated subtree
	if err != nil {
		return nil, err
	}
	_, werr := f.WriteString(b.String())
	if err := errors.Join(werr, f.Close()); err != nil {
		return nil, err
	}
	return want, nil
}

func fields(path string) []string {
	b, err := os.ReadFile(path) // #nosec G304 -- cgroupfs file
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

func ownedBySelf(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
