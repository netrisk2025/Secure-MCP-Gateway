package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ethan03805/secure-mcp-gateway/internal/posixacl"
)

// Secret files for instances under another UID (FR-6.8 S2 and S3 with
// userns = "auto" or runtime.run_as).
//
// The Secret Broker writes each instance's secret files owner-only (0600,
// the Gateway identity) into a per-instance directory, which the sandbox
// mounts read-only at /smcp/secrets. With userns = "auto" the instance
// runs under a subordinate UID chosen by Podman when the container is
// created; with runtime.run_as it runs under the server identity or one of
// its subordinate UIDs. Neither can read a 0600 file of the Gateway. For
// such an instance the launcher creates the container first, reads the
// host UID that the container user maps to, and adds POSIX ACL entries
// for exactly that UID: search on the directory, read on each file. The
// broker copies the directory's entries to every file it writes later
// (per-call S2 files, rotated S3 values). Group and other permissions stay
// empty, and the directory is removed at teardown as before.

// grantTraversal gives uid search permission on dir and on each ancestor
// of dir that the Gateway identity owns, so that Podman running as uid can
// resolve dir as a bind-mount source. It stops at the first ancestor owned
// by someone else (such as /run or /dev/shm).
func (l *Launcher) grantTraversal(dir string, uid int) error {
	self := os.Getuid()
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		st, err := os.Stat(d)
		if err != nil {
			return fmt.Errorf("secret directory %s: %w", d, err)
		}
		if fileUID(st) != self {
			return nil
		}
		if err := l.o.GrantReader(d, uid, posixacl.Execute); err != nil {
			return fmt.Errorf("grant UID %d search permission on %s: %w", uid, d, err)
		}
		if d == filepath.Dir(d) {
			return nil
		}
	}
}

// fileUID is the owner of a stat result, or -1.
func fileUID(st os.FileInfo) int {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1
}

// grantSecretFiles adds the created instance's host UID to the secret
// directory (search) and to each file in it (read).
func (l *Launcher) grantSecretFiles(ctx context.Context, ls LaunchSpec, dir string) error {
	uid, err := l.instanceUID(ctx, ls)
	if err != nil {
		return fmt.Errorf("secret files: %w", err)
	}
	if uid == os.Getuid() {
		return nil
	}
	if err := l.o.GrantReader(dir, uid, posixacl.Execute); err != nil {
		return fmt.Errorf("secret files: grant UID %d on %s: %w (the secret runtime directory needs a file system with POSIX ACLs, such as tmpfs)", uid, dir, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("secret files: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := l.o.GrantReader(filepath.Join(dir, e.Name()), uid, posixacl.Read); err != nil {
			return fmt.Errorf("secret files: grant UID %d on %s: %w", uid, e.Name(), err)
		}
	}
	return nil
}

// instanceUID returns the host UID of the created container's user.
func (l *Launcher) instanceUID(ctx context.Context, ls LaunchSpec) (int, error) {
	if ls.Profile.UserNS == "keep-id" {
		// keep-id maps the identity that runs Podman to itself.
		if l.run.runAs != nil {
			return l.run.runAs.UID, nil
		}
		return os.Getuid(), nil
	}
	cuid, err := containerUID(ls.Profile.User)
	if err != nil {
		return 0, err
	}
	// After `podman init` the container's first process exists (stopped
	// before the server's code); its uid_map, read from the host, maps
	// container UIDs to host UIDs.
	out, err := l.podman(ctx, "inspect", "--type", "container", "--format", "{{.State.Pid}}", ls.Name).Output()
	if err != nil {
		return 0, fmt.Errorf("podman inspect: %w", err)
	}
	if pid, _ := strconv.Atoi(strings.TrimSpace(string(out))); pid > 0 {
		m, err := os.ReadFile(filepath.Join(l.o.ProcRoot, strconv.Itoa(pid), "uid_map")) // #nosec G304 -- procfs path of a container PID
		if err != nil {
			return 0, err
		}
		if host, ok := mapID(string(m), cuid); ok {
			return host, nil
		}
		return 0, fmt.Errorf("container UID %d is not mapped in %s", cuid, ls.Name)
	}
	// No process yet: compose Podman's mapping (container to the rootless
	// namespace) with the rootless namespace's own map (to the host).
	out, err = l.podman(ctx, "inspect", "--type", "container", "--format", "{{json .HostConfig.IDMappings}}", ls.Name).Output()
	if err != nil {
		return 0, fmt.Errorf("podman inspect: %w", err)
	}
	var idm struct {
		UIDMap []string `json:"UidMap"`
	}
	if err := json.Unmarshal(out, &idm); err != nil || len(idm.UIDMap) == 0 {
		return 0, fmt.Errorf("container %s has no UID mapping", ls.Name)
	}
	mid, ok := mapID(strings.ReplaceAll(strings.Join(idm.UIDMap, "\n"), ":", " "), cuid)
	if !ok {
		return 0, fmt.Errorf("container UID %d is not mapped in %s", cuid, ls.Name)
	}
	ns, err := l.podman(ctx, "unshare", "cat", "/proc/self/uid_map").Output()
	if err != nil {
		return 0, fmt.Errorf("podman unshare: %w", err)
	}
	host, ok := mapID(string(ns), mid)
	if !ok {
		return 0, fmt.Errorf("UID %d is not mapped in the rootless user namespace", mid)
	}
	return host, nil
}

// containerUID is the UID part of runtime.user ("uid:gid").
func containerUID(user string) (int, error) {
	u, _, _ := strings.Cut(user, ":")
	n, err := strconv.Atoi(u)
	if err != nil || n < 0 {
		return 0, errors.New("runtime.user must start with a numeric UID")
	}
	return n, nil
}

// mapID translates id through a uid_map ("inside outside count" lines).
func mapID(uidMap string, id int) (int, bool) {
	sc := bufio.NewScanner(strings.NewReader(uidMap))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			continue
		}
		in, e1 := strconv.Atoi(f[0])
		out, e2 := strconv.Atoi(f[1])
		n, e3 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		if id >= in && id < in+n {
			return out + id - in, true
		}
	}
	return 0, false
}
