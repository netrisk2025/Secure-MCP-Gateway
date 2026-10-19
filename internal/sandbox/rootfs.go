package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// rootfsDirs and rootfsFiles are created in the Gateway-built root
// directory. With a read-only root and a user namespace that does not map
// the Gateway's own UID, the runtime cannot create mount points itself, so
// every mount point exists in advance.
var (
	rootfsDirs  = []string{"proc", "dev", "sys", "tmp", "run", "var/tmp", "etc", strings.TrimPrefix(ServerBinDir, "/"), strings.TrimPrefix(WorkDir, "/")}
	rootfsFiles = []string{"etc/hosts", "etc/resolv.conf", "etc/hostname", "etc/passwd", "etc/group", "run/.containerenv"}
)

// PrepareRootfs makes dir an empty root filesystem with mount points for
// every mount of the launch specification. It is idempotent and safe to
// call for each launch. Nothing in it is writable by an instance: the
// container mounts it read-only.
func PrepareRootfs(dir string, mounts []Mount) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("root directory %q must be absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- instances (other UIDs) must traverse it
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- as above
		return err
	}
	for _, d := range rootfsDirs {
		if err := mkdirTree(dir, filepath.Join(dir, d)); err != nil {
			return err
		}
	}
	for _, f := range rootfsFiles {
		if err := touch(filepath.Join(dir, f)); err != nil {
			return err
		}
	}
	mtab := filepath.Join(dir, "etc", "mtab")
	if _, err := os.Lstat(mtab); errors.Is(err, os.ErrNotExist) {
		if err := os.Symlink("/proc/mounts", mtab); err != nil {
			return err
		}
	}
	passwd := filepath.Join(dir, "etc", "passwd")
	if st, err := os.Stat(passwd); err == nil && st.Size() == 0 {
		// A user entry for the default instance user, so getpwuid works.
		if err := os.WriteFile(passwd, []byte("root:x:0:0::/:/nonexistent\nsmcp:x:1000:1000::/work:/nonexistent\n"), 0o644); err != nil { // #nosec G306 -- world-readable by design
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "etc", "group"), []byte("root:x:0:\nsmcp:x:1000:\n"), 0o644); err != nil { // #nosec G306 -- as above
			return err
		}
		for _, f := range []string{passwd, filepath.Join(dir, "etc", "group")} {
			if err := os.Chmod(f, 0o644); err != nil { // #nosec G302 -- world-readable by design; the umask may have narrowed it
				return err
			}
		}
	}
	for _, m := range mounts {
		p := filepath.Join(dir, filepath.Clean("/"+m.Target))
		if !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			return fmt.Errorf("mount target %q leaves the root directory", m.Target)
		}
		st, err := os.Stat(m.Source)
		if err != nil {
			return err
		}
		if st.IsDir() {
			if err := mkdirTree(dir, p); err != nil {
				return err
			}
			continue
		}
		if err := mkdirTree(dir, filepath.Dir(p)); err != nil {
			return err
		}
		if err := touch(p); err != nil {
			return err
		}
	}
	return nil
}

func touch(p string) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDONLY, 0o644) // #nosec G302 G304 -- mount point inside the Gateway root directory
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(p, 0o644) // #nosec G302 -- the umask (UMask=0077 in smcpd.service) must not narrow it
}

// mkdirTree creates p and every missing directory between root and p with
// mode 0755, whatever the process umask: instances run under other UIDs and
// must traverse every mount point (smcpd.service sets UMask=0077).
func mkdirTree(root, p string) error {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("mount point %q leaves the root directory", p)
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		if err := os.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) { // #nosec G301 -- see above
			return err
		}
		if err := os.Chmod(cur, 0o755); err != nil { // #nosec G302 -- see above
			return err
		}
	}
	return nil
}
