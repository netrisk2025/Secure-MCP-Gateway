//go:build linux

package secrets

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const tmpfsMagic = 0x01021994

// IsTmpfs reports whether path is on a tmpfs (memory) file system.
func IsTmpfs(path string) bool {
	var st unix.Statfs_t
	if unix.Statfs(path, &st) != nil {
		return false
	}
	return st.Type == tmpfsMagic
}

// defaultRuntimeDir prefers a tmpfs: $XDG_RUNTIME_DIR, then /dev/shm.
func defaultRuntimeDir(stateDir string) string {
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" && IsTmpfs(x) {
		return filepath.Join(x, "smcp-secrets")
	}
	if IsTmpfs("/dev/shm") {
		return filepath.Join("/dev/shm", "smcp-secrets-"+strconv.Itoa(os.Getuid()))
	}
	return filepath.Join(stateDir, "run", "secrets")
}
