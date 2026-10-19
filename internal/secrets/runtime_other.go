//go:build !linux

package secrets

import "path/filepath"

// IsTmpfs reports whether path is on a tmpfs (memory) file system. macOS
// has no tmpfs; secret files live in an owner-only directory on disk.
func IsTmpfs(string) bool { return false }

func defaultRuntimeDir(stateDir string) string {
	return filepath.Join(stateDir, "run", "secrets")
}
