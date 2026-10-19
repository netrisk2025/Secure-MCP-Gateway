//go:build unix

package testport

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	lockOnce sync.Once
	lockFile *os.File
)

// reserve takes a POSIX record lock on byte p of a file shared by every
// process using this package. The lock belongs to this process and ends
// when it exits, so a port reserved here is never handed out by another
// test process at the same time. It reports false when another process
// holds the byte. Without the file (no writable temporary directory) every
// port is reported free and only the in-process check applies.
func reserve(p int) bool {
	lockOnce.Do(func() {
		f, err := os.OpenFile(filepath.Join(os.TempDir(), "smcp-testport.lock"), os.O_RDWR|os.O_CREATE, 0o600)
		if err == nil {
			lockFile = f
		}
	})
	if lockFile == nil {
		return true
	}
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: int64(p), Len: 1}
	return syscall.FcntlFlock(lockFile.Fd(), syscall.F_SETLK, &lk) == nil
}
