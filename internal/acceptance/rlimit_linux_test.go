//go:build linux

package acceptance

import "golang.org/x/sys/unix"

// limitFileSize sets the soft RLIMIT_FSIZE of a running process: from then
// on, a write that would extend any file of that process beyond n bytes
// fails with EFBIG (Go programs ignore SIGXFSZ).
func limitFileSize(pid int, n uint64) error {
	var cur unix.Rlimit
	if err := unix.Prlimit(pid, unix.RLIMIT_FSIZE, nil, &cur); err != nil {
		return err
	}
	return unix.Prlimit(pid, unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: n, Max: cur.Max}, nil)
}
