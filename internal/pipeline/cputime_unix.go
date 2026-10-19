//go:build linux || darwin

package pipeline

import (
	"time"

	"golang.org/x/sys/unix"
)

// threadCPU returns the CPU time consumed by the calling OS thread.
func threadCPU() (time.Duration, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts); err != nil {
		return 0, false
	}
	return time.Duration(ts.Nano()), true
}
