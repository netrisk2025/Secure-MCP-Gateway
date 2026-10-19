//go:build linux

package analytics

import (
	"bytes"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// backgroundNice is the nice value of the threads that write the
// Observation Store and build baselines. On a host whose processors are
// all busy, observation work at the default priority takes processor time
// from tool calls in proportion to its own use; at nice 10 the kernel gives
// it about a tenth of a call thread's weight, so storage falls behind (the
// bounded queue and backpressure of FR-9.5, FR-9.6 and FR-9.12 apply)
// instead of calls slowing down (FR-11.4).
const backgroundNice = 10

// lowPriority locks the calling goroutine to its OS thread and lowers the
// thread's scheduling priority. The goroutine must keep the lock until it
// returns: a goroutine that exits locked takes its thread with it, so the
// lowered priority never reaches other goroutines. Threads the goroutine's
// cgo calls create (DuckDB's workers) inherit the priority. It reports
// whether the priority was lowered.
func lowPriority() bool {
	runtime.LockOSThread()
	return unix.Setpriority(unix.PRIO_PROCESS, unix.Gettid(), backgroundNice) == nil
}

// idlePriority is lowPriority and, where the kernel allows it, the
// SCHED_IDLE policy for the thread; it reports whether SCHED_IDLE was set.
// A thread at nice 10 that the kernel has picked may keep its processor
// until its slice ends (EEVDF's run-to-parity), so a call thread that
// wakes behind it can wait for milliseconds; a waking thread of a normal
// policy always preempts a SCHED_IDLE thread (FR-11.4). The store writer
// runs here: it spends its time in DuckDB (cgo), during which its
// goroutine hands back its processor slot (P). A goroutine that runs Go
// code here would keep its P while the kernel withholds the thread.
func idlePriority() bool {
	lowPriority()
	attr := unix.SchedAttr{Size: unix.SizeofSchedAttr, Policy: unix.SCHED_IDLE, Nice: backgroundNice}
	return unix.SchedSetAttr(unix.Gettid(), &attr, 0) == nil
}

// threadPolicy returns the scheduling policy of the calling thread (tests).
func threadPolicy() (uint32, bool) {
	a, err := unix.SchedGetAttr(0, 0)
	if err != nil {
		return 0, false
	}
	return a.Policy, true
}

// threadNice returns the nice value of the calling thread (tests), field
// 19 of /proc/thread-self/stat.
func threadNice() (int, bool) {
	b, err := os.ReadFile("/proc/thread-self/stat")
	if err != nil {
		return 0, false
	}
	// The command name (field 2) is parenthesized and may contain spaces.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:])) // fields 3 onwards
	if len(f) < 17 {
		return 0, false
	}
	n, err := strconv.Atoi(f[16])
	return n, err == nil
}
