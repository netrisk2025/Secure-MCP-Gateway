//go:build darwin

package perf

import "syscall"

// flushDisk writes the host's dirty pages out (sync(2)) before a load
// measurement; see Run.
func flushDisk() { _ = syscall.Sync() } // nothing to do about a failure here
