//go:build linux

package perf

import "syscall"

// flushDisk writes the host's dirty pages out (sync(2)) before a load
// measurement; see Run.
func flushDisk() { syscall.Sync() }
