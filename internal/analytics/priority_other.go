//go:build !linux

package analytics

import "runtime"

// lowPriority locks the calling goroutine to its OS thread, as on Linux;
// the thread's priority is not changed on this platform (macOS sets thread
// priority through its own QoS classes, which this release does not use).
func lowPriority() bool {
	runtime.LockOSThread()
	return false
}

// idlePriority is lowPriority on this platform.
func idlePriority() bool { return lowPriority() }
