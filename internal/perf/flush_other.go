//go:build !linux && !darwin

package perf

// flushDisk has no portable equivalent here; the measurements run on Linux
// and macOS.
func flushDisk() {}
