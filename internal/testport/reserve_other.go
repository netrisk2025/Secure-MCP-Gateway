//go:build !unix

package testport

// reserve has no cross-process lock on this platform; the in-process
// check and the bind check apply.
func reserve(int) bool { return true }
