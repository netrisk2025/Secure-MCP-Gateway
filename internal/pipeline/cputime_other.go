//go:build !linux && !darwin

package pipeline

import "time"

// threadCPU is unavailable on this platform.
func threadCPU() (time.Duration, bool) { return 0, false }
