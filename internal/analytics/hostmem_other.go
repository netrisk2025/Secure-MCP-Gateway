//go:build !linux

package analytics

// hostAvailable is not measured on this platform; the heap and
// backpressure triggers still apply.
func hostAvailable() (float64, bool) { return 0, false }
