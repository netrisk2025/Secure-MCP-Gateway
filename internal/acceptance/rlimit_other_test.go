//go:build !linux

package acceptance

import "errors"

// limitFileSize needs prlimit(2), which only Linux has.
func limitFileSize(int, uint64) error {
	return errors.New("setting the file size limit of a running process needs Linux (prlimit)")
}
