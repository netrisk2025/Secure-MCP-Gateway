//go:build !darwin && !linux

package health

import "errors"

func freeBytes(string) (uint64, error) {
	return 0, errors.New("free space is not measured on this platform")
}
