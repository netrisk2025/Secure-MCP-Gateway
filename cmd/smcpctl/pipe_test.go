package main

import (
	"os"
	"testing"
)

// ioPipe returns an OS pipe whose ends are closed when the test ends.
func ioPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}
