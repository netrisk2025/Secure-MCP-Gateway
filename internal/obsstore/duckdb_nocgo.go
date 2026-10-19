//go:build !cgo

package obsstore

const duckdbAvailable = false

func openDuckDB(Options) (Store, error) { return nil, ErrUnavailable }
