//go:build !linux

package sandbox

import "errors"

// watchCgroupEvents needs inotify on cgroup v2 files (Linux); elsewhere the
// monitor relies on polling alone.
func watchCgroupEvents(string, func()) (func(), error) {
	return nil, errors.New("cgroup event notification needs Linux")
}
