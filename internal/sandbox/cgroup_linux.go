package sandbox

import (
	"os"
	"path/filepath"
	"syscall"
)

// watchCgroupEvents calls fire each time the kernel changes memory.events
// or pids.events of the cgroup at dir (cgroup v2 raises a file-modified
// event on every counter change). The monitor then samples at once, which
// catches an OOM kill of the instance's main process before the runtime
// removes the cgroup. The returned function stops the watch.
func watchCgroupEvents(dir string, fire func()) (func(), error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	for _, f := range []string{"memory.events", "pids.events"} {
		if _, err := syscall.InotifyAddWatch(fd, filepath.Join(dir, f), syscall.IN_MODIFY); err != nil {
			_ = syscall.Close(fd)
			return nil, err
		}
	}
	// A non-blocking descriptor is pollable, so Close unblocks Read.
	file := os.NewFile(uintptr(fd), "inotify") // #nosec G115 -- a file descriptor fits in uintptr
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := file.Read(buf); err != nil {
				return
			}
			fire()
		}
	}()
	return func() { _ = file.Close() }, nil
}
