//go:build darwin

package edge

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the kernel-reported user ID of the process at the other
// end of c (LOCAL_PEERCRED).
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) { cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) }); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}
