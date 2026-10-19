//go:build !linux && !darwin

package edge

import (
	"errors"
	"net"
)

// peerUID is not available on this platform; the UDS Harness Profile
// refuses every connection.
func peerUID(*net.UnixConn) (int, error) {
	return -1, errors.New("peer credentials are not supported on this platform")
}
