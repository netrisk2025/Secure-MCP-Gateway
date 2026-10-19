//go:build !linux

package posixacl

// Get is not supported outside Linux.
func Get(string) (ACL, error) { return nil, ErrUnsupported }

// AddUser is not supported outside Linux.
func AddUser(string, int, uint16) error { return ErrUnsupported }
