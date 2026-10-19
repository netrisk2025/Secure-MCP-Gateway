//go:build linux

package posixacl

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Get returns the access ACL of path, or the ACL equivalent to its mode
// when it has no extended entries.
func Get(path string) (ACL, error) {
	buf := make([]byte, 1024)
	n, err := unix.Getxattr(path, attrName, buf)
	if errors.Is(err, unix.ERANGE) {
		if n, err = unix.Getxattr(path, attrName, nil); err == nil {
			buf = make([]byte, n)
			n, err = unix.Getxattr(path, attrName, buf)
		}
	}
	switch {
	case errors.Is(err, unix.ENODATA):
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return fromMode(st.Mode()), nil
	case errors.Is(err, unix.EOPNOTSUPP):
		return nil, ErrUnsupported
	case err != nil:
		return nil, err
	}
	return decode(buf[:n])
}

// AddUser gives uid at least perm on path through a named-user entry,
// keeping the owner, group and other permissions. The caller must own
// path.
func AddUser(path string, uid int, perm uint16) error {
	a, err := Get(path)
	if err != nil {
		return err
	}
	if a.Effective(uid)&perm == perm {
		return nil
	}
	err = unix.Setxattr(path, attrName, a.withUser(uid, perm).encode(), 0)
	if errors.Is(err, unix.EOPNOTSUPP) {
		return ErrUnsupported
	}
	return err
}
