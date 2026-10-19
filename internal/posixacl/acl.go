// Package posixacl adds and reads named-user entries of POSIX access ACLs
// (the system.posix_acl_access extended attribute) without external tools.
//
// The sandbox uses it to let one other UID read a file the Gateway owns:
// an instance running under a subordinate UID (userns = "auto") or under
// the separate server identity (runtime.run_as) reads its secret files
// (S2, S3) through a named-user entry, while the file stays owner-only for
// everyone else. Only Linux implements it; elsewhere every call returns
// ErrUnsupported.
package posixacl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
)

// ErrUnsupported is returned where POSIX ACLs are not available.
var ErrUnsupported = errors.New("posix ACLs are not supported on this platform")

// Permission bits of an entry.
const (
	Read    = 4
	Write   = 2
	Execute = 1
)

// Entry tags (linux/posix_acl_xattr.h).
const (
	tagUserObj  = 0x01
	tagUser     = 0x02
	tagGroupObj = 0x04
	tagGroup    = 0x08
	tagMask     = 0x10
	tagOther    = 0x20

	xattrVersion = 2
	undefinedID  = 0xffffffff
	attrName     = "system.posix_acl_access"
)

// Entry is one ACL entry.
type Entry struct {
	Tag  uint16
	Perm uint16
	ID   uint32
}

// ACL is a decoded access ACL.
type ACL []Entry

// fromMode is the minimal ACL equivalent to a permission mode.
func fromMode(m fs.FileMode) ACL {
	p := uint16(m.Perm()) // #nosec G115 -- nine permission bits
	return ACL{
		{Tag: tagUserObj, Perm: p >> 6 & 7, ID: undefinedID},
		{Tag: tagGroupObj, Perm: p >> 3 & 7, ID: undefinedID},
		{Tag: tagOther, Perm: p & 7, ID: undefinedID},
	}
}

// Users returns the named-user entries as UID to permission bits.
func (a ACL) Users() map[int]uint16 {
	out := map[int]uint16{}
	for _, e := range a {
		if e.Tag == tagUser {
			out[int(e.ID)] = e.Perm
		}
	}
	return out
}

// Effective returns the permission bits that the named-user entry of uid
// grants after the mask (a chmod narrows the mask, not the entries).
func (a ACL) Effective(uid int) uint16 {
	var perm, mask uint16 = 0, 7
	found := false
	for _, e := range a {
		switch {
		case e.Tag == tagUser && int(e.ID) == uid:
			perm, found = e.Perm, true
		case e.Tag == tagMask:
			mask = e.Perm
		}
	}
	if !found {
		return 0
	}
	return perm & mask
}

// withUser returns a copy of a in which uid has at least perm, with the
// mask recomputed as the union of the group class entries.
func (a ACL) withUser(uid int, perm uint16) ACL {
	out := make(ACL, 0, len(a)+2)
	found := false
	for _, e := range a {
		switch e.Tag {
		case tagMask:
			continue
		case tagUser:
			if int(e.ID) == uid {
				e.Perm |= perm
				found = true
			}
		}
		out = append(out, e)
	}
	if !found {
		out = append(out, Entry{Tag: tagUser, Perm: perm, ID: uint32(uid)}) // #nosec G115 -- UIDs are below 2^32
	}
	var mask uint16
	for _, e := range out {
		if e.Tag == tagUser || e.Tag == tagGroup || e.Tag == tagGroupObj {
			mask |= e.Perm
		}
	}
	out = append(out, Entry{Tag: tagMask, Perm: mask, ID: undefinedID})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tag != out[j].Tag {
			return out[i].Tag < out[j].Tag
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// encode returns the extended-attribute form of a.
func (a ACL) encode() []byte {
	b := make([]byte, 4, 4+8*len(a))
	binary.LittleEndian.PutUint32(b, xattrVersion)
	for _, e := range a {
		b = binary.LittleEndian.AppendUint16(b, e.Tag)
		b = binary.LittleEndian.AppendUint16(b, e.Perm)
		b = binary.LittleEndian.AppendUint32(b, e.ID)
	}
	return b
}

// decode parses the extended-attribute form.
func decode(b []byte) (ACL, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, fmt.Errorf("posix ACL: bad length %d", len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != xattrVersion {
		return nil, fmt.Errorf("posix ACL: unknown version %d", v)
	}
	var a ACL
	for i := 4; i < len(b); i += 8 {
		a = append(a, Entry{Tag: binary.LittleEndian.Uint16(b[i:]), Perm: binary.LittleEndian.Uint16(b[i+2:]), ID: binary.LittleEndian.Uint32(b[i+4:])})
	}
	if !slices.ContainsFunc(a, func(e Entry) bool { return e.Tag == tagUserObj }) {
		return nil, errors.New("posix ACL: no owner entry")
	}
	return a, nil
}
