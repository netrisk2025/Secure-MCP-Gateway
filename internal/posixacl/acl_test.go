package posixacl

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWithUserKeepsModeAndSetsMask(t *testing.T) {
	a := fromMode(0o600)
	b := a.withUser(100999, Read)
	want := ACL{
		{Tag: tagUserObj, Perm: 6, ID: undefinedID},
		{Tag: tagUser, Perm: Read, ID: 100999},
		{Tag: tagGroupObj, Perm: 0, ID: undefinedID},
		{Tag: tagMask, Perm: Read, ID: undefinedID},
		{Tag: tagOther, Perm: 0, ID: undefinedID},
	}
	if len(b) != len(want) {
		t.Fatalf("got %v, want %v", b, want)
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("entry %d: got %+v, want %+v", i, b[i], want[i])
		}
	}
	// Adding a second user and widening the first recomputes the mask.
	c := b.withUser(5, Execute).withUser(100999, Execute)
	if got := c.Users(); got[100999] != Read|Execute || got[5] != Execute {
		t.Fatalf("users = %v", got)
	}
	for _, e := range c {
		if e.Tag == tagMask && e.Perm != Read|Execute {
			t.Fatalf("mask = %d", e.Perm)
		}
	}
	// A narrowed mask (chmod 0700 after the grant) makes the entry
	// ineffective, and adding the user again restores the mask.
	narrowed := make(ACL, len(c))
	copy(narrowed, c)
	for i := range narrowed {
		if narrowed[i].Tag == tagMask {
			narrowed[i].Perm = 0
		}
	}
	if narrowed.Effective(100999) != 0 || narrowed.withUser(100999, Read).Effective(100999) != Read|Execute {
		t.Fatalf("mask handling: %v", narrowed.withUser(100999, Read))
	}
	if c.Effective(7) != 0 {
		t.Fatal("unknown user has permissions")
	}
	// Entries stay sorted by tag, then ID (the kernel requires it).
	for i := 1; i < len(c); i++ {
		if c[i-1].Tag > c[i].Tag || (c[i-1].Tag == c[i].Tag && c[i-1].ID > c[i].ID) {
			t.Fatalf("unsorted: %v", c)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	a := fromMode(0o750).withUser(42, Read|Execute)
	got, err := decode(a.encode())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(a) {
		t.Fatalf("got %v, want %v", got, a)
	}
	for i := range a {
		if got[i] != a[i] {
			t.Fatalf("entry %d: got %+v, want %+v", i, got[i], a[i])
		}
	}
	for _, bad := range [][]byte{nil, {1, 0, 0, 0}, {2, 0, 0, 0, 1}, append([]byte{2, 0, 0, 0}, ACL{{Tag: tagOther}}.encode()[4:]...)} {
		if _, err := decode(bad); err == nil {
			t.Errorf("decode(%v) succeeded", bad)
		}
	}
}

func TestAddUserOnHostFileSystem(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := AddUser(p, 4242, Read)
	if runtime.GOOS != "linux" {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("AddUser on %s: %v", runtime.GOOS, err)
		}
		return
	}
	if errors.Is(err, ErrUnsupported) {
		t.Skip("the temporary directory's file system has no POSIX ACLs")
	}
	if err != nil {
		t.Fatal(err)
	}
	a, err := Get(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Users()[4242] != Read {
		t.Fatalf("ACL %v lacks user 4242 with read", a)
	}
	// Idempotent, and the owner keeps read and write.
	if err := AddUser(p, 4242, Read); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "x" {
		t.Fatalf("owner read: %q %v", b, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		// The group bits of the mode show the mask; the owning group's own
		// entry stays empty.
		t.Fatalf("mode %o, want 0640 (mask r)", st.Mode().Perm())
	}
	if a2, _ := Get(p); func() bool {
		for _, e := range a2 {
			if e.Tag == tagGroupObj && e.Perm != 0 {
				return true
			}
		}
		return false
	}() {
		t.Fatalf("owning group gained access: %v", a2)
	}
}
