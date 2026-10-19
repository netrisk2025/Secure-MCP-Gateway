package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/posixacl"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSecretFilesInheritSandboxReaders: a secret file written into an
// instance directory on which the sandbox granted a UID search permission
// (an instance under a subordinate UID or the server identity) is readable
// by that UID and by nobody else; without such a grant it stays
// owner-only.
func TestSecretFilesInheritSandboxReaders(t *testing.T) {
	reqtest.Partial(t, "FR-6.8")
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := writeSecretFile(plain, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(plain); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o without a reader", st.Mode().Perm())
	}
	if err := posixacl.AddUser(dir, 231999, posixacl.Execute); errors.Is(err, posixacl.ErrUnsupported) {
		t.Skip("no POSIX ACLs on this platform or file system")
	} else if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "token")
	if err := writeSecretFile(p, []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}
	a, err := posixacl.Get(p)
	if err != nil {
		t.Fatal(err)
	}
	if u := a.Users(); len(u) != 1 || u[231999] != posixacl.Read {
		t.Fatalf("named users %v, want only 231999 with read", u)
	}
	// A rewrite (rotation) keeps the grant.
	if err := writeSecretFile(p, []byte("rotated")); err != nil {
		t.Fatal(err)
	}
	if a, _ := posixacl.Get(p); a.Users()[231999] != posixacl.Read {
		t.Fatalf("rotated file lost the reader: %v", a)
	}
}
