//go:build linux

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/posixacl"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestIntegrationSecretFilesAutoUserNS: on real rootless Podman, an
// instance in an auto user namespace (a subordinate UID) reads the
// Gateway's owner-only secret files at /smcp/secrets, including one written
// after it started, while an owner-only file in the same directory that
// the broker did not write (no inherited grant) stays unreadable.
func TestIntegrationSecretFilesAutoUserNS(t *testing.T) {
	reqtest.Partial(t, "FR-6.8", "SR-4.1-2")
	h := realHarness(t, itRuntime(t))
	dir := filepath.Join(t.TempDir(), "probe-secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := posixacl.AddUser(dir, os.Getuid(), posixacl.Read); err != nil {
		t.Skipf("no POSIX ACLs on %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("launch-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := h.spec("probe")
	spec.SecretDir = dir
	spec.Env["TOKEN_FILE"] = filepath.Join(dir, "token")
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := connect(t, p)
	if id := callText(t, s, "identity", nil); !strings.Contains(id, "uid=1000 ") {
		t.Fatalf("identity %q", id)
	}
	if got := callText(t, s, "read_file", map[string]any{"path": SecretDir + "/token"}); got != "launch-secret" {
		t.Fatalf("launch-time secret file: %q", got)
	}
	// A file the broker writes later inherits the grant (writeSecretFile
	// copies the directory's named users); emulate it with the same rule.
	later := filepath.Join(dir, "call-1")
	if err := os.WriteFile(later, []byte("per-call"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := callText(t, s, "read_file", map[string]any{"path": SecretDir + "/call-1"}); !strings.HasPrefix(got, "blocked:") {
		t.Fatalf("an owner-only file without a grant was readable: %q", got)
	}
	a, err := posixacl.Get(dir)
	if err != nil {
		t.Fatal(err)
	}
	for uid, perm := range a.Users() {
		if uid != os.Getuid() && perm&posixacl.Execute != 0 {
			if err := posixacl.AddUser(later, uid, posixacl.Read); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := callText(t, s, "read_file", map[string]any{"path": SecretDir + "/call-1"}); got != "per-call" {
		t.Fatalf("per-call secret file after the grant: %q", got)
	}
	// The grant names exactly one subordinate UID, not the Gateway user.
	n := 0
	for uid := range a.Users() {
		if uid != os.Getuid() {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("directory ACL users %v", a.Users())
	}
}
