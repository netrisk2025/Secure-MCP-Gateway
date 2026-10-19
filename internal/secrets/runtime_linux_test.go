//go:build linux

package secrets

import (
	"os"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestDefaultRuntimeDirIsTmpfs(t *testing.T) {
	reqtest.Partial(t, "FR-6.7", "FR-6.8")
	if !IsTmpfs("/dev/shm") && !IsTmpfs(os.Getenv("XDG_RUNTIME_DIR")) {
		t.Skip("no tmpfs on this host")
	}
	d := defaultRuntimeDir("/var/lib/smcp")
	if strings.HasPrefix(d, "/var/lib/smcp") {
		t.Fatalf("default runtime dir %s is not on tmpfs", d)
	}
	if err := prepareRuntimeDir(d); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	if !IsTmpfs(d) {
		t.Fatalf("%s is not tmpfs", d)
	}
	if IsTmpfs(t.TempDir()) && !strings.HasPrefix(t.TempDir(), "/dev/shm") {
		t.Log("TMPDIR is on tmpfs")
	}
}
