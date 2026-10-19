package sandbox

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestPrepareRootfsIgnoresUmask: under smcpd.service (UMask=0077) the
// mount points must still be traversable and the passwd files readable by
// the instance's subordinate UID; otherwise crun fails with "cannot open
// `sys`: Permission denied".
func TestPrepareRootfsIgnoresUmask(t *testing.T) {
	reqtest.Partial(t, "SR-4.7-1", "FR-13.5")
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	src := t.TempDir()
	file := filepath.Join(src, "srv")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := PrepareRootfs(root, []Mount{{Source: src, Target: "/data/deep/dir"}, {Source: file, Target: "/data/file/TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{".", "sys", "proc", "var", "var/tmp", "smcp", "smcp/bin", "data", "data/deep", "data/deep/dir", "data/file"} {
		st, err := os.Stat(filepath.Join(root, d))
		if err != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("%s: mode %v, %v", d, st.Mode(), err)
		}
	}
	for _, f := range []string{"etc/passwd", "etc/group", "etc/hosts", "data/file/TOKEN"} {
		st, err := os.Stat(filepath.Join(root, f))
		if err != nil || st.Mode().Perm() != 0o644 {
			t.Errorf("%s: mode %v, %v", f, st.Mode(), err)
		}
	}
}
