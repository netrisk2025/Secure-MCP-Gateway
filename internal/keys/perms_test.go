package keys

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	if err := CheckPrivate(dir); err != nil {
		t.Fatalf("empty state directory: %v", err)
	}
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); err != nil {
		t.Fatalf("fresh state directory: %v", err)
	}
	for _, name := range []string{AdminTokenFile, EvidenceKeyFile, CAKeyFile, ServerKeyFile} {
		p := filepath.Join(dir, name)
		for _, mode := range []os.FileMode{0o640, 0o604, 0o620} {
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			if err := CheckPrivate(dir); !errors.Is(err, ErrPermissionsOpen) {
				t.Fatalf("%s with mode %04o: err = %v, want ErrPermissionsOpen", name, mode, err)
			}
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Public files may be world-readable.
	if err := os.Chmod(filepath.Join(dir, CACertFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); err != nil {
		t.Fatalf("world-readable CA certificate refused: %v", err)
	}
}
