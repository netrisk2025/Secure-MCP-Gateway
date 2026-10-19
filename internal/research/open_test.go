package research

import (
	"os"
	"path/filepath"
	"testing"
)

// Open serves only files inside one export directory: dot names and
// symbolic links that lead out of the export root are refused.
func TestOpenStaysInsideExports(t *testing.T) {
	dir := t.TempDir()
	x := &Exporter{Dir: filepath.Join(dir, "exports")}
	if err := os.MkdirAll(filepath.Join(x.Dir, "ds1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.Dir, "ds1", "data.csv"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "outside.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside.json"), filepath.Join(x.Dir, "ds1", "link.json")); err != nil {
		t.Fatal(err)
	}
	f, err := x.Open("ds1", "data.csv")
	if err != nil {
		t.Fatalf("open data file: %v", err)
	}
	f.Close()
	for _, c := range [][2]string{{"..", "outside.json"}, {".", "ds1"}, {"ds1", ".."}, {"ds1", "link.json"}, {"ds1/..", "x"}, {".hidden", "x"}} {
		if f, err := x.Open(c[0], c[1]); err == nil {
			f.Close()
			t.Errorf("Open(%q, %q) succeeded", c[0], c[1])
		}
	}
}
