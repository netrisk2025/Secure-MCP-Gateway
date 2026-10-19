package diag

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestRotatingFileBounds(t *testing.T) {
	// FR-17.2: volume beyond several rotations; every file stays within
	// the size bound and at most keep rotated files remain.
	reqtest.Verifies(t, "FR-17.2")
	dir := t.TempDir()
	path := filepath.Join(dir, "log", "smcpd.log")
	const maxBytes, keep = 64 << 10, 5
	rf, err := OpenRotatingFile(path, maxBytes, keep)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 199) + "\n")
	for i := 0; i < (maxBytes/len(line))*12; i++ { // about 12 files of volume
		if _, err := rf.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := rf.Close(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != keep+1 {
		t.Fatalf("%d files, want the live file and %d rotated", len(entries), keep)
	}
	for _, e := range entries {
		info, _ := e.Info()
		if info.Size() > maxBytes {
			t.Errorf("%s is %d bytes", e.Name(), info.Size())
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", e.Name(), info.Mode().Perm())
		}
	}
	for i := 1; i <= keep; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, i)); err != nil {
			t.Errorf("rotated file %d missing", i)
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s.%d", path, keep+1)); err == nil {
		t.Error("more rotated files than kept")
	}
}

func TestDaemonLoggerJSONLinesAndLevels(t *testing.T) {
	// FR-17.1: JSON Lines in the diagnostic log with the four levels and
	// info as the default. The journal separation is structural (the
	// logger has no evidence sink) and is checked in internal/e2e.
	reqtest.Partial(t, "FR-17.1")
	dir := t.TempDir()
	file := filepath.Join(dir, "smcpd.log")
	var stderr bytes.Buffer
	log, lv, closer, err := NewDaemon(Options{Stderr: &stderr, File: file, MaxBytes: 1 << 20, MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("hidden at info")
	log.Info("shown", "k", 1)
	log.Warn("warned")
	log.Error("failed")
	if err := SetLevel(lv, "debug"); err != nil {
		t.Fatal(err)
	}
	log.Debug("debug now")
	if err := SetLevel(lv, "error"); err != nil {
		t.Fatal(err)
	}
	log.Warn("hidden at error")
	_ = closer.Close()
	f, _ := os.Open(file)
	defer f.Close()
	var levels []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("not a JSON line: %q", sc.Text())
		}
		levels = append(levels, fmt.Sprint(rec["level"], ":", rec["msg"]))
	}
	want := "INFO:shown WARN:warned ERROR:failed DEBUG:debug now"
	if got := strings.Join(levels, " "); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if !strings.Contains(stderr.String(), "msg=shown") {
		t.Fatalf("stderr text missing: %q", stderr.String())
	}
	if _, _, _, err := NewDaemon(Options{Level: "trace"}); err == nil {
		t.Fatal("unknown level accepted")
	}
}

func TestRedactSensitiveAttributes(t *testing.T) {
	// FR-17.3 backstop: sensitive attribute names are redacted at every
	// level. Not logging such values in the first place is a code rule;
	// this test does not scan a real session's log (partial).
	reqtest.Partial(t, "FR-17.3")
	var buf bytes.Buffer
	log, _, _, err := NewDaemon(Options{Level: "debug", Format: "json", Stderr: &buf})
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("call", "refresh_token", "rt-secret", "password", "pw-secret", "arguments", `{"q":"marker-arg"}`, "result", "marker-result",
		"secret_value", "sv-secret", "alias", "fs")
	out := buf.String()
	for _, s := range []string{"rt-secret", "pw-secret", "marker-arg", "marker-result", "sv-secret"} {
		if strings.Contains(out, s) {
			t.Errorf("%s reached the log: %s", s, out)
		}
	}
	if !strings.Contains(out, `"alias":"fs"`) {
		t.Fatalf("ordinary attribute lost: %s", out)
	}
}
