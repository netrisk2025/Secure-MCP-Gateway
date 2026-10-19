package diag

import (
	"bytes"
	"strings"
	"testing"
)

func TestLevelsAndFormats(t *testing.T) {
	var b bytes.Buffer
	log, lv, err := New(&b, "warn", "json")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown", "k", 1)
	if strings.Contains(b.String(), "hidden") || !strings.Contains(b.String(), `"msg":"shown"`) {
		t.Fatalf("%s", b.String())
	}
	if err := SetLevel(lv, "debug"); err != nil {
		t.Fatal(err)
	}
	log.Debug("now shown")
	if !strings.Contains(b.String(), "now shown") {
		t.Fatal("level change ignored")
	}
	if _, _, err := New(&b, "loud", "text"); err == nil {
		t.Fatal("bad level accepted")
	}
	if _, _, err := New(&b, "info", "xml"); err == nil {
		t.Fatal("bad format accepted")
	}
}
