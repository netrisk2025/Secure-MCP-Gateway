package audit

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Adversarial cases of the October 2026 review against the verifier:
// reordered and truncated segments, a tampered or replaced anchor (the
// checkpoint), and a bad trust root.
func TestVerifierAdversarialCases(t *testing.T) {
	reqtest.Partial(t, "FR-7.5")
	pub, priv := newKey(t)
	build := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "journal")
		j, err := Open(dir, priv, Options{MaxEvents: 2, MaxAge: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		for range 6 {
			if err := j.Record(decisionEvent()); err != nil {
				t.Fatal(err)
			}
		}
		if err := j.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(dir, pub); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	seg := func(dir string, n int) string { return filepath.Join(dir, segmentName(n)) }
	mustFail := func(t *testing.T, dir, want string) {
		t.Helper()
		if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want failure containing %q, got %v", want, err)
		}
	}

	t.Run("segments swapped", func(t *testing.T) {
		dir := build(t)
		tmp := seg(dir, 1) + ".tmp"
		os.Rename(seg(dir, 1), tmp)
		os.Rename(seg(dir, 2), seg(dir, 1))
		os.Rename(tmp, seg(dir, 2))
		mustFail(t, dir, "header names segment")
	})
	t.Run("events reordered inside a segment", func(t *testing.T) {
		dir := build(t)
		b, _ := os.ReadFile(seg(dir, 2))
		l := strings.Split(string(b), "\n")
		l[1], l[2] = l[2], l[1]
		os.WriteFile(seg(dir, 2), []byte(strings.Join(l, "\n")), 0o600)
		mustFail(t, dir, "body hash")
	})
	t.Run("event removed with the footer count adjusted", func(t *testing.T) {
		dir := build(t)
		b, _ := os.ReadFile(seg(dir, 2))
		l := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		l = append(l[:1], l[2:]...)
		l[len(l)-1] = strings.Replace(l[len(l)-1], `"events":2`, `"events":1`, 1)
		os.WriteFile(seg(dir, 2), []byte(strings.Join(l, "\n")+"\n"), 0o600)
		mustFail(t, dir, "segment-000002")
	})
	t.Run("last closed segment truncated to an open one", func(t *testing.T) {
		dir := build(t)
		last := 4 // Close seals the empty open segment too
		b, _ := os.ReadFile(seg(dir, last))
		l := strings.SplitAfter(string(b), "\n")
		os.WriteFile(seg(dir, last), []byte(strings.Join(l[:len(l)-2], "")), 0o600)
		mustFail(t, dir, "segments were removed")
	})
	t.Run("trailing newline appended to a closed segment", func(t *testing.T) {
		dir := build(t)
		b, _ := os.ReadFile(seg(dir, 2))
		os.WriteFile(seg(dir, 2), append(b, '\n'), 0o600)
		mustFail(t, dir, "chain broken")
	})
	t.Run("anchor field tampered", func(t *testing.T) {
		dir := build(t)
		ap := DefaultAnchorPath(dir)
		b, _ := os.ReadFile(ap)
		var a map[string]any
		json.Unmarshal(b, &a)
		a["events_total"] = 5
		nb, _ := json.Marshal(a)
		os.WriteFile(ap, nb, 0o600)
		mustFail(t, dir, "signature invalid")
	})
	t.Run("anchor replaced with an older signed copy", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "journal")
		j, _ := Open(dir, priv, Options{MaxEvents: 2, MaxAge: time.Hour})
		for range 2 {
			j.Record(decisionEvent())
		}
		old, _ := os.ReadFile(DefaultAnchorPath(dir))
		for range 2 {
			j.Record(decisionEvent())
		}
		j.Close()
		os.WriteFile(DefaultAnchorPath(dir), old, 0o600)
		mustFail(t, dir, "the anchor was replaced")
	})
	t.Run("anchor is not JSON", func(t *testing.T) {
		dir := build(t)
		os.WriteFile(DefaultAnchorPath(dir), []byte("garbage"), 0o600)
		mustFail(t, dir, "not an anchor record")
	})
	t.Run("trust root of the wrong length", func(t *testing.T) {
		dir := build(t)
		if _, err := Verify(dir, pub[:16]); err == nil || !strings.Contains(err.Error(), "trust root") {
			t.Fatalf("short key: %v", err)
		}
	})
	t.Run("open segment events are reported as unsigned", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "journal")
		j, _ := Open(dir, priv, Options{MaxEvents: 2, MaxAge: time.Hour})
		for range 3 {
			j.Commit(decisionEvent())
		}
		rep, err := Verify(dir, pub)
		if err != nil || rep.Open != segmentName(2) || rep.OpenEvents != 1 || rep.Events != 3 {
			t.Fatalf("%+v %v", rep, err)
		}
		j.Close()
	})
}

// The export is the off-machine reference for RR-08: its anchor only moves
// forward and its trust root is never replaced, so a rolled-back local
// anchor or a replaced genesis key is refused at the next export instead
// of being copied over the reference.
func TestExporterRefusesRollbackAndTrustRootChange(t *testing.T) {
	reqtest.Partial(t, "FR-7.14")
	pub, priv := newKey(t)
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	genesis := filepath.Join(root, GenesisKeyName)
	os.WriteFile(genesis, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
	j, err := Open(dir, priv, Options{MaxEvents: 2, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ex := &Exporter{JournalDir: dir, ExportDir: filepath.Join(root, "export"), PublicKeys: map[string]string{GenesisKeyName: genesis}}
	for range 2 {
		j.Record(decisionEvent())
	}
	old, _ := os.ReadFile(DefaultAnchorPath(dir))
	for range 2 {
		j.Record(decisionEvent())
	}
	if res, err := ex.Sync(); err != nil || res.AnchorSegment != 2 {
		t.Fatalf("export: %+v %v", res, err)
	}
	exportedAnchor := DefaultAnchorPath(filepath.Join(ex.ExportDir, "journal"))
	want, _ := os.ReadFile(exportedAnchor)
	// Roll the local anchor back to segment 1.
	os.WriteFile(DefaultAnchorPath(dir), old, 0o600)
	if _, err := ex.Sync(); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("rollback exported: %v", err)
	}
	if got, _ := os.ReadFile(exportedAnchor); string(got) != string(want) {
		t.Fatal("exported anchor was replaced by the older one")
	}
	os.WriteFile(DefaultAnchorPath(dir), want, 0o600)
	// Replace the local trust root.
	other, _ := newKey(t)
	os.WriteFile(genesis, []byte(hex.EncodeToString(other)+"\n"), 0o644)
	if _, err := ex.Sync(); err == nil || !strings.Contains(err.Error(), "trust root") {
		t.Fatalf("changed trust root exported: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(ex.ExportDir, "keys", GenesisKeyName)); !strings.Contains(string(b), hex.EncodeToString(pub)) {
		t.Fatal("exported trust root was replaced")
	}
	j.Close()
}
