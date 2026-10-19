package policystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const doc1 = `{"revision": "r1", "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
  "templates": {"ro": {"rules": [{"id": "ro-fs", "server": "fs", "tools": ["read_file"]}]}}}`

func doc(rev string) []byte { return []byte(strings.Replace(doc1, `"r1"`, `"`+rev+`"`, 1)) }

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRevisionRecordAndSignature(t *testing.T) {
	reqtest.Verifies(t, "FR-3.4")
	reqtest.Partial(t, "SR-1.1-2")
	dir := t.TempDir()
	s := open(t, dir)
	now := time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC)
	s.SetNow(func() time.Time { return now })
	if _, _, err := s.Active(); !errors.Is(err, ErrNoActive) {
		t.Fatalf("empty store: %v", err)
	}
	rev, created, err := s.Put(doc("r1"), Meta{Actor: "admin:alice", Origin: "publish", SimulationRef: "sim-1"})
	if err != nil || !created {
		t.Fatal(err)
	}
	rec := rev.Record
	if rec.Revision != "r1" || rec.Sequence != 1 || rec.Digest != rev.Snapshot.Digest || rec.SchemaVersion != policy.SchemaVersion ||
		rec.EvaluatorVersion != policy.EvaluatorVersion || rec.Actor != "admin:alice" || rec.PublishedAt != "2026-10-16T20:00:00Z" ||
		rec.SimulationRef != "sim-1" || rec.KeyID != s.KeyID() || len(rec.KeyID) != 16 {
		t.Fatalf("record: %+v", rec)
	}
	r2, _, err := s.Put(doc("r2"), Meta{Parent: "r1", Actor: "operator-token"})
	if err != nil || r2.Record.Parent != "r1" || r2.Record.Sequence != 2 || r2.Record.Origin != "publish" {
		t.Fatalf("%+v %v", r2, err)
	}
	if _, err := s.Activate(rev, "admin:alice"); err != nil {
		t.Fatal(err)
	}
	act, ctl, err := s.Active()
	if err != nil || act.Record.Revision != "r1" || ctl.Revision != "r1" || ctl.Actor != "admin:alice" || ctl.Signature == "" {
		t.Fatalf("%+v %+v %v", act, ctl, err)
	}
	// The key persists: reopening verifies everything under the same key.
	s2 := open(t, dir)
	if s2.KeyID() != s.KeyID() || len(s2.List()) != 2 || s2.List()[0].Revision != "r2" {
		t.Fatalf("reopen: %s %+v", s2.KeyID(), s2.List())
	}
	if _, _, err := s2.Active(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, KeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", st.Mode(), err)
	}
	exp, err := s2.Export("r2")
	if err != nil || string(exp) != string(r2.Snapshot.Raw) {
		t.Fatalf("export: %s %v", exp, err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	reqtest.Partial(t, "SR-1.1-2")
	dir := t.TempDir()
	s := open(t, dir)
	rev, _, _ := s.Put(doc("r1"), Meta{Actor: "a"})
	if _, err := s.Activate(rev, "a"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, RevisionsDir, rev.Record.Digest+".json")
	orig, _ := os.ReadFile(path)
	restore := func() {
		_ = os.Chmod(path, 0o644)
		if err := os.WriteFile(path, orig, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	tamper := map[string]func([]byte) []byte{
		"document": func(b []byte) []byte { return []byte(strings.Replace(string(b), `"read_file"`, `"write_file"`, 1)) },
		"record":   func(b []byte) []byte { return []byte(strings.Replace(string(b), `"actor": "a"`, `"actor": "b"`, 1)) },
		"one byte": func(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)-3] ^= 1; return c },
	}
	for name, f := range tamper {
		_ = os.Chmod(path, 0o644)
		if err := os.WriteFile(path, f(orig), 0o644); err != nil {
			t.Fatal(err)
		}
		s2 := open(t, dir) // a damaged file does not stop the store from opening
		if _, _, err := s2.Active(); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: active revision accepted: %v", name, err)
		}
		if len(s2.Damaged()) != 1 || len(s2.List()) != 0 {
			t.Errorf("%s: damaged %v list %v", name, s2.Damaged(), s2.List())
		}
		restore()
	}
	if _, _, err := open(t, dir).Active(); err != nil {
		t.Fatalf("restored file: %v", err)
	}
	// A control record that does not verify is refused too.
	cp := filepath.Join(dir, ControlFile)
	ctl, _ := os.ReadFile(cp)
	if err := os.WriteFile(cp, []byte(strings.Replace(string(ctl), `"actor": "a"`, `"actor": "x"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := open(t, dir).Active(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered control record: %v", err)
	}
	// A different signing key rejects everything.
	if err := os.WriteFile(cp, ctl, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, KeyFile))
	if _, _, err := open(t, dir).Active(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("foreign key: %v", err)
	}
}

func TestPublishedRevisionsAreImmutable(t *testing.T) {
	reqtest.Partial(t, "SR-1.14-1")
	dir := t.TempDir()
	s := open(t, dir)
	rev, _, err := s.Put(doc("r1"), Meta{Actor: "a"})
	if err != nil {
		t.Fatal(err)
	}
	// Same ID, other content: refused.
	other := strings.Replace(string(doc("r1")), `"read_file"`, `"list_directory"`, 1)
	if _, _, err := s.Put([]byte(other), Meta{Actor: "a"}); !errors.Is(err, ErrRevisionExists) {
		t.Fatalf("modified revision accepted: %v", err)
	}
	// Same content again: the existing revision, not a new one.
	again, created, err := s.Put([]byte(" "+string(doc("r1"))+"\n"), Meta{Actor: "b"})
	if err != nil || created || again.Record.Actor != "a" || len(s.List()) != 1 {
		t.Fatalf("%+v %v %v", again, created, err)
	}
	// The file is named by its content digest and is read-only.
	path := filepath.Join(dir, RevisionsDir, rev.Record.Digest+".json")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o400 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	// The writer never replaces an existing file.
	if err := writeImmutable(path, []byte("x")); !errors.Is(err, ErrRevisionExists) {
		t.Fatalf("overwrite: %v", err)
	}
	// Invalid documents never reach the store.
	if _, _, err := s.Put([]byte(`{"revision": "bad"}`), Meta{}); err == nil {
		t.Fatal("invalid document stored")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, RevisionsDir))
	if len(entries) != 1 {
		t.Fatalf("%d files (temporary files left?)", len(entries))
	}
}

func TestActivationAndRestore(t *testing.T) {
	reqtest.Partial(t, "SR-1.15-1")
	dir := t.TempDir()
	s := open(t, dir)
	r1, _, _ := s.Put(doc("r1"), Meta{Actor: "a"})
	r2, _, _ := s.Put(doc("r2"), Meta{Actor: "a"})
	c1, err := s.Activate(r1, "a")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := s.Activate(r2, "a")
	if err != nil || c2.Sequence <= c1.Sequence {
		t.Fatalf("%+v %v", c2, err)
	}
	if act, _, _ := s.Active(); act.Record.Revision != "r2" {
		t.Fatal(act.Record)
	}
	// Restoring the previous record (activation failed after the rename).
	if err := s.Restore(c1); err != nil {
		t.Fatal(err)
	}
	act, ctl, err := s.Active()
	if err != nil || act.Record.Revision != "r1" || ctl.Sequence <= c2.Sequence {
		t.Fatalf("%+v %+v %v", act, ctl, err)
	}
	// No temporary files remain next to the control record.
	entries, _ := os.ReadDir(filepath.Join(dir, "policy"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temporary file left: %s", e.Name())
		}
	}
	if err := s.Restore(Control{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Active(); !errors.Is(err, ErrNoActive) {
		t.Fatalf("zero restore: %v", err)
	}
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

// TestCheckActive: the currency check of FR-7.11 passes for the active
// revision, and fails for another revision, an altered control record, a
// missing control record and an altered or missing revision file (also
// after a successful check cached the file).
func TestCheckActive(t *testing.T) {
	reqtest.Partial(t, "FR-7.11")
	dir := t.TempDir()
	s := open(t, dir)
	rev, _, err := s.Put(doc("r1"), Meta{Actor: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckActive("r1"); !errors.Is(err, ErrNoActive) {
		t.Fatalf("no control record: %v", err)
	}
	if _, err := s.Activate(rev, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckActive("r1"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckActive("r0"); !errors.Is(err, ErrNotCurrent) {
		t.Fatalf("other revision: %v", err)
	}
	ctl := filepath.Join(dir, ControlFile)
	raw, _ := os.ReadFile(ctl)
	_ = os.WriteFile(ctl, []byte(strings.Replace(string(raw), `"actor": "a"`, `"actor": "b"`, 1)), 0o600)
	if err := s.CheckActive("r1"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("altered control record: %v", err)
	}
	_ = os.WriteFile(ctl, raw, 0o600)
	if err := s.CheckActive("r1"); err != nil {
		t.Fatal(err)
	}
	revFile := s.revPath(rev.Record.Digest)
	body, _ := os.ReadFile(revFile)
	_ = os.Chmod(revFile, 0o600)
	if err := os.WriteFile(revFile, []byte(strings.Replace(string(body), "read_file", "rm_rf_all", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckActive("r1"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("altered revision file: %v", err)
	}
	_ = os.Remove(revFile)
	if err := s.CheckActive("r1"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing revision file: %v", err)
	}
}
