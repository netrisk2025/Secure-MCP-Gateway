package audit

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestKeyTransitionsVerify(t *testing.T) {
	// FR-17.8: a journal spanning two rotations verifies from the trust
	// root; tampering with a transition record fails verification.
	reqtest.Verifies(t, "FR-17.8")
	// FR-17.7 evidence-key clause: closing the open segment and writing a
	// transition record signed by the outgoing key (the TLS and CA clauses
	// are tested in internal/keys and internal/e2e).
	reqtest.Partial(t, "FR-17.7")
	pub1, k1 := newKey(t)
	_, k2 := newKey(t)
	pub3, k3 := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := Open(dir, k1, Options{MaxEvents: 100, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = j.Record(decisionEvent())
	}
	if err := j.RotateKey(k2); err != nil {
		t.Fatal(err)
	}
	_ = j.Record(decisionEvent())
	if err := j.RotateKey(k3); err != nil {
		t.Fatal(err)
	}
	if !j.PublicKey().Equal(pub3) {
		t.Fatal("journal did not switch to the incoming key")
	}
	_ = j.Record(decisionEvent())
	if err := j.RotateKey(k3); err == nil {
		t.Fatal("rotation to the same key accepted")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(dir, pub1)
	if err != nil {
		t.Fatalf("verify across transitions: %v", err)
	}
	if len(rep.Keys) != 3 || rep.CurrentKey() != hex.EncodeToString(pub3) || len(rep.Transitions) != 2 || rep.Transitions[0] != 1 || rep.Transitions[1] != 2 {
		t.Fatalf("report %+v", rep)
	}
	// The current key alone is not a trust root for segment 1.
	if _, err := Verify(dir, pub3); err == nil {
		t.Fatal("verification started from the current key instead of the root")
	}
	// Reopening needs the current key.
	if _, err := Open(dir, k1, Options{MaxAge: time.Hour}); err == nil {
		t.Fatal("journal reopened with a retired key")
	}
	j2, err := Open(dir, k3, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("open with the current key: %v", err)
	}
	_ = j2.Record(decisionEvent())
	if err := j2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, pub1); err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}

	// Tamper: point the first transition at another key. The footer
	// signature covers next_key, so verification fails.
	seg := filepath.Join(dir, "segment-000001.jsonl")
	b, _ := os.ReadFile(seg)
	k2hex := hex.EncodeToString(k2.Public().(ed25519.PublicKey))
	_, kx := newKey(t)
	forged := strings.Replace(string(b), `"next_key":"`+k2hex+`"`, `"next_key":"`+hex.EncodeToString(kx.Public().(ed25519.PublicKey))+`"`, 1)
	if forged == string(b) {
		t.Fatal("transition record not found")
	}
	if err := os.WriteFile(seg, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, pub1); err == nil {
		t.Fatal("tampered transition record verified")
	}
	// Removing the transition record entirely also fails: the next
	// segment's signature does not verify under the old key.
	stripped := strings.Replace(string(b), `,"next_key":"`+k2hex+`"`, "", 1)
	_ = os.WriteFile(seg, []byte(stripped), 0o600)
	if _, err := Verify(dir, pub1); err == nil {
		t.Fatal("journal without its transition record verified")
	}
}

func TestCrashAfterKeyTransition(t *testing.T) {
	// A crash right after the transition record: the journal refuses the
	// outgoing key (before crash recovery signs anything) and recovers
	// with the incoming key.
	reqtest.Partial(t, "FR-17.7")
	pub1, k1 := newKey(t)
	_, k2 := newKey(t)
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	j, err := Open(dir, k1, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Commit(decisionEvent())
	if err := j.RotateKey(k2); err != nil {
		t.Fatal(err)
	}
	_ = j.Commit(decisionEvent())
	// Snapshot the files as a crash would leave them.
	crash := filepath.Join(t.TempDir(), "journal")
	_ = os.MkdirAll(crash, 0o700)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		_ = os.WriteFile(filepath.Join(crash, e.Name()), b, 0o600)
	}
	b, _ := os.ReadFile(DefaultAnchorPath(dir))
	_ = os.WriteFile(DefaultAnchorPath(crash), b, 0o600)
	_ = j.Close()
	if nk, err := LastTransition(crash); err != nil || nk != hex.EncodeToString(k2.Public().(ed25519.PublicKey)) {
		t.Fatalf("last transition %q %v", nk, err)
	}
	if _, err := Open(crash, k1, Options{MaxAge: time.Hour}); err == nil || !strings.Contains(err.Error(), "key-transition") {
		t.Fatalf("open with the outgoing key after a crash: %v", err)
	}
	j2, err := Open(crash, k2, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("recover with the incoming key: %v", err)
	}
	if len(j2.Recovered()) != 1 {
		t.Fatalf("recovered %v", j2.Recovered())
	}
	_ = j2.Close()
	if _, err := Verify(crash, pub1); err != nil {
		t.Fatalf("recovered journal: %v", err)
	}
}

func TestSealUnsignedAndFlush(t *testing.T) {
	// CP-27 inputs for the Health & Safety Monitor and SR-7.7-1's seal step.
	reqtest.Partial(t, "SR-6.11-1", "SR-7.7-1")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := Open(dir, priv, Options{MaxEvents: 100, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var flushes atomic.Int64
	j.SetFlushObserver(func(time.Duration) { flushes.Add(1) })
	if n, _ := j.Unsigned(); n != 0 {
		t.Fatalf("unsigned %d", n)
	}
	before := time.Now()
	_ = j.Commit(decisionEvent())
	_ = j.Record(decisionEvent())
	n, oldest := j.Unsigned()
	if n != 2 || oldest.Before(before.Add(-time.Second)) {
		t.Fatalf("unsigned %d %v", n, oldest)
	}
	if flushes.Load() == 0 {
		t.Fatal("flush observer not called")
	}
	if err := j.Seal(); err != nil {
		t.Fatal(err)
	}
	if n, _ := j.Unsigned(); n != 0 {
		t.Fatalf("unsigned after seal %d", n)
	}
	rep, err := Verify(dir, pub)
	if err != nil || rep.AnchorSegment != 1 || rep.Open != "segment-000002.jsonl" {
		t.Fatalf("after seal %+v %v", rep, err)
	}
	if name, sum, err := LastSegment(dir); err != nil || name != "segment-000002.jsonl" || len(sum) != 64 {
		t.Fatalf("last segment %s %s %v", name, sum, err)
	}
	if nk, err := LastTransition(dir); err != nil || nk != "" {
		t.Fatalf("last transition %q %v", nk, err)
	}
	_ = j.Close()
	if err := j.Seal(); err == nil {
		t.Fatal("seal after close")
	}
}

func TestAgeCloseKeepsSigningLagBelowMaxAge(t *testing.T) {
	// A segment opened long before its first event closes before that
	// event is MaxAge old (CP-27 stop threshold), not MaxAge plus a tick.
	reqtest.Partial(t, "SR-6.11-1")
	_, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := Open(dir, priv, Options{MaxAge: 800 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	time.Sleep(500 * time.Millisecond) // segment ages without events
	_ = j.Record(decisionEvent())
	var maxLag time.Duration
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, oldest := j.Unsigned()
		if n == 0 {
			break
		}
		if lag := time.Since(oldest); lag > maxLag {
			maxLag = lag
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n, _ := j.Unsigned(); n != 0 {
		t.Fatal("segment did not close")
	}
	if maxLag > 800*time.Millisecond {
		t.Fatalf("oldest unsigned event reached %v, above MaxAge", maxLag)
	}
}

func TestExporterCopiesOnce(t *testing.T) {
	// The export side of SR-6.10-1 (each event exactly once, also after a
	// restart); the timing of FR-7.14 is tested in internal/e2e.
	reqtest.Partial(t, "SR-6.10-1", "FR-7.14")
	pub, priv := newKey(t)
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	pubFile := filepath.Join(root, "evidence.pub")
	_ = os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
	j, err := Open(dir, priv, Options{MaxEvents: 2, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ex := &Exporter{JournalDir: dir, ExportDir: filepath.Join(root, "export"), PublicKeys: map[string]string{"evidence-genesis.pub": pubFile}}
	if res, err := ex.Sync(); err != nil || len(res.Copied) != 0 {
		t.Fatalf("empty journal export: %+v %v", res, err)
	}
	for i := 0; i < 5; i++ {
		_ = j.Record(decisionEvent())
	}
	res, err := ex.Sync()
	if err != nil || len(res.Copied) != 2 || res.AnchorSegment != 2 || !res.AnchorUpdated {
		t.Fatalf("first export %+v %v", res, err)
	}
	if res, err := ex.Sync(); err != nil || len(res.Copied) != 0 || res.AnchorUpdated {
		t.Fatalf("repeated export copied again: %+v %v", res, err)
	}
	_ = j.Close()
	// A restarted exporter copies only the newly closed segment.
	ex2 := &Exporter{JournalDir: dir, ExportDir: ex.ExportDir}
	res, err = ex2.Sync()
	if err != nil || len(res.Copied) != 1 || res.Copied[0] != "segment-000003.jsonl" {
		t.Fatalf("export after restart %+v %v", res, err)
	}
	exported := filepath.Join(ex.ExportDir, "journal")
	rep, err := Verify(exported, pub)
	if err != nil || rep.Events != 5 || rep.AnchorSegment != 3 {
		t.Fatalf("export does not verify: %+v %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(ex.ExportDir, "keys", "evidence-genesis.pub")); err != nil {
		t.Fatal("public key not exported")
	}
	// A changed copy is never overwritten.
	_ = os.WriteFile(filepath.Join(exported, "segment-000001.jsonl"), []byte("tampered\n"), 0o600)
	if _, err := ex2.Sync(); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("tampered export copy: %v", err)
	}
}
