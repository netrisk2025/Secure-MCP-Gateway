package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const testPassphrase = "correct horse battery staple"

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func passphraseSource(dir string) Passphrase {
	return Passphrase{Path: filepath.Join(dir, MasterKeyFile), Passphrase: func() (string, error) { return testPassphrase, nil }, WorkFactor: 10}
}

type testVault struct {
	v     *Vault
	dir   string
	mem   *audit.Memory
	clock *clock
}

func newTestVault(t *testing.T) *testVault {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	if _, err := Init(dir, passphraseSource(dir)); err != nil {
		t.Fatal(err)
	}
	tv := &testVault{dir: dir, mem: &audit.Memory{}, clock: newClock()}
	v, err := Open(dir, passphraseSource(dir), VaultOptions{Overlap: time.Hour, Now: tv.clock.Now, Evidence: tv.mem})
	if err != nil {
		t.Fatal(err)
	}
	tv.v = v
	return tv
}

func (tv *testVault) create(t *testing.T, name, value string) Meta {
	t.Helper()
	m, err := tv.v.Create("tester", CreateParams{Name: name, Type: "api_key", Value: []byte(value)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (tv *testVault) store(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tv.dir, StoreFile))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func eventsWith(mem *audit.Memory, class, outcome string) []audit.Event {
	var out []audit.Event
	for _, e := range mem.Events() {
		if e.Class == class && e.Outcome == outcome {
			out = append(out, e)
		}
	}
	return out
}

func TestVaultRecordIsEncryptedWithAge(t *testing.T) {
	reqtest.Verifies(t, "FR-6.1")
	reqtest.Partial(t, "SR-2.13-1") // the master key is held by this package's key sources, not internal/keys (E-22)
	tv := newTestVault(t)
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	value := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	if _, err := tv.v.Create("admin:alice", CreateParams{Name: "github-pat", Type: "token", Description: "CI token", Expires: &exp, Value: []byte(value)}); err != nil {
		t.Fatal(err)
	}
	if _, err := tv.v.Rotate("admin:alice", "github-pat", []byte(value+"-v2"), -1); err != nil {
		t.Fatal(err)
	}
	raw := tv.store(t)
	if bytes.Contains(raw, []byte(value)) || bytes.Contains(raw, []byte("0123456789abcdef")) {
		t.Fatal("plaintext in the vault store")
	}
	var st storeFile
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	r := st.Secrets[0]
	if !strings.HasPrefix(r.Ref, "sec_") || r.Name != "github-pat" || r.Type != "token" || r.Owner != "admin:alice" || r.Created.IsZero() ||
		r.Rotated == nil || r.Expires == nil || !r.Expires.Equal(exp) || r.Current != 2 {
		t.Fatalf("record fields: %+v", r)
	}
	for _, ver := range r.Versions {
		if !bytes.HasPrefix(ver.Ciphertext, []byte("age-encryption.org/v1\n")) {
			t.Fatalf("version %d ciphertext is not age: %q", ver.Version, ver.Ciphertext[:min(24, len(ver.Ciphertext))])
		}
	}
	// The master key file is age-encrypted under the passphrase too.
	mk, _ := os.ReadFile(filepath.Join(tv.dir, MasterKeyFile))
	if !bytes.HasPrefix(mk, []byte("age-encryption.org/v1\n")) || bytes.Contains(mk, []byte("AGE-SECRET-KEY")) {
		t.Fatal("master key stored in plaintext")
	}
	for _, p := range []string{tv.dir, filepath.Join(tv.dir, StoreFile), filepath.Join(tv.dir, MasterKeyFile)} {
		if st, _ := os.Stat(p); st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %o", p, st.Mode().Perm())
		}
	}
	// The broker-only accessor returns the current value.
	op, err := tv.v.open("github-pat", 0)
	if err != nil || string(op.Value) != value+"-v2" || op.Version != 2 {
		t.Fatalf("open: %v %q", err, op.Value)
	}
}

func TestVaultReadsReturnMetadataOnly(t *testing.T) {
	reqtest.Partial(t, "FR-6.2") // the control API test verifies the requirement
	tv := newTestVault(t)
	value := "metadata-only-secret-1234"
	tv.create(t, "m", value)
	for _, x := range []any{tv.v.List(), func() Meta { m, _ := tv.v.Get("m"); return m }()} {
		b, _ := json.Marshal(x)
		if bytes.Contains(b, []byte(value)) || bytes.Contains(b, []byte("age-encryption")) || bytes.Contains(b, []byte("ciphertext")) {
			t.Fatalf("read returned value material: %s", b)
		}
	}
}

func TestVaultRotationOverlapAndRetirement(t *testing.T) {
	reqtest.Verifies(t, "FR-6.4")
	reqtest.Partial(t, "FR-6.3") // delivery side in TestBrokerRotationRedeliversAtOverlapLimit
	tv := newTestVault(t)
	tv.create(t, "db", "database-password-v1")
	m, err := tv.v.Rotate("tester", "db", []byte("database-password-v2"), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if m.CurrentVersion != 2 || m.Versions[0].State != StateOverlap || m.Versions[0].DeliverableUntil == nil {
		t.Fatalf("after rotate: %+v", m)
	}
	if op, err := tv.v.open("db", 0); err != nil || string(op.Value) != "database-password-v2" {
		t.Fatalf("current: %v %q", err, op.Value)
	}
	if op, err := tv.v.open("db", 1); err != nil || string(op.Value) != "database-password-v1" {
		t.Fatalf("previous within overlap: %v", err)
	}
	if n, _ := tv.v.Sweep(); n != 0 {
		t.Fatal("retired before the overlap ended")
	}
	var hooked []int
	tv.v.OnRetire(func(ref string, v int) { hooked = append(hooked, v) })
	tv.clock.Advance(30 * time.Minute)
	if _, err := tv.v.open("db", 1); !errors.Is(err, ErrRetired) {
		t.Fatalf("previous after overlap: %v", err)
	}
	if n, err := tv.v.Sweep(); n != 1 || err != nil {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if len(hooked) != 1 || hooked[0] != 1 {
		t.Fatalf("retire hook: %v", hooked)
	}
	var st storeFile
	json.Unmarshal(tv.store(t), &st)
	v1 := st.Secrets[0].Versions[0]
	if v1.State != StateRetired || len(v1.Ciphertext) != 0 || v1.RetiredAt == nil {
		t.Fatalf("retired version keeps ciphertext: %+v", v1)
	}
	ev := eventsWith(tv.mem, "secret", "retired")
	if len(ev) != 1 || ev[0].ReasonCode != "SECRET_RETIRED" || ev[0].Origin != "E-19" {
		t.Fatalf("retirement events: %+v", ev)
	}
	// Overlap 0 retires at once; a second rotation retires the overlap.
	if _, err := tv.v.Rotate("tester", "db", []byte("database-password-v3"), 0); err != nil {
		t.Fatal(err)
	}
	if m, _ := tv.v.Get("db"); m.Versions[1].State != StateRetired || m.CurrentVersion != 3 {
		t.Fatalf("overlap 0: %+v", m)
	}
	if _, err := tv.v.Rotate("tester", "db", []byte("x"), time.Hour); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("short value accepted: %v", err)
	}
	if _, err := tv.v.Rotate("tester", "db", []byte("database-password-v4"), 25*time.Hour); !errors.Is(err, ErrInvalidOverlap) {
		t.Fatalf("overlap above CP-15 accepted: %v", err)
	}
	// Remove retires everything and deletes the record.
	if err := tv.v.Remove("tester", "db"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(tv.store(t), []byte(`"db"`)) {
		t.Fatal("removed record still stored")
	}
	if len(eventsWith(tv.mem, "secret", "removed")) != 1 {
		t.Fatal("no removal event")
	}
}

func TestVaultValidationAndExpiry(t *testing.T) {
	reqtest.Partial(t, "FR-6.1")
	tv := newTestVault(t)
	for _, p := range []CreateParams{
		{Name: "Bad Name", Value: []byte("valid-value-123")},
		{Name: "ok", Value: []byte("short")},
		{Name: "ok", Type: "nope", Value: []byte("valid-value-123")},
	} {
		if _, err := tv.v.Create("t", p); err == nil {
			t.Fatalf("accepted %+v", p.Name)
		}
	}
	exp := tv.clock.Now().Add(time.Minute)
	if _, err := tv.v.Create("t", CreateParams{Name: "temp", Value: []byte("expiring-value-1"), Expires: &exp}); err != nil {
		t.Fatal(err)
	}
	if _, err := tv.v.Create("t", CreateParams{Name: "temp", Value: []byte("expiring-value-1")}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	tv.clock.Advance(time.Minute)
	if _, err := tv.v.open("temp", 0); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired value opened: %v", err)
	}
	// Without an evidence recorder, mutations fail closed.
	v2, err := Open(tv.dir, passphraseSource(tv.dir), VaultOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Create("t", CreateParams{Name: "x", Value: []byte("valid-value-123")}); !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("no evidence: %v", err)
	}
	tv.mem.Fail(errors.New("disk full"))
	if _, err := tv.v.Create("t", CreateParams{Name: "y", Value: []byte("valid-value-123")}); err == nil || strings.Contains(err.Error(), "valid-value") {
		t.Fatalf("audit failure: %v", err)
	}
}

func TestVaultUnlockFailures(t *testing.T) {
	reqtest.Partial(t, "SR-2.13-3") // owner-only file modes; separate service identities need the Enforced profile
	tv := newTestVault(t)
	wrong := Passphrase{Path: filepath.Join(tv.dir, MasterKeyFile), Passphrase: func() (string, error) { return "the wrong passphrase", nil }}
	if _, err := Open(tv.dir, wrong, VaultOptions{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := Open(tv.dir, Keychain{Account: "x"}, VaultOptions{}); err == nil {
		t.Fatal("key source mismatch accepted")
	}
	if _, err := Init(tv.dir, passphraseSource(tv.dir)); err == nil {
		t.Fatal("re-init accepted")
	}
	os.Chmod(filepath.Join(tv.dir, StoreFile), 0o644)
	if _, err := Open(tv.dir, passphraseSource(tv.dir), VaultOptions{}); !errors.Is(err, ErrPermissionsOpen) {
		t.Fatalf("world-readable store: %v", err)
	}
	if _, err := Open(t.TempDir(), passphraseSource(tv.dir), VaultOptions{}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("missing vault: %v", err)
	}
	pf := filepath.Join(t.TempDir(), "pp")
	os.WriteFile(pf, []byte(testPassphrase+"\n"), 0o644)
	if _, err := PassphraseFromFile(pf)(); err == nil {
		t.Fatal("group-readable passphrase file accepted")
	}
	os.Chmod(pf, 0o600)
	if p, err := PassphraseFromFile(pf)(); err != nil || p != testPassphrase {
		t.Fatalf("passphrase file: %v", err)
	}
}

func TestKeychainSource(t *testing.T) {
	reqtest.Partial(t, "SR-2.13-1")
	if !KeychainAvailable() {
		t.Skip("macOS Keychain not available")
	}
	kcPath := filepath.Join(t.TempDir(), "test.keychain-db")
	pw := "test-keychain-password"
	if out, err := exec.Command(securityTool, "create-keychain", "-p", pw, kcPath).CombinedOutput(); err != nil {
		t.Skipf("cannot create a test keychain: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command(securityTool, "delete-keychain", kcPath).Run() })
	if out, err := exec.Command(securityTool, "unlock-keychain", "-p", pw, kcPath).CombinedOutput(); err != nil {
		t.Skipf("cannot unlock the test keychain: %v %s", err, out)
	}
	dir := filepath.Join(t.TempDir(), "vault")
	ks := Keychain{Keychain: kcPath}
	id, err := Init(dir, ks)
	if err != nil {
		t.Fatal(err)
	}
	ks.Account = "vault-" + id
	v, err := Open(dir, ks, VaultOptions{Evidence: &audit.Memory{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create("t", CreateParams{Name: "k", Value: []byte("keychain-held-value")}); err != nil {
		t.Fatal(err)
	}
	if op, err := v.open("k", 0); err != nil || string(op.Value) != "keychain-held-value" {
		t.Fatalf("open: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(raw, []byte("AGE-SECRET-KEY")) {
			t.Fatalf("master key on disk in %s", e.Name())
		}
	}
	if err := ks.Store("AGE-SECRET-KEY-1X"); err == nil {
		t.Fatal("second key stored for one vault")
	}
}

// TestVaultCheck: the FR-7.11 availability check passes for the unlocked
// vault and fails while its store file is missing, open to others, or
// replaced by another vault's.
func TestVaultCheck(t *testing.T) {
	reqtest.Partial(t, "FR-7.11")
	tv := newTestVault(t)
	tv.create(t, "k", "value-of-the-key-0001")
	if err := tv.v.Check(); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(tv.dir, StoreFile)
	if err := os.Rename(store, store+".x"); err != nil {
		t.Fatal(err)
	}
	if err := tv.v.Check(); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("missing store: %v", err)
	}
	_ = os.Rename(store+".x", store)
	_ = os.Chmod(store, 0o644)
	if err := tv.v.Check(); !errors.Is(err, ErrPermissionsOpen) {
		t.Fatalf("open store: %v", err)
	}
	_ = os.Chmod(store, 0o600)
	other := newTestVault(t)
	raw, _ := os.ReadFile(filepath.Join(other.dir, StoreFile))
	saved, _ := os.ReadFile(store)
	_ = os.WriteFile(store, raw, 0o600)
	if err := tv.v.Check(); !errors.Is(err, ErrLocked) {
		t.Fatalf("other vault's store: %v", err)
	}
	_ = os.WriteFile(store, saved, 0o600)
	if err := tv.v.Check(); err != nil {
		t.Fatal(err)
	}
}
