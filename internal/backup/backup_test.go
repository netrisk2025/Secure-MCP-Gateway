package backup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const testConfig = `schema_version = 1
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA"
[policy]
file = "policy.json"
`

const testPolicy = `{"revision": "r1", "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
 "templates": {"ro": {"rules": [{"id": "ro-t", "server": "t", "tools": ["echo"]}]}}}`

// install creates a state directory with keys and a journal, a
// configuration file and a policy file.
func install(t *testing.T, events ...audit.Event) (dir, state, cfg, pol string) {
	t.Helper()
	dir = t.TempDir()
	state = filepath.Join(dir, "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	priv, _ := keys.LoadEvidenceKey(state)
	j, err := audit.Open(filepath.Join(state, "journal"), priv, audit.Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := j.Commit(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(state, "log"), 0o700)
	_ = os.WriteFile(filepath.Join(state, "log", "smcpd.log"), []byte("{}\n"), 0o600)
	cfg = filepath.Join(dir, "smcp.toml")
	pol = filepath.Join(dir, "policy.json")
	_ = os.WriteFile(cfg, []byte(testConfig), 0o600)
	_ = os.WriteFile(pol, []byte(testPolicy), 0o644)
	return dir, state, cfg, pol
}

func fast(e Encryption) Encryption { e.WorkFactor = 10; return e }

func TestEncryptedArchives(t *testing.T) {
	// FR-17.6: a backup with a passphrase and one with a recipient, both
	// encrypted and both restorable; a backup with neither is refused.
	reqtest.Verifies(t, "FR-17.6")
	// FR-9.16 component list (Policy Store, configuration, journal, keys,
	// trust anchors, optional parts); scheduling and the vault and
	// registry directories of later elements are not covered.
	reqtest.Partial(t, "FR-9.16")
	dir, state, cfg, pol := install(t, audit.Event{Class: "admin", Origin: "E-24", Outcome: "x"})
	// Package library: the content-addressed artifact is state; the unpacked
	// tree and work directories are derived and left out.
	for _, f := range []string{"packages/artifacts/sha256/ab", "packages/unpacked/ab/server", "packages/work/fx/cache"} {
		_ = os.MkdirAll(filepath.Join(state, filepath.Dir(f)), 0o700)
		_ = os.WriteFile(filepath.Join(state, f), []byte("x"), 0o755)
	}
	opt := filepath.Join(dir, "obs")
	_ = os.MkdirAll(opt, 0o700)
	_ = os.WriteFile(filepath.Join(opt, "day.parquet"), []byte("observations"), 0o600)
	spec := Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Optional: map[string]string{"observations": opt}, InstallationID: "inst-1"}

	out := filepath.Join(dir, "backups")
	if _, err := Create(out, spec); !errors.Is(err, ErrUnencrypted) {
		t.Fatalf("unencrypted backup: %v", err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Fatal("refused backup left files")
	}

	spec.Encryption = fast(Encryption{Passphrase: "correct horse battery"})
	res, err := Create(out, spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"configuration", "policy_store", "evidence_journal", "key_material", "trust_anchors", "optional:observations"} {
		if !res.Manifest.Has(c) {
			t.Errorf("manifest lacks %s: %v", c, res.Manifest.Components)
		}
	}
	artifact := false
	for _, f := range res.Manifest.Files {
		if strings.HasPrefix(f.Path, "state/log/") {
			t.Errorf("diagnostic log archived: %s", f.Path)
		}
		if strings.HasPrefix(f.Path, "state/packages/unpacked/") || strings.HasPrefix(f.Path, "state/packages/work/") {
			t.Errorf("derived package directory archived: %s", f.Path)
		}
		artifact = artifact || f.Path == "state/packages/artifacts/sha256/ab"
	}
	if !artifact {
		t.Error("package artifact not archived")
	}
	raw, _ := os.ReadFile(res.Path)
	if !strings.HasPrefix(string(raw), "age-encryption.org/v1") || strings.Contains(string(raw), "BEGIN EC PRIVATE KEY") || strings.Contains(string(raw), "revision") {
		t.Fatal("archive is not age ciphertext")
	}
	if ok, err := VerifyChecksum(res.Path); !ok || err != nil {
		t.Fatalf("checksum %v %v", ok, err)
	}
	if _, err := Extract(res.Path, filepath.Join(dir, "x1"), Decryption{Passphrase: "wrong"}); err == nil {
		t.Fatal("wrong passphrase decrypted")
	}
	m, err := Extract(res.Path, filepath.Join(dir, "x2"), Decryption{Passphrase: "correct horse battery"})
	if err != nil || m.InstallationID != "inst-1" {
		t.Fatalf("extract %+v %v", m, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "x2", "optional", "observations", "day.parquet")); string(b) != "observations" {
		t.Fatal("optional part not restored")
	}

	id, _ := age.GenerateX25519Identity()
	idFile := filepath.Join(dir, "id.txt")
	_ = os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600)
	spec.Encryption = Encryption{Recipients: []string{id.Recipient().String()}}
	spec.Now = func() time.Time { return time.Now().Add(time.Second) }
	res2, err := Create(out, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(res2.Path, filepath.Join(dir, "x3"), Decryption{IdentityFile: idFile}); err != nil {
		t.Fatalf("recipient archive: %v", err)
	}
	if _, err := Create(out, Spec{StateDir: state, Encryption: Encryption{Passphrase: "p", Recipients: []string{id.Recipient().String()}}}); err == nil {
		t.Fatal("passphrase and recipient together accepted")
	}
	idx, err := ReadIndex(out)
	if err != nil || len(idx) != 2 || idx[0].SHA256 != res.SHA256 || idx[1].Result != "ok" {
		t.Fatalf("index %+v %v", idx, err)
	}
	// A changed archive fails the recorded checksum.
	_ = os.WriteFile(res.Path, append(raw, 'x'), 0o600)
	if _, err := VerifyChecksum(res.Path); err == nil {
		t.Fatal("tampered archive passed the checksum")
	}
}

func TestRestoreVerifiesBeforeSwapping(t *testing.T) {
	// SR-7.8-1: isolated directory, archive checksum, journal chain and
	// signatures, policy validation and revocations from the restored and
	// the current journal before the swap. The Policy Store signatures,
	// the re-applied revocations and the graph mirror rebuild are
	// TestRestoreVerifiesPolicyStoreReappliesRevocationsAndRebuildsGraph.
	reqtest.Partial(t, "SR-7.8-1")
	revoked := audit.Event{Class: "revocation", Origin: "E-22", Outcome: "revoked", ReasonCode: "CLIENT_REVOKED", PrincipalID: "p1"}
	dir, state, cfg, pol := install(t, revoked)
	res, err := Create(filepath.Join(dir, "backups"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"})})
	if err != nil {
		t.Fatal(err)
	}
	// After the backup: a later revocation in the current journal, and a
	// changed policy file.
	priv, _ := keys.LoadEvidenceKey(state)
	j, err := audit.Open(filepath.Join(state, "journal"), priv, audit.Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Commit(audit.Event{Class: "session", Origin: "E-04", Outcome: "revoked", ReasonCode: "SESSION_REVOKED", SessionID: "s9"})
	_ = j.Close()
	_ = os.WriteFile(pol, []byte(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1)), 0o644)

	opts := RestoreOptions{Archive: res.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol}
	bad := opts
	bad.Decryption.Passphrase = "nope"
	if _, err := Restore(bad); err == nil {
		t.Fatal("wrong passphrase restored")
	}
	verify := opts
	verify.VerifyOnly = true
	rep, err := Restore(verify)
	if err != nil || rep.Applied || len(rep.Revocations) != 2 || !rep.ChecksumVerified {
		t.Fatalf("verify-only %+v %v", rep, err)
	}
	if b, _ := os.ReadFile(pol); !strings.Contains(string(b), `"r2"`) {
		t.Fatal("verify-only changed the policy")
	}
	rep, err = Restore(opts)
	if err != nil || !rep.Applied || rep.PolicyRevision != "r1" || rep.PreviousState == "" {
		t.Fatalf("restore %+v %v", rep, err)
	}
	if b, _ := os.ReadFile(pol); !strings.Contains(string(b), `"r1"`) {
		t.Fatal("policy not restored")
	}
	if _, err := os.Stat(filepath.Join(rep.PreviousState, "journal")); err != nil {
		t.Fatal("previous journal not kept")
	}
	b, err := os.ReadFile(filepath.Join(state, RevocationsFile))
	if err != nil || !strings.Contains(string(b), "CLIENT_REVOKED") || !strings.Contains(string(b), "SESSION_REVOKED") {
		t.Fatalf("revocations file %s %v", b, err)
	}
	root, _ := keys.LoadEvidenceTrustRoot(state)
	if _, err := audit.Verify(filepath.Join(state, "journal"), root); err != nil {
		t.Fatalf("restored journal: %v", err)
	}
	if es, _ := filepath.Glob(filepath.Join(dir, ".smcp-restore-*")); len(es) != 0 {
		t.Fatalf("isolated directory left behind: %v", es)
	}

	// A backup of a damaged journal is refused before anything changes.
	seg := filepath.Join(state, "journal", "segment-000001.jsonl")
	sb, _ := os.ReadFile(seg)
	_ = os.WriteFile(seg, []byte(strings.Replace(string(sb), "CLIENT_REVOKED", "CLIENT_REVOKEX", 1)), 0o600)
	res2, err := Create(filepath.Join(dir, "backups"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"}),
		Now: func() time.Time { return time.Now().Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(pol)
	if _, err := Restore(RestoreOptions{Archive: res2.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol}); err == nil || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("damaged journal restored: %v", err)
	}
	if after, _ := os.ReadFile(pol); string(after) != string(before) {
		t.Fatal("refused restore changed files")
	}
}

// TestRestoreReappliesDirectoryRevocations: a backup taken before a
// principal suspension and a credential revocation does not bring them
// back; the restore writes them into the restored principal directory
// before service starts. A principal enabled again after its suspension
// stays enabled. Partial for SR-7.8-1 (the other clauses are
// TestRestoreVerifiesPolicyStoreReappliesRevocationsAndRebuildsGraph).
func TestRestoreReappliesDirectoryRevocations(t *testing.T) {
	reqtest.Partial(t, "SR-7.8-1")
	dir, state, cfg, pol := install(t)
	const directory = `{"version": 1, "principals": [], "credentials": [
  {"client_id": "c1", "principal": "p1", "redirect_uris": ["http://127.0.0.1/cb"], "created_by": "admin", "created_at": "2026-10-01T00:00:00Z"},
  {"client_id": "c2", "principal": "p1", "redirect_uris": ["http://127.0.0.1/cb"], "created_by": "admin", "created_at": "2026-10-01T00:00:00Z"}],
 "suspended": {}, "future_field": "kept"}`
	if err := os.WriteFile(filepath.Join(state, principalsFile), []byte(directory), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Create(filepath.Join(dir, "backups"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"})})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := keys.LoadEvidenceKey(state)
	j, err := audit.Open(filepath.Join(state, "journal"), priv, audit.Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []audit.Event{
		{Class: "admin", Origin: "E-24", Outcome: "principal_suspended", ReasonCode: "PRINCIPAL_SUSPENDED", PrincipalID: "p1", Detail: map[string]any{"reason": "lost laptop"}},
		{Class: "admin", Origin: "E-24", Outcome: "credential_revoke_requested", ReasonCode: "CREDENTIAL_REVOKED", PrincipalID: "p1", Detail: map[string]any{"client_id": "c1"}},
		{Class: "admin", Origin: "E-24", Outcome: "principal_suspended", ReasonCode: "PRINCIPAL_SUSPENDED", PrincipalID: "p2", Detail: map[string]any{"reason": "x"}},
		{Class: "admin", Origin: "E-24", Outcome: "principal_enabled", ReasonCode: "PRINCIPAL_ENABLED", PrincipalID: "p2", Detail: map[string]any{"reason": "y"}},
	} {
		time.Sleep(2 * time.Millisecond)
		if err := j.Commit(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = j.Close()
	rep, err := Restore(RestoreOptions{Archive: res.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol})
	if err != nil || !rep.Applied || rep.DirectoryChanges != 2 {
		t.Fatalf("restore %+v %v", rep, err)
	}
	b, err := os.ReadFile(filepath.Join(state, principalsFile))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Credentials []struct {
			ClientID  string  `json:"client_id"`
			RevokedAt *string `json:"revoked_at"`
		} `json:"credentials"`
		Suspended map[string]any `json:"suspended"`
		Future    string         `json:"future_field"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Suspended["p1"]; !ok || len(st.Suspended) != 1 || st.Future != "kept" {
		t.Fatalf("restored directory: %s", b)
	}
	for _, c := range st.Credentials {
		if (c.ClientID == "c1") != (c.RevokedAt != nil) {
			t.Fatalf("credential %s revoked_at %v: %s", c.ClientID, c.RevokedAt, b)
		}
	}
	if !after("2026-10-17T11:00:00.12Z", "2026-10-17T11:00:00.1Z") || after("", "2026-10-17T11:00:00Z") {
		t.Fatal("after compares RFC 3339 times as strings")
	}
}

// TestComponentsNameTheStores: the manifest's component list names the
// signed Policy Store and the Local Server Registry where they live in the
// state directory, each once.
func TestComponentsNameTheStores(t *testing.T) {
	got := components([]FileEntry{{Path: "state/policy/active.json"}, {Path: "policy/policy.json"}, {Path: "state/packages/registry.json"},
		{Path: "state/journal/segment-1.jsonl"}}, nil)
	if strings.Join(got, " ") != "evidence_journal policy_store server_registry" {
		t.Fatalf("components %v", got)
	}
}

// signedStore writes a signed Policy Store with the test policy active.
func signedStore(t *testing.T, state string) *policystore.Store {
	t.Helper()
	st, err := policystore.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	rev, _, err := st.Put([]byte(testPolicy), policystore.Meta{Actor: "admin", Origin: "import"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Activate(rev, "admin"); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestRestoreVerifiesPolicyStoreReappliesRevocationsAndRebuildsGraph
// (SR-7.8-1): a backup taken before revocations is restored through an
// isolated directory next to the state directory (removed afterwards)
// after the archive checksum, the journal chain and signatures and the
// restored Policy Store's revision and control-record signatures are
// verified; every revocation recorded in the current journal after the
// backup (a principal suspension, a package revocation, a dynamic client
// registration revocation) is re-applied to the restored state; the graph
// mirror, which held the newer events, is wiped and rebuilt from the
// restored journal before the swap. A verify-only restore leaves the graph
// alone, and an archive whose Policy Store no longer verifies is refused
// without changing the installation. Sessions are not persisted, so a
// restore has no session to revoke. The archive checks against altered
// archives and journals are TestRestoreVerifiesBeforeSwapping; credential
// revocations and re-enabled principals are
// TestRestoreReappliesDirectoryRevocations.
func TestRestoreVerifiesPolicyStoreReappliesRevocationsAndRebuildsGraph(t *testing.T) {
	reqtest.Verifies(t, "SR-7.8-1")
	dir, state, cfg, pol := install(t, audit.Event{Class: "admin", Origin: "E-24", Outcome: "x"})
	signedStore(t, state)
	const registry = `{"version": 1, "revisions": [
  {"server_id": "fx", "revision": "1", "state": "enabled", "alias": "fx", "state_changed_at": "2026-10-01T00:00:00Z", "tools": ["echo"]},
  {"server_id": "fx", "revision": "0", "state": "retired", "alias": "fx", "state_changed_at": "2026-10-01T00:00:00Z", "tools": ["echo"]}]}`
	_ = os.MkdirAll(filepath.Join(state, "packages"), 0o700)
	if err := os.WriteFile(filepath.Join(state, "packages", "registry.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, principalsFile), []byte(`{"version": 1, "principals": [], "credentials": [], "suspended": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const clients = `[{"client_id": "dcr-1", "redirect_uris": ["https://a.example/cb"], "grant_types": ["authorization_code"], "token_endpoint_auth_method": "none",
  "status": "approved", "principal": "p1", "registered_at": "2026-10-01T00:00:00Z"},
 {"client_id": "dcr-2", "redirect_uris": ["https://b.example/cb"], "grant_types": ["authorization_code"], "token_endpoint_auth_method": "none",
  "status": "approved", "principal": "p1", "registered_at": "2026-10-01T00:00:01Z"}]`
	_ = os.MkdirAll(filepath.Join(state, "remote"), 0o700)
	if err := os.WriteFile(filepath.Join(state, "remote", "clients.json"), []byte(clients), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Create(filepath.Join(dir, "backups"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"})})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := keys.LoadEvidenceKey(state)
	j, err := audit.Open(filepath.Join(state, "journal"), priv, audit.Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []audit.Event{
		{Class: "package", Origin: "E-13", Outcome: "revoked", ReasonCode: "REVOKED", ServerRevision: "fx@1", PolicyStatus: "not_evaluated", Detail: map[string]any{"reason": "key compromise"}},
		{Class: "package", Origin: "E-13", Outcome: "revoked", ReasonCode: "REVOKED", ServerRevision: "fy@3", PolicyStatus: "not_evaluated"},
		{Class: "client_registration", Origin: "E-24", Outcome: "revoked", ReasonCode: "DCR_REVOKED", ClientID: "dcr-1", PolicyStatus: "not_evaluated"},
		{Class: "admin", Origin: "E-24", Outcome: "principal_suspended", ReasonCode: "PRINCIPAL_SUSPENDED", PrincipalID: "p1", Detail: map[string]any{"reason": "lost laptop"}},
	} {
		if err := j.Commit(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = j.Close()

	// Verify only: revocations are found, the graph is not touched.
	fake := graph.NewFake()
	rep, err := Restore(RestoreOptions{Archive: res.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol,
		VerifyOnly: true, GraphBackend: fake})
	if err != nil || rep.Applied || rep.PolicyStoreRevision != "r1" || rep.PolicyRevisionsVerified != 1 || rep.PackageRevocations != 1 || rep.ClientRevocations != 1 ||
		!strings.Contains(rep.GraphMirror, "verify only") || fake.Writes() != 0 {
		t.Fatalf("verify only %+v %v (graph writes %d)", rep, err, fake.Writes())
	}

	// The graph mirrors the current journal, with the events written after
	// the backup; the rebuild must remove them.
	mcfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	mcfg.State.Dir = state
	m, err := graph.New(graph.Options{Config: mcfg, Backend: fake, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	m.Start(t.Context(), nil)
	for _, err := m.DAS(); err != nil; _, err = m.DAS() {
		time.Sleep(10 * time.Millisecond)
	}
	if err := m.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	m.Close()
	current, _ := audit.ReadEvents(filepath.Join(state, "journal"))
	if fake.Count("AuditEvent") != len(current) {
		t.Fatalf("mirror of the current journal: %d of %d", fake.Count("AuditEvent"), len(current))
	}
	rep, err = Restore(RestoreOptions{Archive: res.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol,
		GraphBackend: fake, GraphTimeout: 30 * time.Second})
	if err != nil || !rep.Applied || rep.GraphMirror != "rebuilt from the restored journal" || !rep.ChecksumVerified || rep.DirectoryChanges != 1 ||
		filepath.Dir(rep.Isolated) != filepath.Dir(state) || rep.PreviousState == "" {
		t.Fatalf("restore %+v %v", rep, err)
	}
	if _, err := os.Stat(rep.Isolated); !os.IsNotExist(err) {
		t.Fatalf("isolated directory left behind: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(state, principalsFile)); !strings.Contains(string(b), `"p1"`) {
		t.Fatalf("principal suspension not re-applied: %s", b)
	}
	restored, err := audit.ReadEvents(filepath.Join(state, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.JournalEvents != len(restored) {
		t.Fatalf("journal verified %d events, restored %d", rep.JournalEvents, len(restored))
	}
	if got := fake.Count("AuditEvent"); got != len(restored) || len(restored) >= len(current) {
		t.Fatalf("graph holds %d audit events, restored journal %d", got, len(restored))
	}
	var reg struct {
		Revisions []struct {
			ServerID, Revision, State string
			StateReason               string `json:"state_reason"`
		} `json:"revisions"`
		Revocations map[string]string `json:"revocations"`
	}
	b, _ := os.ReadFile(filepath.Join(state, "packages", "registry.json"))
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	for _, r := range reg.Revisions {
		want := map[string]string{"1": "revoked", "0": "retired"}[r.Revision]
		if r.State != want {
			t.Fatalf("revision %s is %s, want %s: %s", r.Revision, r.State, want, b)
		}
	}
	if _, ok := reg.Revocations["fx@1"]; !ok {
		t.Fatalf("revocation of fx@1 not recorded: %s", b)
	}
	if _, ok := reg.Revocations["fy@3"]; !ok { // not in the registry: a later import is refused
		t.Fatalf("revocation of fy@3 not recorded: %s", b)
	}
	var regs []struct {
		ClientID string `json:"client_id"`
		Status   string `json:"status"`
	}
	b, _ = os.ReadFile(filepath.Join(state, "remote", "clients.json"))
	if err := json.Unmarshal(b, &regs); err != nil {
		t.Fatal(err)
	}
	for _, g := range regs {
		if (g.ClientID == "dcr-1") != (g.Status == "revoked") {
			t.Fatalf("registration %s is %s: %s", g.ClientID, g.Status, b)
		}
	}

	// An archive whose Policy Store no longer verifies is refused.
	ctl := filepath.Join(state, policystore.ControlFile)
	raw, _ := os.ReadFile(ctl)
	_ = os.WriteFile(ctl, []byte(strings.Replace(string(raw), `"admin"`, `"intruder"`, 1)), 0o600)
	bad, err := Create(filepath.Join(dir, "backups2"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"})})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(ctl)
	if _, err := Restore(RestoreOptions{Archive: bad.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol,
		GraphBackend: fake}); err == nil || !strings.Contains(err.Error(), "Policy Store") {
		t.Fatalf("tampered Policy Store restored: %v", err)
	}
	if after, _ := os.ReadFile(ctl); string(after) != string(before) {
		t.Fatal("refused restore changed the installation")
	}
}

// TestRestoreGraphUnavailable: with the graph database down, the restore
// is refused before the swap; a best-effort restore (upgrade rollback)
// completes and reports the mirror as not rebuilt.
func TestRestoreGraphUnavailable(t *testing.T) {
	reqtest.Partial(t, "SR-7.8-1")
	dir, state, cfg, pol := install(t, audit.Event{Class: "admin", Origin: "E-24", Outcome: "x"})
	res, err := Create(filepath.Join(dir, "backups"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"})})
	if err != nil {
		t.Fatal(err)
	}
	fake := graph.NewFake()
	fake.Fail(graph.ErrUnavailable)
	o := RestoreOptions{Archive: res.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol,
		GraphBackend: fake, GraphTimeout: 500 * time.Millisecond}
	if rep, err := Restore(o); err == nil || rep.Applied || !strings.Contains(err.Error(), "graph") {
		t.Fatalf("restore with the graph down: %+v %v", rep, err)
	}
	o.GraphBestEffort = true
	rep, err := Restore(o)
	if err != nil || !rep.Applied || !strings.Contains(rep.GraphMirror, "not rebuilt") {
		t.Fatalf("best-effort restore %+v %v", rep, err)
	}
}
