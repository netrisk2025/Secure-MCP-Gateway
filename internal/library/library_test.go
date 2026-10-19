package library

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type env struct {
	t     *testing.T
	state string
	lib   *Library
	key   pkgtest.Key
	rec   *audit.Memory
	now   time.Time
	n     int
}

func newEnv(t *testing.T, classes ...string) *env {
	t.Helper()
	e := &env{t: t, state: t.TempDir(), key: pkgtest.NewKey(t), rec: &audit.Memory{}, now: time.Now()}
	if len(classes) == 0 {
		classes = []string{"low", "moderate"}
	}
	pkgtest.Enroll(t, e.state, "operator", e.key, classes, time.Now().Add(24*time.Hour))
	lib, err := Open(Options{StateDir: e.state, Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	lib.SetRecorder(e.rec)
	t.Cleanup(func() { lib.Close() })
	e.lib = lib
	return e
}

// pkg builds a signed package into a fresh directory.
func (e *env) pkg(s pkgtest.Spec) string {
	e.t.Helper()
	e.n++
	return pkgtest.Signed(e.t, filepath.Join(e.t.TempDir(), "pkg"), e.key, s)
}

func reason(err error) string { return packaging.ReasonOf(err) }

func TestRegistryLockIsExclusive(t *testing.T) {
	e := newEnv(t)
	if _, err := Open(Options{StateDir: e.state}); err != ErrLocked {
		t.Fatalf("second open: %v", err)
	}
}

func TestImportRequiresEveryComponent(t *testing.T) {
	reqtest.Verifies(t, "FR-5.2")
	e := newEnv(t)
	cases := []struct {
		name, reason string
		mutate       func(dir string)
	}{
		{"index", packaging.ReasonIndexMissing, func(d string) { os.Remove(filepath.Join(d, packaging.IndexFile)) }},
		{"signature", packaging.ReasonSignatureMissing, func(d string) { os.Remove(filepath.Join(d, packaging.SignatureFile)) }},
		{"manifest", packaging.ReasonManifestMissing, func(d string) { os.Remove(filepath.Join(d, packaging.ManifestFile)) }},
		{"provenance", packaging.ReasonProvenanceMissing, func(d string) { os.Remove(filepath.Join(d, packaging.ProvenanceFile)) }},
		{"artifact", packaging.ReasonArtifactMissing, func(d string) { os.Remove(filepath.Join(d, "artifact", "server")) }},
		{"signer key id", packaging.ReasonSignerKeyIDMissing, func(d string) {
			p := filepath.Join(d, packaging.IndexFile)
			var ix packaging.Index
			raw, _ := os.ReadFile(p)
			json.Unmarshal(raw, &ix)
			ix.SignerKeyID = ""
			packaging.WriteJSON(p, ix, 0o644)
		}},
	}
	for _, c := range cases {
		dir := e.pkg(pkgtest.Spec{ID: "comp", Revision: "1.0.0"})
		c.mutate(dir)
		rc, err := e.lib.Import(dir, ImportOptions{})
		if reason(err) != c.reason || rc.Result != "rejected" || !strings.Contains(err.Error(), c.name) {
			t.Errorf("missing %s: reason %q (%v), want %s", c.name, reason(err), err, c.reason)
		}
	}
	dir := e.pkg(pkgtest.Spec{ID: "comp", Revision: "1.0.0"})
	if rc, err := e.lib.Import(dir, ImportOptions{}); err != nil || rc.Result != "accepted" {
		t.Fatalf("complete package: %v", err)
	}
}

func TestSignatureTrust(t *testing.T) {
	reqtest.Verifies(t, "SR-3-1")
	e := newEnv(t)
	// Unknown key.
	stranger := pkgtest.NewKey(t)
	dir := pkgtest.Signed(t, filepath.Join(t.TempDir(), "p"), stranger, pkgtest.Spec{ID: "a", Revision: "1"})
	if _, err := e.lib.Import(dir, ImportOptions{}); reason(err) != packaging.ReasonSignerUnknown {
		t.Errorf("unknown key: %v", err)
	}
	// Expired anchor.
	exp := pkgtest.NewKey(t)
	pkgtest.Enroll(t, e.state, "expiring", exp, nil, time.Now().Add(time.Hour))
	dir = pkgtest.Signed(t, filepath.Join(t.TempDir(), "p"), exp, pkgtest.Spec{ID: "b", Revision: "1"})
	e.now = time.Now().Add(2 * time.Hour)
	if _, err := e.lib.Import(dir, ImportOptions{}); reason(err) != packaging.ReasonAnchorExpired {
		t.Errorf("expired anchor: %v", err)
	}
	e.now = time.Now()
	// Out of scope: the operator anchor admits low and moderate only.
	dir = e.pkg(pkgtest.Spec{ID: "c", Revision: "1", Risk: "high"})
	if _, err := e.lib.Import(dir, ImportOptions{}); reason(err) != packaging.ReasonAnchorScope {
		t.Errorf("out-of-scope anchor: %v", err)
	}
	// A tampered index fails the signature.
	dir = e.pkg(pkgtest.Spec{ID: "d", Revision: "1"})
	p := filepath.Join(dir, packaging.IndexFile)
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(raw), `"risk_class": "low"`, `"risk_class": "low" `, 1)), 0o644)
	if _, err := e.lib.Import(dir, ImportOptions{}); reason(err) != packaging.ReasonSignatureInvalid {
		t.Errorf("tampered index: %v", err)
	}
	// In scope and valid.
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "e", Revision: "1", Risk: "moderate"}), ImportOptions{}); err != nil {
		t.Errorf("valid package: %v", err)
	}
}

func TestOperatorAnchorScope(t *testing.T) {
	reqtest.Verifies(t, "FR-14.8")
	e := newEnv(t, "low") // replaced below
	state := t.TempDir()
	a, _ := packaging.LoadAnchors(state)
	def := pkgtest.NewKey(t)
	hi := pkgtest.NewKey(t)
	an, err := a.Add("default", def.Public, nil, time.Now().Add(time.Hour), time.Now(), "t")
	if err != nil || strings.Join(an.Classes, ",") != "low,moderate" {
		t.Fatalf("default classes: %v %v", an.Classes, err)
	}
	if _, err := a.Add("with-high", hi.Public, []string{"low", "moderate", "high"}, time.Now().Add(time.Hour), time.Now(), "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add("no-expiry", pkgtest.NewKey(t).Public, nil, time.Now().Add(-time.Second), time.Now(), "t"); err == nil {
		t.Error("an anchor without a future expiry was enrolled")
	}
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	e.lib.Close()
	lib, err := Open(Options{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Close()
	d1 := pkgtest.Signed(t, filepath.Join(t.TempDir(), "p"), def, pkgtest.Spec{ID: "hi-a", Revision: "1", Risk: "high"})
	if _, err := lib.Import(d1, ImportOptions{}); reason(err) != packaging.ReasonAnchorScope {
		t.Errorf("high package under default anchor: %v", err)
	}
	d2 := pkgtest.Signed(t, filepath.Join(t.TempDir(), "p"), hi, pkgtest.Spec{ID: "hi-b", Revision: "1", Risk: "high"})
	if _, err := lib.Import(d2, ImportOptions{}); err != nil {
		t.Errorf("high package under high anchor: %v", err)
	}
}

func TestSourceEvidenceAndProvenanceBinding(t *testing.T) {
	reqtest.Verifies(t, "SR-3.1-1", "SR-3.2-1")
	e := newEnv(t)
	cases := []struct {
		name   string
		reason string
		edit   func(m *packaging.Manifest, p *packaging.Provenance)
	}{
		{"no source digest in the manifest", packaging.ReasonManifestSchema, func(m *packaging.Manifest, p *packaging.Provenance) { m.Provenance.Source.SHA256 = "" }},
		{"no licenses in the manifest", packaging.ReasonManifestSchema, func(m *packaging.Manifest, p *packaging.Provenance) { m.Provenance.Licenses = nil }},
		{"non-SPDX license", packaging.ReasonManifestSchema, func(m *packaging.Manifest, p *packaging.Provenance) { m.Provenance.Licenses = []string{"see LICENSE"} }},
		{"no source in the statement", packaging.ReasonSourceEvidence, func(m *packaging.Manifest, p *packaging.Provenance) { p.Source = packaging.Source{} }},
		{"no licenses in the statement", packaging.ReasonSourceEvidence, func(m *packaging.Manifest, p *packaging.Provenance) { p.Licenses = nil }},
		{"statement names another artifact", packaging.ReasonProvenanceBinding, func(m *packaging.Manifest, p *packaging.Provenance) {
			p.Artifact.SHA256 = strings.Repeat("0", 64)
		}},
		{"statement names another source", packaging.ReasonProvenanceBinding, func(m *packaging.Manifest, p *packaging.Provenance) {
			p.Source.SHA256 = strings.Repeat("1", 64)
		}},
		{"manifest names another statement", packaging.ReasonProvenanceBinding, func(m *packaging.Manifest, p *packaging.Provenance) {
			m.Provenance.StatementSHA256 = strings.Repeat("2", 64)
		}},
	}
	for i, c := range cases {
		dir := e.pkg(pkgtest.Spec{ID: "prov", Revision: "1." + string(rune('0'+i)), Edit: c.edit})
		if _, err := e.lib.Import(dir, ImportOptions{}); reason(err) != c.reason {
			t.Errorf("%s: %v, want %s", c.name, err, c.reason)
		}
	}
}

func TestRollbackProtection(t *testing.T) {
	reqtest.Verifies(t, "SR-3-5")
	e := newEnv(t)
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "rb", Revision: "2.10.0"}), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	old := e.pkg(pkgtest.Spec{ID: "rb", Revision: "2.9.1"})
	if _, err := e.lib.Import(old, ImportOptions{}); reason(err) != ReasonDowngrade {
		t.Fatalf("downgrade without authorization: %v", err)
	}
	if _, err := e.lib.Import(old, ImportOptions{AllowDowngrade: true, Actor: "admin:alice"}); err != nil {
		t.Fatalf("authorized downgrade: %v", err)
	}
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "rb", Revision: "2.11.0"}), ImportOptions{}); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if compareRevision("2026.8.31", "2026.10.1") >= 0 || compareRevision("1.0.0", "1.0.0") != 0 || compareRevision("1.2", "1.10") >= 0 {
		t.Fatal("compareRevision")
	}
}

func TestImmutableRevisionAndReceipts(t *testing.T) {
	reqtest.Verifies(t, "FR-5.4", "FR-5.5")
	e := newEnv(t)
	dir := e.pkg(pkgtest.Spec{ID: "imm", Revision: "1.0.0", Expires: "2099-01-01", Edit: func(m *packaging.Manifest, p *packaging.Provenance) {
		m.Capabilities.Filesystem = []packaging.FilesystemSlot{{Slot: "data", Mode: "ro"}}
		m.Capabilities.Egress = []packaging.EgressRule{{Host: "example.org", Ports: []int{443}, Methods: []string{"GET"}}}
		m.Secrets = []packaging.SecretSlot{{Slot: "token", Purpose: "api", Modes: []string{"S2"}}}
		m.BehaviorHints = json.RawMessage(`{"rules":[{"kind":"no_process_spawn"}]}`)
		m.InstanceScope = []string{"per-session", "shared"}
		m.Attestations = &packaging.Attestations{ReviewStatus: "reviewed", RecurationDue: "2099-01-01"}
	}})
	rc, err := e.lib.Import(dir, ImportOptions{Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	// Receipt for an accepted import.
	var got Receipt
	raw, err := os.ReadFile(rc.File)
	if err != nil || json.Unmarshal(raw, &got) != nil {
		t.Fatalf("receipt: %v", err)
	}
	if got.Result != "accepted" || got.ServerID != "imm" || got.ArtifactSHA256 == "" || got.SignerKeyID != e.key.ID || got.Anchor != "operator" || got.Time == "" || len(got.Checks) < 7 {
		t.Fatalf("receipt: %+v", got)
	}
	// Receipt for a rejected import.
	bad := e.pkg(pkgtest.Spec{ID: "imm", Revision: "1.0.1"})
	os.WriteFile(filepath.Join(bad, "artifact", "server"), []byte("changed"), 0o755)
	rc2, err := e.lib.Import(bad, ImportOptions{})
	if err == nil {
		t.Fatal("tampered artifact imported")
	}
	raw, _ = os.ReadFile(rc2.File)
	var rej Receipt
	json.Unmarshal(raw, &rej)
	if rej.Result != "rejected" || rej.ReasonCode != packaging.ReasonDigestMismatch || rej.ServerID != "imm" || rej.SignerKeyID == "" || rej.Error == "" {
		t.Fatalf("rejected receipt: %+v", rej)
	}
	// Evidence for both attempts.
	var outcomes []string
	for _, ev := range e.rec.Events() {
		outcomes = append(outcomes, ev.Outcome)
	}
	if !strings.Contains(strings.Join(outcomes, ","), "imported,import_rejected") {
		t.Fatalf("evidence: %v", outcomes)
	}
	// The stored revision holds every manifest field group, read-only.
	m, _, err := e.lib.Manifest("imm", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 1 || m.Tools[0].InputSchema == nil || len(m.Capabilities.Filesystem) != 1 || len(m.Capabilities.Egress) != 1 ||
		len(m.Secrets) != 1 || len(m.BehaviorHints) == 0 || len(m.InstanceScope) != 2 || m.Attestations.ReviewStatus != "reviewed" {
		t.Fatalf("stored manifest lost a field group: %+v", m)
	}
	st, _ := os.Stat(filepath.Join(e.lib.revisionDir("imm", "1.0.0"), packaging.ManifestFile))
	if st.Mode().Perm()&0o222 != 0 {
		t.Fatalf("stored manifest is writable: %v", st.Mode())
	}
	// Re-importing the same package is a no-op; a different package with the
	// same revision is refused (revisions are immutable).
	if rc, err := e.lib.Import(dir, ImportOptions{}); err != nil || rc.Result != "unchanged" {
		t.Fatalf("re-import: %v %v", rc.Result, err)
	}
	other := e.pkg(pkgtest.Spec{ID: "imm", Revision: "1.0.0", Tools: nil, Artifact: []byte("other")})
	if _, err := e.lib.Import(other, ImportOptions{}); reason(err) != ReasonRevisionConflict {
		t.Fatalf("conflicting revision: %v", err)
	}
	r, _ := e.lib.Get("imm", "1.0.0")
	if r.State != StateVerifiedDisabled {
		t.Fatalf("imported revision state %s, want verified-disabled", r.State)
	}
}

func TestStateMachineAndAuthorization(t *testing.T) {
	// SR-3.9-1: automatic enablement after import is refused here; the
	// non-Administrator roles are refused by the control API (api_test).
	reqtest.Partial(t, "SR-3.9-1", "FR-5.7")
	e := newEnv(t)
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "sm", Revision: "1"}), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	// Import alone never enables (SR-3.9-1); the control API is the only
	// network path, and it authenticates Administrators (api_test).
	if r, _ := e.lib.Get("sm", "1"); r.State != StateVerifiedDisabled {
		t.Fatal(r.State)
	}
	steps := []struct {
		to   string
		ok   bool
		call func() error
	}{
		{StateEnabled, true, func() error { _, err := e.lib.Enable("sm", "1", EnableOptions{Actor: "admin:a"}); return err }},
		{StateVerifiedDisabled, true, func() error {
			_, _, err := e.lib.SetState("sm", "1", StateVerifiedDisabled, "r", "admin:a")
			return err
		}},
		{StateEnabled, true, func() error { _, err := e.lib.Enable("sm", "1", EnableOptions{Actor: "admin:a"}); return err }},
		{StateSuspended, true, func() error { _, _, err := e.lib.SetState("sm", "1", StateSuspended, "r", "admin:a"); return err }},
		{StateEnabled, true, func() error { _, err := e.lib.Enable("sm", "1", EnableOptions{Actor: "admin:a"}); return err }},
		{StateRetired, true, func() error { _, _, err := e.lib.SetState("sm", "1", StateRetired, "r", "admin:a"); return err }},
		{StateEnabled, false, func() error { _, err := e.lib.Enable("sm", "1", EnableOptions{Actor: "admin:a"}); return err }},
	}
	for i, s := range steps {
		err := s.call()
		r, _ := e.lib.Get("sm", "1")
		if s.ok && (err != nil || r.State != s.to) {
			t.Fatalf("step %d to %s: %v (state %s)", i, s.to, err, r.State)
		}
		if !s.ok && (err == nil || reason(err) != ReasonState) {
			t.Fatalf("step %d: retired revision enabled: %v", i, err)
		}
	}
	if _, _, err := e.lib.SetState("sm", "1", StateRevoked, "r", "a"); reason(err) != ReasonState {
		t.Fatalf("revocation without an entry: %v", err)
	}
}

func TestEnablementDigestBinding(t *testing.T) {
	reqtest.Verifies(t, "SR-3.7-1")
	e := newEnv(t)
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "bind", Revision: "1"}), ImportOptions{})
	r, err := e.lib.Enable("bind", "1", EnableOptions{Actor: "admin:a"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := e.lib.Manifest("bind", "1")
	want, _ := EnablementDigest(m)
	if r.EnablementSHA256 == "" || r.EnablementSHA256 != want {
		t.Fatalf("enablement digest %q, want %q", r.EnablementSHA256, want)
	}
	m.Tools[0].Description = "changed"
	if d, _ := EnablementDigest(m); d == want {
		t.Fatal("the digest does not cover tool descriptions")
	}
	m, _, _ = e.lib.Manifest("bind", "1")
	m.Capabilities.SpawnsProcesses = true
	if d, _ := EnablementDigest(m); d == want {
		t.Fatal("the digest does not cover capabilities")
	}
	found := false
	for _, ev := range e.rec.Events() {
		if ev.Outcome == "enabled" {
			found = ev.Detail.(map[string]any)["enablement_sha256"] == want
		}
	}
	if !found {
		t.Fatal("enablement evidence lacks the digest")
	}
}

func TestStandaloneRefusesHighRisk(t *testing.T) {
	reqtest.Verifies(t, "SR-4-1")
	e := newEnv(t, "low", "moderate", "high")
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "hi", Revision: "1", Risk: "high"}), ImportOptions{})
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "mod", Revision: "1", Risk: "moderate", Alias: "mod"}), ImportOptions{})
	if _, err := e.lib.Enable("hi", "1", EnableOptions{Standalone: true}); reason(err) != ReasonProfile {
		t.Fatalf("high in standalone: %v", err)
	}
	if _, err := e.lib.Enable("mod", "1", EnableOptions{Standalone: true}); err != nil {
		t.Fatalf("moderate in standalone: %v", err)
	}
	// A per-tool high class counts too.
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "tool-hi", Revision: "1", Alias: "th", Edit: func(m *packaging.Manifest, p *packaging.Provenance) {
		m.Tools[0].RiskClass = "high"
	}}), ImportOptions{})
	if _, err := e.lib.Enable("tool-hi", "1", EnableOptions{Standalone: true}); reason(err) != ReasonProfile {
		t.Fatalf("high tool in standalone: %v", err)
	}
	if _, err := e.lib.Enable("hi", "1", EnableOptions{Standalone: false}); err != nil {
		t.Fatalf("high under a confining launcher: %v", err)
	}
}

func TestAliasUniqueness(t *testing.T) {
	reqtest.Verifies(t, "FR-5.6")
	e := newEnv(t)
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "one", Revision: "1", Alias: "files"}), ImportOptions{})
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "two", Revision: "1", Alias: "files"}), ImportOptions{})
	if _, err := e.lib.Enable("one", "1", EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.lib.Enable("two", "1", EnableOptions{}); reason(err) != ReasonAliasConflict {
		t.Fatalf("colliding default alias: %v", err)
	}
	if _, err := e.lib.Enable("two", "1", EnableOptions{Alias: "Bad_Alias"}); reason(err) != ReasonAliasConflict {
		t.Fatalf("invalid alias: %v", err)
	}
	r, err := e.lib.Enable("two", "1", EnableOptions{Alias: "files2", Actor: "admin:a"})
	if err != nil || r.Alias != "files2" {
		t.Fatalf("unique alias: %v %s", err, r.Alias)
	}
}

func TestStatefulRefused(t *testing.T) {
	reqtest.Verifies(t, "SR-3.14-1")
	e := newEnv(t)
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "st", Revision: "1", Stateful: true}), ImportOptions{})
	if _, err := e.lib.Enable("st", "1", EnableOptions{}); reason(err) != ReasonStateful {
		t.Fatalf("stateful: %v", err)
	}
}

func TestExpirySuspends(t *testing.T) {
	reqtest.Verifies(t, "FR-5.8")
	e := newEnv(t)
	day := time.Now().UTC().Format("2006-01-02")
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "exp", Revision: "1", Expires: day}), ImportOptions{})
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "rec", Revision: "1", Alias: "rec", Edit: func(m *packaging.Manifest, p *packaging.Provenance) {
		m.Attestations = &packaging.Attestations{RecurationDue: day}
	}}), ImportOptions{})
	for _, id := range []string{"exp", "rec"} {
		if _, err := e.lib.Enable(id, "1", EnableOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	rep, gone := e.lib.Scan("t")
	if len(rep.Suspended) != 0 || len(gone) != 0 {
		t.Fatalf("suspended before expiry: %+v", rep)
	}
	// The dates are inclusive: both pass at the end of the named day.
	e.now = time.Now().UTC().Add(25 * time.Hour)
	rep, gone = e.lib.Scan("t")
	if len(rep.Suspended) != 2 || len(gone) != 2 {
		t.Fatalf("after expiry: %+v %v", rep, gone)
	}
	for _, id := range []string{"exp", "rec"} {
		if r, _ := e.lib.Get(id, "1"); r.State != StateSuspended {
			t.Fatalf("%s state %s", id, r.State)
		}
		if _, err := e.lib.Enable(id, "1", EnableOptions{}); reason(err) != ReasonExpired {
			t.Fatalf("re-enable after expiry: %v", err)
		}
	}
}

func TestArtifactCacheSharing(t *testing.T) {
	reqtest.Verifies(t, "FR-5.39")
	e := newEnv(t)
	art := []byte("#!/bin/false\nshared artifact\n")
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "cache", Revision: "1", Artifact: art}), ImportOptions{})
	e.lib.Import(e.pkg(pkgtest.Spec{ID: "cache", Revision: "2", Artifact: art}), ImportOptions{})
	sum := packaging.SHA256Hex(art)
	entries, _ := os.ReadDir(e.lib.path("artifacts", "sha256"))
	if len(entries) != 1 || entries[0].Name() != sum {
		t.Fatalf("cache entries: %v", entries)
	}
	if _, _, err := e.lib.SetState("cache", "1", StateRetired, "r", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.lib.ArtifactPath(sum)); err != nil {
		t.Fatal("artifact removed while revision 2 references it")
	}
	if _, _, err := e.lib.SetState("cache", "2", StateRetired, "r", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.lib.ArtifactPath(sum)); !os.IsNotExist(err) {
		t.Fatal("artifact kept after every revision retired")
	}
	if _, err := os.Stat(e.lib.TreePath(sum)); !os.IsNotExist(err) {
		t.Fatal("unpacked tree kept after every revision retired")
	}
}

func TestLibraryScanAndRevocation(t *testing.T) {
	reqtest.Partial(t, "FR-5.3", "FR-14.12") // interval polling and instance teardown in runtime_test
	reqtest.Verifies(t, "FR-5.1")            // a package imported from the directory library
	e := newEnv(t)
	dst := filepath.Join(e.lib.Dir(), "scan", "1")
	if err := packaging.CopyPackage(e.pkg(pkgtest.Spec{ID: "scan", Revision: "1"}), dst); err != nil {
		t.Fatal(err)
	}
	// A broken package is rejected once, not on every scan (an incomplete
	// one, with a component missing, is retried).
	broken := filepath.Join(e.lib.Dir(), "broken")
	os.MkdirAll(broken, 0o755)
	os.WriteFile(filepath.Join(broken, packaging.IndexFile), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(broken, packaging.SignatureFile), []byte("x"), 0o644)
	rep, _ := e.lib.Scan("t")
	if len(rep.Imported) != 1 || rep.Imported[0] != "scan@1" || len(rep.Rejected) != 1 {
		t.Fatalf("scan: %+v", rep)
	}
	if rep, _ = e.lib.Scan("t"); len(rep.Imported)+len(rep.Rejected) != 0 {
		t.Fatalf("second scan repeated work: %+v", rep)
	}
	if _, err := e.lib.Enable("scan", "1", EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	// An unsigned revocation entry is ignored; a signed one revokes.
	os.MkdirAll(filepath.Join(e.lib.Dir(), packaging.RevocationsDir), 0o755)
	os.WriteFile(filepath.Join(e.lib.Dir(), packaging.RevocationsDir, "scan@1.json"), []byte(`{"revocation_version":1,"server_id":"scan","revision":"1"}`), 0o644)
	rep, gone := e.lib.Scan("t")
	if len(rep.Revoked) != 0 || len(gone) != 0 || len(rep.Errors) != 1 {
		t.Fatalf("unsigned revocation: %+v", rep)
	}
	stranger := pkgtest.NewKey(t)
	if _, err := packaging.WriteRevocation(e.lib.Dir(), "scan", "1", "forged", stranger.Private, time.Now()); err != nil {
		t.Fatal(err)
	}
	if rep, _ = e.lib.Scan("t"); len(rep.Revoked) != 0 {
		t.Fatal("revocation by an unknown key accepted")
	}
	if _, err := packaging.WriteRevocation(e.lib.Dir(), "scan", "1", "vulnerability", e.key.Private, time.Now()); err != nil {
		t.Fatal(err)
	}
	rep, gone = e.lib.Scan("t")
	if len(rep.Revoked) != 1 || len(gone) != 1 || gone[0] != "fx" {
		t.Fatalf("revocation: %+v %v", rep, gone)
	}
	if r, _ := e.lib.Get("scan", "1"); r.State != StateRevoked {
		t.Fatalf("state %s", r.State)
	}
	if _, err := e.lib.Enable("scan", "1", EnableOptions{}); reason(err) != ReasonState {
		t.Fatalf("revoked revision enabled: %v", err)
	}
	// A revoked revision cannot be imported again elsewhere.
	if _, err := packaging.WriteRevocation(e.lib.Dir(), "later", "1", "pre-emptive", e.key.Private, time.Now()); err != nil {
		t.Fatal(err)
	}
	e.lib.Scan("t")
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "later", Revision: "1"}), ImportOptions{}); reason(err) != ReasonRevoked {
		t.Fatalf("import of a revoked revision: %v", err)
	}
}
