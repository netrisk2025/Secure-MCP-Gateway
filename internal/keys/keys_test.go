package keys

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestPasswordHash(t *testing.T) {
	// CP-28 parameters; no SRS requirement is about password hashing alone.
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("CP-28 parameters missing: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "wrong") || VerifyPassword("garbage", "x") {
		t.Fatal("verification wrong")
	}
	// A crafted hash with a huge memory parameter is refused without work.
	huge := strings.Replace(h, "m=65536", "m=4194304", 1)
	if VerifyPassword(huge, "correct horse battery") {
		t.Fatal("oversized parameters accepted")
	}
	if d := DummyHash(); !strings.HasPrefix(d, "$argon2id$") || VerifyPassword(d, "") {
		t.Fatal("dummy hash")
	}
}

func TestEnsureKeys(t *testing.T) {
	// FR-7.7 and FR-7.8 are verified by inspection
	// (docs/verification/inspections.md); this covers the files Ensure makes.
	reqtest.Partial(t, "FR-7.7", "FR-7.8")
	dir := t.TempDir()
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{CAKeyFile, ServerKeyFile, EvidenceKeyFile, AdminTokenFile} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", f, st.Mode().Perm())
		}
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool := x509.NewCertPool()
	ca, _ := os.ReadFile(filepath.Join(dir, CACertFile))
	pool.AppendCertsFromPEM(ca)
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	priv, err := LoadEvidenceKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadEvidencePublicKey(dir)
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatal("evidence key pair mismatch")
	}
	if tok, err := LoadAdminToken(dir); err != nil || len(tok) < 43 {
		t.Fatalf("admin token %q %v", tok, err)
	}
	// Idempotent: a second Ensure keeps the keys.
	before, _ := os.ReadFile(filepath.Join(dir, EvidenceKeyFile))
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, EvidenceKeyFile))
	if string(before) != string(after) {
		t.Fatal("Ensure regenerated existing keys")
	}
}

func TestCANameConstraintsAndLifetimes(t *testing.T) {
	reqtest.Partial(t, "SR-2.8-1")
	dir := t.TempDir()
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	caCert, err := loadCert(filepath.Join(dir, CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := loadCert(filepath.Join(dir, ServerCertFile))
	if !caCert.PermittedDNSDomainsCritical || len(caCert.PermittedDNSDomains) == 0 {
		t.Fatalf("CA lacks name constraints: %v", caCert.PermittedDNSDomains)
	}
	// No iPAddress subtrees: BoringSSL rejects them (CP-53).
	if len(caCert.PermittedIPRanges) != 0 || len(caCert.ExcludedIPRanges) != 0 {
		t.Fatalf("CA has iPAddress constraints: %v %v", caCert.PermittedIPRanges, caCert.ExcludedIPRanges)
	}
	if !caCert.MaxPathLenZero {
		t.Fatal("CA may issue intermediates")
	}
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life > LeafLifetime+2*time.Hour {
		t.Fatalf("leaf lifetime %v exceeds 90 days", life)
	}
	if life := caCert.NotAfter.Sub(caCert.NotBefore); life > CALifetime+2*time.Hour {
		t.Fatalf("CA lifetime %v", life)
	}
	// A certificate for a public name signed by this CA fails verification.
	caKeyPEM, _ := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if len(caKeyPEM) == 0 {
		t.Fatal("no CA key")
	}
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{CACertFile, CAKeyFile, ServerCertFile, ServerKeyFile} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		os.WriteFile(filepath.Join(other, f), b, 0o600)
	}
	// RotateIfDue with a public name reissues a leaf the CA's constraints reject.
	if _, err := RotateIfDue(other, time.Now(), "gateway.example.com"); err != nil {
		t.Fatal(err)
	}
	evil, _ := loadCert(filepath.Join(other, ServerCertFile))
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := evil.Verify(x509.VerifyOptions{Roots: pool, DNSName: "gateway.example.com"}); err == nil {
		t.Fatal("name-constrained CA vouched for a public name")
	}
}

func TestRotateIfDue(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	st, err := RotateIfDue(dir, time.Now())
	if err != nil || st.LeafRotated || st.CADue {
		t.Fatalf("fresh certificates rotated: %+v %v", st, err)
	}
	// Near leaf expiry (but before CA expiry) the leaf is reissued.
	before := st.LeafNotAfter
	st, err = RotateIfDue(dir, before.Add(-RotateBefore+time.Hour))
	if err != nil || !st.LeafRotated {
		t.Fatalf("leaf not rotated: %+v %v", st, err)
	}
	// Near CA expiry the CA is reported and the leaf is capped at the CA's
	// expiry; after it, reissue is refused.
	st, err = RotateIfDue(dir, st.CANotAfter.Add(-time.Hour))
	if err != nil || !st.CADue || st.LeafNotAfter.After(st.CANotAfter) {
		t.Fatalf("CA expiry not reported: %+v %v", st, err)
	}
	if _, err = RotateIfDue(dir, st.CANotAfter.Add(time.Hour)); err == nil {
		t.Fatal("leaf reissued from an expired CA")
	}
}
