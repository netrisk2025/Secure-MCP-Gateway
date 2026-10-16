package keys

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestPasswordHash(t *testing.T) {
	reqtest.Verifies(t, "SR-2.3-1")
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
}

func TestEnsureKeys(t *testing.T) {
	reqtest.Verifies(t, "FR-7.7", "FR-7.8")
	dir := t.TempDir()
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{CAKeyFile, ServerKeyFile, EvidenceKeyFile} {
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
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost"}); err != nil {
		t.Fatal(err)
	}
	priv, err := LoadEvidenceKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadEvidencePublicKey(dir)
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatal("evidence key pair mismatch")
	}
	// Idempotent: a second Ensure keeps the keys.
	before, _ := os.ReadFile(filepath.Join(dir, EvidenceKeyFile))
	Ensure(dir, "127.0.0.1")
	after, _ := os.ReadFile(filepath.Join(dir, EvidenceKeyFile))
	if string(before) != string(after) {
		t.Fatal("Ensure regenerated existing keys")
	}
}
