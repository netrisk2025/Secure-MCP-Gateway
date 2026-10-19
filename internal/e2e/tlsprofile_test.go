package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestTLSProfileOnBothListeners is SR-2.8-1 on the two listeners it names:
// the harness listener (E-01) and the console and control API listener
// (E-24). On each, a TLS 1.3 client that trusts only the Gateway server CA
// and names the configured listener name connects, and the leaf
// certificate is issued by that CA; a client limited to TLS 1.2 is
// refused; a client naming another host fails certificate verification;
// and a client that does not trust the Gateway CA fails verification.
func TestTLSProfileOnBothListeners(t *testing.T) {
	reqtest.Verifies(t, "SR-2.8-1")
	f := start(t, "")
	raw, err := os.ReadFile(filepath.Join(f.stateDir, keys.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		t.Fatal("CA certificate")
	}
	for name, addr := range map[string]string{"harness listener": f.cfg.Listener.Address, "console and control API listener": f.cfg.AdminListener.Address} {
		dial := func(c *tls.Config) (*tls.Conn, error) {
			conn, err := tls.Dial("tcp", addr, c)
			if err == nil {
				t.Cleanup(func() { conn.Close() })
			}
			return conn, err
		}
		conn, err := dial(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatalf("%s: TLS 1.3 with the configured name: %v", name, err)
		}
		st := conn.ConnectionState()
		if st.Version != tls.VersionTLS13 || len(st.VerifiedChains) == 0 {
			t.Fatalf("%s: version %x, %d verified chains", name, st.Version, len(st.VerifiedChains))
		}
		chain := st.VerifiedChains[0]
		if root := chain[len(chain)-1]; string(root.Raw) != string(caRaw(t, raw)) {
			t.Fatalf("%s: chain does not end at the Gateway CA: %s", name, root.Subject)
		}
		if _, err := dial(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}); err == nil {
			t.Fatalf("%s: TLS 1.2 accepted", name)
		}
		_, err = dial(&tls.Config{RootCAs: pool, ServerName: "gateway.example", MinVersion: tls.VersionTLS13})
		var he x509.HostnameError
		if !errors.As(err, &he) {
			t.Fatalf("%s: mismatched name: %v", name, err)
		}
		_, err = dial(&tls.Config{RootCAs: x509.NewCertPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
		var ua x509.UnknownAuthorityError
		if !errors.As(err, &ua) {
			t.Fatalf("%s: untrusted CA: %v", name, err)
		}
	}
}

// caRaw returns the DER bytes of the PEM CA certificate.
func caRaw(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		t.Fatal("CA certificate is not PEM")
	}
	return b.Bytes
}
