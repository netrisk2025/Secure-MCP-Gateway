package remote_test

import (
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// RR-07: the remote listener follows listener certificate rotation for new
// connections without the profile being re-enabled.
func TestRemoteListenerFollowsCertificateRotation(t *testing.T) {
	reqtest.Partial(t, "FR-17.7")
	e := newEnv(t, "")
	e.enable()
	serial := func() string {
		t.Helper()
		c, err := tls.Dial("tcp", e.Config.Remote.Address, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // the test reads the served certificate
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	first := serial()
	if _, err := keys.RotateLeaf(filepath.Dir(filepath.Dir(e.Config.Listener.TLSCert)), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	// The reloader checks the file at most once per second.
	deadline := time.Now().Add(5 * time.Second)
	for serial() == first {
		if time.Now().After(deadline) {
			t.Fatal("remote listener still serves the certificate it opened with")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
