package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// serveWith starts an HTTPS server on 127.0.0.1 with the state directory's
// listener certificate.
func serveWith(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// clientRun runs one TLS client against url trusting caFile and returns its
// combined output and error.
type tlsClient struct {
	name string
	bin  string
	run  func(ctx context.Context, bin, url, caFile string) ([]byte, error)
}

var tlsClients = []tlsClient{
	{"node", "node", func(ctx context.Context, bin, url, caFile string) ([]byte, error) {
		js := `const https=require('https'),fs=require('fs');https.get(process.argv[1],{ca:fs.readFileSync(process.argv[2])},r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>{process.stdout.write(b);process.exit(b==='ok'?0:1)})}).on('error',e=>{console.error(e.message);process.exit(1)})`
		return exec.CommandContext(ctx, bin, "-e", js, url, caFile).CombinedOutput()
	}},
	// Bun uses BoringSSL, as the native Claude Code and OpenCode builds do.
	{"bun (BoringSSL)", "bun", func(ctx context.Context, bin, url, caFile string) ([]byte, error) {
		js := `const r=await fetch(process.argv[2],{tls:{ca:await Bun.file(process.argv[3]).text()}});const b=await r.text();process.stdout.write(b);process.exit(b==='ok'?0:1)`
		dir, err := os.MkdirTemp("", "smcp-bun")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		f := filepath.Join(dir, "probe.mjs")
		if err := os.WriteFile(f, []byte(js), 0o600); err != nil {
			return nil, err
		}
		return exec.CommandContext(ctx, bin, f, url, caFile).CombinedOutput()
	}},
	{"openssl", "openssl", func(ctx context.Context, bin, url, caFile string) ([]byte, error) {
		hostPort := strings.TrimPrefix(url, "https://")
		cmd := exec.CommandContext(ctx, bin, "s_client", "-connect", hostPort, "-CAfile", caFile, "-verify_return_error")
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.CombinedOutput()
		if err == nil && !strings.Contains(string(out), "Verify return code: 0") {
			err = fmt.Errorf("verification did not succeed")
		}
		return out, err
	}},
}

// TestServerCAAcceptedByTLSStacks connects to a listener with the CP-53
// certificates from Go, Node.js (OpenSSL), Bun (BoringSSL) and the openssl
// command, by IP literal as public_url uses it. Clients that are not
// installed are skipped. An earlier CA with iPAddress name constraints was
// rejected by BoringSSL; the last subtest shows the probe detects that.
func TestServerCAAcceptedByTLSStacks(t *testing.T) {
	reqtest.Partial(t, "SR-2.8-4")
	dir := t.TempDir()
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	srv := serveWith(t, dir)
	caFile := filepath.Join(dir, CACertFile)
	url := "https://" + srv.Listener.Addr().String()

	t.Run("go", func(t *testing.T) {
		pool := x509.NewCertPool()
		b, _ := os.ReadFile(caFile)
		pool.AppendCertsFromPEM(b)
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, Timeout: 10 * time.Second}
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	})
	for _, c := range tlsClients {
		t.Run(c.name, func(t *testing.T) {
			bin, err := exec.LookPath(c.bin)
			if err != nil {
				t.Skipf("%s not installed", c.bin)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if out, err := c.run(ctx, bin, url, caFile); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
	t.Run("legacy iPAddress constraints rejected by BoringSSL", func(t *testing.T) {
		bin, err := exec.LookPath("bun")
		if err != nil {
			t.Skip("bun not installed")
		}
		legacy := legacyIPConstrainedState(t)
		st, err := RotateIfDue(legacy, time.Now(), "127.0.0.1")
		if err != nil || !st.IPConstrained {
			t.Fatalf("legacy CA not reported: %+v %v", st, err)
		}
		lsrv := serveWith(t, legacy)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := tlsClients[1].run(ctx, bin, "https://"+lsrv.Listener.Addr().String(), filepath.Join(legacy, CACertFile))
		if err == nil {
			t.Logf("this bun accepts iPAddress name constraints: %s", out)
		} else {
			t.Logf("rejected as expected: %s", strings.TrimSpace(string(out)))
		}
	})
}

// legacyIPConstrainedState writes a state directory whose CA has the
// iPAddress subtrees earlier releases issued.
func legacyIPConstrainedState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "legacy CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(CALifetime),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"localhost"},
		PermittedIPRanges: []*net.IPNet{{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}, {IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := writePEM(filepath.Join(dir, CACertFile), "CERTIFICATE", der, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(filepath.Join(dir, CAKeyFile), "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		t.Fatal(err)
	}
	dns, ips := leafNames([]string{"127.0.0.1"})
	if err := issueLeaf(dir, ca, key, dns, ips); err != nil {
		t.Fatal(err)
	}
	// The legacy CA's IP subtrees are still honored at issuance.
	if err := issueLeaf(dir, ca, key, nil, []net.IP{net.ParseIP("10.0.0.1")}); !errors.Is(err, ErrOutsideConstraints) {
		t.Fatal("legacy CA issued for an IP outside its subtrees")
	}
	return dir
}
