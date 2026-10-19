package acceptance

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// controlPaths are control API routes of several elements; each needs an
// administrator, so an answer other than 401 on the admin listener, or any
// answer that is not a refusal elsewhere, would mean the control API is
// reachable with the credential or on the listener under test.
var controlPaths = []struct{ method, path string }{
	{"GET", "/admin/v1/health"},
	{"GET", "/api/v1/health/status"},
	{"GET", "/api/v1/sessions"},
	{"GET", "/api/v1/audit/events"},
	{"GET", "/api/v1/policy/revisions"},
	{"GET", "/api/v1/packages"},
	{"POST", "/admin/v1/stop"},
	{"POST", "/api/v1/principals"},
}

// harnessClientCert issues a TLS client certificate for the harness
// principal under the Gateway's own CA: the strongest certificate a
// harness could hold.
func harnessClientCert(t *testing.T, g *gateway) tls.Certificate {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(g.state, "tls", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(g.state, "tls", "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(caPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		t.Fatal("CA certificate or key is not PEM")
	}
	ca, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var caKey any
	if caKey, err = x509.ParseECPrivateKey(kb.Bytes); err != nil {
		if caKey, err = x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
			t.Fatalf("CA key: %v", err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "claude-code-local"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// controlStatus sends one control API request to base with the given
// bearer token and HTTP client.
func controlStatus(t *testing.T, hc *http.Client, base, method, path, token string, hdr map[string]string) (int, string) {
	t.Helper()
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader(`{"reason":"listener separation test"}`)
	}
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s%s: %v", method, base, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(raw)
}

// TestControlAPIOnlyOnAdminListener is SR-2.5-1 against the real smcpd,
// with every listener a Gateway can open: the CP-02 TLS harness listener,
// the CP-02 UDS harness socket, the metrics listener, the Remote Access
// listener (through a local tunnel) and the CP-03 admin listener.
//
//   - The operator token is accepted on the admin listener and nowhere
//     else: the control routes are not served on any other listener.
//   - Every harness credential is refused by the control API: the OAuth
//     access token and refresh token of a harness session, the UDS bearer
//     key, and a TLS client certificate issued for the harness principal
//     by the Gateway's own CA, alone and together with the access token.
//   - The harness credentials are valid: the same access token completes a
//     tool call on the harness listener.
func TestControlAPIOnlyOnAdminListener(t *testing.T) {
	reqtest.Verifies(t, "SR-2.5-1")
	sock := filepath.Join(testport.SocketDir(t), "h.sock")
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	grp, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("primary group: %v", err)
	}
	const udsKey = "uds harness key for the separation test"
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", testport.Free(t))
	metricsAddr := fmt.Sprintf("127.0.0.1:%d", testport.Free(t))
	g := newGateway(t, options{})
	hashOut, err := g.ctlRaw("hash-password", "--password-file", writeFile(t, t.TempDir(), "uds.key", udsKey+"\n", 0o600))
	if err != nil {
		t.Fatalf("hash-password: %v %s", err, hashOut)
	}
	hash := strings.TrimSpace(hashOut[strings.LastIndex(hashOut, "$argon2id"):])
	g.appendConfig(fmt.Sprintf(`
[uds]
enabled = true
path = %q
group = %q
[[uds.peer]]
uid = %d
principal = "claude-code-local"
key_hash = %q

[[principal]]
id = "cloud"
framework = "grok-bot"
profile = "dev"

[remote]
address = %q
default_principal = "cloud"
templates = ["read-only"]
`, sock, grp.Name, os.Getuid(), hash, remoteAddr))
	// The bootstrap configuration has metrics off; turn them on, on a free port.
	raw, err := os.ReadFile(g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "[metrics]\nenabled = false\n", "[metrics]\nenabled = true\n", 1)
	cfg = strings.Replace(cfg, `address = "127.0.0.1:9464"`, fmt.Sprintf("address = %q", metricsAddr), 1)
	if cfg == string(raw) || !strings.Contains(cfg, metricsAddr) {
		t.Fatalf("metrics table not found in the bootstrap configuration:\n%s", raw)
	}
	if err := os.WriteFile(g.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	g.start()
	public := g.tunnel(remoteAddr)
	if g.profile() == reqtest.Enforced && os.Geteuid() != 0 {
		g.mustSudoCtl("remote", "enable", "--provider", "manual", "--public-url", public)
		t.Cleanup(func() { _, _ = g.sudoCtl("remote", "disable") })
	} else {
		g.mustCtl("remote", "enable", "--provider", "manual", "--public-url", public)
	}

	opTok, err := os.ReadFile(filepath.Join(g.state, "keys", "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	operator := strings.TrimSpace(string(opTok))
	hc := g.httpClient()

	// The control API answers the operator on the admin listener.
	if code, body := controlStatus(t, hc, g.adminURL, "GET", "/api/v1/sessions", operator, nil); code != 200 {
		t.Fatalf("operator on the admin listener: %d %s", code, body)
	}

	// Not served on the other listeners, even with the operator token.
	plain := &http.Client{Timeout: 30 * time.Second}
	others := []struct {
		name string
		hc   *http.Client
		base string
	}{
		{"harness listener", hc, g.publicURL},
		{"remote access listener (through the tunnel)", &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, public}, //nolint:gosec // the local tunnel's certificate names the Gateway, not 127.0.0.1
		{"metrics listener", plain, "http://" + metricsAddr},
	}
	for _, l := range others {
		for _, p := range controlPaths {
			code, body := controlStatus(t, l.hc, l.base, p.method, p.path, operator, nil)
			if code < 400 || strings.Contains(body, `"sessions"`) || strings.Contains(body, `"state"`) {
				t.Errorf("%s served %s %s: %d %s", l.name, p.method, p.path, code, body)
			}
		}
	}
	// The UDS socket speaks newline-delimited JSON-RPC only: an HTTP
	// control request gets no HTTP answer.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET /api/v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", operator)
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if strings.HasPrefix(line, "HTTP/") || strings.Contains(line, `"sessions"`) {
		t.Fatalf("UDS socket answered an HTTP control request: %q", line)
	}

	// Harness credentials on the admin listener.
	access := g.freshToken()
	g.mu.Lock()
	refresh := g.refresh[access][0]
	g.mu.Unlock()
	if refresh == "" {
		t.Fatal("no refresh token from the sign-in")
	}
	cs := g.session(access)
	g.mustCall(cs, "ref_echo", map[string]any{"text": "harness credential works"}, "harness credential works")

	certClient := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: func() *tls.Config {
		c := g.tlsConfig()
		cert := harnessClientCert(t, g)
		c.Certificates = []tls.Certificate{cert}
		c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
		return c
	}()}}
	creds := []struct {
		name  string
		hc    *http.Client
		token string
		hdr   map[string]string
	}{
		{"harness access token", hc, access, nil},
		{"harness refresh token", hc, refresh, nil},
		{"UDS bearer key", hc, udsKey, nil},
		{"harness client certificate", certClient, "", nil},
		{"harness client certificate and access token", certClient, access, nil},
		{"access token in the session cookie header", hc, "", map[string]string{"Cookie": "__Host-smcp-session=" + access, "X-SMCP-Session": "cookie"}},
	}
	for _, cr := range creds {
		for _, p := range controlPaths {
			if code, body := controlStatus(t, cr.hc, g.adminURL, p.method, p.path, cr.token, cr.hdr); code != http.StatusUnauthorized {
				t.Errorf("%s on %s %s: %d %s", cr.name, p.method, p.path, code, body)
			}
		}
	}
	if st := g.health(); st["state"] == "emergency_stop" || strings.Contains(fmt.Sprint(st["causes"]), "emergency") {
		t.Fatalf("a refused request stopped the Gateway: %v", st)
	}
}
