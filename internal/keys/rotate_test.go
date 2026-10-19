package keys

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func poolOf(t *testing.T, certs ...*x509.Certificate) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func TestCP53ServerCA(t *testing.T) {
	// SR-2.8-4: CP-53 name constraints, path length and validities; a
	// listener certificate for a name outside the constraints is refused,
	// and a TLS client rejects such a certificate even when the CA signed
	// it (TestEnsureKeys covers the client side with a public name).
	reqtest.Verifies(t, "SR-2.8-4")
	dir := t.TempDir()
	if err := Ensure(dir, "127.0.0.1", "gw.local"); err != nil {
		t.Fatal(err)
	}
	ca, _ := loadCert(filepath.Join(dir, CACertFile))
	leaf, _ := loadCert(filepath.Join(dir, ServerCertFile))
	if d := ca.NotAfter.Sub(ca.NotBefore); d < 365*24*time.Hour || d > 365*24*time.Hour+2*time.Hour {
		t.Fatalf("CA validity %v, want 365 days", d)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d < 90*24*time.Hour || d > 90*24*time.Hour+2*time.Hour {
		t.Fatalf("listener validity %v, want 90 days", d)
	}
	if !ca.MaxPathLenZero || ca.MaxPathLen != 0 || !ca.PermittedDNSDomainsCritical {
		t.Fatal("CA path length or critical constraints")
	}
	wantDNS := map[string]bool{"localhost": true, "gw.local": true}
	for _, d := range ca.PermittedDNSDomains {
		delete(wantDNS, d)
	}
	if len(wantDNS) != 0 {
		t.Fatalf("CA DNS constraints %v", ca.PermittedDNSDomains)
	}
	// CP-53: dNSName subtrees only. iPAddress subtrees make BoringSSL
	// clients reject the chain ("unsupported name constraint type").
	if len(ca.PermittedIPRanges) != 0 || len(ca.ExcludedIPRanges) != 0 {
		t.Fatalf("CA IP constraints %v %v", ca.PermittedIPRanges, ca.ExcludedIPRanges)
	}
	// The listener certificate carries the loopback addresses and the
	// listener IP literal, and verifies for them.
	for _, n := range []string{"localhost", "gw.local", "127.0.0.1", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(t, ca), DNSName: n}); err != nil {
			t.Fatalf("listener name %s: %v", n, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(t, ca), DNSName: "10.0.0.1"}); err == nil {
		t.Fatal("listener certificate covers an IP that is not a listener address")
	}
	key, err := loadECKey(filepath.Join(dir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	// DNS names outside the constraints are refused at issuance.
	if err := issueLeaf(dir, ca, key, []string{"gateway.example.com"}, nil); !errors.Is(err, ErrOutsideConstraints) {
		t.Fatalf("outside name: %v", err)
	}
	// RotateIfDue leaves an outside name out of the leaf and reports it.
	st, err := RotateIfDue(dir, time.Now(), "127.0.0.1", "gateway.example.com")
	if err != nil || len(st.Uncovered) != 1 || st.Uncovered[0] != "gateway.example.com" {
		t.Fatalf("uncovered %+v %v", st, err)
	}
}

func TestCARotationOverlap(t *testing.T) {
	// FR-17.7 CA clause: during the overlap the listener still presents the
	// outgoing CA's certificate, so clients trusting the outgoing CA
	// connect, and the published bundle holds both CAs; a client that
	// trusts only the incoming CA connects after the switch. The whole
	// requirement under traffic is TestOpsKeyRotationUnderTraffic
	// (internal/e2e).
	reqtest.Partial(t, "FR-17.7")
	dir := t.TempDir()
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	oldCA, _ := loadCert(filepath.Join(dir, CACertFile))
	now := time.Now()
	rot, _, err := BeginCARotation(dir, now, 24*time.Hour, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := BeginCARotation(dir, now, time.Hour); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("second rotation: %v", err)
	}
	bundle, err := loadBundle(filepath.Join(dir, CACertFile))
	if err != nil || len(bundle) != 2 || !bundle[0].Equal(oldCA) {
		t.Fatalf("bundle during overlap: %d %v", len(bundle), err)
	}
	newCA := bundle[1]
	leaf, _ := loadCert(filepath.Join(dir, ServerCertFile))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(t, oldCA), DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("old-CA client during overlap: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(t, bundle...), DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("bundle client during overlap: %v", err)
	}
	// Not yet due: nothing switches.
	if switched, _, err := AdvanceCARotation(dir, now.Add(time.Hour), "127.0.0.1"); err != nil || switched {
		t.Fatalf("early switch %v %v", switched, err)
	}
	st, err := ReadStatus(dir, now)
	if err != nil || st.CARotation == nil || st.CARotation.SwitchAt.Sub(rot.SwitchAt) != 0 || len(st.TrustBundle) != 2 {
		t.Fatalf("status during overlap %+v %v", st, err)
	}
	// At the end of the overlap the new CA becomes active.
	switched, _, err := AdvanceCARotation(dir, now.Add(25*time.Hour), "127.0.0.1")
	if err != nil || !switched {
		t.Fatalf("switch %v %v", switched, err)
	}
	leaf, _ = loadCert(filepath.Join(dir, ServerCertFile))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(t, newCA), DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("new-CA client after switch: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(t, oldCA), DNSName: "127.0.0.1"}); err == nil {
		t.Fatal("old CA still vouches for the listener after the switch")
	}
	active, _ := loadBundle(filepath.Join(dir, CACertFile))
	if len(active) != 1 || !active[0].Equal(newCA) {
		t.Fatal("bundle after switch")
	}
	if _, err := os.Stat(filepath.Join(dir, CARetiredDir, "ca-"+oldCA.SerialNumber.Text(16)+".crt")); err != nil {
		t.Fatal("outgoing CA not retired")
	}
	for _, f := range []string{CANextCertFile, CANextKeyFile, CARotationFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Fatalf("%s left behind", f)
		}
	}
	// Overlap 0 switches at once.
	if _, _, err := BeginCARotation(dir, now, 0, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := LoadCARotation(dir); r != nil {
		t.Fatal("zero overlap left a rotation in progress")
	}
	if _, err := FinishCARotation(dir, now); err == nil {
		t.Fatal("finish without a rotation")
	}
}

func TestCertReloaderServesRotatedLeaf(t *testing.T) {
	// FR-17.7 TLS clause at the listener: a rotated certificate is used for
	// new connections without restarting; an open connection continues.
	reqtest.Partial(t, "FR-17.7")
	dir := t.TempDir()
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	r, err := NewCertReloader(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	url := "https://" + ln.Addr().String()
	ca, _ := loadCert(filepath.Join(dir, CACertFile))
	serialOf := func(c *http.Client) string {
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.TLS.PeerCertificates[0].SerialNumber.String()
	}
	keep := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: poolOf(t, ca), MinVersion: tls.VersionTLS13}}}
	first := serialOf(keep)
	if _, err := RotateLeaf(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	fresh := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: poolOf(t, ca), MinVersion: tls.VersionTLS13}}}
	if second := serialOf(fresh); second == first {
		t.Fatal("new connection still got the old certificate")
	}
	if again := serialOf(keep); again != first {
		t.Fatal("kept-alive connection was replaced")
	}
}

func TestPendingEvidenceKey(t *testing.T) {
	// Crash-safe storage of an evidence-key rotation (FR-17.7 evidence
	// clause, key side).
	reqtest.Partial(t, "FR-17.7")
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	root, _ := LoadEvidenceTrustRoot(dir)
	_ = os.Remove(filepath.Join(dir, EvidenceGenesisFile)) // an installation from before rotation existed
	next, err := NewEvidenceKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := StagePendingEvidenceKey(dir, next); err != nil {
		t.Fatal(err)
	}
	if g, _ := LoadEvidenceTrustRoot(dir); !g.Equal(root) {
		t.Fatal("genesis key not recorded")
	}
	// The journal did not hand over: the pending key is discarded.
	if act, err := ResolvePendingEvidenceKey(dir, ""); err != nil || act != "discarded" {
		t.Fatalf("resolve %q %v", act, err)
	}
	if cur, _ := LoadEvidencePublicKey(dir); !cur.Equal(root) {
		t.Fatal("current key changed on discard")
	}
	// The journal handed over: the pending key is committed.
	_ = StagePendingEvidenceKey(dir, next)
	nextPub := hex.EncodeToString(next.Public().(ed25519.PublicKey))
	if act, err := ResolvePendingEvidenceKey(dir, nextPub); err != nil || act != "committed" {
		t.Fatalf("resolve %q %v", act, err)
	}
	cur, _ := LoadEvidencePublicKey(dir)
	priv, _ := LoadEvidenceKey(dir)
	if !cur.Equal(next.Public()) || !priv.Equal(next) {
		t.Fatal("pending key not committed")
	}
	if g, _ := LoadEvidenceTrustRoot(dir); !g.Equal(root) {
		t.Fatal("trust root changed by rotation")
	}
	if act, _ := ResolvePendingEvidenceKey(dir, nextPub); act != "" {
		t.Fatal("nothing pending, but resolved")
	}
	st, err := ReadStatus(dir, time.Now())
	if err != nil || st.EvidenceKey != nextPub || st.EvidenceRoot != hex.EncodeToString(root) || st.InstallationID == "" || st.PendingRotate {
		t.Fatalf("status %+v %v", st, err)
	}
}
