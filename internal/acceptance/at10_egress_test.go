package acceptance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const at10Policy = `{
  "revision": "at10-r1",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [
      {"id": "ref", "server": "ref", "tools": ["echo"]},
      {"id": "eg", "server": "eg", "tools": ["fetch", "echo"]}
    ]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// dnsFixture is a UDP DNS server for the broker's resolver ([egress]
// resolvers). It answers A queries from a table; a name with several
// answers returns them in turn and then repeats the last (a rebinding
// server). AAAA queries get an empty answer.
type dnsFixture struct {
	pc      net.PacketConn
	mu      sync.Mutex
	answers map[string][]string
	asked   map[string]int
}

func newDNSFixture(t *testing.T, answers map[string][]string) *dnsFixture {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &dnsFixture{pc: pc, answers: answers, asked: map[string]int{}}
	t.Cleanup(func() { pc.Close() })
	go d.serve()
	return d
}

func (d *dnsFixture) addr() string { return d.pc.LocalAddr().String() }

func (d *dnsFixture) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := d.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
		b.EnableCompression()
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAnswers()
		d.mu.Lock()
		seq, known := d.answers[name]
		if q.Type == dnsmessage.TypeA && known {
			i := min(d.asked[name], len(seq)-1)
			d.asked[name]++
			ip := net.ParseIP(seq[i]).To4()
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}, dnsmessage.AResource{A: [4]byte(ip)})
		}
		d.mu.Unlock()
		if !known {
			b = dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: dnsmessage.RCodeNameError})
			_ = b.StartQuestions()
			_ = b.Question(q)
		}
		msg, err := b.Finish()
		if err == nil {
			_, _ = d.pc.WriteTo(msg, from)
		}
	}
}

// testCA issues one certificate for names, signed by a new CA; it returns
// the TLS certificate and the CA in PEM.
func testCA(t *testing.T, names ...string) (tls.Certificate, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AT-10 test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// lastDenials lists the reason codes and details of the journal's denied
// and failed call events, for a failure message.
func lastDenials(g *gateway) string {
	var b strings.Builder
	for _, e := range g.events() {
		if e.str("reason_code") != "" && e.str("class") != "egress" {
			d, _ := json.Marshal(e.detail())
			fmt.Fprintf(&b, "%s %s %s\n", e.str("phase"), e.str("reason_code"), d)
		}
	}
	return b.String()
}

// probe is the EGRESS fixture's report of one brokered operation.
type probe struct {
	Status       int    `json:"status"`
	Reason       string `json:"reason"`
	Body         string `json:"body"`
	Error        string `json:"error"`
	ReplayStatus int    `json:"replay_status"`
	ReplayReason string `json:"replay_reason"`
	Tokens       int    `json:"tokens"`
}

// TestAT10WebBroker is acceptance scenario AT-10 (SRS Appendix M) against
// the real smcpd: a server (the EGRESS fixture of smcp-hostile) reaches
// HTTPS and HTTP destinations only through the Egress Broker, presenting
// the one-use capabilities the Gateway delivers with each call. The
// broker resolves names with its own resolver (a DNS fixture here) and
// originates TLS to endpoints with a test CA (ca_file).
//
//   - grant scope (SR-4.5-2): an ungranted host and an ungranted method
//     are refused; a granted endpoint request succeeds;
//   - one-use capabilities (SR-5.16-1): no capability, a replayed one and
//     one of another destination are refused, the destination never sees
//     the header, and the evidence names the call that minted it;
//   - reserved addresses and rebinding (SR-5.15-2, SR-5.15-1): a granted
//     name that resolves to a private address is refused before any
//     connection, and a name whose second answer is a loopback address
//     not listed in the grant is refused on the second operation;
//   - redirects (SR-5.15-1): a chain of 3 is followed, a fourth hop, a
//     redirect to a private address and one to an ungranted host are
//     refused;
//   - public fetch (SR-5.19-1): GET succeeds; POST, a body, an
//     Authorization header, an upgrade, CONNECT and plain HTTP through
//     the proxy are refused.
func TestAT10WebBroker(t *testing.T) {
	needBinaries(t)
	cert, caPEM := testCA(t, "web.test", "pub.test", "inner.test")
	var mu sync.Mutex
	var sawAuth []string
	record := func(r *http.Request) {
		mu.Lock()
		sawAuth = append(sawAuth, r.Header.Get("Smcp-Egress-Auth"))
		mu.Unlock()
	}
	var tport int
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		switch {
		case r.URL.Path == "/ok":
			io.WriteString(w, "web-ok")
		case strings.HasPrefix(r.URL.Path, "/chain/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/chain/"))
			if n == 0 {
				io.WriteString(w, "landed")
				return
			}
			http.Redirect(w, r, fmt.Sprintf("/chain/%d", n-1), http.StatusFound)
		case r.URL.Path == "/to-private":
			http.Redirect(w, r, fmt.Sprintf("https://inner.test:%d/ok", tport), http.StatusFound)
		case r.URL.Path == "/to-ungranted":
			http.Redirect(w, r, fmt.Sprintf("https://evil.test:%d/ok", tport), http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	tlsSrv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	tport = tlsSrv.Listener.Addr().(*net.TCPAddr).Port
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		io.WriteString(w, "plain-ok")
	}))
	defer plain.Close()
	hport := plain.Listener.Addr().(*net.TCPAddr).Port
	dns := newDNSFixture(t, map[string][]string{
		"web.test": {"127.0.0.1"}, "pub.test": {"127.0.0.1"}, "tunnel.test": {"127.0.0.1"},
		"inner.test":  {"192.168.77.1"},
		"rebind.test": {"127.0.0.1", "127.0.0.2"},
	})

	dir := t.TempDir()
	caFile := writeFile(t, dir, "egress-ca.pem", string(caPEM), 0o644)
	extra := fmt.Sprintf("\n[[server]]\nalias = \"eg\"\ncommand = %q\nargs = [\"-fixture\", \"EGRESS\"]\n", filepath.Join(binDir, "smcp-hostile"))
	if requestedProfile() == reqtest.Enforced {
		extra += "\n[[runtime.server]]\nalias = \"eg\"\nnetwork = \"egress\"\n"
	}
	extra += fmt.Sprintf(`
[egress]
enabled = true
resolvers = [%q]
ca_file = %q

[[egress.grant]]
server = "eg"
host = "web.test"
ports = [%[3]d]
methods = ["GET"]
addresses = ["127.0.0.1"]
endpoint_env = "WEB_URL"

[[egress.grant]]
server = "eg"
host = "inner.test"
ports = [%[3]d]
methods = ["GET"]

[[egress.grant]]
server = "eg"
host = "pub.test"
ports = [%[3]d]
methods = ["GET"]
class = "public-fetch"
addresses = ["127.0.0.1"]
endpoint_env = "PUB_URL"

[[egress.grant]]
server = "eg"
host = "rebind.test"
ports = [%[4]d]
methods = ["GET"]
addresses = ["127.0.0.1"]

[[egress.grant]]
server = "eg"
host = "tunnel.test"
ports = [%[4]d]
methods = ["CONNECT-TLS"]
addresses = ["127.0.0.1"]
`, dns.addr(), caFile, tport, hport)
	g := newGateway(t, options{extra: extra})
	g.writePolicy(at10Policy)
	g.start()
	g.scenario("AT-10")
	reqtest.Partial(t, "SR-4.5-2", "SR-5.15-1", "SR-5.15-2", "SR-5.19-1", "SR-5.16-1")

	cs := g.session(g.token(""))
	do := func(args map[string]any) probe {
		t.Helper()
		text, isErr, err := call(cs, "eg_fetch", args)
		if err != nil || isErr {
			t.Fatalf("eg_fetch %v: %v %v %q\n%s", args, err, isErr, text, lastDenials(g))
		}
		var p probe
		if err := json.Unmarshal([]byte(text), &p); err != nil {
			t.Fatalf("eg_fetch %v: %q", args, text)
		}
		return p
	}
	web := func(path string) map[string]any {
		return map[string]any{"via": "endpoint", "env": "WEB_URL", "path": path}
	}
	pub := func(extra map[string]any) map[string]any {
		a := map[string]any{"via": "endpoint", "env": "PUB_URL", "path": "/ok"}
		for k, v := range extra {
			a[k] = v
		}
		return a
	}
	with := func(a map[string]any, k string, v any) map[string]any { a[k] = v; return a }
	rebind := fmt.Sprintf("http://rebind.test:%d/", hport)

	for _, tc := range []struct {
		name   string
		args   map[string]any
		status int
		reason string
		body   string
	}{
		// Grant scope.
		{"granted endpoint", web("/ok"), 200, "", "web-ok"},
		{"ungranted host", map[string]any{"url": fmt.Sprintf("http://ungranted.test:%d/", hport)}, 403, "EGRESS_NO_GRANT", ""},
		{"ungranted method", map[string]any{"url": rebind, "method": "POST", "body": "x"}, 403, "EGRESS_METHOD_REFUSED", ""},
		{"CONNECT granted", map[string]any{"via": "connect", "target": fmt.Sprintf("tunnel.test:%d", hport)}, 200, "", ""},
		{"CONNECT ungranted", map[string]any{"via": "connect", "target": fmt.Sprintf("web.test:%d", tport)}, 403, "EGRESS_METHOD_REFUSED", ""},
		// One-use capabilities.
		{"no capability", with(web("/ok"), "cap", "none"), 403, "EGRESS_CAPABILITY_REQUIRED", ""},
		{"capability of another destination", with(web("/ok"), "cap", fmt.Sprintf("pub.test:%d", tport)), 403, "EGRESS_CAPABILITY_MISMATCH", ""},
		// Reserved addresses and rebinding.
		{"granted name resolving to a private address", map[string]any{"url": fmt.Sprintf("http://inner.test:%d/ok", tport)}, 403, "EGRESS_ADDRESS_REFUSED", ""},
		{"rebinding, first answer", map[string]any{"url": rebind}, 200, "", "plain-ok"},
		{"rebinding, second answer", map[string]any{"url": rebind}, 403, "EGRESS_ADDRESS_REFUSED", ""},
		// Redirects.
		{"redirect chain of 3", web("/chain/3"), 200, "", "landed"},
		{"redirect chain of 4", web("/chain/4"), 403, "EGRESS_REDIRECT_REFUSED", ""},
		{"redirect to a private address", web("/to-private"), 403, "EGRESS_ADDRESS_REFUSED", ""},
		{"redirect to an ungranted host", web("/to-ungranted"), 403, "EGRESS_REDIRECT_REFUSED", ""},
		// Public fetch.
		{"public-fetch GET", pub(nil), 200, "", "web-ok"},
		{"public-fetch POST", pub(map[string]any{"method": "POST"}), 403, "EGRESS_METHOD_REFUSED", ""},
		{"public-fetch body", pub(map[string]any{"body": "x"}), 403, "EGRESS_PUBLIC_FETCH_PROFILE", ""},
		{"public-fetch Authorization", pub(map[string]any{"auth": "Bearer x"}), 403, "EGRESS_PUBLIC_FETCH_PROFILE", ""},
		{"public-fetch upgrade", pub(map[string]any{"upgrade": true}), 400, "EGRESS_BAD_REQUEST", ""},
		{"public-fetch CONNECT", map[string]any{"via": "connect", "target": fmt.Sprintf("pub.test:%d", tport)}, 403, "EGRESS_METHOD_REFUSED", ""},
		{"public-fetch through the proxy", map[string]any{"url": fmt.Sprintf("http://pub.test:%d/ok", tport)}, 403, "EGRESS_PUBLIC_FETCH_PROFILE", ""},
	} {
		p := do(tc.args)
		if p.Status != tc.status || p.Reason != tc.reason || tc.body != "" && p.Body != tc.body {
			t.Errorf("%s: %+v, want %d %q %q", tc.name, p, tc.status, tc.reason, tc.body)
		}
		if p.Tokens == 0 {
			t.Errorf("%s: the call delivered no egress capabilities", tc.name)
		}
	}
	// A used capability is refused on replay within the same call.
	if p := do(with(web("/ok"), "cap", "replay")); p.Status != 200 || p.ReplayStatus != 403 || p.ReplayReason != "EGRESS_CAPABILITY_REPLAYED" {
		t.Errorf("replay: %+v", p)
	}

	mu.Lock()
	for _, a := range sawAuth {
		if a != "" {
			t.Errorf("a destination received Smcp-Egress-Auth %q", a)
		}
	}
	if len(sawAuth) == 0 {
		t.Error("no request reached a destination")
	}
	mu.Unlock()

	// Evidence: every forwarded operation names the call that minted its
	// capability, and that call is a dispatched eg_fetch call.
	g.stop()
	evs := g.events()
	calls := dispatchedCorrelations(evs)
	authorized := 0
	for _, e := range evs {
		if e.str("class") != "egress" || e.str("phase") != "authorized" {
			continue
		}
		authorized++
		if c := e.str("correlation_id"); c == "" || !calls[c] || e.str("decision_id") == "" || e.str("policy_revision") == "" {
			t.Errorf("authorized egress event without its call: %v", e)
		}
		if e.detail()["capability"] != "consumed" {
			t.Errorf("authorized egress event without a consumed capability: %v", e.detail())
		}
	}
	if authorized < 6 {
		t.Errorf("%d authorized egress events", authorized)
	}
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
}
