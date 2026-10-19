package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// fakeResolver answers from a table; a host with several answer lists
// returns them in turn (the last one repeats), which models a rebinding
// DNS server.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]string
	calls   map[string]int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seq, ok := f.answers[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	i := min(f.calls[host], len(seq)-1)
	f.calls[host]++
	var out []netip.Addr
	for _, s := range seq[i] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

type harness struct {
	t      *testing.T
	b      *Broker
	ev     *audit.Memory
	res    *fakeResolver
	grants *StaticGrants
	mu     sync.Mutex
	dialed []string
}

func newHarness(t *testing.T, grants []Grant, lim Limits, mod ...func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, ev: &audit.Memory{}, res: &fakeResolver{answers: map[string][][]string{}}, grants: NewStaticGrants(grants)}
	d := &net.Dialer{Timeout: 2 * time.Second}
	o := Options{Grants: h.grants, Evidence: h.ev, Resolver: h.res, Limits: lim, ProxyEnv: true, Recent: 100, Servers: []string{"web"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h.mu.Lock()
			h.dialed = append(h.dialed, addr)
			h.mu.Unlock()
			if _, err := netip.ParseAddrPort(addr); err != nil {
				return nil, fmt.Errorf("broker dialed a name, not a validated address: %s", addr)
			}
			return d.DialContext(ctx, network, addr)
		}}
	for _, m := range mod {
		m(&o)
	}
	b, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	h.b = b
	t.Cleanup(func() { b.Close() })
	return h
}

func (h *harness) attach() *pipeline.EgressAttachment {
	h.t.Helper()
	att, err := h.b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web"})
	if err != nil {
		h.t.Fatal(err)
	}
	return att
}

func (h *harness) dials() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dialed...)
}

func proxyClient(att *pipeline.EgressAttachment, roots *x509.CertPool, serverName string) *http.Client {
	pu, _ := url.Parse(att.Env["HTTP_PROXY"])
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func portOfURL(t *testing.T, raw string) int {
	u, _ := url.Parse(raw)
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func waitRecords(t *testing.T, b *Broker, n int) []Record {
	t.Helper()
	for range 200 {
		if rs := b.Recent(); len(rs) >= n {
			return rs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d egress records, have %d", n, len(b.Recent()))
	return nil
}

func reasonOf(resp *http.Response) string { return resp.Header.Get(ReasonHeader) }

var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

// TestProxyAllowsGrantedHTTP: a granted plain-HTTP request is forwarded
// to the validated address, with Cookie, Set-Cookie and the egress
// capability header removed, and the operation is recorded with host,
// port, address, bytes and decision.
func TestProxyAllowsGrantedHTTP(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-2", "SR-5.17-1")
	var gotCookie, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie, gotAuth = r.Header.Get("Cookie"), r.Header.Get(AuthHeader)
		http.SetCookie(w, &http.Cookie{Name: "track", Value: "1"})
		io.WriteString(w, "hello "+r.URL.Path)
	}))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	h := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{port}, Methods: []string{"GET"}, Class: ClassAPI, Addresses: loopback}}, Limits{})
	h.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	if att.Enforced || att.Env["HTTPS_PROXY"] == "" || att.Env["HTTP_PROXY"] != att.Env["https_proxy"] {
		t.Fatalf("attachment: %+v", att)
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://api.test:%d/x", port), nil)
	req.Header.Set("Cookie", "session=secret")
	req.Header.Set(AuthHeader, "capability")
	resp, err := proxyClient(att, nil, "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello /x" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if gotCookie != "" || gotAuth != "" || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("cookie %q auth %q set-cookie %q", gotCookie, gotAuth, resp.Header.Get("Set-Cookie"))
	}
	rec := waitRecords(t, h.b, 1)[0]
	if rec.Decision != DecisionAllowed || rec.Reason != "" || rec.Host != "api.test" || rec.Port != port || rec.Address != "127.0.0.1" ||
		rec.BytesDown != int64(len(body)) || rec.Status != 200 || rec.Mode != ModeHTTP {
		t.Fatalf("record %+v", rec)
	}
	var phases []audit.Phase
	for _, ev := range h.ev.Events() {
		if ev.Class == "egress" && ev.Origin == Origin {
			phases = append(phases, ev.Phase)
		}
	}
	if strings.Join(phasesStr(phases), ",") != ",authorized,completed" { // attached has no phase
		t.Fatalf("phases %v", phases)
	}
}

func phasesStr(ps []audit.Phase) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

// TestProxyRefusesUngranted: a destination no grant names, a method the
// grant does not list and a port outside the grant are refused before any
// connection is made.
func TestProxyRefusesUngranted(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-2")
	h := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{8080}, Methods: []string{"GET"}, Addresses: loopback}}, Limits{})
	h.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	h.res.answers["other.test"] = [][]string{{"93.184.216.34"}}
	att := h.attach()
	c := proxyClient(att, nil, "")
	for _, tc := range []struct{ method, url, reason string }{
		{"GET", "http://other.test:8080/", ReasonNoGrant},
		{"POST", "http://api.test:8080/", ReasonMethod},
		{"GET", "http://api.test:8081/", ReasonNoGrant},
	} {
		req, _ := http.NewRequest(tc.method, tc.url, strings.NewReader(""))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if tc.reason != "" && reasonOf(resp) != tc.reason || resp.StatusCode < 400 {
			t.Fatalf("%s %s: %d %s", tc.method, tc.url, resp.StatusCode, reasonOf(resp))
		}
	}
	// HTTPS through CONNECT to an ungranted host.
	if _, err := c.Get("https://other.test:8080/"); err == nil {
		t.Fatal("CONNECT to an ungranted host succeeded")
	}
	if d := h.dials(); len(d) != 0 {
		t.Fatalf("broker dialed %v for refused operations", d)
	}
	for _, r := range h.b.Recent() {
		if r.Decision != DecisionDenied || r.Reason == "" {
			t.Fatalf("record %+v", r)
		}
	}
}

// TestReservedAddressesRefused attempts each reserved class for IPv4 and
// IPv6 through the broker and confirms refusal without a dial, and that
// a grant naming the exact address permits it.
func TestReservedAddressesRefused(t *testing.T) {
	reqtest.Verifies(t, "SR-5.15-2")
	cases := map[string]string{
		"127.0.0.1": AddrLoopback, "127.255.0.9": AddrLoopback, "::1": AddrLoopback,
		"10.1.2.3": AddrPrivate, "172.16.5.4": AddrPrivate, "192.168.1.1": AddrPrivate, "fd12:3456::1": AddrPrivate,
		"169.254.10.10": AddrLinkLocal, "fe80::1": AddrLinkLocal,
		"100.64.0.1": AddrCGNAT, "100.127.255.254": AddrCGNAT,
		"224.0.0.1": AddrMulticast, "239.1.1.1": AddrMulticast, "ff02::1": AddrMulticast,
		"0.0.0.0": AddrReserved, "240.0.0.1": AddrReserved, "255.255.255.255": AddrReserved, "192.0.2.1": AddrReserved,
		"198.18.0.1": AddrReserved, "2001:db8::1": AddrReserved, "::": AddrReserved, "100::1": AddrReserved, "2001::1": AddrReserved,
		"169.254.169.254": AddrMetadata, "fd00:ec2::254": AddrMetadata, "100.100.100.200": AddrMetadata,
		"::ffff:10.0.0.1": AddrPrivate, "64:ff9b::a00:1": AddrPrivate, "2002:a00:1::": AddrPrivate, "64:ff9b::a9fe:a9fe": AddrMetadata,
		"8.8.8.8": AddrPublic, "2606:4700::1111": AddrPublic, "64:ff9b::808:808": AddrPublic,
	}
	for a, want := range cases {
		if got := Classify(netip.MustParseAddr(a)); got != want {
			t.Errorf("Classify(%s) = %s, want %s", a, got, want)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	var grants []Grant
	i := 0
	hosts := map[string]string{}
	for a, class := range cases {
		if class == AddrPublic {
			continue
		}
		host := fmt.Sprintf("h%d.test", i)
		i++
		hosts[host] = a
		grants = append(grants, Grant{Server: "web", Host: host, Ports: []int{port}, Methods: []string{"GET", MethodConnect}})
	}
	// Literal addresses are refused as well.
	grants = append(grants, Grant{Server: "web", Host: "169.254.169.254", Ports: []int{port}, Methods: []string{"GET"}},
		Grant{Server: "web", Host: "exact.test", Ports: []int{port}, Methods: []string{"GET"}, Addresses: loopback})
	h := newHarness(t, grants, Limits{RequestsPerMinute: 1000})
	for host, a := range hosts {
		h.res.answers[host] = [][]string{{a}}
	}
	h.res.answers["exact.test"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	c := proxyClient(att, nil, "")
	for host, a := range hosts {
		resp, err := c.Get(fmt.Sprintf("http://%s:%d/", host, port))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || reasonOf(resp) != ReasonAddressRefused {
			t.Errorf("%s -> %s: %d %s", host, a, resp.StatusCode, reasonOf(resp))
		}
		if _, err := c.Get(fmt.Sprintf("https://%s:%d/", host, port)); err == nil {
			t.Errorf("CONNECT %s -> %s succeeded", host, a)
		}
	}
	resp, err := c.Get(fmt.Sprintf("http://169.254.169.254:%d/latest/meta-data/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if reasonOf(resp) != ReasonAddressRefused {
		t.Fatalf("metadata literal: %d %s", resp.StatusCode, reasonOf(resp))
	}
	if d := h.dials(); len(d) != 0 {
		t.Fatalf("broker dialed reserved addresses: %v", d)
	}
	resp, err = c.Get(fmt.Sprintf("http://exact.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("exact grant: %d %s", resp.StatusCode, reasonOf(resp))
	}
}

// TestRebindingAndRedirects: the broker resolves names itself and dials
// only the address it validated, so a later private answer is refused;
// an endpoint follows at most 3 redirects and re-validates each target.
func TestRebindingAndRedirects(t *testing.T) {
	reqtest.Verifies(t, "SR-5.15-1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	h := newHarness(t, []Grant{{Server: "web", Host: "rebind.test", Ports: []int{port}, Methods: []string{"GET"}, Addresses: loopback}}, Limits{})
	// First answer: the granted address. Second: a private address.
	h.res.answers["rebind.test"] = [][]string{{"127.0.0.1"}, {"10.0.0.7"}}
	att := h.attach()
	c := proxyClient(att, nil, "")
	get := func() *http.Response {
		resp, err := c.Get(fmt.Sprintf("http://rebind.test:%d/", port))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := get(); r.StatusCode != 200 {
		t.Fatalf("first: %d %s", r.StatusCode, reasonOf(r))
	}
	if r := get(); r.StatusCode != http.StatusForbidden || reasonOf(r) != ReasonAddressRefused {
		t.Fatalf("rebound: %d %s", r.StatusCode, reasonOf(r))
	}
	for _, d := range h.dials() {
		if d != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)).String() {
			t.Fatalf("dialed %s", d)
		}
	}

	// Redirect chain on an endpoint: a -> b (private) is refused; a chain
	// of four redirects within the grant is refused at the fourth.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/to-private":
			http.Redirect(w, r, fmt.Sprintf("https://inner.test:%d/", portOfReq(r)), http.StatusFound)
		case r.URL.Path == "/to-ungranted":
			http.Redirect(w, r, fmt.Sprintf("https://elsewhere.test:%d/", portOfReq(r)), http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/hop/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
			if n == 0 {
				io.WriteString(w, "landed")
				return
			}
			http.Redirect(w, r, fmt.Sprintf("/hop/%d", n-1), http.StatusFound)
		default:
			io.WriteString(w, "root")
		}
	}))
	defer tlsSrv.Close()
	tp := portOfURL(t, tlsSrv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	h2 := newHarness(t, []Grant{
		{Server: "web", Host: "example.com", Ports: []int{tp}, Methods: []string{"GET"}, Addresses: loopback, EndpointEnv: "API_URL"},
		{Server: "web", Host: "inner.test", Ports: []int{tp}, Methods: []string{"GET"}},
	}, Limits{}, func(o *Options) { o.RootCAs = pool })
	h2.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	h2.res.answers["inner.test"] = [][]string{{"10.9.9.9"}}
	att2 := h2.attach()
	base := att2.Env["API_URL"]
	for _, tc := range []struct {
		path, reason string
		status       int
	}{
		{"/hop/3", "", 200},
		{"/hop/4", ReasonRedirect, http.StatusForbidden},
		{"/to-private", ReasonAddressRefused, http.StatusForbidden},
		{"/to-ungranted", ReasonRedirect, http.StatusForbidden},
	} {
		resp, err := http.Get(base + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status || reasonOf(resp) != tc.reason {
			t.Fatalf("%s: %d %s %s", tc.path, resp.StatusCode, reasonOf(resp), b)
		}
		if tc.status == 200 && string(b) != "landed" {
			t.Fatalf("%s: %q", tc.path, b)
		}
	}
	for _, d := range h2.dials() {
		if strings.HasPrefix(d, "10.") {
			t.Fatalf("dialed private redirect target %s", d)
		}
	}
}

func portOfReq(r *http.Request) int {
	_, p, _ := net.SplitHostPort(r.Host)
	n, _ := strconv.Atoi(p)
	return n
}

// TestConnectTunnel: CONNECT is spliced without TLS interception (the
// client sees the destination's own certificate), the SNI must name the
// granted host, and non-TLS tunnels are refused.
func TestConnectTunnel(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-2")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "secure") }))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	h := newHarness(t, []Grant{{Server: "web", Host: "example.com", Ports: []int{port}, Methods: []string{MethodConnect}, Addresses: loopback}}, Limits{})
	h.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	resp, err := proxyClient(att, pool, "").Get(fmt.Sprintf("https://example.com:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "secure" || !resp.TLS.PeerCertificates[0].Equal(srv.Certificate()) {
		t.Fatalf("%q", b)
	}
	rec := waitRecords(t, h.b, 1)[0]
	if rec.Mode != ModeConnect || rec.SNI != "example.com" || rec.Decision != DecisionAllowed || rec.BytesUp == 0 || rec.BytesDown == 0 {
		t.Fatalf("record %+v", rec)
	}

	// SNI naming another host than the CONNECT target.
	if _, err := proxyClient(att, pool, "evil.test").Get(fmt.Sprintf("https://example.com:%d/", port)); err == nil {
		t.Fatal("SNI mismatch accepted")
	}
	if rec := waitRecords(t, h.b, 2)[0]; rec.Reason != ReasonSNIMismatch {
		t.Fatalf("record %+v", rec)
	}

	// Plain bytes inside the tunnel.
	pc, err := net.Dial("tcp", strings.TrimPrefix(att.Env["HTTP_PROXY"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	fmt.Fprintf(pc, "CONNECT example.com:%d HTTP/1.1\r\nHost: example.com:%d\r\n\r\n", port, port)
	br := bufio.NewReader(pc)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT answer %q", line)
	}
	io.WriteString(pc, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := br.ReadString('\n'); err != nil {
			break
		}
	}
	if rec := waitRecords(t, h.b, 3)[0]; rec.Reason != ReasonNotTLS {
		t.Fatalf("record %+v", rec)
	}
}

// TestEndpoints grants two destinations, confirms two endpoints exist and
// that requests reach each destination over validated TLS originated by
// the broker; an untrusted certificate fails.
func TestEndpoints(t *testing.T) {
	reqtest.Verifies(t, "FR-5.36")
	reqtest.Partial(t, "FR-5.37")
	mk := func(name string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, name+" "+r.Method+" "+r.URL.RequestURI()+" "+strconv.FormatBool(r.TLS != nil))
		}))
	}
	a, c := mk("alpha"), mk("beta")
	defer a.Close()
	defer c.Close()
	pool := x509.NewCertPool()
	pool.AddCert(a.Certificate())
	pool.AddCert(c.Certificate())
	grants := []Grant{
		{Server: "web", Host: "example.com", Ports: []int{portOfURL(t, a.URL)}, Methods: []string{"GET", "POST"}, Addresses: loopback, EndpointEnv: "ALPHA_URL"},
		{Server: "web", Host: "example.com", Ports: []int{portOfURL(t, c.URL)}, Methods: []string{"GET"}, Addresses: loopback, EndpointEnv: "BETA_URL"},
	}
	h := newHarness(t, grants, Limits{}, func(o *Options) { o.RootCAs = pool })
	h.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	if att.Env["ALPHA_URL"] == "" || att.Env["BETA_URL"] == "" || att.Env["ALPHA_URL"] == att.Env["BETA_URL"] {
		t.Fatalf("env %v", att.Env)
	}
	for env, want := range map[string]string{"ALPHA_URL": "alpha GET /p?q=1 true", "BETA_URL": "beta GET /p?q=1 true"} {
		resp, err := http.Get(att.Env[env] + "/p?q=1")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != want {
			t.Fatalf("%s: %d %q", env, resp.StatusCode, b)
		}
	}
	resp, err := http.Post(att.Env["BETA_URL"]+"/", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if reasonOf(resp) != ReasonMethod {
		t.Fatalf("POST on GET-only endpoint: %d %s", resp.StatusCode, reasonOf(resp))
	}
	// An endpoint is not a general proxy.
	pu, _ := url.Parse(att.Env["ALPHA_URL"])
	resp, err = (&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}).Get("http://elsewhere.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if reasonOf(resp) != ReasonBadRequest {
		t.Fatalf("absolute-form on endpoint: %d %s", resp.StatusCode, reasonOf(resp))
	}

	// Without the test CA the destination certificate does not validate.
	h2 := newHarness(t, grants, Limits{})
	h2.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	att2 := h2.attach()
	resp, err = http.Get(att2.Env["ALPHA_URL"] + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || reasonOf(resp) != ReasonUpstream {
		t.Fatalf("untrusted certificate: %d %s", resp.StatusCode, reasonOf(resp))
	}
}

// TestLimits exceeds request size, response size, duration, request rate
// and byte rate and confirms termination and an event for each.
func TestLimits(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/big-declared":
			w.Header().Set("Content-Length", strconv.Itoa(4096))
			w.Write(make([]byte, 4096))
		case "/big-stream":
			for range 8 {
				w.Write(make([]byte, 1024))
				w.(http.Flusher).Flush()
			}
		case "/slow":
			time.Sleep(700 * time.Millisecond)
			io.WriteString(w, "late")
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	grant := Grant{Server: "web", Host: "api.test", Ports: []int{port}, Methods: []string{"GET", "POST"}, Addresses: loopback,
		ResponseBytes: 2048, Timeout: 300 * time.Millisecond}
	h := newHarness(t, []Grant{grant}, Limits{RequestBytes: 1024, RequestsPerMinute: 1000})
	h.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	c := proxyClient(att, nil, "")
	base := fmt.Sprintf("http://api.test:%d", port)
	do := func(method, path string, body io.Reader) (*http.Response, error) {
		req, _ := http.NewRequest(method, base+path, body)
		resp, err := c.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return resp, err
	}
	if r, _ := do("POST", "/", strings.NewReader(strings.Repeat("x", 2000))); r == nil || reasonOf(r) != ReasonRequestTooLarge {
		t.Fatalf("declared request size: %v", r)
	}
	// A chunked body without a declared length is cut at the limit.
	if r, _ := do("POST", "/", io.MultiReader(strings.NewReader(strings.Repeat("y", 3000)))); r == nil || reasonOf(r) != ReasonRequestTooLarge {
		t.Fatalf("streamed request size: %v", r)
	}
	if r, _ := do("GET", "/big-declared", nil); r == nil || reasonOf(r) != ReasonResponseTooLarge {
		t.Fatalf("declared response size: %v", r)
	}
	if _, err := do("GET", "/big-stream", nil); err == nil {
		// The status was already sent; the connection is aborted so the
		// body read fails. Either outcome must leave an event.
		t.Log("streamed response: body read completed before abort was observed")
	}
	if rec := waitRecords(t, h.b, 4)[0]; rec.Reason != ReasonResponseTooLarge {
		t.Fatalf("streamed response record %+v", rec)
	}
	if r, _ := do("GET", "/slow", nil); r == nil || reasonOf(r) != ReasonTimeout {
		t.Fatalf("timeout: %v", r)
	}

	// Request rate: 2 per minute.
	h2 := newHarness(t, []Grant{grant}, Limits{RequestsPerMinute: 2})
	h2.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	c2 := proxyClient(h2.attach(), nil, "")
	var last *http.Response
	for range 3 {
		r, err := c2.Get(base + "/")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		last = r
	}
	if reasonOf(last) != ReasonRateLimited || last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate: %d %s", last.StatusCode, reasonOf(last))
	}

	// Byte rate: a 64 KiB per minute budget is spent by one large body.
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 4 {
			w.Write(make([]byte, 32<<10))
		}
	}))
	defer big.Close()
	bp := portOfURL(t, big.URL)
	h3 := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{bp}, Methods: []string{"GET"}, Addresses: loopback}},
		Limits{BytesPerMinute: 64 << 10})
	h3.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	c3 := proxyClient(h3.attach(), nil, "")
	if r, err := c3.Get(fmt.Sprintf("http://api.test:%d/", bp)); err == nil {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	if rec := waitRecords(t, h3.b, 1)[0]; rec.Reason != ReasonByteRate {
		t.Fatalf("byte rate record %+v", rec)
	}
	for _, r := range h.b.Recent() {
		if r.Reason == "" {
			continue
		}
		found := false
		for _, ev := range h.ev.Events() {
			if d, ok := ev.Detail.(Record); ok && d.ID == r.ID && ev.ReasonCode == r.Reason {
				found = true
			}
		}
		if !found {
			t.Fatalf("no event for %+v", r)
		}
	}
}

// TestPublicFetch attempts each operation the public-fetch profile
// prohibits and confirms refusal; HTTPS GET without a body works.
func TestPublicFetch(t *testing.T) {
	reqtest.Verifies(t, "SR-5.19-1")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "page") }))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	h := newHarness(t, []Grant{{Server: "web", Host: "example.com", Ports: []int{port}, Methods: []string{"GET"}, Class: ClassPublicFetch,
		Addresses: loopback, EndpointEnv: "WEB_URL"}}, Limits{}, func(o *Options) { o.RootCAs = pool })
	h.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	base := att.Env["WEB_URL"]
	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "page" {
		t.Fatalf("GET: %d %q", resp.StatusCode, b)
	}
	try := func(name string, req *http.Request, want string) {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 || reasonOf(resp) != want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, reasonOf(resp))
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "HEAD", "PATCH"} {
		req, _ := http.NewRequest(m, base+"/", nil)
		try(m, req, ReasonMethod)
	}
	req, _ := http.NewRequest("GET", base+"/", strings.NewReader("body"))
	try("GET with body", req, ReasonPublicFetchProfile)
	req, _ = http.NewRequest("GET", base+"/", nil)
	req.Header.Set("Authorization", "Bearer x")
	try("Authorization", req, ReasonPublicFetchProfile)
	req, _ = http.NewRequest("GET", base+"/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	try("WebSocket upgrade", req, ReasonBadRequest)
	// CONNECT and plain HTTP through the proxy.
	if _, err := proxyClient(att, pool, "").Get(fmt.Sprintf("https://example.com:%d/", port)); err == nil {
		t.Error("CONNECT under public-fetch succeeded")
	}
	resp, err = proxyClient(att, nil, "").Get(fmt.Sprintf("http://example.com:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("plain HTTP under public-fetch: %d %s", resp.StatusCode, reasonOf(resp))
	}
}

// TestEvidenceFailClosed: when the journal refuses the authorized event,
// the operation is refused and the destination is never contacted.
func TestEvidenceFailClosed(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	h := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{port}, Methods: []string{"GET"}, Addresses: loopback}}, Limits{})
	h.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	h.ev.Fail(errors.New("disk full"))
	resp, err := proxyClient(att, nil, "").Get(fmt.Sprintf("http://api.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || reasonOf(resp) != ReasonEvidenceFailed || hit {
		t.Fatalf("%d %s hit=%v", resp.StatusCode, reasonOf(resp), hit)
	}
	if _, err := h.b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web"}); err == nil {
		t.Fatal("attach succeeded without evidence")
	}
}

type fakeRules struct {
	netns string
	allow []netip.AddrPort
	gone  bool
	err   error
}

func (f *fakeRules) Install(netns string, allow []netip.AddrPort) (func() error, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.netns, f.allow = netns, allow
	return func() error { f.gone = true; return nil }, nil
}

// TestAttachNetwork: with a sandbox network the broker binds to the
// network's address, confines the namespace to exactly its listeners and
// removes the rules on detach; a failure to confine fails the attach.
func TestAttachNetwork(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-1")
	fr := &fakeRules{}
	h := newHarness(t, []Grant{{Server: "web", Host: "example.com", Ports: []int{443}, Methods: []string{"GET"}, EndpointEnv: "X_URL"}}, Limits{},
		func(o *Options) { o.Rules = fr })
	att, err := h.b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web",
		Network: &pipeline.EgressNetwork{NetNS: "/run/netns/x", ListenAddr: netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if !att.Enforced || fr.netns != "/run/netns/x" || len(fr.allow) != 2 {
		t.Fatalf("%+v %+v", att, fr)
	}
	for _, ap := range fr.allow {
		if !strings.Contains(att.Env["HTTP_PROXY"]+att.Env["X_URL"], ap.String()) {
			t.Fatalf("rule for %s is not a listener of %v", ap, att.Env)
		}
	}
	if st := h.b.Instances(); len(st) != 1 || !st[0].Enforced {
		t.Fatalf("%+v", st)
	}
	if err := att.Close(); err != nil || !fr.gone {
		t.Fatal(err, fr.gone)
	}
	if _, err := http.Get(att.Env["HTTP_PROXY"]); err == nil {
		t.Fatal("listener still open after detach")
	}
	fr.err = errors.New("no nftables")
	if _, err := h.b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web",
		Network: &pipeline.EgressNetwork{NetNS: "/run/netns/x", ListenAddr: netip.MustParseAddr("127.0.0.1")}}); err == nil {
		t.Fatal("attach succeeded without confinement")
	}
	if len(h.b.Instances()) != 0 {
		t.Fatal("failed attach left an instance")
	}
}

// TestAttachLauncherConfines: a rootless launcher confines the namespace
// itself. The broker listens on the host address, advertises the guest
// address in the environment and in Allow, installs no rules and reports
// the attachment as enforced; the listeners serve on the host address.
func TestAttachLauncherConfines(t *testing.T) {
	reqtest.Partial(t, "SR-4.5-1")
	fr := &fakeRules{}
	h := newHarness(t, []Grant{{Server: "web", Host: "example.com", Ports: []int{443}, Methods: []string{"GET"}, EndpointEnv: "X_URL"}}, Limits{},
		func(o *Options) { o.Rules = fr })
	guest := netip.MustParseAddr("10.0.2.2")
	att, err := h.b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web",
		Network: &pipeline.EgressNetwork{ListenAddr: netip.MustParseAddr("127.0.0.1"), GuestAddr: guest, LauncherConfines: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer att.Close()
	if !att.Enforced || fr.netns != "" || len(att.Allow) != 2 {
		t.Fatalf("attachment %+v, rules %+v", att, fr)
	}
	for _, ap := range att.Allow {
		if ap.Addr() != guest || !strings.Contains(att.Env["HTTPS_PROXY"]+att.Env["X_URL"], ap.String()) {
			t.Fatalf("allowed endpoint %s is not an advertised listener of %v", ap, att.Env)
		}
		// The listener is bound on the host address with the same port.
		c, err := net.DialTimeout("tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ap.Port()).String(), time.Second)
		if err != nil {
			t.Fatalf("listener for %s: %v", ap, err)
		}
		c.Close()
	}
	var attached *audit.Event
	for _, e := range h.ev.Events() {
		if e.Outcome == "attached" {
			attached = &e
		}
	}
	if attached == nil || attached.Detail.(map[string]any)["confined_by"] != "launcher" {
		t.Fatalf("attached evidence %+v", attached)
	}
	if _, err := h.b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web",
		Network: &pipeline.EgressNetwork{ListenAddr: netip.MustParseAddr("127.0.0.1")}}); err == nil {
		t.Fatal("a sandbox network without a namespace was attached although the launcher does not confine it")
	}
}

type captureLauncher struct {
	spec pipeline.ServerSpec
	att  pipeline.EgressAttacher
}

func (c *captureLauncher) Name() string   { return "capture" }
func (c *captureLauncher) Confined() bool { return false }
func (c *captureLauncher) Launch(_ context.Context, s pipeline.ServerSpec) (pipeline.Process, error) {
	c.spec = s
	return nopProcess{}, nil
}

type nopProcess struct{}

func (nopProcess) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopProcess) Write(b []byte) (int, error) { return len(b), nil }
func (nopProcess) Close() error                { return nil }
func (nopProcess) Stderr() string              { return "" }

type awareLauncher struct{ captureLauncher }

func (a *awareLauncher) SetEgress(e pipeline.EgressAttacher) { a.att = e }

// TestWrapLauncher: an unconfined launcher's instances get the proxy and
// endpoint variables (advisory) and are detached on close; an
// EgressAware launcher receives the broker instead.
func TestWrapLauncher(t *testing.T) {
	reqtest.Partial(t, "FR-5.37")
	h := newHarness(t, []Grant{{Server: "web", Host: "example.com", Ports: []int{443}, Methods: []string{"GET"}, EndpointEnv: "API_BASE"}}, Limits{})
	cl := &captureLauncher{}
	l := h.b.Wrap(cl)
	if l.Name() != "capture" || l.Confined() {
		t.Fatal("wrapper changed launcher identity")
	}
	p, err := l.Launch(context.Background(), pipeline.ServerSpec{Alias: "web", Env: map[string]string{"PATH": "/bin", "HTTP_PROXY": "http://evil"}})
	if err != nil {
		t.Fatal(err)
	}
	env := cl.spec.Env
	if env["PATH"] != "/bin" || !strings.HasPrefix(env["HTTP_PROXY"], "http://127.0.0.1:") || env["HTTPS_PROXY"] != env["HTTP_PROXY"] ||
		!strings.HasPrefix(env["API_BASE"], "http://127.0.0.1:") {
		t.Fatalf("env %v", env)
	}
	if len(h.b.Instances()) != 1 {
		t.Fatal("no instance")
	}
	p.Close()
	if len(h.b.Instances()) != 0 {
		t.Fatal("instance not detached on close")
	}
	al := &awareLauncher{}
	if got := h.b.Wrap(al); got != pipeline.Launcher(al) || al.att == nil {
		t.Fatal("EgressAware launcher not given the broker")
	}
	var nb *Broker
	if nb.Wrap(cl) != pipeline.Launcher(cl) {
		t.Fatal("nil broker wrapped the launcher")
	}
}

type mux struct{ m *http.ServeMux }

func (m mux) Handle(p string, h http.HandlerFunc) { m.m.HandleFunc(p, h) }

func TestControlAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	h := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{port}, Methods: []string{"GET"}, Addresses: loopback}}, Limits{})
	h.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	c := proxyClient(att, nil, "")
	r1, _ := c.Get(fmt.Sprintf("http://api.test:%d/", port))
	r1.Body.Close()
	r2, _ := c.Get(fmt.Sprintf("http://nope.test:%d/", port))
	r2.Body.Close()
	waitRecords(t, h.b, 2)
	m := mux{http.NewServeMux()}
	h.b.Register(m)
	get := func(path string) (int, string) {
		rr := httptest.NewRecorder()
		m.m.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		return rr.Code, rr.Body.String()
	}
	if code, body := get("/api/v1/egress"); code != 200 || !strings.Contains(body, `"advisory_instances":1`) || !strings.Contains(body, `"requests_per_minute":60`) {
		t.Fatal(code, body)
	}
	if code, body := get("/api/v1/egress/grants"); code != 200 || !strings.Contains(body, `"host":"api.test"`) || !strings.Contains(body, `"addresses":["127.0.0.1"]`) {
		t.Fatal(code, body)
	}
	if code, body := get("/api/v1/egress/connections?decision=denied"); code != 200 || !strings.Contains(body, ReasonNoGrant) || strings.Contains(body, `"decision":"allowed"`) {
		t.Fatal(code, body)
	}
	if code, _ := get("/api/v1/egress/connections?limit=0"); code != 400 {
		t.Fatal(code)
	}
	var nb *Broker
	m2 := mux{http.NewServeMux()}
	nb.Register(m2)
	rr := httptest.NewRecorder()
	m2.m.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/egress", nil))
	if rr.Code != 404 || !strings.Contains(rr.Body.String(), "egress_disabled") {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestCanonicalHost(t *testing.T) {
	for in, want := range map[string]string{"API.Example.COM.": "api.example.com", "[::1]": "::1", "::ffff:10.0.0.1": "10.0.0.1", "10.0.0.1": "10.0.0.1"} {
		if got, err := canonicalHost(in, false); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "a..b", "-a.com", "exa mple.com", "ex_ample.com", "2130706433", "0x7f.1", "*.a.com", "fe80::1%eth0", "ünï.com"} {
		if _, err := canonicalHost(bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !hostMatches("*.a.com", "b.a.com") || hostMatches("*.a.com", "a.com") || hostMatches("*.a.com", "ba.com") {
		t.Fatal("wildcard")
	}
	if urlHost("a.com", 443, 443) != "a.com" || urlHost("::1", 443, 443) != "[::1]" || urlHost("a.com", 8443, 443) != "a.com:8443" ||
		urlHost("::1", 80, 443) != "[::1]:80" || defaultPort("http") != 80 || defaultPort("https") != 443 {
		t.Fatal("urlHost")
	}
}
