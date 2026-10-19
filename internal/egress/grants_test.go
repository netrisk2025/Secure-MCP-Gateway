package egress

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestOnlyCurrentGrantsAreForwarded is SR-4.5-2: the broker forwards an
// operation only to a destination in the calling instance's current
// grants. Through a broker endpoint and through the proxy, a granted
// destination is reached; after the grant is withdrawn (the grant set
// replaced) the same requests are refused before any connection, and a
// destination no grant ever named is refused through the proxy, through
// CONNECT and as a different host behind the endpoint's own port.
func TestOnlyCurrentGrantsAreForwarded(t *testing.T) {
	reqtest.Verifies(t, "SR-4.5-2")
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tls "+r.URL.Path) }))
	defer tls.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain "+r.URL.Path) }))
	defer plain.Close()
	pool := x509.NewCertPool()
	pool.AddCert(tls.Certificate())
	tport, pport := portOfURL(t, tls.URL), portOfURL(t, plain.URL)
	grants := []Grant{
		{Server: "web", Host: "example.com", Ports: []int{tport}, Methods: []string{"GET"}, Addresses: loopback, EndpointEnv: "API_URL"},
		{Server: "web", Host: "plain.test", Ports: []int{pport}, Methods: []string{"GET"}, Addresses: loopback},
	}
	h := newHarness(t, grants, Limits{}, func(o *Options) { o.RootCAs = pool })
	h.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	h.res.answers["plain.test"] = [][]string{{"127.0.0.1"}}
	h.res.answers["other.test"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	proxy := proxyClient(att, nil, "")
	get := func(c *http.Client, u string) (int, string, string) {
		t.Helper()
		resp, err := c.Get(u)
		if err != nil {
			return 0, "", err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), reasonOf(resp)
	}
	endpoint := att.Env["API_URL"] + "/e"
	viaProxy := fmt.Sprintf("http://plain.test:%d/p", pport)
	if st, body, _ := get(http.DefaultClient, endpoint); st != 200 || body != "tls /e" {
		t.Fatalf("endpoint while granted: %d %q", st, body)
	}
	if st, body, _ := get(proxy, viaProxy); st != 200 || body != "plain /p" {
		t.Fatalf("proxy while granted: %d %q", st, body)
	}
	// Never granted: another host on a granted port, and CONNECT.
	if st, _, reason := get(proxy, fmt.Sprintf("http://other.test:%d/p", pport)); st < 400 || reason != ReasonNoGrant {
		t.Fatalf("ungranted host: %d %s", st, reason)
	}
	if _, err := proxy.Get(fmt.Sprintf("https://other.test:%d/", tport)); err == nil {
		t.Fatal("CONNECT to an ungranted host succeeded")
	}
	dials := len(h.dials())
	// The grants are withdrawn: the same requests are refused, nothing dialed.
	h.grants.Replace(nil)
	if st, _, reason := get(http.DefaultClient, endpoint); st < 400 || reason != ReasonNoGrant {
		t.Fatalf("endpoint after withdrawal: %d %s", st, reason)
	}
	if st, _, reason := get(proxy, viaProxy); st < 400 || reason != ReasonNoGrant {
		t.Fatalf("proxy after withdrawal: %d %s", st, reason)
	}
	if d := h.dials(); len(d) != dials {
		t.Fatalf("broker dialed %v for refused operations", d[dials:])
	}
	denied := 0
	for _, r := range h.b.Recent() {
		if r.Decision == DecisionDenied && strings.Contains(r.Reason, ReasonNoGrant) {
			denied++
		}
	}
	if denied < 3 {
		t.Fatalf("%d denied records", denied)
	}
}

// TestNoCookieState is SR-5.17-1 for the operations the broker reads in
// clear (the plain-HTTP proxy and the endpoints, whose TLS the broker
// originates): Cookie headers the instance sends are removed, Set-Cookie
// headers of the destination never reach the instance, and nothing is
// replayed on later operations, because the broker keeps no cookie jar.
func TestNoCookieState(t *testing.T) {
	reqtest.Verifies(t, "SR-5.17-1")
	var cookies []string
	mk := func(tlsSrv bool) *httptest.Server {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies = append(cookies, r.Header.Get("Cookie"))
			http.SetCookie(w, &http.Cookie{Name: "track", Value: "abc", Path: "/"})
			w.Header().Add("Set-Cookie2", "legacy=1")
			io.WriteString(w, "ok")
		})
		if tlsSrv {
			return httptest.NewTLSServer(h)
		}
		return httptest.NewServer(h)
	}
	plain, tlsSrv := mk(false), mk(true)
	defer plain.Close()
	defer tlsSrv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	h := newHarness(t, []Grant{
		{Server: "web", Host: "plain.test", Ports: []int{portOfURL(t, plain.URL)}, Methods: []string{"GET"}, Addresses: loopback},
		{Server: "web", Host: "example.com", Ports: []int{portOfURL(t, tlsSrv.URL)}, Methods: []string{"GET"}, Addresses: loopback, EndpointEnv: "API_URL"},
	}, Limits{}, func(o *Options) { o.RootCAs = pool })
	h.res.answers["plain.test"] = [][]string{{"127.0.0.1"}}
	h.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	proxy := proxyClient(att, nil, "")
	for i, u := range []string{
		fmt.Sprintf("http://plain.test:%d/1", portOfURL(t, plain.URL)), fmt.Sprintf("http://plain.test:%d/2", portOfURL(t, plain.URL)),
		att.Env["API_URL"] + "/1", att.Env["API_URL"] + "/2",
	} {
		c := proxy
		if strings.HasPrefix(u, att.Env["API_URL"]) {
			c = http.DefaultClient
		}
		req, _ := http.NewRequest("GET", u, nil)
		if i%2 == 0 {
			req.Header.Set("Cookie", "session=from-instance")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Set-Cookie2") != "" {
			t.Fatalf("%s: %d set-cookie %q", u, resp.StatusCode, resp.Header.Values("Set-Cookie"))
		}
	}
	if len(cookies) != 4 {
		t.Fatalf("%d requests reached the destinations", len(cookies))
	}
	for i, c := range cookies {
		if c != "" {
			t.Fatalf("request %d carried Cookie %q", i, c)
		}
	}
}
