package egress

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSecretHeaderInjection: an S1 header grant is inserted on endpoint
// requests to its destination only, replaces a value the instance sent,
// is not kept across a redirect to another host, never reaches plain-http
// proxy requests and stops at Withdraw. Evidence names the header, never
// the value.
func TestSecretHeaderInjection(t *testing.T) {
	reqtest.Partial(t, "FR-6.6")
	var mu sync.Mutex
	seen := map[string]string{} // path -> Authorization
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Host+r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		if r.URL.Path == "/away" {
			http.Redirect(w, r, fmt.Sprintf("https://127.0.0.1:%d/landed", portOfReq(r)), http.StatusFound)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tp := portOfURL(t, srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen["plain"+r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		io.WriteString(w, "plain")
	}))
	defer plain.Close()
	h := newHarness(t, []Grant{
		{Server: "web", Host: "example.com", Ports: []int{tp}, Methods: []string{"GET"}, Addresses: loopback, EndpointEnv: "API_URL"},
		{Server: "web", Host: "127.0.0.1", Ports: []int{tp}, Methods: []string{"GET"}, Addresses: loopback},
		{Server: "web", Host: "plain.test", Ports: []int{portOfURL(t, plain.URL)}, Methods: []string{"GET"}, Addresses: loopback},
	}, Limits{}, func(o *Options) { o.RootCAs = pool })
	h.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	h.res.answers["plain.test"] = [][]string{{"127.0.0.1"}}
	var injector pipeline.SecretHeaderInjector = h.b
	secret := "s3cr3t-token-value"
	if err := injector.BindHeader(context.Background(), pipeline.HeaderGrant{GrantID: "g1", Server: "web", Slot: "token", Destination: "example.com",
		Header: "authorization", Template: "Bearer {secret}", SecretRef: "gh", Version: 1, Value: []byte(secret)}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []pipeline.HeaderGrant{
		{GrantID: "x", Server: "web", Destination: "example.com", Header: "X-Key", Template: "no placeholder"},
		{GrantID: "x", Server: "web", Destination: "example.com", Header: AuthHeader, Template: "{secret}"},
		{GrantID: "x", Server: "web", Destination: "api.test:99999", Header: "X-Key", Template: "{secret}"},
	} {
		if err := injector.BindHeader(context.Background(), bad); err == nil {
			t.Fatalf("bad grant accepted: %+v", bad)
		}
	}
	att := h.attach()
	direct := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(u string, hdr string) {
		t.Helper()
		req, _ := http.NewRequest("GET", u, nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		c := direct // endpoint requests go to the endpoint listener itself
		if !strings.HasPrefix(u, att.Env["API_URL"]) {
			c = proxyClient(att, nil, "")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	base := att.Env["API_URL"]
	get(base+"/one", "Bearer instance-supplied")
	get(base+"/away", "")
	get(strings.Replace(plain.URL, "127.0.0.1", "plain.test", 1)+"/p", "")
	mu.Lock()
	host := fmt.Sprintf("example.com:%d", tp)
	if seen[host+"/one"] != "Bearer "+secret {
		t.Fatalf("endpoint request carried %q", seen[host+"/one"])
	}
	if got, ok := seen[fmt.Sprintf("127.0.0.1:%d/landed", tp)]; !ok || got != "" {
		t.Fatalf("redirect to another host: reached %v, header %q", ok, got)
	}
	if seen["plain/p"] != "" {
		t.Fatalf("plain-http proxy request carried %q", seen["plain/p"])
	}
	mu.Unlock()
	for _, r := range h.b.Recent() {
		if r.Path == "/one" && (len(r.Injected) != 1 || r.Injected[0] != "Authorization") {
			t.Fatalf("record %+v", r)
		}
	}
	for _, e := range h.ev.Events() {
		if strings.Contains(fmt.Sprintf("%v", e.Detail), secret) {
			t.Fatalf("evidence contains the secret: %+v", e)
		}
	}
	injector.Withdraw("g1")
	if h.b.HeaderGrants() != 0 {
		t.Fatal("grant not withdrawn")
	}
	get(base+"/two", "")
	mu.Lock()
	defer mu.Unlock()
	if seen[host+"/two"] != "" {
		t.Fatalf("withdrawn grant still inserted: %q", seen[host+"/two"])
	}
}
