package egress

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSecretFingerprintOnEgress: a registered secret in the query string,
// in a header or in the body of a brokered request is refused with
// EGRESS_SECRET_DETECTED and never reaches the destination; the header the
// broker inserts for S1 delivery carries the same secret and is not
// refused (SR-5.8-2).
func TestSecretFingerprintOnEgress(t *testing.T) {
	reqtest.Verifies(t, "SR-5.8-2")
	var mu sync.Mutex
	var reached []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tp := portOfURL(t, srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	h := newHarness(t, []Grant{
		{Server: "web", Host: "example.com", Ports: []int{tp}, Methods: []string{"GET", "POST"}, Addresses: loopback, EndpointEnv: "API_URL"},
	}, Limits{}, func(o *Options) { o.RootCAs = pool })
	h.res.answers["example.com"] = [][]string{{"127.0.0.1"}}
	secret := "tok_live_0123456789abcdefghij"
	fps := filters.NewFingerprintSet()
	fps.Register("vault:api@1", secret)
	h.b.SetFingerprints(fps)
	var injector pipeline.SecretHeaderInjector = h.b
	if err := injector.BindHeader(context.Background(), pipeline.HeaderGrant{GrantID: "g1", Server: "web", Slot: "token", Destination: "example.com",
		Header: "authorization", Template: "Bearer {secret}", SecretRef: "api", Version: 1, Value: []byte(secret)}); err != nil {
		t.Fatal(err)
	}
	base := h.attach().Env["API_URL"]
	do := func(method, path, hdr, body string) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, base+path, rd)
		if hdr != "" {
			req.Header.Set("X-Api-Key", hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header.Get(ReasonHeader)
	}
	for _, c := range []struct{ name, method, path, hdr, body string }{
		{"query", "GET", "/q?key=" + url.QueryEscape(secret), "", ""},
		{"encoded query", "GET", "/e?k=" + url.QueryEscape("x"+secret+"y"), "", ""},
		{"header", "GET", "/h", secret, ""},
		{"body", "POST", "/b", "", `{"token":"` + secret + `"}`},
	} {
		if code, reason := do(c.method, c.path, c.hdr, c.body); code == http.StatusOK || reason != ReasonSecretDetected {
			t.Fatalf("%s: %d %s", c.name, code, reason)
		}
	}
	// A clean request passes, carrying the S1-inserted header with the secret.
	if code, reason := do("POST", "/clean", "public-value", `{"q":"hello"}`); code != http.StatusOK {
		t.Fatalf("clean request: %d %s", code, reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reached) != 1 || reached[0] != "/clean Bearer "+secret {
		t.Fatalf("reached the destination: %q", reached)
	}
	refused := 0
	for _, r := range h.b.Recent() {
		if r.Reason == ReasonSecretDetected {
			refused++
		}
	}
	if refused != 4 {
		t.Fatalf("%d refusal records", refused)
	}
}
