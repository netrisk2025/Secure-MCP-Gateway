package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// cimdServer serves Client ID Metadata Documents over TLS on loopback and
// counts the requests it receives.
type cimdServer struct {
	srv  *httptest.Server
	hits atomic.Int64
}

func newCIMDServer(t *testing.T) *cimdServer {
	t.Helper()
	s := &cimdServer{}
	mux := http.NewServeMux()
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		mux.ServeHTTP(w, r)
	}))
	self := func(r *http.Request) string { return s.srv.URL + r.URL.Path }
	mux.HandleFunc("/good.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Agent","redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none"}`, self(r))
	})
	mux.HandleFunc("/moved.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved-target.json", http.StatusFound)
	})
	mux.HandleFunc("/moved-target.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["http://127.0.0.1/callback"]}`, s.srv.URL+"/moved.json")
	})
	mux.HandleFunc("/elsewhere.json", func(w http.ResponseWriter, r *http.Request) {
		// Same address, another host name: a different host for the
		// redirect rule.
		http.Redirect(w, r, strings.Replace(s.srv.URL, "127.0.0.1", "localhost", 1)+"/good.json", http.StatusFound)
	})
	mux.HandleFunc("/big.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["http://127.0.0.1/callback"],"pad":%q}`, self(r), strings.Repeat("x", 70<<10))
	})
	mux.HandleFunc("/other-id.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"client_id":"https://attacker.example/c.json","redirect_uris":["http://127.0.0.1/callback"]}`)
	})
	mux.HandleFunc("/jwt.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"private_key_jwt"}`, self(r))
	})
	mux.HandleFunc("/no-redirects.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"client_id":%q}`, self(r))
	})
	t.Cleanup(s.srv.Close)
	return s
}

// TestClientMetadataFetchBounds is the CP-52 fetch rules of FR-2.18: a
// valid document is fetched once and cached for 24 hours; redirects stay on
// the same host; documents over 64 KiB, documents naming another client_id
// or no redirect URIs, and documents asking for a client authentication
// method other than none are refused; and the production transport refuses
// to connect to loopback, private and other non-public addresses, so an
// allowlisted host name cannot point the fetch at internal services.
// The registration paths themselves are in
// internal/remote.TestClientRegistrationPaths.
func TestClientMetadataFetchBounds(t *testing.T) {
	reqtest.Partial(t, "FR-2.18")
	s := newCIMDServer(t)
	now := time.Now()
	f := newCIMDFetcherWith(s.srv.Client().Transport, func() time.Time { return now })
	ctx := context.Background()

	good := s.srv.URL + "/good.json"
	doc, err := f.get(ctx, good)
	if err != nil || doc.ClientID != good || len(doc.RedirectURIs) != 1 {
		t.Fatalf("good document: %+v %v", doc, err)
	}
	if _, err := f.get(ctx, good); err != nil || s.hits.Load() != 1 {
		t.Fatalf("cached document refetched: hits %d, %v", s.hits.Load(), err)
	}
	now = now.Add(cimdCacheTTL + time.Second)
	if _, err := f.get(ctx, good); err != nil || s.hits.Load() != 2 {
		t.Fatalf("expired document not refetched: hits %d, %v", s.hits.Load(), err)
	}

	if doc, err := f.get(ctx, s.srv.URL+"/moved.json"); err != nil || doc.ClientID != s.srv.URL+"/moved.json" {
		t.Fatalf("same-host redirect: %+v %v", doc, err)
	}
	for path, want := range map[string]string{
		"/elsewhere.json":    "another host",
		"/big.json":          "exceeds",
		"/other-id.json":     "different client_id",
		"/jwt.json":          "only none",
		"/no-redirects.json": "no redirect_uris",
		"/missing.json":      "HTTP 404",
	} {
		if _, err := f.get(ctx, s.srv.URL+path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error with %q", path, err, want)
		}
	}

	// The production fetcher connects only to public addresses.
	before := s.hits.Load()
	prod := newCIMDFetcher(time.Now)
	if _, err := prod.get(ctx, good); err == nil || !errors.Is(err, errCIMDAddress) {
		t.Fatalf("loopback fetch: %v", err)
	}
	if s.hits.Load() != before {
		t.Fatal("the production fetcher reached a loopback server")
	}
	for addr, public := range map[string]bool{
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fd00::1": false, "::ffff:127.0.0.1": false,
		"224.0.0.1": false, "8.8.8.8": true, "2606:4700::1111": true,
	} {
		if got := publicAddress(netip.MustParseAddr(addr)); got != public {
			t.Errorf("publicAddress(%s) = %v, want %v", addr, got, public)
		}
	}
}
