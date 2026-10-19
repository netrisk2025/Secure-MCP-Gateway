package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// Client ID Metadata Documents (FR-2.18, CP-52). A client whose client_id
// is an HTTPS URL on the CP-52 allowlist is registered by fetching that
// document. Only allowlisted URLs are ever fetched; the fetch is bounded
// (5 s, 64 KiB), follows redirects only within the same scheme and host,
// connects only to public unicast addresses (the document host cannot
// point the Gateway at loopback, private or link-local services), and a
// valid document is cached for 24 hours.
const (
	cimdTimeout  = 5 * time.Second
	cimdMaxBytes = 64 << 10
	cimdCacheTTL = 24 * time.Hour
	cimdMaxHops  = 3
)

// errCIMDAddress refuses a connection to a non-public address.
var errCIMDAddress = errors.New("client metadata host resolves to a non-public address")

// cimdDocument is the part of a Client ID Metadata Document the Gateway
// uses.
type cimdDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type cimdEntry struct {
	doc     cimdDocument
	expires time.Time
}

// cimdFetcher fetches and caches Client ID Metadata Documents.
type cimdFetcher struct {
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	cache   map[string]cimdEntry
	fetches int // documents fetched over the network (tests)
}

// publicAddress reports whether ip is a global unicast address outside the
// private, loopback, link-local and other special ranges.
func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// nonPublic are special-purpose ranges IsGlobalUnicast accepts.
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "fc00::/7"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func newCIMDFetcher(now func() time.Time) *cimdFetcher {
	dialer := &net.Dialer{Timeout: cimdTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !publicAddress(ap.Addr()) {
			return errCIMDAddress
		}
		return nil
	}}
	return newCIMDFetcherWith(&http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: cimdTimeout, ForceAttemptHTTP2: true,
		MaxResponseHeaderBytes: 16 << 10, Proxy: nil}, now)
}

// newCIMDFetcherWith uses rt for the network; tests pass a transport that
// reaches a local server.
func newCIMDFetcherWith(rt http.RoundTripper, now func() time.Time) *cimdFetcher {
	f := &cimdFetcher{now: now, cache: map[string]cimdEntry{}}
	f.client = &http.Client{Transport: rt, Timeout: cimdTimeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= cimdMaxHops {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			return fmt.Errorf("redirect to another host or scheme (%s) refused", req.URL.Redacted())
		}
		return nil
	}}
	return f
}

// get returns the document at u, from the cache when it is younger than
// CP-52's 24 hours.
func (f *cimdFetcher) get(ctx context.Context, u string) (cimdDocument, error) {
	f.mu.Lock()
	if e, ok := f.cache[u]; ok && f.now().Before(e.expires) {
		f.mu.Unlock()
		return e.doc, nil
	}
	f.fetches++
	f.mu.Unlock()
	doc, err := f.fetch(ctx, u)
	if err != nil {
		return cimdDocument{}, err
	}
	f.mu.Lock()
	f.cache[u] = cimdEntry{doc: doc, expires: f.now().Add(cimdCacheTTL)}
	f.mu.Unlock()
	return doc, nil
}

func (f *cimdFetcher) fetch(ctx context.Context, u string) (cimdDocument, error) {
	ctx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) // #nosec G704 -- u is an exact CP-52 allowlist entry; the dialer refuses non-public addresses
	if err != nil {
		return cimdDocument{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req) // #nosec G704 -- allowlisted URL, public addresses only, same-host redirects
	if err != nil {
		return cimdDocument{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cimdDocument{}, fmt.Errorf("client metadata document: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return cimdDocument{}, err
	}
	if len(body) > cimdMaxBytes {
		return cimdDocument{}, fmt.Errorf("client metadata document exceeds %d bytes", cimdMaxBytes)
	}
	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return cimdDocument{}, fmt.Errorf("client metadata document is not a JSON object: %w", err)
	}
	if doc.ClientID != u {
		return cimdDocument{}, errors.New("client metadata document names a different client_id")
	}
	if len(doc.RedirectURIs) == 0 {
		return cimdDocument{}, errors.New("client metadata document lists no redirect_uris")
	}
	for _, r := range doc.RedirectURIs {
		ru, err := url.Parse(r)
		if err != nil || (ru.Scheme != "https" && ru.Scheme != "http") || ru.Host == "" || ru.Fragment != "" {
			return cimdDocument{}, fmt.Errorf("client metadata document has an invalid redirect URI %q", r)
		}
	}
	// A metadata-document client has no secret registered here; it is a
	// public client using PKCE.
	if m := doc.TokenEndpointAuthMethod; m != "" && m != "none" {
		return cimdDocument{}, fmt.Errorf("client metadata document asks for token_endpoint_auth_method %q; only none is supported", m)
	}
	return doc, nil
}

// lookupClient resolves a client ID: a registration in the configuration
// or the directory, or else an allowlisted Client ID Metadata Document URL,
// whose document is fetched (FR-2.18). A client ID that is neither is
// refused without any outbound request.
func (o *OAuth) lookupClient(ctx context.Context, id string) (*config.Client, error) {
	if c := o.cfg.FindClient(id); c != nil {
		return c, nil
	}
	m := o.cfg.FindClientMetadata(id)
	if m == nil {
		return nil, errUnknownClient
	}
	doc, err := o.cimd.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &config.Client{ClientID: id, Principal: m.Principal, RedirectURIs: doc.RedirectURIs}, nil
}

var errUnknownClient = errors.New("unknown client_id")

// SetMetadataTransport replaces the network transport of Client ID Metadata
// Document fetches and empties the document cache. Tests use it to reach a
// document server on loopback, which the default transport refuses.
func (o *OAuth) SetMetadataTransport(rt http.RoundTripper) {
	o.cimd = newCIMDFetcherWith(rt, o.clock)
}
