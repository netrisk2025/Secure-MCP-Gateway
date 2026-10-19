package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// The Egress Broker implements delivery mode S1 of the Secret Broker
// (FR-6.6): a header grant names a server, a destination and a header
// template; the broker inserts the header, with the secret in place of
// "{secret}", on each authorized request of that server's instances to the
// destination. The server process never holds the value.
//
// Insertion happens only where the broker writes the request itself over
// TLS it originates: endpoint requests to an https destination. Requests
// through the forward proxy (plain http, or CONNECT tunnels whose TLS the
// broker does not terminate) never carry an inserted header. The header is
// re-applied on each redirect hop, so a redirect to another host loses it.
var _ pipeline.SecretHeaderInjector = (*Broker)(nil)

type headerGrant struct {
	server string
	host   string
	port   int // 0: any port
	header string
	tmpl   string
	value  []byte
}

type headerSet struct {
	mu     sync.Mutex
	grants map[string]*headerGrant // grant ID -> grant
}

// parseDestination splits "host" or "host:port".
func parseDestination(d string) (string, int, error) {
	host, port := d, 0
	if h, p, err := net.SplitHostPort(d); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", 0, errors.New("egress: destination port must be 1 to 65535")
		}
		host, port = h, n
	}
	h, err := canonicalHost(strings.Trim(host, "[]"), false)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}

// BindHeader implements pipeline.SecretHeaderInjector. The broker owns
// g.Value afterwards and overwrites it on Withdraw.
func (b *Broker) BindHeader(_ context.Context, g pipeline.HeaderGrant) error {
	if g.GrantID == "" || g.Server == "" || g.Header == "" || !strings.Contains(g.Template, "{secret}") {
		return errors.New("egress: a header grant needs an ID, a server, a header and a template containing {secret}")
	}
	if strings.EqualFold(g.Header, AuthHeader) || strings.EqualFold(g.Header, "Host") || strings.EqualFold(g.Header, "Cookie") {
		return errors.New("egress: header " + g.Header + " cannot be inserted")
	}
	host, port, err := parseDestination(g.Destination)
	if err != nil {
		return err
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return errors.New("egress: broker is closed")
	}
	b.headers.mu.Lock()
	defer b.headers.mu.Unlock()
	if b.headers.grants == nil {
		b.headers.grants = map[string]*headerGrant{}
	}
	if old := b.headers.grants[g.GrantID]; old != nil {
		clear(old.value)
	}
	b.headers.grants[g.GrantID] = &headerGrant{server: g.Server, host: host, port: port,
		header: textproto.CanonicalMIMEHeaderKey(g.Header), tmpl: g.Template, value: g.Value}
	return nil
}

// Withdraw implements pipeline.SecretHeaderInjector.
func (b *Broker) Withdraw(grantID string) {
	b.headers.mu.Lock()
	defer b.headers.mu.Unlock()
	if g := b.headers.grants[grantID]; g != nil {
		clear(g.value)
		delete(b.headers.grants, grantID)
	}
}

// HeaderGrants reports how many header grants are bound (status, tests).
func (b *Broker) HeaderGrants() int {
	b.headers.mu.Lock()
	defer b.headers.mu.Unlock()
	return len(b.headers.grants)
}

// applyHeaders sets the bound headers of server for one request hop and
// returns their names. Any header a grant of the server could insert is
// first removed, so an instance cannot supply its own value for it and a
// hop to another destination does not keep it.
func (b *Broker) applyHeaders(r *http.Request, server, host string, port int, scheme string) []string {
	b.headers.mu.Lock()
	defer b.headers.mu.Unlock()
	var names []string
	for _, g := range b.headers.grants {
		if g.server == server {
			r.Header.Del(g.header)
		}
	}
	if scheme != "https" {
		return nil
	}
	for _, g := range b.headers.grants {
		if g.server != server || g.host != host || (g.port != 0 && g.port != port) {
			continue
		}
		r.Header.Set(g.header, strings.ReplaceAll(g.tmpl, "{secret}", string(g.value)))
		names = append(names, g.header)
	}
	return names
}
