package egress

import (
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// MethodConnect is the grant method token that permits an HTTPS CONNECT
// tunnel (the manifest's "CONNECT-TLS").
const MethodConnect = "CONNECT-TLS"

// Grant classes.
const (
	ClassAPI         = config.EgressClassAPI
	ClassPublicFetch = config.EgressClassPublicFetch
)

// Grant permits one server alias to reach one destination.
type Grant struct {
	Server  string
	Host    string // canonical: exact name, "*.suffix" or IP literal
	Ports   []int
	Methods []string
	Class   string
	// Addresses are exact reserved addresses this grant may reach.
	Addresses   []netip.Addr
	EndpointEnv string
	// Limits tighter than the broker defaults; zero means the default.
	RequestBytes  int64
	ResponseBytes int64
	Timeout       time.Duration
}

// Destination names the grant's destination as host:port of its first
// port, for evidence.
func (g Grant) Destination() string {
	port := 443
	if len(g.Ports) > 0 {
		port = g.Ports[0]
	}
	return joinHostPort(g.Host, port)
}

// GrantSource supplies the current grants of a server alias. The broker
// asks on every operation, so a changed source takes effect on the next
// operation. The policy agent (E-05/E-06) can replace the configuration
// source with grants derived from decision obligations.
type GrantSource interface {
	Grants(server string) []Grant
}

// GrantHosts returns the destinations granted to server as host:port
// entries, sorted (an FR-3.12 obligation).
func (b *Broker) GrantHosts(server string) []string {
	if b == nil || b.o.Grants == nil {
		return nil
	}
	var out []string
	for _, g := range b.o.Grants.Grants(server) {
		for _, p := range g.Ports {
			out = append(out, joinHostPort(g.Host, p))
		}
	}
	sort.Strings(out)
	return out
}

// StaticGrants is a GrantSource over a fixed list, replaceable at run time.
type StaticGrants struct {
	mu   sync.RWMutex
	byID map[string][]Grant
}

// NewStaticGrants indexes grants by server alias.
func NewStaticGrants(gs []Grant) *StaticGrants {
	s := &StaticGrants{}
	s.Replace(gs)
	return s
}

// Replace swaps the whole grant list.
func (s *StaticGrants) Replace(gs []Grant) {
	m := map[string][]Grant{}
	for _, g := range gs {
		m[g.Server] = append(m[g.Server], g)
	}
	s.mu.Lock()
	s.byID = m
	s.mu.Unlock()
}

// Grants implements GrantSource.
func (s *StaticGrants) Grants(server string) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.byID[server])
}

// GrantsFromConfig converts the [[egress.grant]] tables.
func GrantsFromConfig(cfg []config.EgressGrant) ([]Grant, error) {
	out := make([]Grant, 0, len(cfg))
	for _, c := range cfg {
		host, err := canonicalHost(c.Host, true)
		if err != nil {
			return nil, err
		}
		g := Grant{Server: c.Server, Host: host, Ports: slices.Clone(c.Ports), Methods: slices.Clone(c.Methods), Class: c.Class,
			EndpointEnv: c.EndpointEnv, RequestBytes: c.RequestBytes, ResponseBytes: c.ResponseBytes, Timeout: c.Timeout.Duration}
		if g.Class == "" {
			g.Class = ClassAPI
		}
		for _, a := range c.Addresses {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				return nil, err
			}
			g.Addresses = append(g.Addresses, ip.Unmap())
		}
		out = append(out, g)
	}
	return out, nil
}

var errBadHost = errors.New("destination host is not a valid DNS name or IP address")

// canonicalHost lowercases a host, removes one trailing dot and the
// brackets of an IPv6 literal, and refuses anything that is neither a
// DNS name of letters, digits and hyphens nor an IP literal. Wildcards are
// accepted only when allowWild is set (grant hosts, not request hosts).
func canonicalHost(h string, allowWild bool) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", errBadHost
		}
		return ip.Unmap().String(), nil
	}
	name := h
	if allowWild && strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	if name == "" || len(name) > 253 {
		return "", errBadHost
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errBadHost
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errBadHost
			}
		}
	}
	// A name whose last label is numeric would be parsed as an IPv4
	// address by some resolvers (for example 0x7f.1 or 2130706433); no
	// top-level domain is numeric, so refuse it.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", errBadHost
	}
	return h, nil
}

func hostMatches(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix) && len(host) > len(suffix)+1
	}
	return pattern == host
}

// match returns the first grant of the list that permits method on
// host:port. The second result tells whether some grant names the
// destination at all, to distinguish an ungranted destination from a
// refused method.
func match(gs []Grant, host string, port int, method string) (Grant, bool, bool) {
	known := false
	for _, g := range gs {
		if !hostMatches(g.Host, host) || !slices.Contains(g.Ports, port) {
			continue
		}
		known = true
		if slices.Contains(g.Methods, method) {
			return g, true, true
		}
	}
	return Grant{}, false, known
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}
