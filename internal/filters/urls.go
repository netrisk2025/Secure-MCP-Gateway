package filters

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// URLOptions configure url-canonicalize (SR-1.8-5).
type URLOptions struct {
	Schemes      []string // allowed schemes; default http and https
	Hosts        []string // allowed hosts ("example.com", "*.example.com"); empty allows any public host
	DenyHosts    []string // refused hosts, same forms
	AllowPrivate bool     // allow loopback, private, link-local and similar destinations
	Names        []string // extra property names treated as URLs
	IgnoreNames  []string
	Rewrite      bool
}

type urlFilter struct {
	opts  URLOptions
	kind  argKind
	allow []string
	deny  []string
}

func newURLFilter(o URLOptions) (*urlFilter, error) {
	if len(o.Schemes) == 0 {
		o.Schemes = []string{"http", "https"}
	}
	for i, s := range o.Schemes {
		o.Schemes[i] = strings.ToLower(s)
	}
	f := &urlFilter{opts: o, kind: withNames(urlKind, o.Names)}
	canon := func(list []string) ([]string, error) {
		var out []string
		for _, h := range list {
			wild := strings.HasPrefix(h, "*.")
			c, err := canonicalHostName(strings.TrimPrefix(h, "*."))
			if err != nil {
				return nil, fmt.Errorf("host %q: %w", h, err)
			}
			if wild {
				c = "*." + c
			}
			out = append(out, c)
		}
		return out, nil
	}
	var err error
	if f.allow, err = canon(o.Hosts); err != nil {
		return nil, err
	}
	if f.deny, err = canon(o.DenyHosts); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *urlFilter) ID() string      { return IDURLCanonicalize }
func (f *urlFilter) Version() string { return filterVersion }

func (f *urlFilter) FilterRequest(_ context.Context, call *pipeline.Call, args json.RawMessage) (pipeline.RequestVerdict, error) {
	v, _, ok := argSurfaces(args)
	if !ok {
		return invalidArguments(), nil
	}
	changed := false
	var findings []pipeline.Finding
	for _, ts := range typedSurfaces(call.InputSchema, v, f.kind) {
		if slices.Contains(f.opts.IgnoreNames, ts.name) {
			continue
		}
		cu, err := f.Check(ts.get())
		if err != nil {
			var ue *URLError
			reason, rule := ReasonURLInvalid, "invalid"
			if errors.As(err, &ue) {
				reason, rule = ue.Reason, ue.Rule
			}
			return pipeline.RequestVerdict{Action: pipeline.Block, ReasonCode: reason, Finding: "URL argument at " + ts.loc + ": " + err.Error(),
				Findings: []pipeline.Finding{{Filter: IDURLCanonicalize, Rule: rule, Location: ts.loc}}}, nil
		}
		if f.opts.Rewrite && cu != ts.get() {
			ts.set(cu)
			changed = true
			findings = append(findings, pipeline.Finding{Filter: IDURLCanonicalize, Rule: "canonicalized", Location: ts.loc})
		}
	}
	if !changed {
		return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return pipeline.RequestVerdict{}, err
	}
	return pipeline.RequestVerdict{Action: pipeline.Transform, Arguments: raw, Findings: findings}, nil
}

// URLError explains a refused URL.
type URLError struct {
	Reason string // ReasonURLInvalid, ReasonURLNotAllowed or ReasonURLPrivate
	Rule   string
	Msg    string
}

func (e *URLError) Error() string { return e.Msg }

func urlErr(reason, rule, format string, a ...any) error {
	return &URLError{Reason: reason, Rule: rule, Msg: fmt.Sprintf(format, a...)}
}

// Check canonicalizes raw and applies the scheme, host and address rules.
// It returns the canonical URL.
func (f *urlFilter) Check(raw string) (string, error) {
	u, host, ip, err := CanonicalURL(raw)
	if err != nil {
		return "", err
	}
	if !slices.Contains(f.opts.Schemes, u.Scheme) {
		return "", urlErr(ReasonURLNotAllowed, "scheme", "scheme %q is not allowed", u.Scheme)
	}
	if ip.IsValid() {
		if !f.opts.AllowPrivate && privateAddr(ip) {
			return "", urlErr(ReasonURLPrivate, "private-address", "destination %s is a loopback, private or reserved address", ip)
		}
	} else if !f.opts.AllowPrivate && privateName(host) {
		return "", urlErr(ReasonURLPrivate, "private-name", "destination %s is a local name", host)
	}
	if hostListed(f.deny, host) {
		return "", urlErr(ReasonURLNotAllowed, "denied-host", "host %s is denied", host)
	}
	if len(f.allow) > 0 && !hostListed(f.allow, host) {
		return "", urlErr(ReasonURLNotAllowed, "host-not-allowed", "host %s is not in the allowed hosts", host)
	}
	return u.String(), nil
}

func hostListed(list []string, host string) bool {
	for _, h := range list {
		if strings.HasPrefix(h, "*.") {
			if strings.HasSuffix(host, h[1:]) {
				return true
			}
		} else if h == host {
			return true
		}
	}
	return false
}

// CanonicalURL parses raw and normalizes the scheme (lower case), the host
// (percent-decoding, IDNA to its A-label form, lower case, no trailing
// dot), IPv4 literals in decimal, octal, hexadecimal or shortened form,
// IPv4-mapped IPv6, and the port (a scheme's default port is removed). It
// refuses userinfo, control characters and URLs without a host. The host
// and, for an IP literal, the address are returned with the URL.
func CanonicalURL(raw string) (*url.URL, string, netip.Addr, error) {
	var none netip.Addr
	s := strings.TrimSpace(raw)
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == ' ' || c == '\\' {
			return nil, "", none, urlErr(ReasonURLInvalid, "control-character", "URL contains a space, backslash or control character")
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, "", none, urlErr(ReasonURLInvalid, "unparseable", "URL cannot be parsed")
	}
	if u.Scheme == "" || u.Opaque != "" || u.Host == "" {
		return nil, "", none, urlErr(ReasonURLInvalid, "not-absolute", "URL must be absolute with a host")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.User != nil {
		return nil, "", none, urlErr(ReasonURLNotAllowed, "userinfo", "URL must not carry user information")
	}
	hostport := u.Host
	host, port := hostport, ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = hostport[1 : len(hostport)-1]
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, "", none, urlErr(ReasonURLInvalid, "port", "port %q is invalid", port)
		}
		port = strconv.Itoa(n)
		if (u.Scheme == "http" && n == 80) || (u.Scheme == "https" && n == 443) {
			port = ""
		}
	}
	if dec, err := url.PathUnescape(host); err == nil {
		host = dec
	}
	var ip netip.Addr
	if a, err := netip.ParseAddr(strings.Split(host, "%")[0]); err == nil && strings.Contains(host, ":") {
		ip = a.Unmap()
		host = ip.String()
	} else {
		ch, err := canonicalHostName(host)
		if err != nil {
			return nil, "", none, err
		}
		host = ch
		if a, ok := parseLegacyIPv4(host); ok {
			ip = a
			host = a.String()
		}
	}
	h := host
	if ip.Is6() {
		h = "[" + host + "]"
	}
	if port != "" {
		h += ":" + port
	}
	u.Host = h
	return u, host, ip, nil
}

var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.BidiRule(), idna.StrictDomainName(false))

func canonicalHostName(h string) (string, error) {
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", urlErr(ReasonURLInvalid, "empty-host", "host is empty")
	}
	a, err := idnaProfile.ToASCII(h)
	if err != nil {
		return "", urlErr(ReasonURLInvalid, "idna", "host is not a valid internationalized domain name")
	}
	a = strings.TrimSuffix(strings.ToLower(a), ".")
	for _, c := range a {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return "", urlErr(ReasonURLInvalid, "host-character", "host contains a character outside the DNS alphabet")
		}
	}
	return a, nil
}

// parseLegacyIPv4 accepts the inet_aton forms browsers and resolvers still
// accept: 1 to 4 parts, each decimal, octal (leading 0) or hexadecimal
// (0x), with the last part filling the remaining bytes.
func parseLegacyIPv4(h string) (netip.Addr, bool) {
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var vals []uint64
	for _, p := range parts {
		if p == "" {
			return netip.Addr{}, false
		}
		base := 10
		switch {
		case strings.HasPrefix(p, "0x"):
			base, p = 16, p[2:]
			if p == "" {
				p = "0"
			}
		case len(p) > 1 && p[0] == '0':
			base, p = 8, p[1:]
		}
		v, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		vals = append(vals, v)
	}
	var n uint64
	for i, v := range vals[:len(vals)-1] {
		if v > 255 {
			return netip.Addr{}, false
		}
		n |= v << (24 - 8*uint(i))
	}
	last := vals[len(vals)-1]
	if last >= 1<<(8*uint(5-len(vals))) {
		return netip.Addr{}, false
	}
	n |= last
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n)) //nolint:gosec // n < 2^32: each part is bounded above
	return netip.AddrFrom4(b), true
}

var reservedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32", "64:ff9b::/96", "64:ff9b:1::/48", "2001:db8::/32", "100::/64", "2002::/16"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func privateAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range reservedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func privateName(h string) bool {
	for _, suf := range []string{"localhost", "local", "internal", "home.arpa", "localdomain"} {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}
