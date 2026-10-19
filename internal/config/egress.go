package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Egress configures the Egress Broker (E-18). Grants are per server alias:
// a server instance may reach only the destinations granted to its alias
// (SR-4.5-2). The limits are broker-wide defaults; a grant may set a
// smaller request size, response size or timeout, never a larger one
// (FR-5.38).
type Egress struct {
	Enabled           bool     `toml:"enabled" json:"enabled"`
	ProxyEnv          *bool    `toml:"proxy_env" json:"proxy_env"`
	RequestBytes      int64    `toml:"request_bytes" json:"request_bytes"`
	ResponseBytes     int64    `toml:"response_bytes" json:"response_bytes"`
	OperationTimeout  Duration `toml:"operation_timeout" json:"operation_timeout"`
	DialTimeout       Duration `toml:"dial_timeout" json:"dial_timeout"`
	RequestsPerMinute int      `toml:"requests_per_minute" json:"requests_per_minute"`
	BytesPerMinute    int64    `toml:"bytes_per_minute" json:"bytes_per_minute"`
	RecentRecords     int      `toml:"recent_records" json:"recent_records"`
	// RequireCapability (default true) makes the broker forward an
	// operation only with a one-use capability of the current call in the
	// Smcp-Egress-Auth header (SR-5.16-1).
	RequireCapability *bool `toml:"require_capability" json:"require_capability"`
	// CapabilityTokens is the number of capabilities delivered per grant
	// with each call (default 8).
	CapabilityTokens int `toml:"capability_tokens" json:"capability_tokens"`
	// Resolvers, when set, are the DNS servers (host:port) the broker asks
	// instead of the host's resolver.
	Resolvers []string `toml:"resolvers" json:"resolvers"`
	// CAFile is a PEM file of certificates trusted, in addition to the
	// system trust store, for destinations whose TLS the broker originates.
	CAFile string        `toml:"ca_file" json:"ca_file"`
	Grants []EgressGrant `toml:"grant" json:"grant"`
}

// EgressGrant permits one server alias to reach one destination host on the
// listed ports with the listed methods. Host is an exact DNS name, a
// "*.suffix" wildcard (subdomains only) or an IP literal. Addresses lists
// exact addresses that may be reached for this grant even though they are
// loopback, private, link-local or otherwise reserved (SR-5.15-2).
// EndpointEnv, when set, gives the instance a plain-HTTP endpoint for this
// destination whose base URL is passed in that variable; the broker
// originates TLS to the destination (FR-5.36, FR-5.37).
type EgressGrant struct {
	Server        string   `toml:"server" json:"server"`
	Host          string   `toml:"host" json:"host"`
	Ports         []int    `toml:"ports" json:"ports"`
	Methods       []string `toml:"methods" json:"methods"`
	Class         string   `toml:"class" json:"class"`
	Addresses     []string `toml:"addresses" json:"addresses"`
	EndpointEnv   string   `toml:"endpoint_env" json:"endpoint_env"`
	RequestBytes  int64    `toml:"request_bytes" json:"request_bytes"`
	ResponseBytes int64    `toml:"response_bytes" json:"response_bytes"`
	Timeout       Duration `toml:"timeout" json:"timeout"`
}

// Egress grant classes.
const (
	EgressClassAPI         = "api"
	EgressClassPublicFetch = "public-fetch"
)

// EgressDefault is one default applied to an [egress] key that is absent.
type EgressDefault struct {
	Key   string
	Value any
	field func(*Egress) any
}

// EgressDefaults lists the [egress] defaults by key. A test checks that
// this list and the schema's egress properties agree.
var EgressDefaults = []EgressDefault{
	{"request_bytes", int64(1 << 20), func(e *Egress) any { return &e.RequestBytes }},
	{"response_bytes", int64(8 << 20), func(e *Egress) any { return &e.ResponseBytes }},
	{"operation_timeout", 30 * time.Second, func(e *Egress) any { return &e.OperationTimeout }},
	{"dial_timeout", 10 * time.Second, func(e *Egress) any { return &e.DialTimeout }},
	{"requests_per_minute", 60, func(e *Egress) any { return &e.RequestsPerMinute }},
	{"bytes_per_minute", int64(64 << 20), func(e *Egress) any { return &e.BytesPerMinute }},
	{"recent_records", 256, func(e *Egress) any { return &e.RecentRecords }},
	{"capability_tokens", 8, func(e *Egress) any { return &e.CapabilityTokens }},
}

func (e *Egress) applyDefaults(set map[string]bool) {
	for _, d := range EgressDefaults {
		if set[d.Key] {
			continue
		}
		switch v := d.Value.(type) {
		case int:
			*d.field(e).(*int) = v
		case int64:
			*d.field(e).(*int64) = v
		case time.Duration:
			d.field(e).(*Duration).Duration = v
		}
	}
	if e.ProxyEnv == nil {
		t := true
		e.ProxyEnv = &t
	}
	if e.RequireCapability == nil {
		t := true
		e.RequireCapability = &t
	}
	for i := range e.Grants {
		g := &e.Grants[i]
		g.Host = strings.TrimSuffix(strings.ToLower(g.Host), ".")
		if g.Class == "" {
			g.Class = EgressClassAPI
		}
		if len(g.Ports) == 0 {
			g.Ports = []int{443}
		}
		for j := range g.Methods {
			g.Methods[j] = strings.ToUpper(g.Methods[j])
		}
	}
}

func (e *Egress) check(servers map[string]bool) error {
	for _, d := range []struct {
		key string
		v   Duration
	}{{"operation_timeout", e.OperationTimeout}, {"dial_timeout", e.DialTimeout}} {
		if d.v.Duration <= 0 {
			return fmt.Errorf("egress.%s must be a positive duration", d.key)
		}
	}
	for _, r := range e.Resolvers {
		if _, err := netip.ParseAddrPort(r); err != nil {
			return fmt.Errorf("egress.resolvers: %q is not an IP address and port", r)
		}
	}
	envs := map[string]string{}
	for i, g := range e.Grants {
		where := fmt.Sprintf("egress.grant[%d] (%s %s)", i, g.Server, g.Host)
		if !servers[g.Server] {
			return fmt.Errorf("%s names unknown server alias %q", where, g.Server)
		}
		if g.Timeout.Duration < 0 {
			return fmt.Errorf("%s: timeout must not be negative", where)
		}
		for _, a := range g.Addresses {
			if _, err := netip.ParseAddr(a); err != nil {
				return fmt.Errorf("%s: address %q is not an IP address", where, a)
			}
		}
		if g.Class == EgressClassPublicFetch {
			if g.EndpointEnv == "" {
				return fmt.Errorf("%s: public-fetch grants are served only through an endpoint; set endpoint_env", where)
			}
			if slices.ContainsFunc(g.Methods, func(m string) bool { return m != "GET" }) {
				return fmt.Errorf("%s: public-fetch grants permit only GET", where)
			}
		}
		if g.EndpointEnv != "" {
			if strings.HasPrefix(g.Host, "*.") {
				return fmt.Errorf("%s: an endpoint needs an exact host, not a wildcard", where)
			}
			if len(g.Ports) != 1 {
				return fmt.Errorf("%s: an endpoint needs exactly one port", where)
			}
			key := g.Server + "/" + g.EndpointEnv
			if prev, dup := envs[key]; dup {
				return fmt.Errorf("%s: endpoint_env %s is already used by the grant for %s", where, g.EndpointEnv, prev)
			}
			envs[key] = g.Host
		}
	}
	return nil
}
