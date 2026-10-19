// Package egress is the Egress Broker (E-18): the only path from server
// instances to external networks. Each instance gets its own listeners:
//
//   - a forward proxy (HTTP CONNECT for HTTPS, absolute-form requests for
//     plain HTTP) whose address is passed to the instance in HTTP_PROXY and
//     HTTPS_PROXY;
//   - one plain-HTTP endpoint per grant that names an endpoint variable,
//     for which the broker originates TLS to the HTTPS destination
//     (FR-5.36).
//
// Every operation is checked against the current grants of the instance's
// server alias (host, port, method; for tunnels also the TLS SNI). The
// broker resolves names itself, refuses loopback, private, link-local,
// CGNAT, multicast, reserved and cloud-metadata addresses unless the grant
// names the exact address, and dials the validated IP, so a second DNS
// answer cannot redirect the connection (rebinding). Request size,
// response size, duration, request rate and byte rate are bounded. Tunnels
// are spliced without TLS interception. Each operation is recorded as
// evidence with host, port, address, bytes and decision. With
// RequireCapability, each operation must also present a one-use
// capability minted for the call the instance is serving (SR-5.16-1,
// capability.go).
//
// In the enforced profile the confining launcher passes the instance's
// network namespace and the broker installs nftables rules in it so that
// the broker's listeners are the only reachable endpoints (SR-4.5-1). In
// the standalone profile the proxy variables are advisory: an instance
// can ignore them and connect directly.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Origin is the element ID on evidence events.
const Origin = "E-18"

// MaxRedirects bounds the redirects an endpoint follows (SR-5.15-1).
const MaxRedirects = 3

// AuthHeader is the egress capability header (CP-23, SR-5.16-1). The
// broker checks it when capabilities are required and removes it before
// forwarding.
const AuthHeader = pipeline.EgressAuthHeader

// ReasonHeader carries the reason code of a refusal to the instance.
const ReasonHeader = "Smcp-Egress-Reason"

// Limits bound egress. Zero values select the defaults of config.Egress.
type Limits struct {
	RequestBytes      int64
	ResponseBytes     int64
	OperationTimeout  time.Duration
	DialTimeout       time.Duration
	RequestsPerMinute int
	BytesPerMinute    int64
}

func (l *Limits) defaults() {
	if l.RequestBytes <= 0 {
		l.RequestBytes = 1 << 20
	}
	if l.ResponseBytes <= 0 {
		l.ResponseBytes = 8 << 20
	}
	if l.OperationTimeout <= 0 {
		l.OperationTimeout = 30 * time.Second
	}
	if l.DialTimeout <= 0 {
		l.DialTimeout = 10 * time.Second
	}
	if l.RequestsPerMinute <= 0 {
		l.RequestsPerMinute = 60
	}
	if l.BytesPerMinute < 64<<10 {
		l.BytesPerMinute = 64 << 20
	}
}

// effective returns the limits for one operation under grant g: the
// smaller of the broker limit and the grant's own. Broker.opLimits adds
// the manifest and the decision obligation (FR-5.38).
func (l Limits) effective(g Grant) Limits {
	minPos := func(a, b int64) int64 {
		if b > 0 && b < a {
			return b
		}
		return a
	}
	out := l
	out.RequestBytes = minPos(l.RequestBytes, g.RequestBytes)
	out.ResponseBytes = minPos(l.ResponseBytes, g.ResponseBytes)
	out.OperationTimeout = time.Duration(minPos(int64(l.OperationTimeout), int64(g.Timeout)))
	return out
}

// Resolver resolves destination names. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// RuleInstaller confines a network namespace so that only the listed
// endpoints are reachable from it. The nftables implementation is the
// default on Linux.
type RuleInstaller interface {
	Install(netns string, allow []netip.AddrPort) (remove func() error, err error)
}

// Options configure a Broker.
type Options struct {
	Grants   GrantSource
	Limits   Limits
	Evidence audit.Recorder
	// Servers lists the server aliases, for the control API's grant view.
	Servers []string
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// Dial connects to an IP:port the broker has validated; default a
	// net.Dialer. Tests use it to observe that only validated addresses
	// are dialed.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// RootCAs verifies destination certificates; nil uses the system pool.
	RootCAs *x509.CertPool
	// ProxyEnv adds HTTP_PROXY and HTTPS_PROXY to instance environments.
	ProxyEnv bool
	// Rules confines sandbox networks; default nftables on Linux.
	Rules RuleInstaller
	// Recent is the number of operation records kept for the control API.
	Recent int
	// RequireCapability makes the broker forward an operation only with a
	// one-use capability minted for the current call (SR-5.16-1,
	// capability.go). FromConfig sets it unless [egress]
	// require_capability = false.
	RequireCapability bool
	// CapabilityTokens is the number of tokens minted per grant and call;
	// default DefaultCapabilityTokens.
	CapabilityTokens int
	Log              *slog.Logger
	Now              func() time.Time
}

// Broker is the Egress Broker. It implements pipeline.EgressAttacher.
type Broker struct {
	o         Options
	limits    Limits
	transport *http.Transport
	scan      secretScan // registered secret fingerprints (SR-5.8-2)

	mu        sync.Mutex
	instances map[string]*instance
	limiters  map[string]*serverLimiter
	recent    []Record
	next      int
	full      bool
	closed    bool

	headers  headerSet      // S1 header grants (inject.go)
	caps     capStore       // one-use egress capabilities (capability.go)
	manifest ManifestLimits // manifest egress limits (bounds.go); under mu
}

type serverLimiter struct {
	requests *rate.Limiter
	bytes    *rate.Limiter
}

// New builds a broker. Evidence and Grants are required.
func New(o Options) (*Broker, error) {
	if o.Evidence == nil || o.Grants == nil {
		return nil, errors.New("egress: evidence and grants are required")
	}
	o.Limits.defaults()
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Recent < 0 {
		o.Recent = 0
	}
	if o.Rules == nil {
		o.Rules = defaultRules()
	}
	b := &Broker{o: o, limits: o.Limits, instances: map[string]*instance{}, limiters: map[string]*serverLimiter{}}
	if o.Dial == nil {
		d := &net.Dialer{Timeout: o.Limits.DialTimeout}
		b.o.Dial = d.DialContext
	}
	b.transport = &http.Transport{
		Proxy:                  nil, // never chain to an ambient proxy
		DialContext:            b.dialFromContext,
		TLSClientConfig:        &tls.Config{RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    o.Limits.DialTimeout,
		DisableKeepAlives:      true, // one connection per operation: exact evidence, no reuse across grants
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
		ResponseHeaderTimeout:  o.Limits.OperationTimeout,
	}
	return b, nil
}

// FromConfig builds the broker of a configuration, or returns nil when
// [egress] is not enabled.
func FromConfig(cfg *config.Config, rec audit.Recorder, log *slog.Logger) (*Broker, error) {
	e := cfg.Egress
	if !e.Enabled {
		return nil, nil
	}
	gs, err := GrantsFromConfig(e.Grants)
	if err != nil {
		return nil, err
	}
	servers := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		servers = append(servers, s.Alias)
	}
	res, roots, err := destinationTrust(e)
	if err != nil {
		return nil, err
	}
	return New(Options{Grants: NewStaticGrants(gs), Evidence: rec, Servers: servers, Log: log, Recent: e.RecentRecords,
		ProxyEnv: e.ProxyEnv == nil || *e.ProxyEnv, Resolver: res, RootCAs: roots,
		RequireCapability: e.RequireCapability == nil || *e.RequireCapability, CapabilityTokens: e.CapabilityTokens,
		Limits: Limits{RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes, OperationTimeout: e.OperationTimeout.Duration,
			DialTimeout: e.DialTimeout.Duration, RequestsPerMinute: e.RequestsPerMinute, BytesPerMinute: e.BytesPerMinute}})
}

// instance is one attached server instance and its listeners.
type instance struct {
	id        string
	alias     string
	enforced  bool
	attached  time.Time
	proxyURL  string
	endpoints map[string]string // variable -> base URL
	servers   []*http.Server
	remove    func() error
	once      sync.Once
	err       error
	// calls holds the egress-limit obligations of the calls the instance
	// is serving when capabilities are not required (bounds.go); under
	// Broker.mu.
	calls map[uint64]pipeline.EgressLimits
	seq   uint64
}

// InstanceInfo is the control API view of an attachment.
type InstanceInfo struct {
	ID        string            `json:"id"`
	Server    string            `json:"server"`
	Enforced  bool              `json:"enforced"`
	Proxy     string            `json:"proxy"`
	Endpoints map[string]string `json:"endpoints"`
	Attached  time.Time         `json:"attached_at"`
}

// Attach implements pipeline.EgressAttacher: it opens the instance's
// proxy listener and one endpoint listener per endpoint grant and, when
// req.Network is set, confines the namespace to them. On any failure
// nothing stays open.
func (b *Broker) Attach(_ context.Context, req pipeline.EgressRequest) (att *pipeline.EgressAttachment, err error) {
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return nil, errors.New("egress: broker is closed")
	}
	in := &instance{id: ids.New(), alias: req.Alias, attached: b.o.Now(), endpoints: map[string]string{}}
	defer func() {
		if err != nil {
			_ = in.close()
		}
	}()
	host := netip.MustParseAddr("127.0.0.1")
	var guest netip.Addr
	if req.Network != nil {
		if (req.Network.NetNS == "" && !req.Network.LauncherConfines) || !req.Network.ListenAddr.IsValid() {
			return nil, errors.New("egress: a sandbox network needs a namespace and a listen address")
		}
		host, guest = req.Network.ListenAddr, req.Network.GuestAddr
	}
	var allow []netip.AddrPort
	listen := func(h http.Handler) (string, error) {
		ln, err := net.Listen("tcp", netip.AddrPortFrom(host, 0).String())
		if err != nil {
			return "", fmt.Errorf("egress: listen on %s: %w", host, err)
		}
		ap, err := netip.ParseAddrPort(ln.Addr().String())
		if err != nil {
			ln.Close()
			return "", err
		}
		// The instance addresses the listener by the guest address when
		// its namespace translates it (slirp4netns host loopback).
		if guest.IsValid() {
			ap = netip.AddrPortFrom(guest, ap.Port())
		}
		allow = append(allow, ap)
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, ErrorLog: slog.NewLogLogger(b.o.Log.Handler(), slog.LevelDebug)}
		in.servers = append(in.servers, srv)
		go func() { _ = srv.Serve(ln) }()
		return "http://" + ap.String(), nil
	}
	if in.proxyURL, err = listen(b.proxyHandler(in)); err != nil {
		return nil, err
	}
	for _, g := range b.o.Grants.Grants(req.Alias) {
		if g.EndpointEnv == "" {
			continue
		}
		u, err := listen(b.endpointHandler(in, g.EndpointEnv, g.Host, g.Ports[0]))
		if err != nil {
			return nil, err
		}
		in.endpoints[g.EndpointEnv] = u
	}
	confinedBy := ""
	switch {
	case req.Network != nil && req.Network.LauncherConfines:
		in.enforced, confinedBy = true, "launcher"
	case req.Network != nil:
		if in.remove, err = b.o.Rules.Install(req.Network.NetNS, allow); err != nil {
			return nil, fmt.Errorf("egress: confine %s: %w", req.Network.NetNS, err)
		}
		in.enforced, confinedBy = true, "broker"
	}
	env := map[string]string{}
	if b.o.ProxyEnv {
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			env[k] = in.proxyURL
		}
		env["NO_PROXY"], env["no_proxy"] = "", ""
	}
	for k, v := range in.endpoints {
		env[k] = v
	}
	if err := b.o.Evidence.Record(audit.Event{Class: "egress", Origin: Origin, Outcome: "attached", PolicyStatus: "not_evaluated",
		Detail: map[string]any{"instance": in.id, "server": in.alias, "enforced": in.enforced, "confined_by": confinedBy, "proxy": in.proxyURL, "endpoints": in.endpoints}}); err != nil {
		return nil, fmt.Errorf("egress: evidence: %w", err)
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("egress: broker is closed")
	}
	b.instances[in.id] = in
	b.mu.Unlock()
	if !in.enforced {
		b.o.Log.Warn("egress for this instance is advisory: the standalone profile does not confine its network", "server", in.alias, "proxy", in.proxyURL)
	}
	att = &pipeline.EgressAttachment{ID: in.id, Env: env, Enforced: in.enforced, Allow: slices.Clone(allow), Close: func() error { return b.detach(in) }}
	// With capabilities required, Issue mints the call's tokens; without,
	// it records the call's egress-limit obligation for the instance
	// (FR-5.38) and returns no tokens.
	att.Issue = func(bnd pipeline.Binding) (*pipeline.EgressAuth, func()) { return b.issue(in, bnd) }
	return att, nil
}

func (b *Broker) detach(in *instance) error {
	b.mu.Lock()
	_, live := b.instances[in.id]
	delete(b.instances, in.id)
	b.mu.Unlock()
	err := in.close()
	if live {
		if rerr := b.o.Evidence.Record(audit.Event{Class: "egress", Origin: Origin, Outcome: "detached", PolicyStatus: "not_evaluated",
			Detail: map[string]any{"instance": in.id, "server": in.alias}}); rerr != nil {
			b.o.Log.Error("evidence write failed", "err", rerr)
		}
	}
	return err
}

func (in *instance) close() error {
	in.once.Do(func() {
		var errs []error
		for _, s := range in.servers {
			errs = append(errs, s.Close())
		}
		if in.remove != nil {
			errs = append(errs, in.remove())
		}
		in.err = errors.Join(errs...)
	})
	return in.err
}

// Instances lists the live attachments.
func (b *Broker) Instances() []InstanceInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]InstanceInfo, 0, len(b.instances))
	for _, in := range b.instances {
		out = append(out, InstanceInfo{ID: in.id, Server: in.alias, Enforced: in.enforced, Proxy: in.proxyURL, Endpoints: in.endpoints, Attached: in.attached})
	}
	slices.SortFunc(out, func(a, c InstanceInfo) int { return a.Attached.Compare(c.Attached) })
	return out
}

// Limits returns the broker-wide limits in effect.
func (b *Broker) Limits() Limits { return b.limits }

// Close detaches every instance. Later Attach calls fail.
func (b *Broker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	b.closed = true
	all := make([]*instance, 0, len(b.instances))
	for _, in := range b.instances {
		all = append(all, in)
	}
	b.mu.Unlock()
	var errs []error
	for _, in := range all {
		errs = append(errs, b.detach(in))
	}
	b.transport.CloseIdleConnections()
	b.headers.mu.Lock()
	for id, g := range b.headers.grants {
		clear(g.value)
		delete(b.headers.grants, id)
	}
	b.headers.mu.Unlock()
	return errors.Join(errs...)
}

func (b *Broker) limiter(server string) *serverLimiter {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.limiters[server]
	if l == nil {
		l = &serverLimiter{
			requests: rate.NewLimiter(rate.Limit(float64(b.limits.RequestsPerMinute)/60), b.limits.RequestsPerMinute),
			bytes:    rate.NewLimiter(rate.Limit(float64(b.limits.BytesPerMinute)/60), int(b.limits.BytesPerMinute)),
		}
		b.limiters[server] = l
	}
	return l
}

func portOf(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("invalid port")
	}
	return p, nil
}
