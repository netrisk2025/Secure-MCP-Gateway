package pipeline

import (
	"context"
	"net/netip"
	"slices"
	"time"
)

// EgressAttacher connects one server instance to the Egress Broker (E-18).
// A Launcher calls Attach before the instance's code runs and closes the
// returned attachment after the instance has exited. The attachment's
// environment is added to the instance environment (FR-5.37).
//
// The broker (internal/egress) implements this interface. A confining
// launcher (E-16) that implements EgressAware receives the attacher through
// SetEgress and passes the sandbox network in EgressRequest.Network; any
// other launcher is wrapped so that Attach runs with a nil network, which
// gives the instance proxy variables without enforcement (standalone
// profile).
type EgressAttacher interface {
	Attach(ctx context.Context, req EgressRequest) (*EgressAttachment, error)
}

// EgressAware is implemented by launchers that attach egress themselves,
// because the sandbox network must exist before the broker can bind to it
// and confine it.
type EgressAware interface {
	SetEgress(EgressAttacher)
}

// EgressRequest describes the instance being attached.
type EgressRequest struct {
	// Alias is the server alias; grants are looked up by it.
	Alias string
	// Network is the instance's sandbox network. Nil means the instance
	// shares the host network (standalone profile): the broker listens on
	// loopback and nothing is enforced.
	Network *EgressNetwork
}

// EgressNetwork is the sandbox network of one instance (E-16).
type EgressNetwork struct {
	// NetNS is the path of the instance's network namespace, for example
	// /proc/<pid>/ns/net or /run/netns/<name>. The broker installs nftables
	// rules in it so that the only reachable endpoints are the broker's
	// listeners (SR-4.5-1).
	NetNS string
	// ListenAddr is the host address, reachable from inside the namespace,
	// on which the broker binds the instance's listeners.
	ListenAddr netip.Addr
	// GuestAddr, when valid, is the address at which the instance reaches
	// ListenAddr from inside its namespace (10.0.2.2 for a slirp4netns
	// network with host loopback enabled). The environment URLs and the
	// allowed endpoints use it. When unset they use ListenAddr.
	GuestAddr netip.Addr
	// LauncherConfines means the launcher installs the confinement rules
	// itself, before the instance's code runs, from the attachment's Allow
	// list (a rootless launcher reaches the namespace only through its own
	// user namespace). NetNS may then be empty; the broker installs
	// nothing and reports the attachment as enforced. A launcher that
	// cannot confine the namespace must close the attachment and fail the
	// launch.
	LauncherConfines bool
}

// EgressAttachment is the result of Attach.
type EgressAttachment struct {
	// ID identifies the attachment in evidence and in the control API.
	ID string
	// Env holds the variables to add to the instance environment: proxy
	// variables and one base URL per granted destination endpoint.
	Env map[string]string
	// Enforced reports whether network rules confine the instance to the
	// broker. False in the standalone profile, where the variables are
	// advisory.
	Enforced bool
	// Allow lists the endpoints, as the instance addresses them, that the
	// confinement rules must leave reachable: the broker's listeners.
	Allow []netip.AddrPort
	// Close stops the instance's listeners and removes its rules. It is
	// safe to call more than once.
	Close func() error
	// Issue, when set, mints the one-use egress capabilities of one call
	// to this instance (SR-5.16-1). The launcher exposes it through the
	// Process it returns (EgressIssuer). When the broker does not require
	// capabilities it mints none (nil EgressAuth) and only records the
	// call's egress-limit obligation (FR-5.38) until the returned function
	// is called.
	Issue func(Binding) (*EgressAuth, func())
}

// NoEgress attaches nothing: the instance gets no egress variables. It is
// the default when no broker is configured.
type NoEgress struct{}

// Attach implements EgressAttacher.
func (NoEgress) Attach(context.Context, EgressRequest) (*EgressAttachment, error) {
	return &EgressAttachment{Env: map[string]string{}, Close: func() error { return nil }}, nil
}

// EgressAuthMeta is the _meta key under which the Gateway delivers the
// one-use egress capabilities of a call to the server instance (CP-23
// prefix, SR-5.16-1).
const EgressAuthMeta = "local.smcpgw/egress_auth"

// EgressAuthHeader is the request header in which an instance presents
// one egress capability to the Egress Broker.
const EgressAuthHeader = "Smcp-Egress-Auth"

// EgressAuth is the set of one-use egress capabilities minted for one
// call to one instance. Each token authorizes exactly one brokered
// operation (one proxy request, one CONNECT tunnel or one endpoint
// request) to the destination of its grant while the call is in
// progress.
type EgressAuth struct {
	Header       string             `json:"header"`
	ExpiresAt    time.Time          `json:"expires_at"`
	Destinations []EgressCapability `json:"destinations"`
}

// EgressCapability lists the tokens for one granted destination: the
// grant's host (an exact name, a "*.suffix" wildcard or an IP literal)
// and ports, and the endpoint variable when the grant has one.
type EgressCapability struct {
	Host     string   `json:"host"`
	Ports    []int    `json:"ports"`
	Endpoint string   `json:"endpoint_env,omitempty"`
	Tokens   []string `json:"tokens"`
}

// Take returns an unused token of the first destination whose host is
// exactly host and whose ports include port, and removes it from the
// list; "" when none is left.
func (a *EgressAuth) Take(host string, port int) string {
	if a == nil {
		return ""
	}
	for i := range a.Destinations {
		d := &a.Destinations[i]
		if d.Host == host && slices.Contains(d.Ports, port) && len(d.Tokens) > 0 {
			t := d.Tokens[0]
			d.Tokens = d.Tokens[1:]
			return t
		}
	}
	return ""
}

// EgressIssuer mints the egress capabilities of one call. The Tool
// Dispatcher (E-10) calls IssueEgress with the call's binding before it
// sends tools/call to the instance and calls revoke after the call
// returns; revoke invalidates every token of the call that was not used.
// A nil EgressAuth means the instance has no capabilities to receive.
type EgressIssuer interface {
	IssueEgress(b Binding) (auth *EgressAuth, revoke func())
}

// ProcessUnwrapper is implemented by Process wrappers so that optional
// interfaces of the wrapped process (EgressIssuer) stay reachable.
type ProcessUnwrapper interface {
	Unwrap() Process
}

// EgressIssuerOf returns the EgressIssuer of p or of a process it wraps,
// or nil.
func EgressIssuerOf(p Process) EgressIssuer {
	for range 16 {
		if p == nil {
			return nil
		}
		if is, ok := p.(EgressIssuer); ok {
			return is
		}
		u, ok := p.(ProcessUnwrapper)
		if !ok {
			return nil
		}
		p = u.Unwrap()
	}
	return nil
}
