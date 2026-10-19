package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// refusal is an operation refused by the broker with a reason code.
type refusal struct {
	reason string
	detail string
}

func (e *refusal) Error() string { return e.reason + ": " + e.detail }

func refused(reason, format string, a ...any) error {
	return &refusal{reason: reason, detail: fmt.Sprintf(format, a...)}
}

// asRefusal extracts a refusal from err, or classifies err as an upstream
// failure or timeout.
func asRefusal(err error) *refusal {
	var r *refusal
	if errors.As(err, &r) {
		return r
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errDeadline) {
		return &refusal{ReasonTimeout, "operation timeout reached"}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &refusal{ReasonTimeout, "operation timeout reached"}
	}
	return &refusal{ReasonUpstream, err.Error()}
}

var errDeadline = errors.New("deadline")

// resolve returns the candidate addresses of host: the literal itself, or
// the broker's own DNS answers. The resolver of the instance is never
// consulted (SR-5.15-1).
func (b *Broker) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	addrs, err := b.o.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, refused(ReasonDNSFailed, "resolve %s: %v", host, err)
	}
	if len(addrs) == 0 {
		return nil, refused(ReasonDNSFailed, "resolve %s: no addresses", host)
	}
	return addrs, nil
}

// dialPinned resolves host, keeps only the addresses grant g permits and
// dials them in order by IP. The connection therefore goes to an address
// that was validated at connection time, whatever a later DNS answer says
// (rebinding defense, SR-5.15-1, SR-5.15-2).
func (b *Broker) dialPinned(ctx context.Context, rec *Record, g Grant, host string, port int) (net.Conn, error) {
	addrs, err := b.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var ok []netip.Addr
	rec.Resolved = rec.Resolved[:0]
	refusedClass := ""
	for _, a := range addrs {
		a = a.Unmap()
		rec.Resolved = append(rec.Resolved, a.String())
		if allowed, class := permitted(a, g); allowed {
			ok = append(ok, a)
		} else if refusedClass == "" {
			refusedClass = class
		}
	}
	if len(ok) == 0 {
		rec.AddressClass = refusedClass
		return nil, refused(ReasonAddressRefused, "%s resolves only to %s addresses %v", host, refusedClass, rec.Resolved)
	}
	dctx, cancel := context.WithTimeout(ctx, b.limits.DialTimeout)
	defer cancel()
	var errs []error
	for _, a := range ok {
		conn, err := b.o.Dial(dctx, "tcp", netip.AddrPortFrom(a, uint16(port)).String()) // #nosec G115 -- port is 1..65535
		if err == nil {
			rec.Address = a.String()
			rec.AddressClass = Classify(a)
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("connect %s: %w", host, errors.Join(errs...))
}

type dialKey struct{}

// dialState travels in the request context to the transport's dialer.
type dialState struct {
	grant Grant
	rec   *Record
}

// dialFromContext is the transport's DialContext. It refuses any dial that
// was not prepared by forward, so the transport cannot reach a destination
// that no grant covers.
func (b *Broker) dialFromContext(ctx context.Context, _, addr string) (net.Conn, error) {
	st, _ := ctx.Value(dialKey{}).(*dialState)
	if st == nil {
		return nil, refused(ReasonNoGrant, "dial outside an authorized operation")
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, refused(ReasonBadRequest, "bad address %q", addr)
	}
	port, err := portOf(p, 0)
	if err != nil {
		return nil, refused(ReasonBadRequest, "bad port in %q", addr)
	}
	host, err := canonicalHost(h, false)
	if err != nil || !hostMatches(st.grant.Host, host) {
		return nil, refused(ReasonNoGrant, "dial to %s is not the authorized destination", addr)
	}
	return b.dialPinned(ctx, st.rec, st.grant, host, port)
}
