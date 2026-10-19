package egress

import (
	"crypto/sha256"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// One-use egress capabilities (SR-5.16-1).
//
// When Options.RequireCapability is set, the broker forwards an operation
// only when the instance presents, in the Smcp-Egress-Auth header, a token
// the broker minted for one call to that instance and for the grant that
// permits the destination. The Tool Dispatcher asks for the tokens when it
// sends tools/call (pipeline.EgressIssuer) and delivers them in the
// request's _meta under pipeline.EgressAuthMeta. Each token is bound to the
// instance, to one grant (host and ports) and to the call's correlation
// ID, decision ID and policy revision, which the operation record and its
// evidence carry. A token is spent by the first operation that presents
// it, whether that operation is then forwarded or refused. When the call
// returns, its unused tokens are revoked; spent tokens are remembered until
// they would have expired, so a replay is reported as a replay.

// DefaultCapabilityTokens is the number of tokens minted per grant and
// call when Options.CapabilityTokens is zero.
const DefaultCapabilityTokens = 8

// CapabilityTTL bounds the lifetime of a token whose call never returns.
const CapabilityTTL = 10 * time.Minute

type capEntry struct {
	instance string
	grant    string // grantKey of the grant it was minted for
	dest     string // the grant's destination, for refusal details
	binding  pipeline.Binding
	expires  time.Time
	call     uint64
	used     bool
}

type capStore struct {
	mu     sync.Mutex
	byHash map[[32]byte]*capEntry
	calls  map[uint64][][32]byte
	seq    uint64
}

// grantKey identifies a grant for token binding: host, ports and endpoint.
func grantKey(g Grant) string {
	ps := make([]string, len(g.Ports))
	for i, p := range g.Ports {
		ps[i] = strconv.Itoa(p)
	}
	return g.Host + "|" + strings.Join(ps, ",") + "|" + g.EndpointEnv
}

// issue mints the tokens of one call to in: CapabilityTokens per current
// grant of its server alias.
func (b *Broker) issue(in *instance, bnd pipeline.Binding) (*pipeline.EgressAuth, func()) {
	if !b.o.RequireCapability {
		return nil, b.track(in, bnd.Egress)
	}
	gs := b.o.Grants.Grants(in.alias)
	if len(gs) == 0 {
		return nil, func() {}
	}
	n := b.o.CapabilityTokens
	if n <= 0 {
		n = DefaultCapabilityTokens
	}
	now := b.o.Now()
	exp := now.Add(CapabilityTTL)
	s := &b.caps
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byHash == nil {
		s.byHash, s.calls = map[[32]byte]*capEntry{}, map[uint64][][32]byte{}
	}
	for h, e := range s.byHash {
		if !now.Before(e.expires) {
			delete(s.byHash, h)
		}
	}
	s.seq++
	call := s.seq
	auth := &pipeline.EgressAuth{Header: AuthHeader, ExpiresAt: exp.UTC()}
	var hashes [][32]byte
	for _, g := range gs {
		d := pipeline.EgressCapability{Host: g.Host, Ports: slices.Clone(g.Ports), Endpoint: g.EndpointEnv}
		for range n {
			tok := "smcpe_" + ids.Secret()
			h := sha256.Sum256([]byte(tok))
			s.byHash[h] = &capEntry{instance: in.id, grant: grantKey(g), dest: g.Destination(), binding: bnd, expires: exp, call: call}
			hashes = append(hashes, h)
			d.Tokens = append(d.Tokens, tok)
		}
		auth.Destinations = append(auth.Destinations, d)
	}
	s.calls[call] = hashes
	var once sync.Once
	return auth, func() { once.Do(func() { b.revoke(call) }) }
}

// revoke removes the unused tokens of a call.
func (b *Broker) revoke(call uint64) {
	s := &b.caps
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.calls[call] {
		if e := s.byHash[h]; e != nil && !e.used {
			delete(s.byHash, h)
		}
	}
	delete(s.calls, call)
}

// consume checks and spends the capability an operation presents for
// grant g, and copies its binding into the record.
func (b *Broker) consume(rec *Record, g Grant, h http.Header) error {
	if !b.o.RequireCapability {
		// The operation is not bound to one call: the tightest obligation
		// of the calls in progress applies (FR-5.38).
		rec.obligation = b.inProgress(rec.Instance)
		return nil
	}
	vals := h.Values(AuthHeader)
	if len(vals) == 0 || strings.TrimSpace(vals[0]) == "" {
		rec.Capability = CapabilityMissing
		return refused(ReasonCapabilityRequired, "no %s capability; use a token delivered with the current call", AuthHeader)
	}
	if len(vals) > 1 {
		rec.Capability = CapabilityInvalid
		return refused(ReasonCapabilityInvalid, "more than one %s header", AuthHeader)
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(vals[0])))
	now := b.o.Now()
	s := &b.caps
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.byHash[sum]
	if e == nil || !now.Before(e.expires) {
		rec.Capability = CapabilityInvalid
		return refused(ReasonCapabilityInvalid, "the capability is unknown, expired or revoked (its call has ended)")
	}
	rec.CorrelationID, rec.DecisionID, rec.PolicyRevision = e.binding.CorrelationID, e.binding.DecisionID, e.binding.PolicyRevision
	rec.obligation = e.binding.Egress // FR-5.38
	if e.used {
		rec.Capability = CapabilityReplayed
		return refused(ReasonCapabilityReplayed, "the capability was already used")
	}
	e.used = true
	switch {
	case e.instance != rec.Instance:
		rec.Capability = CapabilityMismatch
		return refused(ReasonCapabilityMismatch, "the capability was issued to another instance")
	case e.grant != grantKey(g):
		rec.Capability = CapabilityMismatch
		return refused(ReasonCapabilityMismatch, "the capability was issued for %s, not %s", e.dest, joinHostPort(rec.Host, rec.Port))
	}
	rec.Capability = CapabilityConsumed
	return nil
}

// Capability states in operation records.
const (
	CapabilityConsumed = "consumed"
	CapabilityMissing  = "missing"
	CapabilityInvalid  = "invalid"
	CapabilityReplayed = "replayed"
	CapabilityMismatch = "mismatch"
)

// outstanding returns the number of live tokens, for tests.
func (b *Broker) outstanding() int {
	b.caps.mu.Lock()
	defer b.caps.mu.Unlock()
	n := 0
	for _, e := range b.caps.byHash {
		if !e.used {
			n++
		}
	}
	return n
}
