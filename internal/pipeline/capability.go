package pipeline

import (
	"errors"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// Binding is what a launch capability is bound to (FR-4.13): the call's
// correlation ID, the decision that permitted it, the policy revision of
// that decision and the public tool name.
type Binding struct {
	CorrelationID  string
	DecisionID     string
	PolicyRevision string
	PublicName     string
	// Egress is the decision's egress-limit obligation (FR-5.38). The
	// Egress Broker applies it to every operation that spends a
	// capability minted for the call.
	Egress EgressLimits
}

// EgressLimits bound each brokered operation of one call: request size,
// response size and duration. Zero sets no bound.
type EgressLimits struct {
	RequestBytes  int64
	ResponseBytes int64
	Timeout       time.Duration
}

// Capability errors. The dispatcher refuses the call on any of them.
var (
	ErrNoCapability       = errors.New("no launch capability")
	ErrCapabilityUnknown  = errors.New("launch capability unknown or expired")
	ErrCapabilityUsed     = errors.New("launch capability already used")
	ErrCapabilityMismatch = errors.New("launch capability issued for another call")
)

// CapabilityChecker is the dispatcher's side of the ledger.
type CapabilityChecker interface {
	Consume(id string, b Binding) error
}

// Capabilities is the one-use launch capability ledger. The Enforcement
// Coordinator (E-12) issues a capability only after the decision intent is
// durable; the Tool Dispatcher (E-10) consumes it before sending anything to
// a backend. A consumed capability is remembered until it would have
// expired, so reuse is reported as reuse.
type Capabilities struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*capEntry
	issued  int
}

type capEntry struct {
	b       Binding
	expires time.Time
	used    bool
}

// NewCapabilities returns a ledger whose capabilities expire after ttl
// (default one minute).
func NewCapabilities(ttl time.Duration) *Capabilities {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &Capabilities{ttl: ttl, now: time.Now, entries: map[string]*capEntry{}}
}

// SetNow replaces the clock (tests).
func (c *Capabilities) SetNow(f func() time.Time) { c.mu.Lock(); c.now = f; c.mu.Unlock() }

// Issue records a new capability for b and returns its ID (256-bit random).
func (c *Capabilities) Issue(b Binding) string {
	id := ids.Secret()
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.issued++
	if c.issued%256 == 0 {
		c.pruneLocked(now)
	}
	c.entries[id] = &capEntry{b: b, expires: now.Add(c.ttl)}
	return id
}

// Consume validates and spends a capability.
func (c *Capabilities) Consume(id string, b Binding) error {
	if id == "" {
		return ErrNoCapability
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[id]
	if e == nil || c.now().After(e.expires) {
		return ErrCapabilityUnknown
	}
	if e.used {
		return ErrCapabilityUsed
	}
	if e.b != b {
		return ErrCapabilityMismatch
	}
	e.used = true
	return nil
}

// Outstanding returns the number of entries held (tests and health).
func (c *Capabilities) Outstanding() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Prune drops expired entries.
func (c *Capabilities) Prune() {
	c.mu.Lock()
	c.pruneLocked(c.now())
	c.mu.Unlock()
}

func (c *Capabilities) pruneLocked(now time.Time) {
	for id, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, id)
		}
	}
}
