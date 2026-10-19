// Package authguard protects password and secret verification endpoints
// (the OAuth authorization and token endpoints of E-03 and the control API
// sign-in of E-24): a per-source request rate limit, per-source and
// per-account lockout with exponential backoff after repeated failures, a
// bound on concurrent Argon2id verifications, and verification against a
// dummy hash when the account is unknown so that the response time does not
// reveal which accounts exist.
//
// Source is the TCP peer address. Behind a tunnel (Remote Access profile)
// every request arrives from the tunnel's local endpoint, so the per-source
// limit becomes a global limit; the per-account lockout still applies.
package authguard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// Errors returned by Check and Verify.
var (
	ErrRateLimited = errors.New("too many requests")
	ErrLocked      = errors.New("temporarily locked after repeated failures")
	ErrBusy        = errors.New("verification capacity exhausted")
)

// Config bounds the guard. Zero fields take the defaults in brackets.
type Config struct {
	PerSourcePerMinute int           // requests per source per minute [30]
	MaxFailures        int           // failures before lockout [5]
	FailureWindow      time.Duration // failures older than this are forgotten [15m]
	LockoutBase        time.Duration // first lockout [30s], doubled per further failure
	LockoutMax         time.Duration // longest lockout [15m]
	VerifyConcurrency  int           // concurrent Argon2id verifications [2]
	VerifyWait         time.Duration // longest wait for a verification slot [5s]
	MaxEntries         int           // tracked sources and accounts before pruning [10000]
	Now                func() time.Time
}

func (c *Config) defaults() {
	if c.PerSourcePerMinute <= 0 {
		c.PerSourcePerMinute = 30
	}
	if c.MaxFailures <= 0 {
		c.MaxFailures = 5
	}
	if c.FailureWindow <= 0 {
		c.FailureWindow = 15 * time.Minute
	}
	if c.LockoutBase <= 0 {
		c.LockoutBase = 30 * time.Second
	}
	if c.LockoutMax <= 0 {
		c.LockoutMax = 15 * time.Minute
	}
	if c.VerifyConcurrency <= 0 {
		c.VerifyConcurrency = 2
	}
	if c.VerifyWait <= 0 {
		c.VerifyWait = 5 * time.Second
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 10000
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Guard tracks request rates and failures.
type Guard struct {
	cfg Config
	sem chan struct{}

	mu      sync.Mutex
	rate    map[string]*window
	failure map[string]*failures
}

type window struct {
	start time.Time
	n     int
}

type failures struct {
	n           int
	last        time.Time
	lockedUntil time.Time
}

// New returns a guard.
func New(cfg Config) *Guard {
	cfg.defaults()
	return &Guard{cfg: cfg, sem: make(chan struct{}, cfg.VerifyConcurrency), rate: map[string]*window{}, failure: map[string]*failures{}}
}

// Source returns the rate-limit key of a request: the peer IP.
func Source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func accountKey(account string) string {
	// Hash the account name so the table never holds attacker-chosen
	// strings of unbounded length.
	s := sha256.Sum256([]byte(account))
	return "a:" + string(s[:16])
}

// Check is called before any verification work. It counts the request
// against the source's rate and refuses locked sources and accounts. The
// returned duration is a retry hint.
func (g *Guard) Check(source, account string) (time.Duration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	if len(g.rate)+len(g.failure) > g.cfg.MaxEntries {
		g.pruneLocked(now)
	}
	source = g.sourceLocked(now, source)
	w := g.rate[source]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		g.rate[source] = w
	}
	w.n++
	if w.n > g.cfg.PerSourcePerMinute {
		return w.start.Add(time.Minute).Sub(now), ErrRateLimited
	}
	for _, k := range []string{"s:" + source, accountKey(account)} {
		if f := g.failure[k]; f != nil && now.Before(f.lockedUntil) {
			return f.lockedUntil.Sub(now), ErrLocked
		}
	}
	return 0, nil
}

// Failure records a failed attempt for the source and the account.
func (g *Guard) Failure(source, account string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	source = g.sourceLocked(now, source)
	for _, k := range []string{"s:" + source, accountKey(account)} {
		g.failLocked(now, k)
	}
}

func (g *Guard) failLocked(now time.Time, k string) {
	f := g.failure[k]
	if f == nil || now.Sub(f.last) > g.cfg.FailureWindow {
		f = &failures{}
		g.failure[k] = f
	}
	f.n++
	f.last = now
	if f.n >= g.cfg.MaxFailures {
		lock := g.cfg.LockoutBase << min(f.n-g.cfg.MaxFailures, 20)
		if lock > g.cfg.LockoutMax || lock <= 0 {
			lock = g.cfg.LockoutMax
		}
		f.lockedUntil = now.Add(lock)
	}
}

// FailAccount records a failed attempt for the account only, for a second
// account checked in the same request (the source was already counted by
// Failure).
func (g *Guard) FailAccount(account string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failLocked(g.cfg.Now(), accountKey(account))
}

// Success clears the account's failures (the source's remain, so one valid
// account cannot be used to reset a spraying source).
func (g *Guard) Success(account string) {
	g.mu.Lock()
	delete(g.failure, accountKey(account))
	g.mu.Unlock()
}

// overflowSource is the source key shared by every new source that
// arrives while the rate table is full of live entries, so a caller who
// rotates source addresses shares one limit instead of growing the table
// without bound. Account failures are always recorded: each one costs an
// Argon2id verification, which bounds their rate.
const overflowSource = "\x00overflow"

// sourceLocked returns source, or overflowSource when source is not yet
// tracked and the rate table holds MaxEntries live sources after pruning.
func (g *Guard) sourceLocked(now time.Time, source string) string {
	if _, ok := g.rate[source]; ok || len(g.rate) < g.cfg.MaxEntries {
		return source
	}
	g.pruneLocked(now)
	if len(g.rate) < g.cfg.MaxEntries {
		return source
	}
	return overflowSource
}

func (g *Guard) pruneLocked(now time.Time) {
	for k, w := range g.rate {
		if now.Sub(w.start) >= time.Minute {
			delete(g.rate, k)
		}
	}
	for k, f := range g.failure {
		if now.After(f.lockedUntil) && now.Sub(f.last) > g.cfg.FailureWindow {
			delete(g.failure, k)
		}
	}
}

// Prune drops expired entries; call it from a janitor.
func (g *Guard) Prune() {
	g.mu.Lock()
	g.pruneLocked(g.cfg.Now())
	g.mu.Unlock()
}

// Verify checks password against hash under the concurrency bound. An empty
// hash (unknown account) is verified against a dummy hash and never matches,
// so both paths cost one Argon2id evaluation.
func (g *Guard) Verify(ctx context.Context, hash, password string) (bool, error) {
	if err := g.acquire(ctx); err != nil {
		return false, err
	}
	defer func() { <-g.sem }()
	if hash == "" {
		keys.VerifyPassword(keys.DummyHash(), password)
		return false, nil
	}
	return keys.VerifyPassword(hash, password), nil
}

// Hash computes an Argon2id hash of password under the same concurrency
// bound as Verify, so that endpoints which create secrets for
// unauthenticated callers cannot run unbounded Argon2id evaluations.
func (g *Guard) Hash(ctx context.Context, password string) (string, error) {
	if err := g.acquire(ctx); err != nil {
		return "", err
	}
	defer func() { <-g.sem }()
	return keys.HashPassword(password)
}

func (g *Guard) acquire(ctx context.Context) error {
	t := time.NewTimer(g.cfg.VerifyWait)
	defer t.Stop()
	select {
	case g.sem <- struct{}{}:
		return nil
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

// EqualName compares two account names in time independent of where they
// differ.
func EqualName(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// RetryAfter sets the Retry-After header from a hint.
func RetryAfter(w http.ResponseWriter, d time.Duration) {
	secs := int(d.Round(time.Second) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}
