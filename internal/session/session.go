// Package session is the slice of the Identity & Authentication Service
// (E-03) and Session Manager (E-04): principals and OAuth client
// registrations from configuration (FR-2.1, FR-2.18), the session table
// (FR-2.8, FR-2.9, FR-2.10, FR-2.16), template selection and claim narrowing
// from scopes (FR-2.6, FR-2.7, FR-2.21), bearer-token authentication on
// every request (FR-2.5, SR-2.1-1, SR-2.1-3) and refresh-token rotation with
// reuse detection (FR-2.22). Tokens are 256-bit CSPRNG values stored only as
// SHA-256 verifiers (SR-2.3-1).
//
// Concurrency: the Store owns every *Session it holds. Methods return
// copies, so callers can read fields without the Store's lock and cannot
// change the table by writing to them.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// States of FR-2.8.
const (
	StateActive     = "active"
	StateSuspended  = "suspended"
	StateTerminated = "terminated"
	StateExpired    = "expired"
)

// Reasons a session ends.
const (
	EndIdle         = "IDLE_TIMEOUT"
	EndMaxLifetime  = "MAX_LIFETIME"
	EndTerminated   = "TERMINATED"
	EndRefreshReuse = "REFRESH_TOKEN_REUSE"
)

// Session binds a principal to a policy template for a bounded time.
type Session struct {
	ID             string
	PrincipalID    string
	Framework      string
	Profile        string
	ClientID       string
	Template       string
	PolicyRevision string
	Purpose        string
	Project        string
	EndUser        string
	ApprovedBy     string // Session Approver who signed in at the authorization endpoint (FR-2.19)
	HarnessVersion string
	// HarnessType is the harness type the create request named, or the
	// principal's framework type when it named none (FR-2.3).
	HarnessType  string
	State        string
	EndReason    string
	CreatedAt    time.Time
	IdleDeadline time.Time
	MaxDeadline  time.Time
	EndedAt      time.Time
	Listener     string
	// ClientAddress is the tunnel-supplied caller address at creation
	// (Remote Access Profile); a server-asserted value, not verified.
	ClientAddress string
	// ObservationPolicy is the Observation Policy in force at creation and
	// ContextKey the session's baseline context key under it (FR-2.13).
	ObservationPolicy string
	ContextKey        string

	idle        time.Duration // idle timeout of this session; 0 = CP-18
	accessHash  string
	refreshHash string
	usedRefresh []string // rotated-out refresh verifiers of this session's family
}

// Claims are the narrowing parameters of ARCH §7.1 layer 4, carried as
// OAuth scopes (FR-2.21) or session-API fields (FR-2.3).
type Claims struct {
	Template string
	Purpose  string
	Project  string
	EndUser  string
}

// ParseScopes maps the smcp: scopes of FR-2.21 to claims. Any other smcp:
// scope is an error; scopes without the prefix are ignored.
func ParseScopes(scopes []string) (Claims, error) {
	var c Claims
	for _, s := range scopes {
		if !strings.HasPrefix(s, "smcp:") {
			continue
		}
		rest := s[len("smcp:"):]
		kind, val, ok := strings.Cut(rest, ":")
		if !ok || val == "" {
			return c, fmt.Errorf("invalid_scope: %q", s)
		}
		switch kind {
		case "template":
			c.Template = val
		case "purpose":
			c.Purpose = val
		case "project":
			c.Project = val
		case "user":
			c.EndUser = val
		default:
			return c, fmt.Errorf("invalid_scope: %q", s)
		}
	}
	return c, nil
}

// Scopes renders claims back as the scope string granted on a token.
func (c Claims) Scopes() string {
	var out []string
	if c.Template != "" {
		out = append(out, "smcp:template:"+c.Template)
	}
	if c.Purpose != "" {
		out = append(out, "smcp:purpose:"+c.Purpose)
	}
	if c.Project != "" {
		out = append(out, "smcp:project:"+c.Project)
	}
	if c.EndUser != "" {
		out = append(out, "smcp:user:"+c.EndUser)
	}
	return strings.Join(out, " ")
}

// Errors returned by the store; the edge maps them to Appendix B codes.
var (
	ErrUnknownPrincipal = errors.New("unknown or disabled principal")
	ErrNoTemplate       = errors.New("template not permitted for this principal") // -31001
	ErrTooManySessions  = errors.New("concurrent session limit reached")          // -31005
	ErrSessionInvalid   = errors.New("session invalid")                           // -31006
	ErrNoSnapshot       = errors.New("no policy snapshot loaded")                 // -31004
	ErrRefreshReuse     = errors.New("refresh token reused; session revoked")
)

// EndedRetention is how long an ended session stays readable (status API,
// reuse detection) before the janitor removes it.
const EndedRetention = 10 * time.Minute

// Store is the session table (D-07). It is held in memory only, so every
// session ends when the Gateway restarts and tokens issued before the
// restart are refused; resumption after a restart (FR-2.16) is deferred
// (SRS Appendix N).
type Store struct {
	cfg      *config.Config
	snapshot func() *policy.Snapshot

	mu          sync.Mutex
	now         func() time.Time
	onEnd       func(Session)
	sessions    map[string]*Session
	byAccess    map[string]*Session
	byRefresh   map[string]*Session
	usedRefresh map[string]string              // rotated-out refresh verifier -> session ID
	active      map[string]map[string]*Session // principal -> active sessions
	obsContext  func() (policyID string, dims []string)
}

// SessionDimensions are the baseline context dimensions fixed for a
// session's lifetime; the others (server, server revision, tool, hour,
// weekday) vary per call and complete the key when a call is scored.
var SessionDimensions = []string{"principal", "framework_type", "session_template", "end_user"}

// SetObservationContext sets the source of the Observation Policy in force
// and its baseline context dimensions; sessions created afterwards record
// the policy and their context key (FR-2.13).
func (s *Store) SetObservationContext(f func() (policyID string, dims []string)) {
	s.mu.Lock()
	s.obsContext = f
	s.mu.Unlock()
}

// ContextKey is the session-scoped part of a baseline context key: each of
// dims that SessionDimensions lists, in the order of dims, as
// "dimension=value", joined with "|" (FR-2.13).
func ContextKey(sess *Session, dims []string) string {
	vals := map[string]string{"principal": sess.PrincipalID, "framework_type": sess.Framework, "session_template": sess.Template, "end_user": sess.EndUser}
	var parts []string
	for _, d := range dims {
		if slices.Contains(SessionDimensions, d) {
			parts = append(parts, d+"="+vals[d])
		}
	}
	return strings.Join(parts, "|")
}

// NewStore returns an empty session table.
func NewStore(cfg *config.Config, snapshot func() *policy.Snapshot) *Store {
	return &Store{cfg: cfg, snapshot: snapshot, now: time.Now,
		sessions: map[string]*Session{}, byAccess: map[string]*Session{}, byRefresh: map[string]*Session{},
		usedRefresh: map[string]string{}, active: map[string]map[string]*Session{}}
}

// SetNow replaces the clock (tests).
func (s *Store) SetNow(f func() time.Time) { s.mu.Lock(); s.now = f; s.mu.Unlock() }

// OnEnd registers a callback invoked, on its own goroutine, when a session
// leaves the active state (FR-2.11 effects are applied by the caller).
func (s *Store) OnEnd(f func(Session)) { s.mu.Lock(); s.onEnd = f; s.mu.Unlock() }

// CreateParams are the FR-2.3 inputs.
type CreateParams struct {
	PrincipalID    string
	ClientID       string
	HarnessVersion string
	HarnessType    string
	Claims         Claims
	ApprovedBy     string
	Listener       string
	// Remote Access Profile (FR-16.12): a non-zero MaxLifetime or
	// IdleTimeout replaces the CP-18 value for this session, and a non-nil
	// AllowedTemplates refuses a resolved template that is not listed.
	MaxLifetime      time.Duration
	IdleTimeout      time.Duration
	AllowedTemplates []string
	ClientAddress    string
	// Remote marks a session created through the Remote Access listener:
	// its template must be one the Framework Profile marks remote_allowed
	// (FR-16.12).
	Remote bool
}

// Tokens are the secrets returned once at creation or refresh.
type Tokens struct {
	Access  string
	Refresh string
}

func hash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func copyOf(e *Session) *Session {
	c := *e
	c.usedRefresh = slices.Clone(e.usedRefresh)
	return &c
}

// Create establishes a session (FR-2.3, FR-2.4, FR-2.6, FR-2.7, FR-2.10).
func (s *Store) Create(p CreateParams) (*Session, Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr := s.cfg.FindPrincipal(p.PrincipalID)
	if pr == nil || pr.Enabled == nil || !*pr.Enabled {
		return nil, Tokens{}, ErrUnknownPrincipal
	}
	snap := s.snapshot()
	if snap == nil {
		return nil, Tokens{}, ErrNoSnapshot
	}
	prof, ok := snap.Profiles[pr.Profile]
	if !ok {
		return nil, Tokens{}, fmt.Errorf("%w: framework profile %q not in policy", ErrNoTemplate, pr.Profile)
	}
	tmpl := p.Claims.Template
	if tmpl == "" {
		tmpl = prof.DefaultTemplate
	} else if !slices.Contains(prof.Templates, tmpl) {
		return nil, Tokens{}, ErrNoTemplate
	}
	if p.Remote && !slices.Contains(prof.RemoteAllowed, tmpl) {
		return nil, Tokens{}, fmt.Errorf("%w: template %q is not marked remote_allowed in framework profile %q", ErrNoTemplate, tmpl, pr.Profile)
	}
	if p.AllowedTemplates != nil && !slices.Contains(p.AllowedTemplates, tmpl) {
		return nil, Tokens{}, fmt.Errorf("%w: template %q is not allowed on this listener", ErrNoTemplate, tmpl)
	}
	// Only this principal's sessions are checked, so creation does not scan
	// the whole table.
	for _, e := range s.active[p.PrincipalID] {
		s.checkLocked(e)
	}
	if len(s.active[p.PrincipalID]) >= s.cfg.Limits.SessionsPerPrincipal {
		return nil, Tokens{}, ErrTooManySessions
	}
	now := s.now()
	idle, maxLife := s.cfg.Limits.SessionIdleTimeout.Duration, s.cfg.Limits.SessionMaxLifetime.Duration
	if p.IdleTimeout > 0 {
		idle = p.IdleTimeout
	}
	if p.MaxLifetime > 0 {
		maxLife = p.MaxLifetime
	}
	sess := &Session{
		ID: ids.New(), PrincipalID: pr.ID, Framework: pr.Framework, Profile: pr.Profile, ClientID: p.ClientID,
		Template: tmpl, PolicyRevision: snap.Revision,
		Purpose: p.Claims.Purpose, Project: p.Claims.Project, EndUser: p.Claims.EndUser,
		ApprovedBy: p.ApprovedBy, HarnessVersion: p.HarnessVersion, HarnessType: p.HarnessType, State: StateActive,
		CreatedAt: now, IdleDeadline: now.Add(idle),
		MaxDeadline: now.Add(maxLife), Listener: p.Listener, ClientAddress: p.ClientAddress, idle: p.IdleTimeout,
	}
	if sess.HarnessType == "" {
		sess.HarnessType = pr.Framework
	}
	if sess.IdleDeadline.After(sess.MaxDeadline) {
		sess.IdleDeadline = sess.MaxDeadline
	}
	if s.obsContext != nil {
		var dims []string
		sess.ObservationPolicy, dims = s.obsContext()
		sess.ContextKey = ContextKey(sess, dims)
	}
	tok := Tokens{Access: ids.Secret(), Refresh: ids.Secret()}
	sess.accessHash, sess.refreshHash = hash(tok.Access), hash(tok.Refresh)
	s.sessions[sess.ID] = sess
	s.byAccess[sess.accessHash] = sess
	s.byRefresh[sess.refreshHash] = sess
	if s.active[sess.PrincipalID] == nil {
		s.active[sess.PrincipalID] = map[string]*Session{}
	}
	s.active[sess.PrincipalID][sess.ID] = sess
	return copyOf(sess), tok, nil
}

// checkLocked expires one session past its deadlines (FR-2.9) and reports
// whether it is active. A suspended session keeps its deadlines and is
// expired by them like an active one, but is never reported active.
func (s *Store) checkLocked(e *Session) bool {
	if e.State != StateActive && e.State != StateSuspended {
		return false
	}
	now := s.now()
	switch {
	case now.After(e.MaxDeadline):
		s.endLocked(e, StateExpired, EndMaxLifetime)
	case now.After(e.IdleDeadline):
		s.endLocked(e, StateExpired, EndIdle)
	default:
		return e.State == StateActive
	}
	return false
}

func (s *Store) endLocked(e *Session, state, reason string) {
	e.State, e.EndReason, e.EndedAt = state, reason, s.now()
	delete(s.byAccess, e.accessHash)
	delete(s.byRefresh, e.refreshHash)
	if m := s.active[e.PrincipalID]; m != nil {
		delete(m, e.ID)
		if len(m) == 0 {
			delete(s.active, e.PrincipalID)
		}
	}
	if s.onEnd != nil {
		go s.onEnd(*copyOf(e))
	}
}

func (s *Store) touchLocked(e *Session) {
	idle := s.cfg.Limits.SessionIdleTimeout.Duration
	if e.idle > 0 {
		idle = e.idle
	}
	e.IdleDeadline = s.now().Add(idle)
	if e.IdleDeadline.After(e.MaxDeadline) {
		e.IdleDeadline = e.MaxDeadline
	}
}

// Authenticate verifies a bearer token presented on the named listener and
// returns a copy of the active session, extending its idle deadline
// (FR-2.5, FR-2.9, SR-2.1-2, SR-2.11-1).
func (s *Store) Authenticate(bearer, listener string) (*Session, error) {
	if bearer == "" {
		return nil, ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.byAccess[hash(bearer)]
	if e == nil || !s.checkLocked(e) || e.Listener != listener {
		return nil, ErrSessionInvalid
	}
	s.touchLocked(e)
	return copyOf(e), nil
}

// Refresh rotates the session's tokens (FR-2.22): it issues a new access
// token and a new refresh token, extends the idle deadline and leaves the
// maximum lifetime unchanged. The presented refresh token becomes invalid.
// Presenting a rotated-out refresh token again is treated as theft: the
// session (the token family) is revoked and ErrRefreshReuse returned. A
// refresh token presented by a client other than the one it was issued to
// is refused without rotation.
func (s *Store) Refresh(refresh, clientID string) (*Session, Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hash(refresh)
	if sid, reused := s.usedRefresh[h]; reused {
		if e := s.sessions[sid]; e != nil && (e.State == StateActive || e.State == StateSuspended) {
			s.endLocked(e, StateTerminated, EndRefreshReuse)
			return copyOf(e), Tokens{}, ErrRefreshReuse
		}
		return nil, Tokens{}, ErrSessionInvalid
	}
	e := s.byRefresh[h]
	if e == nil || !s.checkLocked(e) || e.ClientID != clientID {
		return nil, Tokens{}, ErrSessionInvalid
	}
	delete(s.byAccess, e.accessHash)
	delete(s.byRefresh, e.refreshHash)
	s.usedRefresh[e.refreshHash] = e.ID
	e.usedRefresh = append(e.usedRefresh, e.refreshHash)
	tok := Tokens{Access: ids.Secret(), Refresh: ids.Secret()}
	e.accessHash, e.refreshHash = hash(tok.Access), hash(tok.Refresh)
	s.byAccess[e.accessHash] = e
	s.byRefresh[e.refreshHash] = e
	s.touchLocked(e)
	return copyOf(e), tok, nil
}

// Get returns a copy of a session by ID, or nil.
func (s *Store) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.sessions[id]
	if e == nil {
		return nil
	}
	s.checkLocked(e)
	return copyOf(e)
}

// IsActive reports whether the session exists and is active.
func (s *Store) IsActive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.sessions[id]
	return e != nil && s.checkLocked(e)
}

// Terminate ends an active or suspended session (FR-2.11 effects via
// OnEnd).
func (s *Store) Terminate(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.sessions[id]
	if e == nil || (e.State != StateActive && e.State != StateSuspended) {
		return false
	}
	s.endLocked(e, StateTerminated, EndTerminated)
	return true
}

// Suspend stops an active session from being used without ending it
// (FR-2.8, FR-8.19): its access and refresh tokens are refused and the
// edge refuses its calls in flight at the next session check, until Resume.
// The session keeps its deadlines and its place in the principal's session
// count, and expires as usual.
func (s *Store) Suspend(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.sessions[id]
	if e == nil || !s.checkLocked(e) {
		return false
	}
	e.State = StateSuspended
	return true
}

// Resume makes a suspended session active again, unless it expired
// meanwhile.
func (s *Store) Resume(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.sessions[id]
	if e == nil || e.State != StateSuspended {
		return false
	}
	s.checkLocked(e)
	if e.State != StateSuspended {
		return false
	}
	e.State = StateActive
	return true
}

// List returns copies of the active and suspended sessions, newest first.
func (s *Store) List() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Session
	for _, m := range s.active {
		for _, e := range m {
			s.checkLocked(e)
			if e.State == StateActive || e.State == StateSuspended {
				out = append(out, copyOf(e))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Active lists copies of the active sessions, newest first.
func (s *Store) Active() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Session
	for _, m := range s.active {
		for _, e := range m {
			if s.checkLocked(e) {
				out = append(out, copyOf(e))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Len returns the number of sessions held, active or ended (tests).
func (s *Store) Len() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sessions) }

// Sweep expires active and suspended sessions past their deadlines and
// removes sessions that ended more than EndedRetention ago, with their
// rotated-out refresh verifiers. A suspended session has not ended and is
// kept.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, m := range s.active {
		for _, e := range m {
			s.checkLocked(e)
		}
	}
	for id, e := range s.sessions {
		if e.State != StateActive && e.State != StateSuspended && now.Sub(e.EndedAt) > EndedRetention {
			for _, h := range e.usedRefresh {
				delete(s.usedRefresh, h)
			}
			delete(s.sessions, id)
		}
	}
}

// Run sweeps every interval until ctx ends.
func (s *Store) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// ExpiresInFor is the access-token lifetime in seconds of one session: its
// own idle timeout when it has one, otherwise CP-18.
func (s *Store) ExpiresInFor(sess *Session) int {
	if sess != nil && sess.idle > 0 {
		return int(sess.idle.Seconds())
	}
	return s.ExpiresIn()
}

// ExpiresIn is the access-token lifetime in seconds (CP-18 idle timeout).
func (s *Store) ExpiresIn() int { return int(s.cfg.Limits.SessionIdleTimeout.Duration.Seconds()) }
