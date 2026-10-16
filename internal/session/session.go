// Package session is the slice of the Identity & Authentication Service
// (E-03) and Session Manager (E-04): principals and OAuth client
// registrations from configuration (FR-2.1, FR-2.18), the session table
// (FR-2.8, FR-2.9, FR-2.10, FR-2.16), template selection and claim narrowing
// from scopes (FR-2.6, FR-2.7, FR-2.21), and bearer-token authentication on
// every request (FR-2.5, SR-2.1-1, SR-2.1-3). Tokens are 256-bit CSPRNG values
// stored only as SHA-256 verifiers (SR-2.3-1).
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	ApprovedBy     string // administrator who signed in at the authorization endpoint (FR-2.19)
	HarnessVersion string
	State          string
	CreatedAt      time.Time
	IdleDeadline   time.Time
	MaxDeadline    time.Time
	Listener       string

	accessHash  string
	refreshHash string
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
)

// Store is the session table (D-07, memory only in this slice, so every
// session is gone after a restart as FR-2.16 requires).
type Store struct {
	cfg      *config.Config
	snapshot func() *policy.Snapshot
	now      func() time.Time
	onEnd    func(*Session)

	mu        sync.Mutex
	sessions  map[string]*Session
	byAccess  map[string]*Session
	byRefresh map[string]*Session
}

// NewStore returns an empty session table.
func NewStore(cfg *config.Config, snapshot func() *policy.Snapshot) *Store {
	return &Store{cfg: cfg, snapshot: snapshot, now: time.Now,
		sessions: map[string]*Session{}, byAccess: map[string]*Session{}, byRefresh: map[string]*Session{}}
}

// SetNow replaces the clock (tests).
func (s *Store) SetNow(f func() time.Time) { s.mu.Lock(); s.now = f; s.mu.Unlock() }

// OnEnd registers a callback invoked when a session leaves the active state
// (FR-2.11 effects are applied by the caller).
func (s *Store) OnEnd(f func(*Session)) { s.mu.Lock(); s.onEnd = f; s.mu.Unlock() }

// CreateParams are the FR-2.3 inputs.
type CreateParams struct {
	PrincipalID    string
	ClientID       string
	HarnessVersion string
	Claims         Claims
	ApprovedBy     string
	Listener       string
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
	} else {
		permitted := false
		for _, t := range prof.Templates {
			if t == tmpl {
				permitted = true
			}
		}
		if !permitted {
			return nil, Tokens{}, ErrNoTemplate
		}
	}
	s.expireLocked()
	active := 0
	for _, e := range s.sessions {
		if e.PrincipalID == p.PrincipalID && e.State == StateActive {
			active++
		}
	}
	if active >= s.cfg.Limits.SessionsPerPrincipal {
		return nil, Tokens{}, ErrTooManySessions
	}
	now := s.now()
	sess := &Session{
		ID: ids.New(), PrincipalID: pr.ID, Framework: pr.Framework, Profile: pr.Profile, ClientID: p.ClientID,
		Template: tmpl, PolicyRevision: snap.Revision,
		Purpose: p.Claims.Purpose, Project: p.Claims.Project, EndUser: p.Claims.EndUser,
		ApprovedBy: p.ApprovedBy, HarnessVersion: p.HarnessVersion, State: StateActive,
		CreatedAt: now, IdleDeadline: now.Add(s.cfg.Limits.SessionIdleTimeout.Duration),
		MaxDeadline: now.Add(s.cfg.Limits.SessionMaxLifetime.Duration), Listener: p.Listener,
	}
	tok := Tokens{Access: ids.Secret(), Refresh: ids.Secret()}
	sess.accessHash, sess.refreshHash = hash(tok.Access), hash(tok.Refresh)
	s.sessions[sess.ID] = sess
	s.byAccess[sess.accessHash] = sess
	s.byRefresh[sess.refreshHash] = sess
	return sess, tok, nil
}

// expireLocked moves sessions past their deadlines to expired (FR-2.9).
func (s *Store) expireLocked() {
	now := s.now()
	for _, e := range s.sessions {
		if e.State == StateActive && (now.After(e.IdleDeadline) || now.After(e.MaxDeadline)) {
			s.endLocked(e, StateExpired)
		}
	}
}

func (s *Store) endLocked(e *Session, state string) {
	e.State = state
	delete(s.byAccess, e.accessHash)
	delete(s.byRefresh, e.refreshHash)
	if s.onEnd != nil {
		go s.onEnd(e)
	}
}

// Authenticate verifies a bearer token presented on the named listener and
// returns the active session, extending its idle deadline (FR-2.5, FR-2.9,
// SR-2.1-2, SR-2.11-1).
func (s *Store) Authenticate(bearer, listener string) (*Session, error) {
	if bearer == "" {
		return nil, ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	e := s.byAccess[hash(bearer)]
	if e == nil || e.State != StateActive {
		return nil, ErrSessionInvalid
	}
	if e.Listener != listener {
		return nil, ErrSessionInvalid
	}
	e.IdleDeadline = s.now().Add(s.cfg.Limits.SessionIdleTimeout.Duration)
	if e.IdleDeadline.After(e.MaxDeadline) {
		e.IdleDeadline = e.MaxDeadline
	}
	return e, nil
}

// Refresh issues a new access token for the session of a refresh token
// (FR-2.22). The maximum lifetime is unchanged.
func (s *Store) Refresh(refresh string) (*Session, Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	e := s.byRefresh[hash(refresh)]
	if e == nil || e.State != StateActive {
		return nil, Tokens{}, ErrSessionInvalid
	}
	delete(s.byAccess, e.accessHash)
	tok := Tokens{Access: ids.Secret(), Refresh: refresh}
	e.accessHash = hash(tok.Access)
	s.byAccess[e.accessHash] = e
	e.IdleDeadline = s.now().Add(s.cfg.Limits.SessionIdleTimeout.Duration)
	if e.IdleDeadline.After(e.MaxDeadline) {
		e.IdleDeadline = e.MaxDeadline
	}
	return e, tok, nil
}

// Get returns a session by ID.
func (s *Store) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	return s.sessions[id]
}

// Terminate ends a session (FR-2.11 effects via OnEnd).
func (s *Store) Terminate(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.sessions[id]
	if e == nil || e.State != StateActive {
		return false
	}
	s.endLocked(e, StateTerminated)
	return true
}

// Active lists active sessions, newest first.
func (s *Store) Active() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	var out []*Session
	for _, e := range s.sessions {
		if e.State == StateActive {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ExpiresIn is the access-token lifetime in seconds (CP-18 idle timeout).
func (s *Store) ExpiresIn() int { return int(s.cfg.Limits.SessionIdleTimeout.Duration.Seconds()) }
