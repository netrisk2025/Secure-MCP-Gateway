// Package remote is the Remote Access Profile (FR-16): a second TLS
// listener on the CP-48 loopback address that a tunnel connector (Tailscale
// Funnel, Cloudflare Tunnel, a vendor MCP tunnel) forwards one public HTTPS
// name to, so agents running on a vendor's computer can reach a Gateway
// that stays on the user's computer.
//
// The listener serves only the MCP endpoint and the OAuth endpoints a
// remote agent needs (FR-16.4): protected-resource and authorization-server
// metadata naming the public URL (FR-16.3), RFC 7591 Dynamic Client
// Registration whose registrations stay pending until an operator approves
// them (FR-16.5, SR-2.11-2), the authorization-code grant with PKCE and a
// Session Approver sign-in, the RFC 8628 device authorization grant used by
// smcp-connect, and refresh. Every request is bounded before parsing
// (FR-16.7), rate limited per source and per client, sign-in and token
// failures lock the client and source (FR-16.6), sessions are bound to the
// remote listener with the CP-49 lifetime and only remote-allowed templates
// (FR-16.12), and every event carries the remote origin (FR-16.8).
//
// Enabling the profile is an Administrator action on the control API
// (/api/v1/remote/enable) recorded as a remote_access_enabled event; the
// enabled state is kept in <state>/remote/state.json (FR-16.11).
package remote

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// MCPSource builds the MCP endpoint handler the remote listener delegates
// to; edge.Gateway implements it.
type MCPSource interface {
	MCPHandler(metadataURL func() string) http.Handler
}

// Options are the components the service is built over.
type Options struct {
	Config   *config.Config
	Store    *session.Store
	Evidence audit.Recorder
	Gateway  MCPSource
	Log      *slog.Logger
	// Now replaces the clock (tests).
	Now func() time.Time
}

// Providers accepted in an enable request.
var Providers = []string{"tailscale", "cloudflare", "vendor", "manual"}

// State is the persisted enabled state.
type State struct {
	Enabled   bool      `json:"enabled"`
	PublicURL string    `json:"public_url,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	ChangedBy string    `json:"changed_by,omitempty"`
	ChangedAt time.Time `json:"changed_at,omitzero"`
}

// Service is the Remote Access Profile.
type Service struct {
	cfg   *config.Config
	store *session.Store
	rec   audit.Recorder
	log   *slog.Logger
	now   func() time.Time
	mcp   http.Handler
	guard *authguard.Guard
	// approvers locks Session Approver usernames after twice the client
	// threshold of failures across all clients and sources.
	approvers *authguard.Guard
	reg       *registry
	lim       *limiters
	oauth     *oauthState
	dir       string

	mu    sync.Mutex
	state State
	ln    net.Listener
	srv   *http.Server
	done  chan struct{}
}

// Errors of Enable and Disable.
var (
	ErrBadRequest       = errors.New("bad request")
	ErrAuditUnavailable = errors.New("evidence journal unavailable")
)

// New loads the persisted state and registrations. It does not open the
// listener; Start does when the profile is enabled.
func New(o Options) (*Service, error) {
	if o.Config == nil || o.Store == nil || o.Evidence == nil || o.Gateway == nil {
		return nil, errors.New("remote: config, store, evidence and gateway are required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	l := o.Config.Remote.Limits
	s := &Service{cfg: o.Config, store: o.Store, rec: o.Evidence, log: o.Log, now: o.Now,
		dir: filepath.Join(o.Config.State.Dir, "remote"),
		guard: authguard.New(authguard.Config{PerSourcePerMinute: 1 << 30, MaxFailures: l.LockoutFailures, FailureWindow: l.Lockout.Duration,
			LockoutBase: l.Lockout.Duration, LockoutMax: l.Lockout.Duration, Now: o.Now}),
		approvers: authguard.New(authguard.Config{PerSourcePerMinute: 1 << 30, MaxFailures: 2 * l.LockoutFailures, FailureWindow: l.Lockout.Duration,
			LockoutBase: l.Lockout.Duration, LockoutMax: l.Lockout.Duration, Now: o.Now}),
		lim: newLimiters(l, o.Now), oauth: newOAuthState()}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	var err error
	if s.reg, err = loadRegistry(filepath.Join(s.dir, "clients.json"), o.Config.Remote.MaxPendingRegistrations, o.Config.Remote.MaxPendingPerSource); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(s.dir, "state.json")); err == nil {
		if err := json.Unmarshal(b, &s.state); err != nil {
			return nil, fmt.Errorf("remote state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.mcp = o.Gateway.MCPHandler(s.resourceMetadataURL)
	return s, nil
}

// Start opens the listener when the persisted state is enabled, and runs
// the janitor until ctx ends.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	enabled := s.state.Enabled
	s.mu.Unlock()
	go s.janitor(ctx)
	if !enabled {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.openLocked(); err != nil {
		return fmt.Errorf("remote listener: %w", err)
	}
	if err := s.rec.Commit(audit.Event{Class: "remote_access", Origin: "E-01", Outcome: "remote_access_resumed", ReasonCode: "REMOTE_ACCESS_RESUMED",
		PolicyStatus: "not_evaluated", Detail: map[string]any{"public_url": s.state.PublicURL, "provider": s.state.Provider, "listener": s.cfg.Remote.Address}}); err != nil {
		s.closeLocked()
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

func (s *Service) janitor(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Close()
			return
		case <-t.C:
			s.guard.Prune()
			s.approvers.Prune()
			s.lim.prune()
			s.oauth.prune(s.now())
			s.reg.prunePending(s.now(), s.cfg.Remote.PendingLifetime.Duration)
		}
	}
}

// Status is the GET /api/v1/remote body.
type Status struct {
	State
	Listener    string `json:"listener"`
	Listening   bool   `json:"listening"`
	ResourceURI string `json:"resource_uri,omitempty"`
	Pending     int    `json:"pending_registrations"`
	Sessions    int    `json:"remote_sessions"`
}

// Status reports the profile state.
func (s *Service) Status() Status {
	s.mu.Lock()
	st := Status{State: s.state, Listener: s.cfg.Remote.Address, Listening: s.ln != nil}
	s.mu.Unlock()
	if st.Enabled {
		st.ResourceURI = st.PublicURL + s.cfg.Listener.MCPPath
	}
	st.Pending = s.reg.countStatus(StatusPending)
	for _, se := range s.store.Active() {
		if se.Listener == channel.Remote {
			st.Sessions++
		}
	}
	return st
}

// Addr returns the bound listener address, or "" (tests).
func (s *Service) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Service) publicURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.PublicURL
}

func (s *Service) resourceURI() string { return s.publicURL() + s.cfg.Listener.MCPPath }

func (s *Service) resourceMetadataURL() string {
	return s.publicURL() + pathPRM + s.cfg.Listener.MCPPath
}

// Enable turns the profile on (FR-16.11). The event is committed before
// the listener serves; when it cannot be written the profile stays off.
func (s *Service) Enable(actor, publicURL, provider string) (Status, error) {
	if publicURL == "" {
		publicURL = s.cfg.Remote.PublicURL
	}
	publicURL = strings.TrimSuffix(publicURL, "/")
	if err := config.CheckPublicURL(publicURL); err != nil {
		return Status{}, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	if provider == "" {
		provider = "manual"
	}
	if !contains(Providers, provider) {
		return Status{}, fmt.Errorf("%w: provider must be one of %s", ErrBadRequest, strings.Join(Providers, ", "))
	}
	s.mu.Lock()
	prev := s.state
	if s.ln == nil {
		if err := s.openLocked(); err != nil {
			s.mu.Unlock()
			return Status{}, err
		}
	}
	next := State{Enabled: true, PublicURL: publicURL, Provider: provider, ChangedBy: actor, ChangedAt: s.now().UTC()}
	if err := s.rec.Commit(audit.Event{Class: "remote_access", Origin: "E-24", Outcome: "remote_access_enabled", ReasonCode: "REMOTE_ACCESS_ENABLED",
		PolicyStatus: "not_evaluated", Detail: map[string]any{"actor": actor, "public_url": publicURL, "provider": provider, "listener": s.cfg.Remote.Address,
			"previous_public_url": prev.PublicURL}}); err != nil {
		if !prev.Enabled {
			s.closeLocked()
		}
		s.mu.Unlock()
		return Status{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	s.state = next
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return Status{}, err
	}
	s.log.Warn("remote access enabled", "public_url", publicURL, "provider", provider, "listener", s.cfg.Remote.Address, "actor", actor)
	return s.Status(), nil
}

// Disable turns the profile off: the listener closes and every remote
// session ends. Disabling proceeds even when evidence fails (the safe
// direction); the error is still returned.
func (s *Service) Disable(actor string) (Status, error) {
	s.mu.Lock()
	prev := s.state
	s.closeLocked()
	s.state = State{Enabled: false, PublicURL: prev.PublicURL, Provider: prev.Provider, ChangedBy: actor, ChangedAt: s.now().UTC()}
	saveErr := s.saveLocked()
	s.mu.Unlock()
	ended := 0
	for _, se := range s.store.Active() {
		if se.Listener == channel.Remote && s.store.Terminate(se.ID) {
			ended++
		}
	}
	err := s.rec.Commit(audit.Event{Class: "remote_access", Origin: "E-24", Outcome: "remote_access_disabled", ReasonCode: "REMOTE_ACCESS_DISABLED",
		PolicyStatus: "not_evaluated", Detail: map[string]any{"actor": actor, "public_url": prev.PublicURL, "sessions_ended": ended}})
	s.log.Warn("remote access disabled", "actor", actor, "sessions_ended", ended)
	if err != nil {
		return s.Status(), fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return s.Status(), saveErr
}

func (s *Service) saveLocked() error {
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, "state.json"), b)
}

func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// openLocked binds and serves the remote listener (SR-2.9-3: loopback
// only, checked by config).
func (s *Service) openLocked() error {
	// RR-07: the certificate is re-read when its file changes, as on the
	// harness and admin listeners, so listener certificate rotation applies
	// to new remote connections without re-enabling the profile.
	certs, err := keys.NewCertReloader(s.cfg.Listener.TLSCert, s.cfg.Listener.TLSKey)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.cfg.Remote.Address)
	if err != nil {
		return err
	}
	l := s.cfg.Remote.Limits
	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         &tls.Config{GetCertificate: certs.GetCertificate, MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    l.HeaderBytes, // FR-16.7; the handler enforces the exact bound
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	done := make(chan struct{})
	s.ln, s.srv, s.done = ln, srv, done
	go func() {
		defer close(done)
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("remote listener stopped", "err", err)
		}
	}()
	return nil
}

func (s *Service) closeLocked() {
	if s.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.srv.Shutdown(ctx); err != nil {
		_ = s.srv.Close()
	}
	<-s.done
	s.ln, s.srv, s.done = nil, nil, nil
}

// Close stops the listener without changing the persisted state.
func (s *Service) Close() {
	s.mu.Lock()
	s.closeLocked()
	s.mu.Unlock()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// publicHost is the Host a request on the remote listener must carry.
func publicHost(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	return u.Host
}
