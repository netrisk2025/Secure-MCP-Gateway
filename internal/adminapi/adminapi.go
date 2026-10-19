// Package adminapi is the base of the control API of the Management
// Console & Control API (E-24): a JSON API on its own loopback TLS listener
// (CP-03), separate from the harness listener so that harness session
// tokens are never accepted for administration (SR-2.5-1).
//
// Clients other than the browser authenticate with a bearer token in the
// Authorization header: the local operator token in the state directory
// (keys/admin.token, used by smcpctl on the same machine) or a short-lived
// sign-in token issued by POST /admin/v1/login against the administrator
// password. The console instead signs in for a browser session: a
// Secure, HttpOnly, SameSite=Strict cookie with the CP-29 limits, whose
// state-changing requests also need a CSRF token and an If-Match revision
// precondition (browser.go, SR-2.6-1, SR-8.9-1). Requests are further
// refused when they carry a foreign Origin or a cross-site Sec-Fetch-Site,
// and every POST must be application/json.
//
// Endpoints (all under /admin/v1):
//
//	POST login            {username, password} -> {token, expires_in}
//	POST logout
//	POST session/logout   end the caller's browser session (browser.go)
//	POST bootstrap        {token, password}: one-use admin password setup
//	GET  health           full health report
//	POST stop             {reason}: emergency stop (FR-4.14), audited
//	POST resume           leave emergency stop, audited
//	POST policy/reload    validate and activate the policy file (FR-3.10)
//	GET  approvals        pending approvals (the Approval Service, E-07, when registered)
//	POST approvals/{id}   {decision: approve|deny, reason}
//
// Later E-24 work adds routes with Server.Handle, which applies the same
// authentication and CSRF rules. Handle routes are Administrator-only;
// HandleRoles admits other roles whose tokens an element's Authenticator
// resolves (roles.go). The Approval Service's /api/v1/approvals routes are
// registered that way (internal/approval).
package adminapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// AdminPasswordFile holds the administrator password hash set through the
// bootstrap token, under the state directory.
const AdminPasswordFile = "keys/admin.password"

// SessionTTL is the lifetime of an administrator session token.
const SessionTTL = 30 * time.Minute

// Controller is what the control API drives. *edge.Gateway implements it.
type Controller interface {
	Health() edge.Health
	Stop(actor, reason string) error
	Resume(actor string) error
	ActivatePolicy(actor string, snap *policy.Snapshot) (bool, error)
}

// Approvals is the seam for the Approval Service (E-07) queue. Until an
// implementation is registered the approval endpoints report that no
// approval service is running.
type Approvals interface {
	Pending(ctx context.Context) (any, error)
	Decide(ctx context.Context, id string, approve bool, actor, reason string) error
}

// Options configure the server.
type Options struct {
	Config     *config.Config
	Controller Controller
	Evidence   audit.Recorder
	Guard      *authguard.Guard
	Approvals  Approvals
	Log        *slog.Logger
	Now        func() time.Time
}

// Server is the control API.
type Server struct {
	cfg       *config.Config
	ctl       Controller
	rec       audit.Recorder
	guard     *authguard.Guard
	approvals Approvals
	log       *slog.Logger
	now       func() time.Time
	operator  [32]byte
	mux       *http.ServeMux

	rev      atomic.Uint64 // control-state sequence (revision.go)
	revEpoch string
	revMu    sync.Mutex
	changed  map[string]uint64 // object key -> sequence of its last change (revision.go)

	mu       sync.Mutex
	sessions map[[32]byte]adminSession
	browser  map[[32]byte]*browserSession // browser.go
	authn    []Authenticator              // roles.go
	routes   []RouteInfo                  // rolematrix.go
}

type adminSession struct {
	user    string
	expires time.Time
}

type actorKey struct{}

// New builds the control API. The operator token is read from the state
// directory.
func New(o Options) (*Server, error) {
	if o.Config == nil || o.Controller == nil || o.Evidence == nil {
		return nil, errors.New("adminapi: config, controller and evidence are required")
	}
	tok, err := keys.LoadAdminToken(o.Config.State.Dir)
	if err != nil {
		return nil, fmt.Errorf("operator token: %w", err)
	}
	if o.Guard == nil {
		o.Guard = authguard.New(authguard.Config{})
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Server{cfg: o.Config, ctl: o.Controller, rec: o.Evidence, guard: o.Guard, approvals: o.Approvals, log: o.Log, now: o.Now,
		operator: sha256.Sum256([]byte(tok)), mux: http.NewServeMux(), sessions: map[[32]byte]adminSession{}, browser: map[[32]byte]*browserSession{},
		revEpoch: ids.Secret()[:8], changed: map[string]uint64{}}
	s.HandlePublic("POST /admin/v1/login", s.login)
	s.HandlePublic("POST /admin/v1/bootstrap", s.bootstrap)
	s.HandlePublic("POST /admin/v1/session/logout", s.browserLogout)
	s.Handle("POST /admin/v1/logout", s.logout)
	s.Handle("GET /admin/v1/health", s.health)
	s.Handle("POST /admin/v1/stop", s.stop)
	s.Handle("POST /admin/v1/resume", s.resume)
	s.Handle("POST /admin/v1/policy/reload", s.reload)
	s.Handle("GET /admin/v1/approvals", s.listApprovals)
	s.Handle("POST /admin/v1/approvals/{id}", s.decideApproval)
	return s, nil
}

// Handle registers an authenticated route for the Administrator role and
// the roles the Appendix C matrix admits to the pattern (rolematrix.go);
// HandleRoles admits further roles.
func (s *Server) Handle(pattern string, h http.HandlerFunc) {
	roles := mergeRoles(pattern, nil)
	s.record(pattern, roles, false)
	s.mux.Handle(pattern, s.authenticatedRoles(pattern, h, roles))
}

// Handler returns the listener's handler with the host, origin and
// content-type checks.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if !s.hostAllowed(r.Host) { // SR-2.9-2
			writeError(w, http.StatusMisdirectedRequest, "unknown_host", "unknown host")
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, s.cfg.AdminURL()) {
			writeError(w, http.StatusForbidden, "origin_refused", "cross-origin requests are refused")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, http.StatusForbidden, "origin_refused", "cross-site requests are refused")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/admin/") {
			h.Set("ETag", s.Revision()) // SR-8.9-1; mutations replace it (browser.go)
		}
		if r.Method == http.MethodPost {
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "json_required", "POST bodies must be application/json")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	_, port, err := net.SplitHostPort(s.cfg.AdminListener.Address)
	if err != nil {
		return false
	}
	for _, h := range []string{s.cfg.AdminListener.Address, "localhost:" + port, "127.0.0.1:" + port, "[::1]:" + port} {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// authenticated accepts the operator token, a live administrator session
// token, a registered authenticator's token, or a browser session cookie
// (browser.go). A request with an Authorization header is authenticated by
// it alone. Session tokens of the harness listener are unknown here.
func (s *Server) authenticated(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		actor, role := s.tokenActor(tok)
		done := func() {}
		if tok == "" {
			var ok bool
			actor, role, r, done, ok = s.browserActor(w, r)
			if !ok {
				return
			}
		}
		defer done()
		if actor == "" {
			if err := s.rec.Commit(audit.Event{Class: "auth_failure", Origin: "E-24", Outcome: "deny", ReasonCode: "ADMIN_AUTH_FAILED", PolicyStatus: "not_evaluated",
				Detail: map[string]any{"path": r.URL.Path}}); err != nil {
				s.log.Error("evidence write failed", "err", err)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="smcp-admin"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "administrator authentication required")
			return
		}
		ctx := withRole(r.Context(), actor, role)
		if tok != "" {
			ctx = context.WithValue(ctx, stillValidKey{}, func() bool { a, _ := s.tokenActor(tok); return a == actor })
		} else {
			// A browser session's request context ends with the session
			// (browserActor), so the context alone tells.
			reqCtx := r.Context()
			ctx = context.WithValue(ctx, stillValidKey{}, func() bool { return reqCtx.Err() == nil })
		}
		next(w, r.WithContext(ctx))
	})
}

type stillValidKey struct{}

// StillAuthenticated reports whether the credential of an authenticated
// request still resolves to the same actor: a bearer token has not expired
// or been signed out, a browser session has not ended. Long-lived responses such as event streams call it
// periodically and end when it turns false. It is false for a request
// that did not pass through an authenticated route.
func StillAuthenticated(r *http.Request) bool {
	f, ok := r.Context().Value(stillValidKey{}).(func() bool)
	return ok && f()
}

func actorOf(r *http.Request) string { a, _ := r.Context().Value(actorKey{}).(string); return a }

// AdminPasswordHash returns the Administrator's password hash, "" before
// bootstrap redemption. FR-2.23 uses it to refuse a Session Approver
// password equal to the Administrator's.
func (s *Server) AdminPasswordHash() string { return s.adminHash() }

// adminHash returns the administrator password hash: from configuration,
// else from the state file written by bootstrap, else "".
func (s *Server) adminHash() string {
	if s.cfg.Admin.PasswordHash != "" {
		return s.cfg.Admin.PasswordHash
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.State.Dir, AdminPasswordFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {username, password}")
		return
	}
	src := authguard.Source(r)
	if d, err := s.guard.Check(src, "admin:"+body.Username); err != nil {
		authguard.RetryAfter(w, d)
		writeError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		return
	}
	hash := ""
	if authguard.EqualName(body.Username, s.cfg.Admin.Username) {
		hash = s.adminHash()
	}
	ok, err := s.guard.Verify(r.Context(), hash, body.Password)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy", "sign-in capacity exhausted")
		return
	}
	if !ok {
		s.guard.Failure(src, "admin:"+body.Username)
		_ = s.rec.Commit(audit.Event{Class: "auth_failure", Origin: "E-24", Outcome: "deny", ReasonCode: "ADMIN_SIGNIN_FAILED", PolicyStatus: "not_evaluated"})
		writeError(w, http.StatusUnauthorized, "signin_failed", "sign-in failed")
		return
	}
	s.guard.Success("admin:" + body.Username)
	tok := ids.Secret()
	if err := s.rec.Commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: "signed_in", ReasonCode: "ADMIN_SIGNIN", PolicyStatus: "not_evaluated", Detail: map[string]any{"actor": "admin:" + body.Username}}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "evidence journal unavailable")
		return
	}
	s.mu.Lock()
	now := s.now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[sha256.Sum256([]byte(tok))] = adminSession{user: body.Username, expires: now.Add(SessionTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(SessionTTL.Seconds())})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sum := sha256.Sum256([]byte(bearer(r)))
	s.mu.Lock()
	delete(s.sessions, sum)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// bootstrap redeems the one-use bootstrap token to set the administrator
// password.
func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {token, password}")
		return
	}
	src := authguard.Source(r)
	if d, err := s.guard.Check(src, "bootstrap"); err != nil {
		authguard.RetryAfter(w, d)
		writeError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		return
	}
	want, err := hex.DecodeString(s.cfg.Admin.BootstrapTokenSHA256)
	got := sha256.Sum256([]byte(body.Token))
	exp, perr := time.Parse(time.RFC3339, s.cfg.Admin.BootstrapTokenExpires)
	switch {
	case s.cfg.Admin.PasswordHash != "" || s.adminHash() != "" || err != nil || len(want) != 32:
		writeError(w, http.StatusConflict, "no_bootstrap", "no bootstrap token is pending")
		return
	case subtle.ConstantTimeCompare(got[:], want) != 1:
		s.guard.Failure(src, "bootstrap")
		_ = s.rec.Commit(audit.Event{Class: "auth_failure", Origin: "E-24", Outcome: "deny", ReasonCode: "BOOTSTRAP_TOKEN_INVALID", PolicyStatus: "not_evaluated"})
		writeError(w, http.StatusUnauthorized, "token_invalid", "bootstrap token invalid")
		return
	case perr != nil || s.now().After(exp):
		writeError(w, http.StatusGone, "token_expired", "bootstrap token expired; rerun smcpctl bootstrap")
		return
	case len(body.Password) < 12:
		writeError(w, http.StatusBadRequest, "weak_password", "password must be at least 12 characters")
		return
	}
	hash, err := keys.HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "hash failed")
		return
	}
	// O_EXCL makes the token one-use even under concurrent redemptions.
	f, err := os.OpenFile(filepath.Join(s.cfg.State.Dir, AdminPasswordFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeError(w, http.StatusConflict, "no_bootstrap", "the bootstrap token was already used")
		return
	}
	_, werr := f.WriteString(hash + "\n")
	serr := f.Sync()
	if cerr := f.Close(); werr != nil || serr != nil || cerr != nil {
		os.Remove(f.Name())
		writeError(w, http.StatusInternalServerError, "internal", "could not store the password")
		return
	}
	if err := s.rec.Commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: "password_set", ReasonCode: "BOOTSTRAP_REDEEMED", PolicyStatus: "not_evaluated"}); err != nil {
		s.log.Error("evidence write failed", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ctl.Health())
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {reason}")
		return
	}
	err := s.ctl.Stop(actorOf(r), body.Reason)
	resp := map[string]any{"state": "stopped"}
	if err != nil {
		resp["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) resume(w http.ResponseWriter, r *http.Request) {
	if err := s.ctl.Resume(actorOf(r)); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "running"})
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	snap, err := policy.Load(s.cfg.Policy.File)
	if err != nil {
		_ = s.rec.Commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "rejected", ReasonCode: "POLICY_INVALID", PolicyStatus: "not_evaluated", Detail: map[string]any{"actor": actorOf(r), "error": err.Error()}})
		writeError(w, http.StatusUnprocessableEntity, "policy_invalid", err.Error())
		return
	}
	changed, err := s.ctl.ActivatePolicy(actorOf(r), snap)
	switch {
	case errors.Is(err, policy.ErrRevisionReused):
		writeError(w, http.StatusConflict, "revision_reused", err.Error())
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "activation_failed", err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]any{"revision": snap.Revision, "digest": snap.Digest, "changed": changed})
	}
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		writeJSON(w, http.StatusOK, map[string]any{"service": "none", "approvals": []any{}})
		return
	}
	p, err := s.approvals.Pending(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "approvals_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"service": "running", "approvals": p})
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := decode(r, &body); err != nil || (body.Decision != "approve" && body.Decision != "deny") {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {decision: approve|deny, reason}")
		return
	}
	if s.approvals == nil {
		writeError(w, http.StatusNotImplemented, "no_approval_service", "no approval service is running")
		return
	}
	if err := s.approvals.Decide(r.Context(), r.PathValue("id"), body.Decision == "approve", actorOf(r), body.Reason); err != nil {
		writeError(w, http.StatusConflict, "decision_refused", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Listen opens the admin listener after the loopback check.
func (s *Server) Listen() (net.Listener, error) {
	if err := edge.CheckLoopback(s.cfg.AdminListener.Address); err != nil {
		return nil, err
	}
	return net.Listen("tcp", s.cfg.AdminListener.Address)
}

// Serve runs the admin TLS listener on ln until ctx ends. It uses the same
// server certificate as the harness listener.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	tc, err := edge.TLSConfig(s.cfg.Listener.TLSCert, s.cfg.Listener.TLSKey)
	if err != nil {
		return err
	}
	return edge.ServeTLS(ctx, ln, s.Handler(), tc, s.log)
}
