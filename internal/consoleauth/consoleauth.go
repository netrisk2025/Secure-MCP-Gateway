// Package consoleauth signs in the control API accounts of the Appendix C
// roles that no other element owns (FR-8.2): Operator, Policy Author,
// Auditor and Researcher accounts of [[console.account]], and Session
// Approvers of [[approver]], whose console use is limited to deciding
// dynamic client registrations and reading health. The Administrator signs
// in with POST /admin/v1/login and Approvers with POST
// /api/v1/approvals/login.
//
// Tokens are bearer tokens like the administrator's: 256-bit random
// values, held in memory as SHA-256 digests, valid for SessionTTL. What a
// token may reach is decided by the control API's role matrix
// (adminapi/rolematrix.go).
//
// Routes (docs/api/console.md):
//
//	POST /api/v1/console/login    {username, password, role?} -> {token, expires_in, role, actor}
//	POST /api/v1/console/logout
//	GET  /api/v1/console/session  the caller's actor and role and the route permissions
//	                              (and, for a browser session, its CSRF token)
package consoleauth

import (
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// SessionTTL is the lifetime of a console sign-in token.
const SessionTTL = 30 * time.Minute

// Options configure the service.
type Options struct {
	Config   *config.Config
	Evidence audit.Recorder
	Guard    *authguard.Guard
	Log      *slog.Logger
	Now      func() time.Time
}

// Service holds the sign-in tokens.
type Service struct {
	cfg   *config.Config
	rec   audit.Recorder
	guard *authguard.Guard
	log   *slog.Logger
	now   func() time.Time
	admin *adminapi.Server

	mu     sync.Mutex
	tokens map[[32]byte]session
}

type session struct {
	user    string
	role    string
	expires time.Time
}

// New builds the service.
func New(o Options) *Service {
	if o.Guard == nil {
		o.Guard = authguard.New(authguard.Config{})
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{cfg: o.Config, rec: o.Evidence, guard: o.Guard, log: o.Log, now: o.Now, tokens: map[[32]byte]session{}}
}

// Register adds the routes and the token authenticator to the control API.
func (s *Service) Register(a *adminapi.Server) {
	s.admin = a
	a.AddAuthenticator(s)
	a.HandlePublic("POST /api/v1/console/login", s.login)
	a.Handle("POST /api/v1/console/logout", s.logout)
	a.Handle("GET /api/v1/console/session", s.session)
}

// Authenticate implements adminapi.Authenticator.
func (s *Service) Authenticate(tok string) (string, string, bool) {
	sum := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.tokens[sum]
	if !ok {
		return "", "", false
	}
	if !s.now().Before(ss.expires) {
		delete(s.tokens, sum)
		return "", "", false
	}
	// A Session Approver removed from the directory (FR-2.23) loses its
	// tokens at the next request.
	if ss.role == adminapi.RoleSessionApprover && s.cfg.FindApprover(ss.user) == nil {
		delete(s.tokens, sum)
		return "", "", false
	}
	return ss.role + ":" + ss.user, ss.role, true
}

// Revoke implements adminapi.TokenRevoker: a browser sign-in keeps only
// its cookie session.
func (s *Service) Revoke(tok string) {
	sum := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	delete(s.tokens, sum)
	s.mu.Unlock()
}

// lookup returns the password hash and role of an account, "" when unknown.
// A Session Approver signs in with role "session_approver"; every other
// account is found in [[console.account]].
func (s *Service) lookup(user, role string) (hash, resolved string) {
	if role == adminapi.RoleSessionApprover {
		for _, a := range s.cfg.SessionApprovers() {
			if authguard.EqualName(a.Username, user) {
				return a.PasswordHash, role
			}
		}
		return "", role
	}
	for _, a := range s.cfg.Console.Accounts {
		if authguard.EqualName(a.Username, user) && (role == "" || role == a.Role) {
			return a.PasswordHash, a.Role
		}
	}
	return "", role
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {username, password, role}")
		return
	}
	switch body.Role {
	case "", adminapi.RoleOperator, adminapi.RolePolicyAuthor, adminapi.RoleAuditor, adminapi.RoleResearcher, adminapi.RoleSessionApprover:
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "role must be operator, policy_author, auditor, researcher or session_approver")
		return
	}
	src := authguard.Source(r)
	account := "console:" + body.Username
	if d, err := s.guard.Check(src, account); err != nil {
		authguard.RetryAfter(w, d)
		writeError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		return
	}
	hash, role := s.lookup(body.Username, body.Role)
	ok, err := s.guard.Verify(r.Context(), hash, body.Password)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy", "sign-in capacity exhausted")
		return
	}
	if !ok || role == "" {
		s.guard.Failure(src, account)
		if err := s.rec.Commit(audit.Event{Class: "auth_failure", Origin: "E-24", Outcome: "deny", ReasonCode: "CONSOLE_SIGNIN_FAILED", PolicyStatus: "not_evaluated"}); err != nil {
			s.log.Error("evidence write failed", "err", err)
		}
		writeError(w, http.StatusUnauthorized, "signin_failed", "sign-in failed")
		return
	}
	s.guard.Success(account)
	actor := role + ":" + body.Username
	if err := s.rec.Commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: "signed_in", ReasonCode: "CONSOLE_SIGNIN", PolicyStatus: "not_evaluated",
		Detail: map[string]any{"actor": actor, "role": role}}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "evidence journal unavailable")
		return
	}
	tok := ids.Secret()
	s.mu.Lock()
	now := s.now()
	for k, v := range s.tokens {
		if !now.Before(v.expires) {
			delete(s.tokens, k)
		}
	}
	s.tokens[sha256.Sum256([]byte(tok))] = session{user: body.Username, role: role, expires: now.Add(SessionTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(SessionTTL.Seconds()), "role": role, "actor": actor})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	sum := sha256.Sum256([]byte(bearer(r)))
	s.mu.Lock()
	delete(s.tokens, sum)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// session answers the caller's actor and role with the route permissions,
// from which the console builds its navigation (FR-8.28).
// A browser session (cookie) also gets its CSRF token and CP-29 limits, so
// that a reloaded page can continue the session.
func (s *Service) session(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"actor":  adminapi.ActorOf(r),
		"role":   adminapi.RoleOf(r),
		"roles":  adminapi.Roles,
		"routes": s.admin.Routes(),
	}
	if bs, ok := adminapi.BrowserSessionOf(r); ok {
		out["session"] = "cookie"
		out["csrf_token"] = bs.CSRFToken
		out["idle_timeout"] = bs.IdleTimeout
		out["expires_at"] = bs.ExpiresAt
	}
	writeJSON(w, http.StatusOK, out)
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
