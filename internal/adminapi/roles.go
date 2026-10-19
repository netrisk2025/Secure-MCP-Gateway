package adminapi

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Application roles of SRS Appendix C (the others are in rolematrix.go).
// The operator token and administrator session tokens carry
// RoleAdministrator; other roles come from an Authenticator registered by
// the element that owns the accounts (E-07 registers Approver accounts,
// internal/consoleauth the remaining roles).
const (
	RoleAdministrator = "administrator"
	RoleApprover      = "approver"
)

// Authenticator resolves a bearer token that is neither the operator token
// nor an administrator session token. It returns the actor recorded in
// evidence (for example "approver:alice") and the actor's role.
type Authenticator interface {
	Authenticate(token string) (actor, role string, ok bool)
}

// AddAuthenticator registers an additional token authenticator. Tokens it
// accepts reach only the routes whose roles (the HandleRoles list plus the
// Appendix C matrix of rolematrix.go) include the token's role.
func (s *Server) AddAuthenticator(a Authenticator) {
	s.mu.Lock()
	s.authn = append(s.authn, a)
	s.mu.Unlock()
}

// HandleRoles registers an authenticated route that accepts the
// Administrator and the listed roles.
func (s *Server) HandleRoles(pattern string, h http.HandlerFunc, roles ...string) {
	roles = mergeRoles(pattern, roles)
	s.record(pattern, roles, false)
	s.mux.Handle(pattern, s.authenticatedRoles(pattern, h, roles))
}

// HandlePublic registers a route without bearer authentication, for an
// element's own sign-in endpoint. The listener's host, origin and
// content-type checks still apply.
//
// A POST route ending in /login is a sign-in route: with the header
// "X-SMCP-Session: cookie" its successful answer becomes a browser session
// (browser.go).
func (s *Server) HandlePublic(pattern string, h http.HandlerFunc) {
	s.record(pattern, nil, true)
	if strings.HasPrefix(pattern, "POST ") && strings.HasSuffix(pattern, "/login") {
		h = s.browserLogin(h)
	}
	s.mux.HandleFunc(pattern, h)
}

// ActorOf returns the authenticated actor of a request ("operator-token",
// "admin:<user>" or an Authenticator's actor).
func ActorOf(r *http.Request) string { return actorOf(r) }

// RoleOf returns the authenticated role of a request.
func RoleOf(r *http.Request) string { v, _ := r.Context().Value(roleKey{}).(string); return v }

type roleKey struct{}

// extraActor runs the registered authenticators. It returns ok=false when
// none accepts the token.
func (s *Server) extraActor(tok string) (actor, role string, ok bool) {
	if tok == "" {
		return "", "", false
	}
	s.mu.Lock()
	authn := slices.Clone(s.authn)
	s.mu.Unlock()
	for _, a := range authn {
		if actor, role, ok := a.Authenticate(tok); ok {
			return actor, role, true
		}
	}
	return "", "", false
}

// authenticatedRoles authenticates like Handle routes and additionally
// accepts actors of the listed roles from registered authenticators. An
// authenticated actor without one of the roles is refused with 403.
func (s *Server) authenticatedRoles(pattern string, next http.HandlerFunc, roles []string) http.Handler {
	narrow := refine[pattern]
	return s.authenticated(func(w http.ResponseWriter, r *http.Request) {
		role := RoleOf(r)
		if role != RoleAdministrator && (!slices.Contains(roles, role) || (narrow != nil && !narrow(role, r))) {
			if err := s.rec.Commit(audit.Event{Class: "auth_failure", Origin: "E-24", Outcome: "deny", ReasonCode: "ADMIN_ROLE_REFUSED", PolicyStatus: "not_evaluated",
				Detail: map[string]any{"path": r.URL.Path, "actor": actorOf(r), "role": role}}); err != nil {
				s.log.Error("evidence write failed", "err", err)
			}
			writeError(w, http.StatusForbidden, "role_refused", "this account's role does not permit this operation")
			return
		}
		if !s.precondition(w, r, pattern) {
			return
		}
		next(w, r)
	})
}

// WithRole returns ctx carrying actor and role as an authenticated request
// does; for handlers called without the listener (tests).
func WithRole(ctx context.Context, actor, role string) context.Context {
	return withRole(ctx, actor, role)
}

func withRole(ctx context.Context, actor, role string) context.Context {
	return context.WithValue(context.WithValue(ctx, actorKey{}, actor), roleKey{}, role)
}
