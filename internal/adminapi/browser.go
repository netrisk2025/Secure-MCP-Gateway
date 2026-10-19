package adminapi

// Browser sessions of the console (SR-2.6-1, SR-8.9-1, CP-29).
//
// smcpctl and scripts authenticate with a bearer token. The console signs in
// with the same login routes but sends "X-SMCP-Session: cookie"; the server
// then keeps the sign-in token to itself (it is revoked at once) and answers
// with a session cookie instead:
//
//   - The session ID is 256 random bits, held server-side as its SHA-256
//     digest, in a __Host- cookie with Secure, HttpOnly and SameSite=Strict
//     and no Domain or Max-Age.
//   - Every sign-in issues a new ID; an ID presented to a login route is
//     destroyed first, so a pre-login ID never becomes a signed-in one. The
//     role of a session never changes: a different role needs a new sign-in,
//     which issues a new ID.
//   - CP-29: the session ends after 15 minutes without user activity and 8
//     hours after sign-in. Requests marked "X-SMCP-Background: 1" (refreshes
//     the console makes on its own) do not count as activity. Ending a
//     session cancels its requests in flight, including open event streams.
//   - Sign-out (POST /admin/v1/session/logout, or any /logout route) deletes
//     the session immediately.
//   - Every state-changing request (POST, PUT, PATCH, DELETE) of a browser
//     session must carry the session's CSRF token in X-CSRF-Token and an
//     If-Match precondition naming a revision at which the session read the
//     object it changes.
//
// Revisions are per object (revision.go): a browser mutation is refused
// with 412 only when its own object changed after the revision it names, so
// a change to an unrelated object does not force a re-read. Sign-out routes
// are exempt from If-Match (they change no Gateway state) but not from the
// CSRF token.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

const (
	// SessionCookie is the name of the console session cookie.
	SessionCookie = "__Host-smcp-session"
	// CSRFHeader carries the session's CSRF token on state-changing requests.
	CSRFHeader = "X-CSRF-Token"
	// SessionModeHeader set to "cookie" on a login route asks for a browser
	// session instead of a bearer token.
	SessionModeHeader = "X-SMCP-Session"
	// BackgroundHeader set to "1" marks a request that does not count as
	// user activity for the idle limit.
	BackgroundHeader = "X-SMCP-Background"

	// BrowserIdleTimeout and BrowserAbsoluteTimeout are CP-29.
	BrowserIdleTimeout     = 15 * time.Minute
	BrowserAbsoluteTimeout = 8 * time.Hour
)

// TokenRevoker is implemented by an Authenticator that can invalidate one
// of its tokens. Browser sign-in revokes the bearer token a login route
// issued, so that only the cookie remains.
type TokenRevoker interface {
	Revoke(token string)
}

// BrowserSession describes the browser session of a request.
type BrowserSession struct {
	CSRFToken   string    `json:"csrf_token"`
	IdleTimeout int       `json:"idle_timeout"` // seconds
	ExpiresAt   time.Time `json:"expires_at"`   // absolute limit
}

type browserSession struct {
	actor, role string
	csrf        string
	created     time.Time
	lastActive  time.Time
	ctx         context.Context
	cancel      context.CancelFunc
	timer       *time.Timer
}

type browserKey struct{}

// BrowserSessionOf returns the browser session of a request authenticated
// by cookie; ok is false for bearer-token requests.
func BrowserSessionOf(r *http.Request) (BrowserSession, bool) {
	v, ok := r.Context().Value(browserKey{}).(BrowserSession)
	return v, ok
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func isLogout(path string) bool { return strings.HasSuffix(path, "/logout") }

// tokenActor resolves a bearer token: the operator token, an administrator
// session token or a registered authenticator's token.
func (s *Server) tokenActor(tok string) (actor, role string) {
	if tok == "" {
		return "", ""
	}
	sum := sha256.Sum256([]byte(tok))
	if subtle.ConstantTimeCompare(sum[:], s.operator[:]) == 1 {
		return "operator-token", RoleAdministrator
	}
	s.mu.Lock()
	if as, ok := s.sessions[sum]; ok {
		if s.now().Before(as.expires) {
			s.mu.Unlock()
			return "admin:" + as.user, RoleAdministrator
		}
		delete(s.sessions, sum)
	}
	s.mu.Unlock()
	actor, role, _ = s.extraActor(tok)
	return actor, role
}

// revoke invalidates a sign-in token wherever it was issued.
func (s *Server) revoke(tok string) {
	sum := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	delete(s.sessions, sum)
	authn := append([]Authenticator(nil), s.authn...)
	s.mu.Unlock()
	for _, a := range authn {
		if rv, ok := a.(TokenRevoker); ok {
			rv.Revoke(tok)
		}
	}
}

func sessionKey(id string) [32]byte { return sha256.Sum256([]byte(id)) }

func (s *Server) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// expired reports whether bs is past CP-29 at now. Callers hold s.mu.
func expired(bs *browserSession, now time.Time) bool {
	return !now.Before(bs.lastActive.Add(BrowserIdleTimeout)) || !now.Before(bs.created.Add(BrowserAbsoluteTimeout))
}

// endBrowserLocked deletes a session and cancels its requests. Callers
// hold s.mu.
func (s *Server) endBrowserLocked(k [32]byte) {
	bs, ok := s.browser[k]
	if !ok {
		return
	}
	delete(s.browser, k)
	bs.cancel()
	if bs.timer != nil {
		bs.timer.Stop()
	}
}

// EndSessionsOf ends every browser session of an actor ("role:user"),
// cancelling its requests, and returns how many it ended. It is used when
// an account is removed.
func (s *Server) EndSessionsOf(actor string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, bs := range s.browser {
		if bs.actor == actor {
			s.endBrowserLocked(k)
			n++
		}
	}
	return n
}

func (s *Server) endBrowser(id string) {
	s.mu.Lock()
	s.endBrowserLocked(sessionKey(id))
	s.mu.Unlock()
}

// sweep ends a session whose limits passed, or re-arms its timer. The timer
// ends sessions that see no request at all, so that their open streams stop.
func (s *Server) sweep(k [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bs, ok := s.browser[k]
	if !ok {
		return
	}
	now := s.now()
	if expired(bs, now) {
		s.endBrowserLocked(k)
		return
	}
	next := earlier(bs.lastActive.Add(BrowserIdleTimeout), bs.created.Add(BrowserAbsoluteTimeout)).Sub(now)
	bs.timer = time.AfterFunc(max(next, time.Second), func() { s.sweep(k) })
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// lookupBrowser returns the live session of a cookie value. A request that
// is not marked as background counts as activity.
func (s *Server) lookupBrowser(id string, background bool) *browserSession {
	k := sessionKey(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	bs, ok := s.browser[k]
	if !ok {
		return nil
	}
	now := s.now()
	if expired(bs, now) {
		s.endBrowserLocked(k)
		return nil
	}
	if !background {
		bs.lastActive = now
	}
	return bs
}

func (s *Server) newBrowser(actor, role string) (id string, bs *browserSession) {
	id = ids.Secret()
	ctx, cancel := context.WithCancel(context.Background())
	now := s.now()
	bs = &browserSession{actor: actor, role: role, csrf: ids.Secret(), created: now, lastActive: now, ctx: ctx, cancel: cancel}
	k := sessionKey(id)
	s.mu.Lock()
	for kk, v := range s.browser {
		if expired(v, now) {
			s.endBrowserLocked(kk)
		}
	}
	s.browser[k] = bs
	bs.timer = time.AfterFunc(BrowserIdleTimeout, func() { s.sweep(k) })
	s.mu.Unlock()
	return id, bs
}

func (bs *browserSession) info() BrowserSession {
	return BrowserSession{CSRFToken: bs.csrf, IdleTimeout: int(BrowserIdleTimeout.Seconds()), ExpiresAt: bs.created.Add(BrowserAbsoluteTimeout).UTC()}
}

// bufferWriter records a login handler's answer.
type bufferWriter struct {
	header http.Header
	status int
	body   []byte
}

func (b *bufferWriter) Header() http.Header { return b.header }
func (b *bufferWriter) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}
func (b *bufferWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	b.body = append(b.body, p...)
	return len(p), nil
}

func (b *bufferWriter) replay(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	if b.status == 0 {
		b.status = http.StatusOK
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body)
}

// browserLogin wraps a login route. Without "X-SMCP-Session: cookie" the
// route answers as before (a bearer token). With it, a successful sign-in
// becomes a browser session: the token is revoked and never sent, the
// answer carries the CSRF token instead, and the session cookie is set.
func (s *Server) browserLogin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(SessionModeHeader) != "cookie" {
			h(w, r)
			return
		}
		// A session ID presented before sign-in is never carried over.
		if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
			s.endBrowser(c.Value)
			clearSessionCookie(w)
		}
		rec := &bufferWriter{header: http.Header{}}
		h(rec, r)
		var body map[string]any
		if rec.status != http.StatusOK || json.Unmarshal(rec.body, &body) != nil {
			rec.replay(w)
			return
		}
		tok, _ := body["token"].(string)
		if tok == "" {
			rec.replay(w)
			return
		}
		actor, role := s.tokenActor(tok)
		s.revoke(tok)
		if actor == "" {
			writeError(w, http.StatusInternalServerError, "internal", "the sign-in token did not resolve")
			return
		}
		id, bs := s.newBrowser(actor, role)
		if err := s.rec.Commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: "session_started", ReasonCode: "BROWSER_SESSION_STARTED", PolicyStatus: "not_evaluated",
			Detail: map[string]any{"actor": actor, "role": role}}); err != nil {
			s.endBrowser(id)
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "evidence journal unavailable")
			return
		}
		delete(body, "token")
		info := bs.info()
		body["session"] = "cookie"
		body["actor"] = actor
		body["role"] = role
		body["csrf_token"] = info.CSRFToken
		body["idle_timeout"] = info.IdleTimeout
		body["expires_in"] = int(BrowserAbsoluteTimeout.Seconds())
		body["expires_at"] = info.ExpiresAt
		s.setSessionCookie(w, id)
		w.Header().Set("ETag", s.Revision())
		writeJSON(w, http.StatusOK, body)
	}
}

// browserLogout ends the caller's browser session. It needs the CSRF token
// so that another site cannot sign the operator out.
func (s *Server) browserLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mu.Lock()
	bs := s.browser[sessionKey(c.Value)]
	s.mu.Unlock()
	if bs != nil && subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(bs.csrf)) != 1 {
		s.csrfRefused(w, r, bs.actor)
		return
	}
	s.endBrowser(c.Value)
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) csrfRefused(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.rec.Commit(audit.Event{Class: "auth_failure", Origin: "E-24", Outcome: "deny", ReasonCode: "CSRF_TOKEN_INVALID", PolicyStatus: "not_evaluated",
		Detail: map[string]any{"path": r.URL.Path, "actor": actor}}); err != nil {
		s.log.Error("evidence write failed", "err", err)
	}
	writeError(w, http.StatusForbidden, "csrf_invalid", "a valid "+CSRFHeader+" header is required for this request")
}

// browserActor authenticates a request by its session cookie. It returns
// false after answering when the request must not proceed. On success the
// returned request carries the session's cancellation and BrowserSession;
// done must be called when the request ends.
func (s *Server) browserActor(w http.ResponseWriter, r *http.Request) (actor, role string, out *http.Request, done func(), ok bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return "", "", r, func() {}, true
	}
	bs := s.lookupBrowser(c.Value, r.Header.Get(BackgroundHeader) == "1")
	if bs == nil {
		clearSessionCookie(w)
		return "", "", r, func() {}, true
	}
	if isMutation(r.Method) && subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(bs.csrf)) != 1 {
		s.csrfRefused(w, r, bs.actor)
		return "", "", r, func() {}, false
	}
	ctx, cancel := context.WithCancel(context.WithValue(r.Context(), browserKey{}, bs.info()))
	stop := context.AfterFunc(bs.ctx, cancel)
	if isMutation(r.Method) && isLogout(r.URL.Path) {
		s.endBrowser(c.Value)
		clearSessionCookie(w)
	}
	return bs.actor, bs.role, r.WithContext(ctx), func() { stop(); cancel() }, true
}
