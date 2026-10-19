package approval

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// SessionTTL is the lifetime of an Approver sign-in token.
const SessionTTL = 30 * time.Minute

// watchKeepAlive is the comment interval of the watch stream.
const watchKeepAlive = 15 * time.Second

// maxWatchStreams bounds concurrent watch streams; each holds a goroutine
// for as long as the client keeps it open.
const maxWatchStreams = 32

type approverSession struct {
	user    string
	expires time.Time
}

// Register adds the /api/v1/approvals routes to the control API and the
// Approver token authenticator. See docs/api/approvals.md.
func (s *Service) Register(a *adminapi.Server) {
	a.AddAuthenticator(s)
	a.HandlePublic("POST /api/v1/approvals/login", s.login)
	a.HandleRoles("POST /api/v1/approvals/logout", s.logout, adminapi.RoleApprover)
	a.HandleRoles("GET /api/v1/approvals", s.list, adminapi.RoleApprover)
	a.HandleRoles("GET /api/v1/approvals/watch", s.watch, adminapi.RoleApprover)
	a.HandleRoles("GET /api/v1/approvals/{id}", s.show, adminapi.RoleApprover)
	a.HandleRoles("POST /api/v1/approvals/{id}/approve", s.decision(true), adminapi.RoleApprover)
	a.HandleRoles("POST /api/v1/approvals/{id}/deny", s.decision(false), adminapi.RoleApprover)
}

// Authenticate implements adminapi.Authenticator for Approver sign-in
// tokens.
func (s *Service) Authenticate(tok string) (string, string, bool) {
	sum := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	as, ok := s.tokens[sum]
	if !ok {
		return "", "", false
	}
	if !s.now().Before(as.expires) {
		delete(s.tokens, sum)
		return "", "", false
	}
	return "approver:" + as.user, adminapi.RoleApprover, true
}

// Revoke implements adminapi.TokenRevoker: a browser sign-in keeps only
// its cookie session.
func (s *Service) Revoke(tok string) {
	sum := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	delete(s.tokens, sum)
	s.mu.Unlock()
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

func (s *Service) commit(ev audit.Event) error {
	s.mu.Lock()
	rec := s.rec
	s.mu.Unlock()
	if rec == nil {
		return ErrNotAttached
	}
	return rec.Commit(ev)
}

// login signs in an Approver account ([[approvals.account]]) and returns a
// bearer token for the approval routes.
func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {username, password}")
		return
	}
	src := authguard.Source(r)
	account := "approver:" + body.Username
	if d, err := s.guard.Check(src, account); err != nil {
		authguard.RetryAfter(w, d)
		writeError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		return
	}
	hash := ""
	for _, a := range s.cfg.Approvals.Accounts {
		if authguard.EqualName(a.Username, body.Username) {
			hash = a.PasswordHash
		}
	}
	ok, err := s.guard.Verify(r.Context(), hash, body.Password)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy", "sign-in capacity exhausted")
		return
	}
	if !ok {
		s.guard.Failure(src, account)
		if err := s.commit(audit.Event{Class: "auth_failure", Origin: "E-07", Outcome: "deny", ReasonCode: "APPROVER_SIGNIN_FAILED", PolicyStatus: "not_evaluated"}); err != nil {
			s.log.Error("evidence write failed", "err", err)
		}
		writeError(w, http.StatusUnauthorized, "signin_failed", "sign-in failed")
		return
	}
	s.guard.Success(account)
	if err := s.commit(audit.Event{Class: "admin", Origin: "E-07", Outcome: "signed_in", ReasonCode: "APPROVER_SIGNIN", PolicyStatus: "not_evaluated",
		Detail: map[string]any{"actor": account}}); err != nil {
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
	s.tokens[sha256.Sum256([]byte(tok))] = approverSession{user: body.Username, expires: now.Add(SessionTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(SessionTTL.Seconds()), "role": adminapi.RoleApprover})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	sum := sha256.Sum256([]byte(bearer(r)))
	s.mu.Lock()
	delete(s.tokens, sum)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	switch state {
	case "":
		state = StatePending
	case "all", StatePending, StateApproved, StateDenied, StateExpired, StateConsumed:
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "state must be pending, approved, denied, expired, consumed or all")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": s.List(state)})
}

func (s *Service) show(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such approval")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Service) decision(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Comment string `json:"comment"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "bad_request", "body must be {comment}")
			return
		}
		if len(body.Comment) > 1000 {
			writeError(w, http.StatusBadRequest, "bad_request", "comment is limited to 1000 characters")
			return
		}
		rec, err := s.decide(r.PathValue("id"), approve, adminapi.ActorOf(r), body.Comment)
		switch {
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such approval")
		case errors.Is(err, ErrNotPending):
			writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": "not_pending", "message": err.Error()}, "state": rec.State})
		case err != nil:
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
		default:
			writeJSON(w, http.StatusOK, rec)
		}
	}
}

// watch streams notices as text/event-stream: first one "snapshot" event
// with the pending approvals, then one "approval" event per notice.
func (s *Service) watch(w http.ResponseWriter, r *http.Request) {
	if s.streams.Add(1) > maxWatchStreams {
		s.streams.Add(-1)
		w.Header().Set("Retry-After", "15")
		writeError(w, http.StatusServiceUnavailable, "too_many_streams", "too many approval watch streams are open")
		return
	}
	defer s.streams.Add(-1)
	ch, cancel := s.Watch()
	defer cancel()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	send := func(name string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := io.WriteString(w, "event: "+name+"\ndata: "+string(b)+"\n\n"); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send("snapshot", map[string]any{"approvals": s.List(StatePending)}) {
		return
	}
	t := time.NewTicker(watchKeepAlive)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case n := <-ch:
			if !adminapi.StillAuthenticated(r) { // signed out or expired
				return
			}
			if !send("approval", n) {
				return
			}
		case <-t.C:
			if !adminapi.StillAuthenticated(r) {
				return
			}
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}

// harnessStatus is GET /smcp/v1/approvals/{id} on the harness listener
// (FR-3.16): the state of an approval, for the session that created it
// only; any other session gets 404.
func (s *Service) harnessStatus(w http.ResponseWriter, r *http.Request, sess session.Session) {
	rec, ok := s.Get(r.PathValue("id"))
	if !ok || rec.SessionID != sess.ID {
		writeError(w, http.StatusNotFound, "not_found", "no such approval")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvalId": rec.ID, "state": rec.State, "expiresAt": rec.ExpiresAt.UTC().Format(time.RFC3339), "approvalUrl": rec.URL})
}
