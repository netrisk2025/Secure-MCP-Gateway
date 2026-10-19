package principals

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Sessions is what the routes need from the session table; *session.Store
// implements it.
type Sessions interface {
	List() []*session.Session
	Suspend(id string) bool
	Terminate(id string) bool
}

// Service serves the principal routes.
type Service struct {
	Dir      *Directory
	Sessions Sessions
	Snapshot func() *policy.Snapshot
	Evidence audit.Recorder
	Log      *slog.Logger
	// AdminHash returns the Administrator's password hash; Register
	// defaults it to the control API's.
	AdminHash func() string
	// EndSessions ends the console sessions of an actor; Register
	// defaults it to the control API's browser sessions.
	EndSessions func(actor string) int
	// Gate runs a revocation (the directory change and the end of the
	// sessions it affects) under the Enforcement Coordinator's gate
	// (SR-1.16-1, edge.Gateway.Serialize); nil runs it directly.
	Gate func(func())
}

// serialize runs fn under Gate.
func (s *Service) serialize(fn func()) {
	if s.Gate == nil {
		fn()
		return
	}
	s.Gate(fn)
}

// Register adds the routes to the control API. Reads are open to the
// Operator and Auditor (Appendix C row "principals, credentials, sessions");
// changes are the Administrator's.
func (s *Service) Register(a *adminapi.Server) {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	a.Handle("GET /api/v1/principals", s.list)
	a.Handle("POST /api/v1/principals", s.create)
	a.Handle("POST /api/v1/principals/{id}/suspend", s.suspension(true))
	a.Handle("POST /api/v1/principals/{id}/enable", s.suspension(false))
	a.Handle("POST /api/v1/principals/{id}/credentials", s.issue)
	a.Handle("POST /api/v1/credentials/{client_id}/revoke", s.revoke)
	if s.AdminHash == nil {
		s.AdminHash = a.AdminPasswordHash
	}
	if s.EndSessions == nil {
		s.EndSessions = a.EndSessionsOf
	}
	a.Handle("GET /api/v1/approvers", s.listApprovers)
	a.Handle("POST /api/v1/approvers", s.createApprover)
	a.Handle("POST /api/v1/approvers/{username}/remove", s.removeApprover)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func mutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
	case errors.Is(err, ErrExists):
		writeError(w, http.StatusConflict, "exists", err.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, ErrFromFile):
		writeError(w, http.StatusConflict, "defined_in_file", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "store_failed", "the principal directory could not be written: "+err.Error())
	}
}

// commit records the action before it takes effect; a journal failure
// refuses the action.
func (s *Service) commit(w http.ResponseWriter, r *http.Request, outcome, reason, principal string, detail map[string]any) bool {
	detail["actor"] = adminapi.ActorOf(r)
	if err := s.Evidence.Commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: outcome, ReasonCode: reason, PolicyStatus: "not_evaluated", PrincipalID: principal, Detail: detail}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the evidence journal could not record the action; nothing was changed")
		return false
	}
	return true
}

func (s *Service) profiles() []string {
	var out []string
	if s.Snapshot != nil {
		if snap := s.Snapshot(); snap != nil {
			for p := range snap.Profiles {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	counts := map[string]map[string]int{}
	for _, se := range s.Sessions.List() {
		if counts[se.PrincipalID] == nil {
			counts[se.PrincipalID] = map[string]int{}
		}
		counts[se.PrincipalID][se.State]++
	}
	type row struct {
		View
		ActiveSessions    int `json:"active_sessions"`
		SuspendedSessions int `json:"suspended_sessions"`
	}
	out := []row{}
	for _, v := range s.Dir.List() {
		out = append(out, row{View: v, ActiveSessions: counts[v.ID][session.StateActive], SuspendedSessions: counts[v.ID][session.StateSuspended]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"principals": out, "frameworks": Frameworks, "profiles": s.profiles()})
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID          string `json:"id"`
		Framework   string `json:"framework"`
		DisplayName string `json:"display_name"`
		Profile     string `json:"profile"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {id, framework, display_name, profile}")
		return
	}
	// Validate before recording, so that refused requests leave no event.
	if _, err := s.Dir.validate(Principal{ID: body.ID, Framework: body.Framework, DisplayName: body.DisplayName, Profile: body.Profile}, s.profiles()); err != nil {
		mutationError(w, err)
		return
	}
	if !s.commit(w, r, "principal_created", "PRINCIPAL_CREATED", body.ID, map[string]any{"framework": body.Framework, "profile": body.Profile}) {
		return
	}
	p, err := s.Dir.AddPrincipal(Principal{ID: body.ID, Framework: body.Framework, DisplayName: body.DisplayName, Profile: body.Profile}, s.profiles(), adminapi.ActorOf(r))
	if err != nil {
		mutationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Service) suspension(suspend bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &body); err != nil || len(body.Reason) > 1000 {
			writeError(w, http.StatusBadRequest, "bad_request", "body must be {reason} with at most 1000 characters")
			return
		}
		id := r.PathValue("id")
		outcome, reason := "principal_enabled", "PRINCIPAL_ENABLED"
		if suspend {
			outcome, reason = "principal_suspended", "PRINCIPAL_SUSPENDED"
		}
		if _, ok := s.Dir.known(id); !ok {
			writeError(w, http.StatusNotFound, "not_found", "no such principal")
			return
		}
		if !s.commit(w, r, outcome, reason, id, map[string]any{"reason": body.Reason}) {
			return
		}
		var err error
		suspended := []string{}
		s.serialize(func() {
			if err = s.Dir.SetSuspended(id, suspend, adminapi.ActorOf(r), body.Reason); err != nil || !suspend {
				return
			}
			for _, se := range s.Sessions.List() {
				if se.PrincipalID == id && se.State == session.StateActive && s.Sessions.Suspend(se.ID) {
					suspended = append(suspended, se.ID)
				}
			}
		})
		if err != nil {
			mutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": !suspend, "suspended_sessions": suspended})
	}
}

func (s *Service) issue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
		Confidential bool     `json:"confidential"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {redirect_uris, confidential}")
		return
	}
	id := r.PathValue("id")
	if _, ok := s.Dir.known(id); !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such principal")
		return
	}
	if err := validRedirects(body.RedirectURIs); err != nil {
		mutationError(w, err)
		return
	}
	if !s.commit(w, r, "credential_issue_requested", "CREDENTIAL_ISSUED", id, map[string]any{"redirect_uris": body.RedirectURIs, "confidential": body.Confidential}) {
		return
	}
	c, secret, err := s.Dir.Issue(id, body.RedirectURIs, body.Confidential, adminapi.ActorOf(r))
	if err != nil {
		mutationError(w, err)
		return
	}
	out := map[string]any{"client_id": c.ClientID, "principal": c.Principal, "redirect_uris": c.RedirectURIs, "confidential": body.Confidential, "created_at": c.CreatedAt}
	if secret != "" {
		out["client_secret"] = secret
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Service) revoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil || len(body.Reason) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {reason} with at most 1000 characters")
		return
	}
	id := r.PathValue("client_id")
	c, ok := s.Dir.Client(id)
	if !ok {
		_, err := s.Dir.Revoke(id, "") // explains file clients, unknown and revoked ones
		mutationError(w, err)
		return
	}
	if !s.commit(w, r, "credential_revoke_requested", "CREDENTIAL_REVOKED", c.Principal, map[string]any{"client_id": id, "reason": body.Reason}) {
		return
	}
	var err error
	ended := []string{}
	s.serialize(func() {
		if _, err = s.Dir.Revoke(id, adminapi.ActorOf(r)); err != nil {
			return
		}
		for _, se := range s.Sessions.List() {
			if se.ClientID == id && s.Sessions.Terminate(se.ID) {
				ended = append(ended, se.ID)
			}
		}
	})
	if err != nil {
		mutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client_id": id, "revoked": true, "terminated_sessions": ended})
}
