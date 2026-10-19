package consoleapi

import (
	"net/http"
	"sort"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// SessionView is the JSON form of a harness session.
type SessionView struct {
	ID             string `json:"id"`
	State          string `json:"state"`
	EndReason      string `json:"end_reason,omitempty"`
	PrincipalID    string `json:"principal_id"`
	Framework      string `json:"framework,omitempty"`
	Profile        string `json:"profile,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	Template       string `json:"template"`
	PolicyRevision string `json:"policy_revision,omitempty"`
	Purpose        string `json:"purpose,omitempty"`
	Project        string `json:"project,omitempty"`
	EndUser        string `json:"end_user,omitempty"`
	ApprovedBy     string `json:"approved_by,omitempty"`
	HarnessVersion string `json:"harness_version,omitempty"`
	Listener       string `json:"listener,omitempty"`
	CreatedAt      string `json:"created_at"`
	IdleDeadline   string `json:"idle_deadline,omitempty"`
	MaxDeadline    string `json:"max_deadline,omitempty"`
	EndedAt        string `json:"ended_at,omitempty"`
}

func viewSession(s *session.Session) SessionView {
	return SessionView{ID: s.ID, State: s.State, EndReason: s.EndReason, PrincipalID: s.PrincipalID, Framework: s.Framework, Profile: s.Profile,
		ClientID: s.ClientID, Template: s.Template, PolicyRevision: s.PolicyRevision, Purpose: s.Purpose, Project: s.Project, EndUser: s.EndUser,
		ApprovedBy: s.ApprovedBy, HarnessVersion: s.HarnessVersion, Listener: s.Listener, CreatedAt: rfc3339(s.CreatedAt),
		IdleDeadline: rfc3339(s.IdleDeadline), MaxDeadline: rfc3339(s.MaxDeadline), EndedAt: rfc3339(s.EndedAt)}
}

func (c *Console) listSessions(w http.ResponseWriter, r *http.Request) {
	out := []SessionView{}
	for _, s := range c.d.Sessions.List() {
		out = append(out, viewSession(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (c *Console) getSession(w http.ResponseWriter, r *http.Request) {
	s := c.d.Sessions.Get(r.PathValue("id"))
	if s == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such session; ended sessions are kept for a limited time")
		return
	}
	writeJSON(w, http.StatusOK, viewSession(s))
}

// terminateSession ends an active session (FR-8.19). The operator's action
// is committed to the journal before the session ends; the session end
// itself is recorded by the edge (FR-2.11).
func (c *Console) terminateSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil || len(body.Reason) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {reason} with at most 1000 characters")
		return
	}
	id := r.PathValue("id")
	s := c.d.Sessions.Get(id)
	if s == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such session")
		return
	}
	if s.State != session.StateActive && s.State != session.StateSuspended {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": "not_active", "message": "the session has already ended"}, "state": s.State})
		return
	}
	if err := c.commit(r, "terminate_requested", "SESSION_TERMINATED_BY_OPERATOR", audit.Event{SessionID: id, PrincipalID: s.PrincipalID,
		Detail: map[string]any{"reason": body.Reason}}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the evidence journal could not record the action; the session was not ended")
		return
	}
	if !c.d.Sessions.Terminate(id) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": "not_active", "message": "the session ended before it could be terminated"}})
		return
	}
	writeJSON(w, http.StatusOK, viewSession(c.d.Sessions.Get(id)))
}

// suspendSession suspends an active session or resumes a suspended one
// (FR-2.8, FR-8.19). A suspended session's tokens are refused and its calls
// in flight are refused at the next session check; it keeps its deadlines.
// The action is committed to the journal before it takes effect.
func (c *Console) suspendSession(suspend bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &body); err != nil || len(body.Reason) > 1000 {
			writeError(w, http.StatusBadRequest, "bad_request", "body must be {reason} with at most 1000 characters")
			return
		}
		id := r.PathValue("id")
		s := c.d.Sessions.Get(id)
		if s == nil {
			writeError(w, http.StatusNotFound, "not_found", "no such session")
			return
		}
		want, outcome, reason := session.StateActive, "suspend_requested", "SESSION_SUSPENDED_BY_OPERATOR"
		if !suspend {
			want, outcome, reason = session.StateSuspended, "resume_requested", "SESSION_RESUMED_BY_OPERATOR"
		}
		if s.State != want {
			writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": "wrong_state", "message": "the session is " + s.State}, "state": s.State})
			return
		}
		if err := c.commit(r, outcome, reason, audit.Event{SessionID: id, PrincipalID: s.PrincipalID, Detail: map[string]any{"reason": body.Reason}}); err != nil {
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the evidence journal could not record the action; the session was not changed")
			return
		}
		ok := c.d.Sessions.Resume(id)
		if suspend {
			ok = c.d.Sessions.Suspend(id)
		}
		if !ok {
			cur := c.d.Sessions.Get(id)
			st := ""
			if cur != nil {
				st = cur.State
			}
			writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": "wrong_state", "message": "the session changed state before the action applied"}, "state": st})
			return
		}
		writeJSON(w, http.StatusOK, viewSession(c.d.Sessions.Get(id)))
	}
}

// principals lists the configured framework principals, their OAuth
// clients and the Session Approver accounts (usernames only).
func (c *Console) principals(w http.ResponseWriter, r *http.Request) {
	active := map[string]int{}
	for _, s := range c.d.Sessions.Active() {
		active[s.PrincipalID]++
	}
	type principal struct {
		ID             string `json:"id"`
		Framework      string `json:"framework"`
		DisplayName    string `json:"display_name,omitempty"`
		Profile        string `json:"profile"`
		Enabled        bool   `json:"enabled"`
		ActiveSessions int    `json:"active_sessions"`
	}
	type client struct {
		ClientID     string   `json:"client_id"`
		Principal    string   `json:"principal"`
		Confidential bool     `json:"confidential"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	type approver struct {
		Username string `json:"username"`
	}
	ps, cs, as := []principal{}, []client{}, []approver{}
	for _, p := range c.d.Config.Principals {
		ps = append(ps, principal{ID: p.ID, Framework: p.Framework, DisplayName: p.DisplayName, Profile: p.Profile,
			Enabled: p.Enabled == nil || *p.Enabled, ActiveSessions: active[p.ID]})
	}
	for _, cl := range c.d.Config.Clients {
		uris := append([]string{}, cl.RedirectURIs...)
		cs = append(cs, client{ClientID: cl.ClientID, Principal: cl.Principal, Confidential: cl.ClientSecretHash != "", RedirectURIs: uris})
	}
	for _, a := range c.d.Config.SessionApprovers() {
		as = append(as, approver{a.Username})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{"principals": ps, "clients": cs, "session_approvers": as})
}
