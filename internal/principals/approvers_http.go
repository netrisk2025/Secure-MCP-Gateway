package principals

import (
	"net/http"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
)

func (s *Service) listApprovers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"approvers": s.Dir.ListApprovers()})
}

// createApprover is FR-2.23: the Administrator creates a Session Approver
// whose password differs from the Administrator's. The password is never
// recorded or returned.
func (s *Service) createApprover(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {username, password}")
		return
	}
	// Validate before recording, so that refused requests leave no event.
	if err := s.Dir.CheckApprover(body.Username, body.Password, s.AdminHash()); err != nil {
		mutationError(w, err)
		return
	}
	if !s.commit(w, r, "session_approver_created", "SESSION_APPROVER_CREATED", "", map[string]any{"username": body.Username}) {
		return
	}
	v, err := s.Dir.AddApprover(body.Username, body.Password, s.AdminHash(), adminapi.ActorOf(r))
	if err != nil {
		mutationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// removeApprover deletes a Session Approver of the directory and ends its
// console sessions. Harness sessions it approved earlier are not affected.
func (s *Service) removeApprover(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil || len(body.Reason) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {reason} with at most 1000 characters")
		return
	}
	u := r.PathValue("username")
	if !s.Dir.hasApprover(u) {
		mutationError(w, s.Dir.RemoveApprover(u)) // explains file and unknown accounts
		return
	}
	if !s.commit(w, r, "session_approver_removed", "SESSION_APPROVER_REMOVED", "", map[string]any{"username": u, "reason": body.Reason}) {
		return
	}
	if err := s.Dir.RemoveApprover(u); err != nil {
		mutationError(w, err)
		return
	}
	ended := 0
	if s.EndSessions != nil {
		ended = s.EndSessions(adminapi.RoleSessionApprover + ":" + u)
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": u, "removed": true, "ended_console_sessions": ended})
}
