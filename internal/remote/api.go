package remote

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
)

// Register adds the /api/v1/remote* and /api/v1/clients* routes to the
// control API. All of them are Administrator-only (adminapi.Handle); see
// docs/api/remote.md.
func (s *Service) Register(a *adminapi.Server) {
	a.Handle("GET /api/v1/remote", s.apiStatus)
	a.Handle("POST /api/v1/remote/enable", s.apiEnable)
	a.Handle("POST /api/v1/remote/disable", s.apiDisable)
	a.Handle("GET /api/v1/clients", s.apiClients)
	a.Handle("GET /api/v1/clients/{id}", s.apiClient)
	a.Handle("POST /api/v1/clients/{id}/approve", s.apiDecide(StatusApproved))
	a.Handle("POST /api/v1/clients/{id}/deny", s.apiDecide(StatusDenied))
	a.Handle("POST /api/v1/clients/{id}/revoke", s.apiDecide(StatusRevoked))
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func decodeBody(r *http.Request, v any) error {
	err := json.NewDecoder(r.Body).Decode(v)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (s *Service) apiStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Status())
}

func (s *Service) apiEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PublicURL string `json:"public_url"`
		Provider  string `json:"provider"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "body must be JSON")
		return
	}
	st, err := s.Enable(adminapi.ActorOf(r), body.PublicURL, body.Provider)
	switch {
	case errors.Is(err, ErrBadRequest):
		apiError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, ErrAuditUnavailable):
		apiError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
	case err != nil:
		apiError(w, http.StatusInternalServerError, "remote_listener", err.Error())
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Service) apiDisable(w http.ResponseWriter, r *http.Request) {
	st, err := s.Disable(adminapi.ActorOf(r))
	if errors.Is(err, ErrAuditUnavailable) {
		apiError(w, http.StatusServiceUnavailable, "audit_unavailable", "remote access is disabled, but "+err.Error())
		return
	}
	if err != nil {
		apiError(w, http.StatusInternalServerError, "state", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// staticView describes a pre-registered client allowed on the remote
// listener.
func (s *Service) staticView(id string) map[string]any {
	c := s.cfg.FindClient(id)
	if c == nil {
		return nil
	}
	return map[string]any{"client_id": c.ClientID, "status": StatusApproved, "principal": c.Principal, "redirect_uris": c.RedirectURIs,
		"registration": "pre-registered", "token_endpoint_auth_method": map[bool]string{true: "client_secret_basic", false: "none"}[c.ClientSecretHash != ""]}
}

func (s *Service) apiClients(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	out := []map[string]any{}
	for _, g := range s.reg.list() {
		if status == "" || g.Status == status {
			out = append(out, g.View())
		}
	}
	if status == "" || status == StatusApproved {
		for _, id := range s.cfg.Remote.Clients {
			if v := s.staticView(id); v != nil {
				out = append(out, v)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *Service) apiClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if g, ok := s.reg.get(id); ok {
		writeJSON(w, http.StatusOK, g.View())
		return
	}
	if slices.Contains(s.cfg.Remote.Clients, id) {
		if v := s.staticView(id); v != nil {
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	apiError(w, http.StatusNotFound, "not_found", "no such remote client")
}

// apiDecide approves, denies or revokes a dynamic registration. Approval
// binds the client to one principal (FR-2.18); revocation ends the
// client's remote sessions.
func (s *Service) apiDecide(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Principal string `json:"principal"`
			Comment   string `json:"comment"`
		}
		if err := decodeBody(r, &body); err != nil {
			apiError(w, http.StatusBadRequest, "bad_request", "body must be JSON")
			return
		}
		id := r.PathValue("id")
		if status == StatusApproved {
			if body.Principal == "" {
				body.Principal = s.cfg.Remote.DefaultPrincipal
			}
			if body.Principal == "" {
				apiError(w, http.StatusBadRequest, "principal_required", "name the principal to bind the client to (or set remote.default_principal)")
				return
			}
			if p := s.cfg.FindPrincipal(body.Principal); p == nil || p.Enabled == nil || !*p.Enabled {
				apiError(w, http.StatusBadRequest, "unknown_principal", "unknown or disabled principal "+body.Principal)
				return
			}
		}
		if _, ok := s.reg.get(id); !ok {
			apiError(w, http.StatusNotFound, "not_found", "no such dynamic registration")
			return
		}
		actor := adminapi.ActorOf(r)
		if err := s.rec.Commit(audit.Event{Class: "client_registration", Origin: "E-24", Outcome: status, ReasonCode: "DCR_" + map[string]string{
			StatusApproved: "APPROVED", StatusDenied: "DENIED", StatusRevoked: "REVOKED"}[status], ClientID: id, PolicyStatus: "not_evaluated",
			Detail: map[string]any{"actor": actor, "principal": body.Principal, "comment": boundText(body.Comment, 512)}}); err != nil {
			apiError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
			return
		}
		g, err := s.reg.decide(id, status, body.Principal, actor, s.now())
		switch {
		case errors.Is(err, errWrongStatus):
			apiError(w, http.StatusConflict, "wrong_status", "registration is "+g.Status)
			return
		case err != nil:
			apiError(w, http.StatusInternalServerError, "state", err.Error())
			return
		}
		if status == StatusRevoked {
			for _, se := range s.store.Active() {
				if se.ClientID == id && se.Listener == channel.Remote {
					s.store.Terminate(se.ID)
				}
			}
		}
		writeJSON(w, http.StatusOK, g.View())
	}
}
