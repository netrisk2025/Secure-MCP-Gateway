package secrets

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Handler registers authenticated control API routes;
// *adminapi.Server implements it.
type Handler interface {
	Handle(pattern string, h http.HandlerFunc)
}

// RegisterRoutes adds the /api/v1/secrets routes (docs/api/secrets.md).
// Every read returns metadata only (FR-6.2); values are accepted on create
// and rotate and never returned.
func (s *Service) RegisterRoutes(h Handler) {
	h.Handle("GET /api/v1/secrets", s.list)
	h.Handle("POST /api/v1/secrets", s.create)
	h.Handle("POST /api/v1/secrets/reload", s.reload)
	h.Handle("GET /api/v1/secrets/{name}", s.get)
	h.Handle("DELETE /api/v1/secrets/{name}", s.remove)
	h.Handle("POST /api/v1/secrets/{name}/rotate", s.rotate)
	h.Handle("GET /api/v1/secrets/{name}/impact", s.impact)
	h.Handle("POST /api/v1/secrets/{name}/resume", s.resume)
	s.registerUsePolicy(h)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// vaultError maps a vault error to a response. Vault error texts never
// contain a value.
func vaultError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "secret_not_found", err.Error())
	case errors.Is(err, ErrExists):
		writeError(w, http.StatusConflict, "secret_exists", err.Error())
	case errors.Is(err, ErrInvalidName), errors.Is(err, ErrInvalidValue), errors.Is(err, ErrInvalidType), errors.Is(err, ErrInvalidOverlap):
		writeError(w, http.StatusBadRequest, "invalid_secret", err.Error())
	case errors.Is(err, ErrNoEvidence):
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
	default:
		writeError(w, http.StatusServiceUnavailable, "vault_error", "vault operation failed")
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Status is the vault part of GET /api/v1/secrets.
type Status struct {
	VaultID      string            `json:"vault_id"`
	KeySource    string            `json:"key_source"`
	RuntimeDir   string            `json:"runtime_dir"`
	RuntimeTmpfs bool              `json:"runtime_tmpfs"`
	Overlap      string            `json:"rotation_overlap"`
	Fingerprints int               `json:"fingerprints"`
	Suspended    map[string]string `json:"suspended"`
}

func (s *Service) status() Status {
	return Status{VaultID: s.Vault.ID(), KeySource: s.Vault.KeySource(), RuntimeDir: s.Settings.RuntimeDir, RuntimeTmpfs: IsTmpfs(s.Settings.RuntimeDir),
		Overlap: s.Vault.DefaultOverlap().String(), Fingerprints: s.Broker.Fingerprints().Len(), Suspended: s.Broker.Suspended()}
}

func (s *Service) list(w http.ResponseWriter, _ *http.Request) {
	use := s.Broker.UsePolicy()
	writeJSON(w, http.StatusOK, map[string]any{
		"vault":      s.status(),
		"use_policy": map[string]any{"revision": use.Revision, "digest": use.Digest, "slots": use.Slots(), "bindings": use.Bindings()},
		"secrets":    s.Vault.List(),
	})
}

type createBody struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Owner       string  `json:"owner"`
	Description string  `json:"description"`
	Expires     string  `json:"expires"`
	Value       *string `json:"value"`
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var body createBody
	if err := decode(r, &body); err != nil || body.Value == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {name, type, owner, description, expires, value}")
		return
	}
	p := CreateParams{Name: body.Name, Type: body.Type, Owner: body.Owner, Description: body.Description, Value: []byte(*body.Value)}
	body.Value = nil
	if body.Expires != "" {
		t, err := time.Parse(time.RFC3339, body.Expires)
		if err != nil {
			wipe(p.Value)
			writeError(w, http.StatusBadRequest, "bad_request", "expires must be an RFC 3339 time")
			return
		}
		p.Expires = &t
	}
	m, err := s.Vault.Create(adminapi.Actor(r), p)
	if err != nil {
		vaultError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	m, err := s.Vault.Get(r.PathValue("name"))
	if err != nil {
		vaultError(w, err)
		return
	}
	reason, suspended := s.Broker.Suspended()[m.Ref]
	writeJSON(w, http.StatusOK, map[string]any{"secret": m, "suspended": suspended, "suspended_reason": reason})
}

func (s *Service) remove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Vault.Remove(adminapi.Actor(r), name); err != nil {
		vaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": name})
}

type rotateBody struct {
	Value   *string `json:"value"`
	Overlap string  `json:"overlap"`
}

func (s *Service) rotate(w http.ResponseWriter, r *http.Request) {
	var body rotateBody
	if err := decode(r, &body); err != nil || body.Value == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {value, overlap}")
		return
	}
	value := []byte(*body.Value)
	body.Value = nil
	overlap := time.Duration(-1)
	if body.Overlap != "" {
		d, err := time.ParseDuration(body.Overlap)
		if err != nil || d < 0 {
			wipe(value)
			writeError(w, http.StatusBadRequest, "invalid_secret", ErrInvalidOverlap.Error())
			return
		}
		overlap = d
	}
	m, err := s.Vault.Rotate(adminapi.Actor(r), r.PathValue("name"), value, overlap)
	if err != nil && m.Ref == "" {
		vaultError(w, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Service) impact(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	m, err := s.Vault.Get(name)
	if err != nil {
		vaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": name, "ref": m.Ref, "references": s.Broker.Impact(name)})
}

func (s *Service) resume(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {}")
		return
	}
	m, err := s.Vault.Get(r.PathValue("name"))
	if err != nil {
		vaultError(w, err)
		return
	}
	was := s.Broker.Unsuspend(m.Ref)
	if was {
		if err := s.Broker.commit(event{outcome: "unsuspended", secret: m.Name, ref: m.Ref, extra: map[string]any{"actor": adminapi.Actor(r)}}); err != nil {
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": m.Name, "resumed": was})
}

func (s *Service) reload(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {}")
		return
	}
	use, err := LoadUsePolicy(s.Settings.UsePolicyFile, s.cfg.Servers)
	b := s.Broker
	b.mu.Lock()
	rec := b.rec
	b.mu.Unlock()
	if err != nil {
		if rec != nil {
			_ = rec.Commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "rejected", ReasonCode: "SECRET_USE_POLICY_INVALID", PolicyStatus: "not_evaluated",
				Detail: map[string]any{"actor": adminapi.Actor(r), "error": err.Error()}})
		}
		writeError(w, http.StatusUnprocessableEntity, "use_policy_invalid", err.Error())
		return
	}
	if rec == nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", ErrNoEvidence.Error())
		return
	}
	if err := rec.Commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "activated", ReasonCode: "SECRET_USE_POLICY_ACTIVATED", PolicyRevision: use.Revision,
		PolicyStatus: "not_evaluated", Detail: map[string]any{"actor": adminapi.Actor(r), "digest": use.Digest, "bindings": len(use.bindings)}}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
		return
	}
	b.SetUsePolicy(use)
	writeJSON(w, http.StatusOK, map[string]any{"revision": use.Revision, "digest": use.Digest, "bindings": len(use.bindings)})
}
