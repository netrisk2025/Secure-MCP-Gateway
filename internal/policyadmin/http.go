package policyadmin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
)

// Register adds the /api/v1/policy* routes to the control API. They use the
// control API's authentication, origin and content-type checks; see
// docs/api/policy.md for the request and response bodies.
func (s *Service) Register(srv *adminapi.Server) {
	srv.Handle("GET /api/v1/policy", s.httpStatus)
	srv.Handle("GET /api/v1/policy/revisions", s.httpList)
	srv.Handle("GET /api/v1/policy/revisions/{id}", s.httpGet)
	srv.Handle("GET /api/v1/policy/revisions/{id}/permissions", s.httpPermissions)
	srv.Handle("POST /api/v1/policy/revisions", s.httpPublish)
	srv.Handle("POST /api/v1/policy/validate", s.httpValidate)
	srv.Handle("POST /api/v1/policy/diff", s.httpDiff)
	srv.Handle("POST /api/v1/policy/simulate", s.httpSimulate)
	srv.Handle("POST /api/v1/policy/rollback", s.httpRollback)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// writeErr maps service errors to status codes and error codes.
func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "policy_invalid", err.Error())
	case errors.Is(err, policystore.ErrRevisionExists):
		writeError(w, http.StatusConflict, "revision_exists", err.Error())
	case errors.Is(err, ErrPublished):
		writeError(w, http.StatusConflict, "revision_published", err.Error())
	case errors.Is(err, ErrParentMismatch):
		writeError(w, http.StatusConflict, "parent_mismatch", err.Error())
	case errors.Is(err, policystore.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, policystore.ErrIntegrity):
		writeError(w, http.StatusUnprocessableEntity, "policy_signature", err.Error())
	case errors.Is(err, policy.ErrNoFixtures):
		writeError(w, http.StatusUnprocessableEntity, "no_fixtures", err.Error())
	case errors.Is(err, ErrAudit):
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
	case errors.Is(err, ErrActivation):
		writeError(w, http.StatusServiceUnavailable, "activation_failed", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func present(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

func (s *Service) activeRecord() (*policystore.Record, error) {
	rev, _, err := s.o.Store.Active()
	if err != nil {
		return nil, err
	}
	return &rev.Record, nil
}

// GET /api/v1/policy
func (s *Service) httpStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"fault": s.Fault(), "key_id": s.o.Store.KeyID(), "revisions": len(s.o.Store.List()),
		"schema_version": policy.SchemaVersion, "evaluator_version": policy.EvaluatorVersion}
	if d := s.o.Store.Damaged(); len(d) > 0 {
		out["damaged"] = d
	}
	if rec, err := s.activeRecord(); err == nil {
		out["active"] = rec
	} else {
		out["active_error"] = err.Error()
	}
	if snap := s.o.Active(); snap != nil {
		out["loaded_revision"] = snap.Revision
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/policy/revisions
func (s *Service) httpList(w http.ResponseWriter, r *http.Request) {
	active := ""
	if snap := s.o.Active(); snap != nil {
		active = snap.Revision
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": active, "revisions": s.o.Store.List()})
}

// GET /api/v1/policy/revisions/{id}
func (s *Service) httpGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "active" {
		if snap := s.o.Active(); snap != nil {
			id = snap.Revision
		}
	}
	rev, err := s.o.Store.Get(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	active := false
	if snap := s.o.Active(); snap != nil {
		active = snap.Revision == rev.Record.Revision
	}
	writeJSON(w, http.StatusOK, map[string]any{"record": rev.Record, "active": active, "document": json.RawMessage(rev.Snapshot.Raw)})
}

// Permission is one entry of the effective permission report.
type Permission struct {
	Server          string   `json:"server"`
	Tool            string   `json:"tool"`
	Rule            string   `json:"rule"`
	Approval        bool     `json:"approval"`
	CallsPerMinute  int      `json:"calls_per_minute,omitempty"`
	CallsPerSession int      `json:"calls_per_session,omitempty"`
	SideEffect      string   `json:"side_effect,omitempty"`
	SourceTrust     string   `json:"source_trust,omitempty"`
	Filters         []string `json:"filters,omitempty"`
	// EgressLimits bound each egress operation of the permitted calls
	// (FR-5.38).
	EgressLimits *policy.EgressLimits `json:"egress_limits,omitempty"`
	// Constraints are the rule's argument predicates (FR-3.6): the call
	// is permitted only when every one holds.
	Constraints []policy.Predicate `json:"constraints,omitempty"`
}

// Permissions lists what a template of snap permits after deny rules, with
// each grant's argument constraints (FR-3.6).
func Permissions(snap *policy.Snapshot, template string) []Permission {
	out := []Permission{}
	for _, g := range snap.Grants(template) {
		approval := g.Rule.Approval
		for _, p := range g.Rule.When {
			if p.Op == policy.OpApproval {
				approval = true
			}
		}
		out = append(out, Permission{Server: g.Server, Tool: g.Tool, Rule: g.Rule.ID, Approval: approval, CallsPerMinute: g.Rule.CallsPerMinute,
			CallsPerSession: g.Rule.CallsPerSession, SideEffect: g.Rule.SideEffect, SourceTrust: g.Rule.SourceTrust, Filters: g.Rule.Filters,
			EgressLimits: g.Rule.EgressLimits, Constraints: g.Rule.When})
	}
	return out
}

// PermissionReport is the effective permission report of a template: its
// grants and, when secretBindings is set, the Secret Use Policy bindings of
// the servers the template grants (FR-6.5).
func PermissionReport(snap *policy.Snapshot, template string, secretBindings func(servers []string) any) map[string]any {
	perms := Permissions(snap, template)
	out := map[string]any{"permissions": perms}
	if secretBindings != nil {
		seen := map[string]bool{}
		var servers []string
		for _, p := range perms {
			if !seen[p.Server] {
				seen[p.Server] = true
				servers = append(servers, p.Server)
			}
		}
		out["secret_bindings"] = secretBindings(servers)
	}
	return out
}

// GET /api/v1/policy/revisions/{id}/permissions?template=T[&principal=P]
func (s *Service) httpPermissions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "active" {
		if snap := s.o.Active(); snap != nil {
			id = snap.Revision
		}
	}
	rev, err := s.o.Store.Get(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	tmpl := r.URL.Query().Get("template")
	if !rev.Snapshot.HasTemplate(tmpl) {
		writeError(w, http.StatusNotFound, "no_template", "the revision has no template "+strconv.Quote(tmpl))
		return
	}
	out := PermissionReport(rev.Snapshot, tmpl, s.o.SecretBindings)
	out["revision"], out["template"], out["principal"] = rev.Record.Revision, tmpl, r.URL.Query().Get("principal")
	writeJSON(w, http.StatusOK, out)
}

type publishBody struct {
	Document      json.RawMessage `json:"document"`
	Parent        string          `json:"parent"`
	SimulationRef string          `json:"simulation_ref"`
}

// POST /api/v1/policy/revisions
func (s *Service) httpPublish(w http.ResponseWriter, r *http.Request) {
	var b publishBody
	if err := decode(r, &b); err != nil || !present(b.Document) {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {document, parent?, simulation_ref?}")
		return
	}
	res, err := s.Publish(b.Document, PublishOptions{Actor: adminapi.ActorOf(r), Parent: b.Parent, SimulationRef: b.SimulationRef})
	if err != nil {
		writeErr(w, err)
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, res)
}

// POST /api/v1/policy/rollback
func (s *Service) httpRollback(w http.ResponseWriter, r *http.Request) {
	var b struct {
		To       string `json:"to"`
		Revision string `json:"revision"`
	}
	if err := decode(r, &b); err != nil || b.To == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {to, revision?}")
		return
	}
	res, err := s.Rollback(b.To, b.Revision, adminapi.ActorOf(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

// POST /api/v1/policy/validate
func (s *Service) httpValidate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Document json.RawMessage `json:"document"`
	}
	if err := decode(r, &b); err != nil || !present(b.Document) {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {document}")
		return
	}
	_, sum, err := Summarize(b.Document)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "summary": sum})
}

// POST /api/v1/policy/diff
func (s *Service) httpDiff(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Document json.RawMessage `json:"document"`
		From     string          `json:"from"`
		To       string          `json:"to"`
	}
	if err := decode(r, &b); err != nil || (present(b.Document) && b.To != "") || (!present(b.Document) && b.To == "") {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {document, from?} or {from?, to}")
		return
	}
	from := s.o.Active()
	if b.From != "" {
		rev, err := s.o.Store.Get(b.From)
		if err != nil {
			writeErr(w, err)
			return
		}
		from = rev.Snapshot
	}
	var to *policy.Snapshot
	if present(b.Document) {
		snap, err := policy.Compile(b.Document)
		if err != nil {
			writeErr(w, errors.Join(ErrInvalid, err))
			return
		}
		to = snap
	} else {
		rev, err := s.o.Store.Get(b.To)
		if err != nil {
			writeErr(w, err)
			return
		}
		to = rev.Snapshot
	}
	writeJSON(w, http.StatusOK, policy.Diff(from, to))
}

// POST /api/v1/policy/simulate
func (s *Service) httpSimulate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Document json.RawMessage  `json:"document"`
		Fixtures []policy.Fixture `json:"fixtures"`
		Limit    int              `json:"limit"`
		All      bool             `json:"all"`
	}
	if err := decode(r, &b); err != nil || !present(b.Document) {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {document, fixtures?, limit?, all?}")
		return
	}
	if b.Fixtures != nil && len(b.Fixtures) == 0 {
		writeErr(w, policy.ErrNoFixtures)
		return
	}
	res, err := s.Simulate(b.Document, b.Fixtures, b.Limit, b.All, adminapi.ActorOf(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
