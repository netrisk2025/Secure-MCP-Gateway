package obspolicy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Service serves the object routes:
//
//	GET  /api/v1/observations/objects                 every kind: active revision, revision in force, pending; effective settings
//	GET  /api/v1/observations/objects/{kind}          revisions of one kind, newest first
//	POST /api/v1/observations/audit-profile           {body: AuditProfile, reason}       (G-03)
//	POST /api/v1/observations/observation-policy      {body: ObservationPolicy, reason}  (G-04)
//	POST /api/v1/observations/anomaly-response        {body: AnomalyResponse, reason}    (G-06)
//	POST /api/v1/observations/memory-budget           {body: MemoryBudget, reason}       (G-08)
//
// A publication is committed to the journal (class admin, reason code
// OBSERVATION_OBJECT_PUBLISHED, with kind, revision and digest) before it is
// stored; a journal failure refuses it.
type Service struct {
	Store    *Store
	Evidence audit.Recorder
}

// Register adds the routes. Who may publish each kind is the Appendix C
// matrix (adminapi/rolematrix.go).
func (s *Service) Register(a *adminapi.Server) {
	a.Handle("GET /api/v1/observations/objects", s.status)
	a.Handle("GET /api/v1/observations/objects/{kind}", s.revisions)
	a.Handle("POST /api/v1/observations/audit-profile", s.publish(KindAuditProfile))
	a.Handle("POST /api/v1/observations/observation-policy", s.publish(KindObservationPolicy))
	a.Handle("POST /api/v1/observations/anomaly-response", s.publish(KindAnomalyResponse))
	a.Handle("POST /api/v1/observations/memory-budget", s.publish(KindMemoryBudget))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// applies says when a publication takes effect.
func (s *Service) applies() string {
	if live, _ := s.Store.Live(); live {
		return "at once, except the settings an object lists in restart_required, which apply at the next start of smcpd"
	}
	return "at the next start of smcpd"
}

func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	objs, eff, err := s.Store.Status()
	out := map[string]any{"objects": objs, "applies": s.applies()}
	if _, aerr := s.Store.Live(); aerr != nil {
		out["apply_error"] = aerr.Error()
	}
	if err != nil {
		out["effective_error"] = err.Error()
	} else {
		out["effective"] = map[string]any{
			"policy_id": eff.PolicyID, "parameters": eff.Parameters, "escalation_parameters": eff.EscalationParameters,
			"sampling_rate": eff.SamplingRate, "retention": eff.Retention.String(), "scoring": eff.Scoring,
			"require_approval_band": eff.RequireApprovalBand, "withhold_band": eff.WithholdBand,
			"escalate_capture_band": eff.EscalateCaptureBand, "uncharacterized": eff.UncharacterizedAction,
			"escalation_bands": eff.EscalationBands, "features": eff.Baseline.Features, "scope": eff.Scope,
			"memory_limit_bytes": eff.MemoryLimitBytes, "contexts": eff.Baseline.Contexts, "bands": eff.Baseline.Bands,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) revisions(w http.ResponseWriter, r *http.Request) {
	revs, err := s.Store.Revisions(r.PathValue("kind"))
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown_kind", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kind": r.PathValue("kind"), "revisions": revs})
}

func (s *Service) publish(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "unreadable body")
			return
		}
		var req struct {
			Body   json.RawMessage `json:"body"`
			Reason string          `json:"reason"`
		}
		if err := json.Unmarshal(raw, &req); err != nil || len(req.Body) == 0 || len(req.Reason) > 1000 {
			writeError(w, http.StatusBadRequest, "bad_request", "body must be {body, reason} with a reason of at most 1000 characters")
			return
		}
		if err := s.Store.Validate(kind, req.Body); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
			return
		}
		actor := adminapi.ActorOf(r)
		if err := s.Evidence.Commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: "publish_requested", ReasonCode: "OBSERVATION_OBJECT_PUBLISHED", PolicyStatus: "not_evaluated",
			Detail: map[string]any{"actor": actor, "kind": kind, "reason": req.Reason}}); err != nil {
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the evidence journal could not record the publication; nothing was published")
			return
		}
		rev, err := s.Store.Publish(kind, req.Body, actor, req.Reason)
		switch {
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		case err != nil:
			writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		default:
			out := map[string]any{"revision": rev, "applies": s.applies()}
			if _, aerr := s.Store.Live(); aerr != nil {
				out["apply_error"] = aerr.Error()
			}
			writeJSON(w, http.StatusCreated, out)
		}
	}
}
