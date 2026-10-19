package graph

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Register adds the /api/v1/graph* routes to the control API. They take
// the Administrator role and the control API's authentication, origin and
// content-type checks. See docs/api/graph.md.
func (m *Mirror) Register(a *adminapi.Server) {
	a.Handle("GET /api/v1/graph/status", m.httpStatus)
	a.Handle("POST /api/v1/graph/rebuild", m.httpRebuild)
	a.Handle("GET /api/v1/graph/neighborhood", m.httpNeighborhood)
	a.Handle("GET /api/v1/graph/events/{id}/path", m.httpEventPath)
	a.Handle("GET /api/v1/graph/queries", m.httpQueries)
	a.Handle("GET /api/v1/graph/queries/{name}", m.httpQuery)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// writeGraphError maps service errors to control API errors.
func writeGraphError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrDisabled):
		writeError(w, http.StatusServiceUnavailable, "graph_disabled", "the graph mirror is disabled ([graph] enabled = false)")
	case errors.Is(err, ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "graph_unavailable", "the graph database is unavailable; enforcement is not affected")
	case errors.Is(err, ErrBadParameter):
		writeError(w, http.StatusBadRequest, "invalid_parameter", err.Error())
	case errors.Is(err, ErrUnknownOp):
		writeError(w, http.StatusNotFound, "unknown_query", err.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such node in the graph mirror")
	case errors.Is(err, ErrRebuildRunning):
		writeError(w, http.StatusConflict, "rebuild_queued", "a rebuild is already queued")
	default:
		writeError(w, http.StatusBadGateway, "graph_error", "graph query failed")
	}
}

func limitParam(r *http.Request) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return DefaultLimit, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > MaxLimit {
		return 0, ErrBadParameter
	}
	return n, nil
}

func (m *Mirror) httpStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.Status(r.Context(), r.URL.Query().Get("detail") != "0"))
}

func (m *Mirror) httpRebuild(w http.ResponseWriter, r *http.Request) {
	if _, err := m.DAS(); err != nil {
		writeGraphError(w, err)
		return
	}
	if rec := m.recorder(); rec != nil {
		if err := rec.Commit(audit.Event{Class: "admin", Origin: "E-26", Outcome: "requested", ReasonCode: "GRAPH_REBUILD", PolicyStatus: "not_evaluated",
			Detail: map[string]any{"actor": adminapi.ActorOf(r)}}); err != nil {
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "evidence journal unavailable")
			return
		}
	}
	if err := m.RequestRebuild(); err != nil {
		writeGraphError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "queued"})
}

func (m *Mirror) httpNeighborhood(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_parameter", "limit must be 1..500")
		return
	}
	label, id := q.Get("label"), q.Get("id")
	if !contains(NeighborhoodLabels, label) {
		writeError(w, http.StatusBadRequest, "invalid_label", "label must be one of the neighborhood labels")
		return
	}
	if id == "" || len(id) > MaxStringParam {
		writeError(w, http.StatusBadRequest, "invalid_parameter", "id is required")
		return
	}
	das, err := m.DAS()
	if err != nil {
		writeGraphError(w, err)
		return
	}
	nb, err := das.Neighborhood(r.Context(), label, id, limit)
	if err != nil {
		writeGraphError(w, m.noteErr(err))
		return
	}
	writeJSON(w, http.StatusOK, nb)
}

func (m *Mirror) httpEventPath(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_parameter", "limit must be 1..500")
		return
	}
	das, err := m.DAS()
	if err != nil {
		writeGraphError(w, err)
		return
	}
	p, err := das.EventPath(r.Context(), r.PathValue("id"), limit)
	if err != nil {
		writeGraphError(w, m.noteErr(err))
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (m *Mirror) httpQueries(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"queries": CannedQueries})
}

func (m *Mirror) httpQuery(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_parameter", "limit must be 1..500")
		return
	}
	params := map[string]string{}
	for k, v := range r.URL.Query() {
		if k == "limit" {
			continue
		}
		if len(v) != 1 {
			writeError(w, http.StatusBadRequest, "invalid_parameter", "each parameter must appear once")
			return
		}
		params[k] = v[0]
	}
	das, err := m.DAS()
	if err != nil {
		writeGraphError(w, err)
		return
	}
	name := r.PathValue("name")
	rows, err := das.Query(r.Context(), name, params, limit)
	if err != nil {
		writeGraphError(w, m.noteErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": name, "limit": limit, "rows": rows})
}

// noteErr logs unexpected query failures.
func (m *Mirror) noteErr(err error) error {
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrBadParameter) && !errors.Is(err, ErrUnknownOp) {
		m.log.Warn("graph query failed", "err", err)
	}
	return err
}
