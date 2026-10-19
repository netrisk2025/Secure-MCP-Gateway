package analytics

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/research"
)

// Register adds the control API routes (docs/api/observation.md). Every
// route is Administrator-only and goes through the control API's
// authentication, origin and content-type checks.
func (s *Service) Register(a *adminapi.Server) {
	a.Handle("GET /api/v1/observations/status", s.status)
	a.Handle("GET /api/v1/observations/parameters", s.parameters)
	a.Handle("GET /api/v1/observations", s.needStore(s.listRecords))
	a.Handle("GET /api/v1/observations/aggregate", s.needStore(s.aggregate))
	a.Handle("GET /api/v1/observations/metrics", s.needStore(s.metrics))
	a.Handle("GET /api/v1/observations/cost", s.needStore(s.cost))
	a.Handle("POST /api/v1/observations/purge", s.needStore(s.purge))
	a.Handle("GET /api/v1/baselines", s.enabled(s.baselines))
	a.Handle("POST /api/v1/baselines/snapshots", s.enabled(s.buildSnapshot))
	a.Handle("POST /api/v1/baselines/flags", s.enabled(s.flag))
	a.Handle("GET /api/v1/baselines/{id}", s.enabled(s.snapshot))
	a.Handle("GET /api/v1/baselines/{id}/drift", s.enabled(s.drift))
	a.Handle("POST /api/v1/baselines/{id}/promote", s.enabled(s.promote))
	a.Handle("GET /api/v1/anomalies", s.needStore(s.anomalies))
	a.Handle("GET /api/v1/research/campaigns", s.enabled(s.listCampaigns))
	a.Handle("POST /api/v1/research/campaigns", s.enabled(s.createCampaign))
	a.Handle("GET /api/v1/research/campaigns/{id}", s.enabled(s.getCampaign))
	a.Handle("POST /api/v1/research/campaigns/{id}/{action}", s.enabled(s.actCampaign))
	a.Handle("GET /api/v1/research/exports", s.needStore(s.listExports))
	a.Handle("POST /api/v1/research/exports", s.needStore(s.export))
	a.Handle("GET /api/v1/research/exports/{id}", s.needStore(s.getExport))
	a.Handle("GET /api/v1/research/exports/{id}/files/{name}", s.needStore(s.download))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (s *Service) enabled(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Disabled() {
			writeError(w, http.StatusServiceUnavailable, "observation_disabled", "observation is disabled ([observation] enabled = false)")
			return
		}
		h(w, r)
	}
}

func (s *Service) needStore(h http.HandlerFunc) http.HandlerFunc {
	return s.enabled(func(w http.ResponseWriter, r *http.Request) {
		if s.Store == nil {
			msg := "observation store unavailable"
			if s.storeErr != nil {
				msg += ": " + s.storeErr.Error()
			}
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", msg)
			return
		}
		h(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// commit records an operator action durably; on failure the action is
// reported as failed (the control API never acts without evidence).
func (s *Service) commit(w http.ResponseWriter, ev audit.Event) bool {
	rec := s.recorder()
	if rec == nil {
		return true
	}
	if ev.PolicyStatus == "" {
		ev.PolicyStatus = "not_evaluated"
	}
	if err := rec.Commit(ev); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the action could not be recorded")
		return false
	}
	return true
}

func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	if s.Disabled() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	out := map[string]any{"enabled": true, "policy_id": s.cur().PolicyID, "catalog_version": s.Catalog.Version,
		"scoring": s.cur().Scoring, "require_approval_band": s.cur().RequireApproval, "withhold_band": s.cur().Withhold,
		"escalate_capture_band": s.S.EscalateCapture, "uncharacterized": s.S.Uncharacterized, "escalation_bands": s.S.EscalationByBand, "scope": s.S.Scope,
		"sampling_rate": s.cur().SamplingRate, "parameters": s.Collector.SelectedParameters(), "escalation_parameters": s.cur().Escalation,
		"retention": s.cur().Retention.String(), "collector": s.Collector.Stats(), "drops": s.Drops(),
		"baseline": s.Baselines.LifecycleStatus(), "loaded_snapshot": s.Scorer.SnapshotID(), "thresholds": s.Scorer.Thresholds(),
		"contexts": s.S.Baseline.Dimensions, "features": s.S.Baseline.Features, "duckdb_available": obsstore.DuckDBAvailable(),
		"degradation": map[string]any{"stage": s.degrade.Stage(), "name": StageNames[s.degrade.Stage()], "reason": s.degrade.Reason(),
			"backpressure": s.writer.underPressure()}}
	if s.Store != nil {
		if st, err := s.Store.Stats(); err == nil {
			out["store"] = st
		}
	} else if s.storeErr != nil {
		out["store_error"] = s.storeErr.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) parameters(w http.ResponseWriter, r *http.Request) {
	esc := map[string]bool{}
	for _, p := range s.cur().Escalation {
		esc[p] = true
	}
	var out []map[string]any
	for _, p := range s.Catalog.Params {
		sel := false
		if !s.Disabled() {
			sel = s.Collector.Selected(p.Name)
		}
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "description": p.Description, "unit": p.Unit, "data_type": p.DataType,
			"sensitivity": p.Sensitivity, "capture_point": p.CapturePoint, "baselinable": p.Baselinable, "selected": sel, "escalation": esc[p.Name],
			"cost_class": p.CostClass, "derivation": p.Derivation, "source_element": p.SourceElement})
	}
	writeJSON(w, http.StatusOK, map[string]any{"catalog_version": s.Catalog.Version, "parameters": out})
}

// filterFrom parses from, to (RFC 3339 or a duration back from now, e.g.
// "24h"), principal, server, tool, session and limit.
func (s *Service) filterFrom(r *http.Request, defLimit, maxLimit int) (obsstore.Filter, error) {
	q := r.URL.Query()
	f := obsstore.Filter{Equals: map[string][]string{}}
	var err error
	if f.From, err = parseWhen(q.Get("from"), s.now()); err != nil {
		return f, errors.New("from: " + err.Error())
	}
	if f.To, err = parseWhen(q.Get("to"), s.now()); err != nil {
		return f, errors.New("to: " + err.Error())
	}
	for param, col := range map[string]string{"principal": "principal_id", "server": "server_id", "tool": "tool_name", "session": "session_id", "band": "band"} {
		if v := q[param]; len(v) > 0 {
			f.Equals[col] = v
		}
	}
	f.Limit = defLimit
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > maxLimit {
			return f, errors.New("limit must be 1 to " + strconv.Itoa(maxLimit))
		}
		f.Limit = n
	}
	return f, nil
}

func parseWhen(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

// visible reports whether a console user of role may see a field of
// sensitivity sens (Appendix C, SR-6-3): S0 and S1 every role that reaches
// the route; S2 the Administrator, Policy Author and Auditor (a Researcher
// sees S2 values only pseudonymized, in campaign exports); S3 nobody,
// because payload access needs a separate grant that release 1.0 does not
// issue.
func visible(role, sens string) bool {
	switch sens {
	case "S2":
		return role == adminapi.RoleAdministrator || role == adminapi.RolePolicyAuthor || role == adminapi.RoleAuditor
	case "S3":
		return false
	}
	return true
}

// sensitivity is the catalog sensitivity of a stored column; columns that
// are not catalog parameters (timestamps, IDs, bands) are "".
func (s *Service) sensitivity(col string) string {
	if s.Catalog == nil {
		return ""
	}
	if p, ok := s.Catalog.Lookup(col); ok {
		return p.Sensitivity
	}
	return ""
}

// redact removes the columns of row that role may not see.
func (s *Service) redact(role string, row obsstore.Row) obsstore.Row {
	for col := range row {
		if !visible(role, s.sensitivity(col)) {
			delete(row, col)
		}
	}
	return row
}

func (s *Service) scan(w http.ResponseWriter, r *http.Request, table string, f obsstore.Filter) {
	if table != "scores" {
		delete(f.Equals, "band")
	}
	role := adminapi.RoleOf(r)
	rows := []obsstore.Row{}
	err := s.Store.Scan(table, f, func(row obsstore.Row) error { rows = append(rows, s.redact(role, row)); return nil })
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "count": len(rows)})
}

func (s *Service) listRecords(w http.ResponseWriter, r *http.Request) {
	f, err := s.filterFrom(r, 100, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	s.scan(w, r, "records", f)
}

func (s *Service) metrics(w http.ResponseWriter, r *http.Request) {
	f, err := s.filterFrom(r, 360, 10000)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	f.Equals = nil
	s.scan(w, r, "metrics", f)
}

func (s *Service) anomalies(w http.ResponseWriter, r *http.Request) {
	f, err := s.filterFrom(r, 100, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if _, ok := f.Equals["band"]; !ok {
		f.Equals["band"] = []string{anomaly.Elevated, anomaly.Abnormal, anomaly.Critical}
	}
	delete(f.Equals, "server_id")
	s.scan(w, r, "scores", f)
}

func floats(s string) ([]float64, error) {
	if s == "" {
		return nil, nil
	}
	var out []float64
	for _, p := range strings.Split(s, ",") {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) aggregate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f, err := s.filterFrom(r, 0, 1)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	f.Limit = 0
	aq := obsstore.AggQuery{Table: q.Get("table"), Feature: q.Get("feature"), Filter: f}
	if aq.Table == "" {
		aq.Table = "records"
	}
	if aq.Table != "scores" {
		delete(f.Equals, "band")
	}
	if g := q.Get("group_by"); g != "" {
		for _, c := range strings.Split(g, ",") {
			c = strings.TrimSpace(c)
			if c == "context" {
				for _, d := range s.S.Baseline.Dimensions {
					if col := dimColumn[d]; col != "" {
						aq.GroupBy = append(aq.GroupBy, col)
					}
				}
				continue
			}
			aq.GroupBy = append(aq.GroupBy, c)
		}
	}
	if b := q.Get("bucket"); b != "" {
		if aq.Bucket, err = time.ParseDuration(b); err != nil || aq.Bucket < time.Second {
			writeError(w, http.StatusBadRequest, "bad_request", "bucket must be a duration of at least 1s")
			return
		}
	}
	if aq.Quantiles, err = floats(q.Get("quantiles")); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "quantiles: "+err.Error())
		return
	}
	if aq.Histogram, err = floats(q.Get("histogram")); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "histogram: "+err.Error())
		return
	}
	// SR-6-3: no aggregate over, or grouped by, a field the role may not
	// see; a Researcher's aggregates stay within S0 and S1.
	role := adminapi.RoleOf(r)
	for _, col := range append([]string{aq.Feature}, aq.GroupBy...) {
		sens := s.sensitivity(col)
		if !visible(role, sens) || (role == adminapi.RoleResearcher && sens == "S2") {
			writeError(w, http.StatusForbidden, "sensitivity_refused", col+" is "+sens+" data, which this role may not query")
			return
		}
	}
	res, err := s.Store.Aggregate(aq)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_query", err.Error())
		return
	}
	if res == nil {
		res = []obsstore.AggRow{} // "rows": [] when nothing matched, never null
	}
	writeJSON(w, http.StatusOK, map[string]any{"feature": aq.Feature, "group_by": aq.GroupBy, "bucket": q.Get("bucket"), "rows": res})
}

// dimColumn maps context dimensions to record columns.
var dimColumn = map[string]string{"principal": "principal_id", "framework_type": "framework_type", "session_template": "session_template",
	"end_user": "end_user_claim", "server": "server_id", "server_revision": "server_revision", "tool": "tool_name"}

// cost ranks the time spent per stage and policy object (FR-10.11).
func (s *Service) cost(w http.ResponseWriter, r *http.Request) {
	f, err := s.filterFrom(r, 0, 1)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	f.Limit = 0
	delete(f.Equals, "server_id")
	delete(f.Equals, "session_id")
	delete(f.Equals, "band")
	group := []string{"stage", "policy_revision", "observation_policy"}
	res, err := s.Store.Aggregate(obsstore.AggQuery{Table: "spans", Feature: "duration_ms", GroupBy: group, Filter: f, Quantiles: []float64{0.5, 0.95, 0.99}})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	type ranked struct {
		obsstore.AggRow
		TotalMs float64 `json:"total_ms"`
	}
	out := make([]ranked, 0, len(res))
	for _, a := range res {
		out = append(out, ranked{a, a.Mean * float64(a.Count)})
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].TotalMs > out[j-1].TotalMs; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	// FR-10.11: span time of the call path aggregated by policy revision,
	// decisive rule revision, filter and Observation Policy since start,
	// the most expensive first; "filters" ranks the filters alone.
	writeJSON(w, http.StatusOK, map[string]any{"rows": out, "policy_objects": s.Collector.Cost(false), "filters": s.Collector.Cost(true)})
}

func (s *Service) baselines(w http.ResponseWriter, r *http.Request) {
	list, err := s.Baselines.Store().List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	hist, _ := s.Baselines.Store().History()
	if list == nil {
		list = []baseline.Summary{}
	}
	if hist == nil {
		hist = []baseline.Promotion{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": s.Baselines.LifecycleStatus(), "snapshots": list, "history": hist,
		"flagged_sessions": s.Baselines.Flagged(), "last_drift": s.Baselines.LastDrift()})
}

func (s *Service) buildSnapshot(w http.ResponseWriter, r *http.Request) {
	actor := adminapi.ActorOf(r)
	res, err := s.Baselines.BuildSnapshot("operator", actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "snapshot_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func snapshotErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, baseline.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, baseline.ErrDigest):
		writeError(w, http.StatusConflict, "snapshot_integrity", err.Error())
	case errors.Is(err, baseline.ErrAlreadyPromoted):
		writeError(w, http.StatusConflict, "already_promoted", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "snapshot_error", err.Error())
	}
}

func (s *Service) snapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Baselines.Store().Load(r.PathValue("id"))
	if err != nil {
		snapshotErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Service) drift(w http.ResponseWriter, r *http.Request) {
	d, err := s.Baselines.DriftOf(r.PathValue("id"))
	if err != nil {
		snapshotErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Service) promote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Comment string `json:"comment"`
	}
	if !decode(w, r, &body) {
		return
	}
	p, err := s.Baselines.Promote(r.PathValue("id"), adminapi.ActorOf(r))
	if err != nil {
		snapshotErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"promotion": p, "loaded_snapshot": s.Scorer.SnapshotID()})
}

func (s *Service) flag(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID string `json:"session_id"`
		Flagged   *bool  `json:"flagged"`
		Reason    string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.SessionID == "" || len(body.SessionID) > 128 {
		writeError(w, http.StatusBadRequest, "bad_request", "session_id is required")
		return
	}
	on := body.Flagged == nil || *body.Flagged
	outcome := "session_flagged"
	if !on {
		outcome = "session_unflagged"
	}
	if !s.commit(w, audit.Event{Class: "baseline", Origin: "E-30", SessionID: body.SessionID, Outcome: outcome,
		Detail: map[string]any{"actor": adminapi.ActorOf(r), "reason": body.Reason}}) {
		return
	}
	if on {
		s.Baselines.Flag(body.SessionID)
	} else {
		s.Baselines.Unflag(body.SessionID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": body.SessionID, "flagged": on})
}

func campaignErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, research.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, research.ErrTransition):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	case errors.Is(err, research.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_campaign", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "campaign_error", err.Error())
	}
}

func (s *Service) listCampaigns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"campaigns": s.Campaigns.List()})
}

func (s *Service) createCampaign(w http.ResponseWriter, r *http.Request) {
	var spec research.Spec
	if !decode(w, r, &spec) {
		return
	}
	cp, err := s.Campaigns.Create(spec, adminapi.ActorOf(r))
	if err != nil {
		campaignErr(w, err)
		return
	}
	s.audit(audit.Event{Class: "research", Origin: "E-32", Outcome: research.Draft, Detail: map[string]any{"campaign_id": cp.ID, "actor": adminapi.ActorOf(r)}})
	writeJSON(w, http.StatusCreated, cp)
}

func (s *Service) getCampaign(w http.ResponseWriter, r *http.Request) {
	cp, err := s.Campaigns.Get(r.PathValue("id"))
	if err != nil {
		campaignErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cp)
}

func (s *Service) actCampaign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	id, action := r.PathValue("id"), r.PathValue("action")
	if _, err := s.Campaigns.Get(id); err != nil {
		campaignErr(w, err)
		return
	}
	if !s.commit(w, audit.Event{Class: "research", Origin: "E-32", Outcome: action, Detail: map[string]any{"campaign_id": id, "actor": adminapi.ActorOf(r), "reason": body.Reason}}) {
		return
	}
	cp, err := s.Campaigns.Act(id, action, adminapi.ActorOf(r), body.Reason)
	if err != nil {
		campaignErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cp)
}

func (s *Service) listExports(w http.ResponseWriter, r *http.Request) {
	list, err := s.Exporter.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exports": list})
}

func (s *Service) export(w http.ResponseWriter, r *http.Request) {
	var req research.Request
	if !decode(w, r, &req) {
		return
	}
	actor := adminapi.ActorOf(r)
	m, err := s.Exporter.Export(req, actor)
	if err != nil {
		switch {
		case errors.Is(err, research.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", err.Error())
		case errors.Is(err, research.ErrNoParquet):
			writeError(w, http.StatusConflict, "parquet_unavailable", err.Error())
		case errors.Is(err, research.ErrRawGrant):
			writeError(w, http.StatusForbidden, "raw_export_not_granted", err.Error())
		case errors.Is(err, research.ErrFormat), errors.Is(err, research.ErrNotExported), errors.Is(err, research.ErrNoSnapshot),
			strings.Contains(err.Error(), "unknown parameter"):
			writeError(w, http.StatusBadRequest, "bad_export", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "export_error", err.Error())
		}
		return
	}
	campaign := ""
	if m.Campaign != nil {
		campaign = m.Campaign.ID
	}
	if !s.commit(w, audit.Event{Class: "research", Origin: "E-32", Outcome: "exported", Detail: map[string]any{"dataset_id": m.DatasetID,
		"format": m.Format, "rows": m.Rows, "campaign_id": campaign, "actor": actor, "files": m.Files}}) {
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Service) getExport(w http.ResponseWriter, r *http.Request) {
	m, err := s.Exporter.Manifest(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "export not found")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// download serves one export file (G-09 delivery, FR-10.36).
func (s *Service) download(w http.ResponseWriter, r *http.Request) {
	id, name := r.PathValue("id"), r.PathValue("name")
	f, err := s.Exporter.Open(id, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "file not found")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, "not_found", "file not found")
		return
	}
	s.audit(audit.Event{Class: "research", Origin: "E-32", Outcome: "downloaded", Detail: map[string]any{"dataset_id": id, "file": name, "actor": adminapi.ActorOf(r)}})
	ct := "application/octet-stream"
	switch {
	case strings.HasSuffix(name, ".json"):
		ct = "application/json"
	case strings.HasSuffix(name, ".csv"):
		ct = "text/csv; charset=utf-8"
	case strings.HasSuffix(name, ".jsonl"):
		ct = "application/x-ndjson"
	case strings.HasSuffix(name, ".graphml"):
		ct = "application/xml"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	_, _ = io.Copy(w, f)
}
