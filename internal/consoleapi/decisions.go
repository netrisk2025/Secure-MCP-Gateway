package consoleapi

import (
	"net/http"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// decisionExplanation serves GET /api/v1/decisions/{id}/explanation
// (SR-1.19-1): the decision record committed with the call's decision
// event, or with its approval refusal when an approval obligation stopped
// the call before launch (considered, applicable and decisive
// rule-revision IDs, the route and the effective obligations) and the
// anomaly evidence recorded for the same call. A decision that a
// re-decision replaced (SR-5.12-1) names its replacement.
func (c *Console) decisionExplanation(w http.ResponseWriter, r *http.Request) {
	evs, err := c.readEvents()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unreadable", err.Error())
		return
	}
	id := r.PathValue("id")
	var dec *audit.Event
	supersededBy := ""
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.Class != "decision" && e.Class != "approval" {
			continue
		}
		d, _ := e.Detail.(map[string]any)
		if _, ok := d["considered_rules"]; !ok {
			continue // an approval event without the decision record
		}
		if e.DecisionID == id && (dec == nil || e.Class == "decision") {
			dec = &evs[i]
			if e.Class == "decision" {
				break
			}
		}
		if s, _ := d["superseded_decision_id"].(string); s == id && supersededBy == "" {
			supersededBy = e.DecisionID
		}
	}
	if dec == nil {
		if supersededBy != "" {
			writeJSON(w, http.StatusOK, map[string]any{"decision_id": id, "superseded_by": supersededBy,
				"note": "a request filter transformed the arguments; the call was decided again"})
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "no decision with this ID in the journal")
		return
	}
	detail, _ := dec.Detail.(map[string]any)
	out := map[string]any{
		"decision_id": dec.DecisionID, "correlation_id": dec.CorrelationID, "session_id": dec.SessionID, "principal_id": dec.PrincipalID,
		"policy_revision": dec.PolicyRevision, "server_revision": dec.ServerRevision, "tool_revision": dec.ToolRevision,
		"time": dec.Time, "phase": dec.Phase, "reason_code": dec.ReasonCode, "event_id": dec.EventID,
	}
	for _, k := range []string{"outcome", "template", "route", "considered_rules", "applicable_rules", "decisive_rules", "obligations",
		"side_effect", "source_trust", "tainted", "superseded_decision_id", "redecision_reason", "anomaly_obligation", "failed_predicate", "baseline_snapshot_id"} {
		if v, ok := detail[k]; ok {
			out[k] = v
		}
	}
	// The baseline snapshot the decision used (FR-8.22): the one the
	// decision point recorded, else the one behind its anomaly obligation.
	if s, _ := out["baseline_snapshot_id"].(string); s == "" {
		delete(out, "baseline_snapshot_id")
		if ob, _ := detail["anomaly_obligation"].(map[string]any); ob != nil {
			if s, _ := ob["snapshot_id"].(string); s != "" {
				out["baseline_snapshot_id"] = s
			}
		}
	}
	anomaly := []map[string]any{}
	if dec.CorrelationID != "" {
		for _, e := range evs {
			if e.CorrelationID == dec.CorrelationID && strings.HasPrefix(e.Class, "anomaly") {
				anomaly = append(anomaly, map[string]any{"event_id": e.EventID, "class": e.Class, "outcome": e.Outcome,
					"reason_code": e.ReasonCode, "detail": e.Detail})
			}
		}
	}
	out["anomaly"] = anomaly
	writeJSON(w, http.StatusOK, out)
}
