package analytics

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// ReasonDataPurged is the reason code of a deletion receipt (SR-6.15-1).
const ReasonDataPurged = "DATA_PURGED"

// purge serves POST /api/v1/observations/purge: an Administrator deletes
// the observation data (records, spans, metrics, scores, including any
// captured payloads) of every day before a date. The deletion receipt is
// committed to the Evidence Journal before anything is deleted, so every
// purge that happens has a retained receipt (SR-6.15-1); if the receipt
// cannot be recorded nothing is deleted.
func (s *Service) purge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Before string `json:"before"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	before, err := time.Parse("2006-01-02", body.Before)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "before must be a date (YYYY-MM-DD)")
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "reason is required")
		return
	}
	if !before.Before(s.now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)) {
		writeError(w, http.StatusBadRequest, "bad_request", "before must not be after today")
		return
	}
	st, err := s.Store.Stats()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", err.Error())
		return
	}
	var victims []string
	for table, days := range st.Days {
		for _, d := range days {
			if d < body.Before {
				victims = append(victims, table+"/day="+d)
			}
		}
	}
	sort.Strings(victims)
	receipt := map[string]any{"receipt_id": ids.New(), "actor": adminapi.ActorOf(r), "reason": body.Reason, "before": body.Before,
		"partitions": victims, "partition_count": len(victims), "issued_at": s.now().UTC().Format(time.RFC3339Nano)}
	if !s.commit(w, audit.Event{Class: "observation", Origin: "E-28", Outcome: "purged", ReasonCode: ReasonDataPurged, Detail: receipt}) {
		return
	}
	removed, err := s.Store.Retain(before, 0)
	if err != nil {
		s.log.Error("observation purge incomplete", "err", err, "receipt", receipt["receipt_id"])
		writeError(w, http.StatusInternalServerError, "purge_failed", err.Error())
		return
	}
	receipt["removed"] = removed
	writeJSON(w, http.StatusOK, receipt)
}
