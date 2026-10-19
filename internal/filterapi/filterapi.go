// Package filterapi serves the filter test workbench of the Policy Studio
// (G-02, FR-8.27) on the control API: GET /api/v1/filters and POST
// /api/v1/filters/scan, the control API form of `smcpctl filters rules`
// and `smcpctl filters scan` (docs/api/filters.md). It is a package of its
// own because internal/filters must not import the control API.
package filterapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// RegisterRoutes adds GET /api/v1/filters and POST /api/v1/filters/scan to
// the control API (docs/api/filters.md). The workbench uses the rule sets
// and limits of cfg's [filters] section, as the running chain does.
func RegisterRoutes(a *adminapi.Server, cfg *config.Config) {
	sem := make(chan struct{}, 2) // a scan builds an inspector; bound the work
	a.Handle("GET /api/v1/filters", func(w http.ResponseWriter, r *http.Request) {
		o := filters.OptionsFrom(cfg)
		o.Log = diag.Discard()
		in, err := filters.New(o)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "filters_unavailable", err.Error())
			return
		}
		type ruleSet struct {
			ID       string  `json:"id"`
			Version  string  `json:"version"`
			Rules    int     `json:"rules"`
			InEffect bool    `json:"in_effect"`
			Digest   string  `json:"digest"`
			FPMax    float64 `json:"false_positive_max"`
			FNMax    float64 `json:"false_negative_max"`
		}
		sets := []ruleSet{}
		for _, rs := range in.Library().All() {
			sets = append(sets, ruleSet{ID: rs.ID, Version: rs.Version, Rules: len(rs.Rules), InEffect: in.RuleSet(rs.ID) == rs, Digest: rs.Digest,
				FPMax: rs.Targets.FalsePositiveRate, FNMax: rs.Targets.FalseNegativeRate})
		}
		mandReq, mandResp := cfg.Filters.MandatoryRequest, cfg.Filters.MandatoryResponse
		if mandReq == nil {
			mandReq = filters.DefaultMandatoryRequest
		}
		if mandResp == nil {
			mandResp = filters.DefaultMandatoryResponse
		}
		st := filters.StageFilters()
		apiJSON(w, http.StatusOK, map[string]any{
			"request":            st[pipeline.StageRequest],
			"response":           st[pipeline.StageResponse],
			"mandatory_request":  mandReq,
			"mandatory_response": mandResp,
			"rule_sets":          sets,
		})
	})
	a.Handle("POST /api/v1/filters/scan", func(w http.ResponseWriter, r *http.Request) {
		var req filters.ScanRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			apiError(w, http.StatusBadRequest, "bad_request", "body must be {stage, filters, input}")
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-r.Context().Done():
			return
		}
		rep, err := filters.Scan(r.Context(), filters.OptionsFrom(cfg), req)
		switch {
		case errors.Is(err, filters.ErrScan):
			apiError(w, http.StatusBadRequest, "bad_request", err.Error())
		case err != nil:
			apiError(w, http.StatusInternalServerError, "filters_unavailable", err.Error())
		default:
			apiJSON(w, http.StatusOK, rep)
		}
	})
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	apiJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
