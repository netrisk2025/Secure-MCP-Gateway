package filters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// The filter test workbench of the Policy Studio (FR-8.27): the control
// API equivalent of `smcpctl filters scan`. It runs a selection of the
// built-in request or response filters, with the rule sets and limits of
// the Gateway's [filters] configuration, against operator-supplied
// synthetic input and reports each filter's findings, action and timing
// and the final disposition. Nothing reaches a server and no evidence is
// written: the input is not a call.

// ScanRequest is the body of POST /api/v1/filters/scan.
type ScanRequest struct {
	// Stage is "request" (Input is tool arguments: a JSON object, or text
	// wrapped as {"text": ...}) or "response" (Input is the text of a tool
	// result).
	Stage string `json:"stage"`
	// Filters selects the filters to run; empty runs every built-in filter
	// of the stage.
	Filters []string `json:"filters"`
	Input   string   `json:"input"`
}

// ScanReport is the response. It never echoes the input; Output is the
// transformed text when a filter changed it.
type ScanReport struct {
	Stage       string             `json:"stage"`
	Disposition string             `json:"disposition"`
	ReasonCode  string             `json:"reasonCode,omitempty"`
	Finding     string             `json:"finding,omitempty"`
	Filters     []ScanRun          `json:"filters"`
	Output      *string            `json:"output,omitempty"`
	InputBytes  int                `json:"inputBytes"`
	DurationUs  int64              `json:"durationUs"`
	Findings    []pipeline.Finding `json:"findings,omitempty"`
}

// ScanRun is one filter's run.
type ScanRun struct {
	ID         string             `json:"id"`
	Version    string             `json:"version"`
	Action     string             `json:"action"`
	ReasonCode string             `json:"reasonCode,omitempty"`
	DurationUs int64              `json:"durationUs"`
	Findings   []pipeline.Finding `json:"findings,omitempty"`
}

// ErrScan marks a request the workbench refuses (unknown stage or filter).
var ErrScan = errors.New("filters scan")

// StageFilters lists the built-in filter IDs of each stage in chain order.
func StageFilters() map[string][]string {
	order := func(m map[string]int) []string {
		ids := make([]string, 0, len(m))
		for id := range m {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return m[ids[i]] < m[ids[j]] })
		return ids
	}
	return map[string][]string{pipeline.StageRequest: order(requestOrder), pipeline.StageResponse: order(responseOrder)}
}

// Scan runs the selected filters of one stage on synthetic input.
func Scan(ctx context.Context, o Options, req ScanRequest) (ScanReport, error) {
	all := StageFilters()
	ids, ok := all[req.Stage]
	if !ok {
		return ScanReport{}, errors.Join(ErrScan, errors.New("stage must be request or response"))
	}
	sel := req.Filters
	if len(sel) == 0 {
		sel = ids
	}
	for _, id := range sel {
		if !slices.Contains(ids, id) {
			return ScanReport{}, errors.Join(ErrScan, errors.New("unknown "+req.Stage+" filter "+id))
		}
	}
	o.Log, o.Evidence = diag.Discard(), nil
	if req.Stage == pipeline.StageRequest {
		o.Config.MandatoryRequest = slices.Clone(sel)
		o.Config.MandatoryResponse = nil
	} else {
		o.Config.MandatoryResponse = slices.Clone(sel)
		o.Config.MandatoryRequest = nil
	}
	in, err := New(o)
	if err != nil {
		return ScanReport{}, err
	}
	chain := pipeline.NewFilters()
	if err := in.Register(chain); err != nil {
		return ScanReport{}, err
	}
	rep := ScanReport{Stage: req.Stage, Disposition: "release", InputBytes: len(req.Input), Filters: []ScanRun{}}
	call := &pipeline.Call{CorrelationID: "workbench", Server: "workbench", PublicName: "workbench_input", InputSchema: map[string]any{"type": "object"}}
	start := time.Now()
	if req.Stage == pipeline.StageRequest {
		args := []byte(req.Input)
		if v := bytes.TrimSpace(args); len(v) == 0 || v[0] != '{' || !json.Valid(v) {
			args, _ = json.Marshal(map[string]string{"text": req.Input})
		}
		out, _, v := chain.RunRequest(ctx, call, args)
		switch {
		case v != nil:
			rep.Disposition, rep.ReasonCode, rep.Finding = "block", v.ReasonCode, v.Finding
		case !bytes.Equal(out, args):
			rep.Disposition = "transform"
			s := string(out)
			rep.Output = &s
		}
	} else {
		res, _, v := chain.RunResponse(ctx, call, &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: req.Input}}})
		if v != nil {
			rep.Disposition, rep.ReasonCode, rep.Finding = "withhold", v.ReasonCode, v.Finding
		} else {
			rep.Disposition = call.Inspection.Disposition()
			if res != nil && len(res.Content) > 0 {
				if tc, ok := res.Content[0].(*mcp.TextContent); ok && tc.Text != req.Input {
					rep.Output = &tc.Text
				}
			}
		}
	}
	rep.DurationUs = time.Since(start).Microseconds()
	for _, r := range call.Inspection.Runs() {
		rep.Filters = append(rep.Filters, ScanRun{ID: r.Filter, Version: r.Version, Action: r.Action.String(), ReasonCode: r.ReasonCode,
			DurationUs: r.Duration.Microseconds(), Findings: r.Findings})
		rep.Findings = append(rep.Findings, r.Findings...)
	}
	return rep, nil
}
