package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// analyzer implements observe.Analyzer over the Service.
type analyzer Service

func (a *analyzer) svc() *Service { return (*Service)(a) }

// dimensions maps baseline context dimensions to record values.
func dimensions(get func(string) string, serverID string, t time.Time) map[string]string {
	t = t.UTC()
	return map[string]string{
		"principal": get("principal_id"), "framework_type": get("framework_type"), "session_template": get("session_template"),
		"end_user": get("end_user_claim"), "server": serverID, "server_revision": get("server_revision"), "tool": get("tool_name"),
		"hour": fmt.Sprintf("%02d", t.Hour()), "weekday": t.Weekday().String()[:3],
	}
}

func catString(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, true
	default:
		b, err := json.Marshal(x)
		return string(b), err == nil
	}
}

// sample converts a record for the Baseline Engine.
func (a *analyzer) sample(r *observe.Record, prevTool string) baseline.Sample {
	t := r.Time
	if t.IsZero() {
		t = r.End
	}
	s := baseline.Sample{Time: t, Session: r.Str("session_id"), Dims: dimensions(r.Str, r.ServerID, t), Numeric: map[string]float64{},
		Categorical: map[string]string{}, Tool: r.Str("tool_name"), PrevTool: prevTool}
	for _, f := range a.S.Baseline.Features {
		if f.Kind == "categorical" {
			if v, ok := catString(r.Values[f.Name]); ok {
				s.Categorical[f.Name] = v
			}
		} else if v, ok := r.Float(f.Name); ok {
			s.Numeric[f.Name] = v
		}
	}
	return s
}

func (a *analyzer) TransitionSurprise(r *observe.Record, prev string) (float64, bool) {
	return a.Baselines.TransitionSurprise(a.sample(r, prev))
}

func (a *analyzer) input(s baseline.Sample) anomaly.Input {
	return anomaly.Input{Context: a.Baselines.ContextKey(s), Numeric: s.Numeric, Categorical: s.Categorical}
}

// bandActions are the asynchronous restrict-only actions of the Anomaly
// Response Policy for a band (FR-8.14): elevated and worse alert, bands
// from EscalateCapture on also escalate capture, and the uncharacterized
// state escalates capture when its action is escalate or approve.
func (s Settings) bandActions(band string) []string {
	if band == anomaly.Uncharacterized {
		if s.Uncharacterized == "escalate" || s.Uncharacterized == "approve" {
			return []string{"capture_escalation"}
		}
		return nil
	}
	if anomaly.Rank(band) < anomaly.Rank(anomaly.Elevated) {
		return nil
	}
	acts := []string{"alert"}
	if s.EscalateCapture != "off" && anomaly.Rank(band) >= anomaly.Rank(s.EscalateCapture) {
		acts = append(acts, "capture_escalation")
	}
	return acts
}

// Score scores assembled records asynchronously (FR-10.28): with async
// scoring every record, with sync scoring the records that never reached
// the request inspection stage (refused earlier). Actions are alert and
// capture escalation only.
func (a *analyzer) Score(r *observe.Record) *anomaly.Result {
	if a.svc().cur().Scoring == "off" {
		return nil
	}
	prev, _ := r.Values["previous_tool"].(string)
	res := a.Scorer.Score(a.input(a.sample(r, prev)))
	if acts := a.S.bandActions(res.Band); len(acts) > 0 {
		res.Actions = acts
	}
	a.svc().writeScoreLater(r, &res, "async")
	return &res
}

func (a *analyzer) Learn(r *observe.Record) {
	band := ""
	if r.Score != nil {
		band = r.Score.Band
	}
	if r.Score != nil && a.svc().scoreMode(r) == "sync" {
		a.svc().writeScoreLater(r, r.Score, "sync")
	}
	prev, _ := r.Values["previous_tool"].(string)
	a.Baselines.Learn(a.sample(r, prev), baseline.LearnInfo{Denied: r.Str("decision_outcome") != "permit" || !r.Released(), Band: band})
}

func (a *analyzer) Captured(r *observe.Record) {
	s := a.svc()
	s.writeRecord(r)
	if r.Score != nil && anomaly.Rank(r.Score.Band) < anomaly.Rank(anomaly.Elevated) {
		s.writeScore(r, r.Score, s.scoreMode(r))
	}
}

func (s *Service) scoreMode(r *observe.Record) string {
	if r.Score != nil && r.Score.Actions != nil && len(r.Score.Actions) > 0 && r.Score.Actions[0] == "sync" {
		return "sync"
	}
	return s.cur().Scoring
}

// writeScoreLater records the scoring record of an elevated or worse score
// at once (anomaly evidence), and leaves normal scores to Captured so that
// only captured normal calls get a scores row.
func (s *Service) writeScoreLater(r *observe.Record, res *anomaly.Result, mode string) {
	if anomaly.Rank(res.Band) >= anomaly.Rank(anomaly.Elevated) {
		s.writeScore(r, res, mode)
	}
}

// requestProbe is the "observe-request" filter: it computes the request
// features, and with synchronous scoring scores the call before launch
// authorization and may add the approval obligation (FR-4.15).
type requestProbe struct{ s *Service }

func (p *requestProbe) ID() string { return "observe-request" }

func (p *requestProbe) FilterRequest(_ context.Context, call *pipeline.Call, args json.RawMessage) (pipeline.RequestVerdict, error) {
	start := time.Now()
	s := p.s
	vals, digest := observe.ArgumentFeatures(args)
	if scan := s.secretScanner(); scan != nil { // FR-6.10: fingerprints registered with E-29
		vals[observe.ProbeSecretMatchesRequest] = int64(scan(args))
	}
	if call.TraceParent != "" { // FR-1.44
		vals["trace_parent"] = call.TraceParent
	}
	if call.ClientInfo != "" { // FR-1.45: self-asserted, observation only
		vals["harness_adapter_version"] = call.ClientInfo
	}
	pr := &observe.Probe{CorrelationID: call.CorrelationID, Time: s.now(), ServerID: call.Server, Template: call.Template, EndUser: call.EndUser,
		DecisiveRules: call.DecisiveRules, Obligations: append([]string{}, call.Obligations.Filters...), ArgsDigest: digest, Values: vals}
	if s.cur().Scoring == "sync" {
		st := time.Now()
		res := p.score(call, vals)
		res.Actions = append([]string{"sync"}, s.S.bandActions(res.Band)...)
		switch {
		case s.cur().RequireApproval != "off" && anomaly.Rank(res.Band) >= anomaly.Rank(s.cur().RequireApproval):
			call.RequireApproval = true
			call.ApprovalReason = "anomaly band " + res.Band
			call.AnomalySnapshot = res.SnapshotID // SR-1.12-3
			call.Anomaly = anomalyEvidence(res)   // FR-3.18
			res.Actions = append(res.Actions, "require_approval")
		case res.Band == anomaly.Uncharacterized && s.S.Uncharacterized == "approve":
			call.RequireApproval = true
			call.ApprovalReason = "anomaly context uncharacterized"
			call.Anomaly = anomalyEvidence(res)
			res.Actions = append(res.Actions, "require_approval")
		}
		pr.Score = &res
		pr.ScoringCost = time.Since(st)
	}
	pr.CaptureCost = time.Since(start) - pr.ScoringCost
	s.Collector.Offer(pr)
	return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
}

// anomalyEvidence is the approver's view of a score (FR-3.18).
func anomalyEvidence(res anomaly.Result) *pipeline.AnomalyEvidence {
	return &pipeline.AnomalyEvidence{Band: res.Band, Feature: res.Contributor, ZScore: res.Combined, SnapshotID: res.SnapshotID, Context: res.Context}
}

// score scores the request-time features of a call: the argument features
// and the sequence features the call will get.
func (p *requestProbe) score(call *pipeline.Call, vals map[string]any) anomaly.Result {
	s := p.s
	now := s.now()
	get := func(k string) string {
		switch k {
		case "principal_id":
			return call.PrincipalID
		case "session_template":
			return call.Template
		case "end_user_claim":
			return call.EndUser
		case "server_revision":
			return call.ServerRevision
		case "tool_name":
			return call.Tool
		}
		return ""
	}
	smp := baseline.Sample{Time: now, Session: call.SessionID, Dims: dimensions(get, call.Server, now), Numeric: map[string]float64{},
		Categorical: map[string]string{}, Tool: call.Tool}
	if prev, interval, ok := s.Collector.PeekSequence(call.SessionID, now); ok {
		smp.PrevTool = prev
		smp.Numeric["inter_call_interval"] = float64(int64(interval))
		if sv, ok := s.Baselines.TransitionSurprise(smp); ok {
			smp.Numeric["transition_surprise"] = sv
		}
	}
	for k, v := range vals {
		if k != "" && k[0] == '_' { // probe-internal keys (observe.ProbeSecretMatches*) are not features
			continue
		}
		switch x := v.(type) {
		case int64:
			smp.Numeric[k] = float64(x)
		case float64:
			smp.Numeric[k] = x
		}
	}
	return s.Scorer.Score(anomaly.Input{Context: s.Baselines.ContextKey(smp), Numeric: smp.Numeric})
}

// responseProbe is the "observe-response" filter: it computes the response
// features, and with synchronous scoring scores them before release
// authorization and may withhold the result.
type responseProbe struct{ s *Service }

func (p *responseProbe) ID() string { return "observe-response" }

// ReasonAnomalyWithheld is the reason code of a result withheld for its
// anomaly band.
const ReasonAnomalyWithheld = "ANOMALY_WITHHELD"

func (p *responseProbe) FilterResponse(ctx context.Context, call *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	start := time.Now()
	s := p.s
	hasSchema := call.OutputSchema != nil
	vals, finish := observe.ResponseFeaturesDeferred(res, func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			return "unserializable"
		}
		return pipeline.ValidateArgumentsContext(ctx, call.OutputSchema, raw)
	}, hasSchema)
	if scan := s.secretScanner(); scan != nil { // FR-6.10: fingerprints registered with E-29
		texts := resultTexts(res)
		base := finish
		finish = func() {
			base()
			n := 0
			for _, t := range texts {
				n += scan([]byte(t))
			}
			vals[observe.ProbeSecretMatchesResponse] = int64(n)
		}
	}
	pr := &observe.Probe{Response: true, CorrelationID: call.CorrelationID, Time: s.now(), ServerID: call.Server, Values: vals}
	verdict := pipeline.ResponseVerdict{Action: pipeline.Pass}
	syncScoring := s.cur().Scoring == "sync"
	if syncScoring {
		finish() // the score needs every response feature now
	} else {
		pr.Finish = finish // the text parts are read by the collector, off the call path (FR-11.4)
	}
	if syncScoring {
		st := time.Now()
		now := s.now()
		get := func(k string) string {
			switch k {
			case "principal_id":
				return call.PrincipalID
			case "session_template":
				return call.Template
			case "end_user_claim":
				return call.EndUser
			case "server_revision":
				return call.ServerRevision
			case "tool_name":
				return call.Tool
			}
			return ""
		}
		num := map[string]float64{}
		for k, v := range vals {
			if k != "" && k[0] == '_' { // probe-internal keys (observe.ProbeSecretMatches*) are not features
				continue
			}
			switch x := v.(type) {
			case int64:
				num[k] = float64(x)
			case float64:
				num[k] = x
			}
		}
		smp := baseline.Sample{Dims: dimensions(get, call.Server, now)}
		r := s.Scorer.Score(anomaly.Input{Context: s.Baselines.ContextKey(smp), Numeric: num})
		r.Actions = []string{"sync"}
		if s.cur().Withhold != "off" && anomaly.Rank(r.Band) >= anomaly.Rank(s.cur().Withhold) {
			r.Actions = append(r.Actions, "withhold")
			verdict = pipeline.ResponseVerdict{Action: pipeline.Block, ReasonCode: ReasonAnomalyWithheld,
				Finding: fmt.Sprintf("response anomaly band %s (%s)", r.Band, r.Contributor)}
		}
		pr.Score = &r
		pr.ScoringCost = time.Since(st)
	}
	pr.CaptureCost = time.Since(start) - pr.ScoringCost
	s.Collector.Offer(pr)
	return verdict, nil
}
