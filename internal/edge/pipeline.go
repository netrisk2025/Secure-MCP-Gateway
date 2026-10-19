package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// callRun carries one tool call through the pipeline and writes its
// evidence. record appends; commit appends and waits for fsync. A failure of
// either is returned so the stage can fail closed.
type callRun struct {
	g    *Gateway
	base audit.Event
	corr string
	dec  policy.Decision
	prog *progressRelay
	// superseded is the ID of the call's first decision when a request
	// filter transformed the arguments and the call was decided again.
	superseded string
	// call is the pipeline view of the call once the decision permitted
	// it; an anomaly obligation added by a request probe is read from it.
	call *pipeline.Call
	// spans records the call's stage spans (nil when no collector takes
	// them).
	spans *pipeline.SpanTimer
}

// stage starts a span of the call; the returned function ends it.
func (c *callRun) stage(name string) func() {
	if c.spans == nil {
		return func() {}
	}
	return c.spans.Start(name)
}

// decided records the policy objects of the call's decision for the spans
// that follow it.
func (c *callRun) decided() {
	if c.spans == nil {
		return
	}
	c.spans.PolicyRevision = c.dec.PolicyRevision
	c.spans.Rule = ""
	if len(c.dec.DecisiveRules) > 0 {
		c.spans.Rule = policy.RuleRevisionID(c.dec.PolicyRevision, c.dec.Template, c.dec.DecisiveRules[0])
	}
}

// filterSpans records the filter runs of the inspection stage that just
// ended.
func (c *callRun) filterSpans(stage string) {
	if c.spans == nil || c.call == nil || c.call.Inspection == nil {
		return
	}
	var runs []pipeline.FilterRun
	for _, r := range c.call.Inspection.Runs() {
		if r.Stage == stage {
			runs = append(runs, r)
		}
	}
	c.spans.AddFilterRuns(runs)
}

func (c *callRun) event(class string, phase audit.Phase, origin, outcome, reason, status string, detail any) audit.Event {
	e := c.base
	e.Class, e.Phase, e.Origin, e.Outcome, e.ReasonCode, e.PolicyStatus, e.Detail = class, phase, origin, outcome, reason, status, detail
	e.DecisionID, e.PolicyRevision = c.dec.ID, c.dec.PolicyRevision
	return e
}

// Evidence writes wait for the journal (its lock, and for a commit the
// group fsync), so they are made outside the stage's CPU measurement.
func (c *callRun) record(class string, phase audit.Phase, origin, outcome, reason, status string) error {
	return c.recordDetail(class, phase, origin, outcome, reason, status, nil)
}

func (c *callRun) recordDetail(class string, phase audit.Phase, origin, outcome, reason, status string, detail any) error {
	ev := c.event(class, phase, origin, outcome, reason, status, detail)
	var err error
	c.spans.Wait(func() { err = c.g.evidence.Record(ev) })
	return err
}

func (c *callRun) commit(class string, phase audit.Phase, origin, outcome, reason, status string, detail any) error {
	// FR-17.1, FR-17.3: a debug trace of the call's progress; identifiers
	// and outcomes only, never arguments or results.
	c.g.log.Debug("call event", "correlation", c.corr, "class", class, "phase", string(phase), "outcome", outcome, "reason", reason)
	ev := c.event(class, phase, origin, outcome, reason, status, detail)
	var err error
	c.spans.Wait(func() { err = c.g.evidence.Commit(ev) })
	return err
}

// refuse commits a terminal refusal event and returns err. A refusal is the
// safe outcome, so it is returned even when its evidence cannot be written;
// the failure is logged and the journal's sticky error fails the Gateway
// closed for later calls.
func (c *callRun) refuse(err *jsonrpc.Error, class string, phase audit.Phase, origin, outcome, reason, status string) error {
	var detail any
	if class == "decision" || class == "approval" {
		detail = c.decisionDetail()
	}
	if aerr := c.commit(class, phase, origin, outcome, reason, status, detail); aerr != nil {
		c.g.log.Error("evidence write failed", "err", aerr, "correlation", c.corr)
	}
	return err
}

// decisionDetail is the FR-3.11 decision record carried by decision
// events: considered, applicable and decisive rule-revision IDs, the route
// and the effective obligations (SR-1.19-1, SR-6.4-1). superseded names an
// earlier decision of the call that a re-decision replaced (SR-5.12-1).
func (c *callRun) decisionDetail() map[string]any {
	d := c.dec
	rr := func(rules []string) []string {
		out := make([]string, 0, len(rules))
		for _, r := range rules {
			out = append(out, policy.RuleRevisionID(d.PolicyRevision, d.Template, r))
		}
		return out
	}
	ob := d.Obligations
	m := map[string]any{
		"outcome": d.Outcome, "reason_code": d.ReasonCode, "template": d.Template, "route": d.Route,
		"considered_rules": rr(d.ConsideredRules), "applicable_rules": rr(d.ApplicableRules), "decisive_rules": rr(d.DecisiveRules),
		"obligations": map[string]any{"approval": ob.Approval, "approval_reason": ob.ApprovalReason, "calls_per_minute": ob.CallsPerMinute,
			"burst": ob.Burst, "calls_per_session": ob.CallsPerSession, "filters": append([]string{}, ob.Filters...),
			// FR-3.12: the obligations that come from objects outside the
			// policy document.
			"audit_profile": ob.AuditProfile, "observation_policy": ob.ObservationPolicy, "anomaly_response": ob.AnomalyResponse,
			"size_limit_bytes": ob.SizeLimit, "timeout_ms": ob.Timeout.Milliseconds(), "egress_grants": append([]string{}, ob.EgressGrants...),
			"secret_grants": append([]string{}, ob.SecretGrants...), "runtime_profile": ob.RuntimeProfile, "egress_limits": ob.EgressLimits},
		"side_effect": d.SideEffect, "source_trust": d.SourceTrust, "tainted": d.Tainted, "duration_us": d.Duration.Microseconds(),
		"baseline_snapshot_id": d.BaselineSnapshot,
	}
	if d.FailedPredicate != "" {
		m["failed_predicate"] = d.FailedPredicate
	}
	if c.superseded != "" {
		m["superseded_decision_id"] = c.superseded
		m["redecision_reason"] = "arguments_transformed"
	}
	if c.call != nil && c.call.RequireApproval {
		// SR-1.12-3: an anomaly obligation records the baseline snapshot
		// that produced it.
		m["obligations"].(map[string]any)["approval"] = true
		m["anomaly_obligation"] = map[string]any{"obligation": "approval", "reason": c.call.ApprovalReason, "snapshot_id": c.call.AnomalySnapshot}
	}
	return m
}

func (c *callRun) auditFailure(err error) error {
	c.g.log.Error("evidence write failed; refusing call", "err", err, "correlation", c.corr)
	return gatewayError(CodeGatewayFailClosed, "gateway fail-closed: evidence unavailable", ReasonJournalUnavailable, c.corr, c.dec.ID, nil)
}

// toolHandler is the per-call enforcement pipeline (FR-4.3): authenticate
// (mcpChain), session check, decision, request inspection, approval,
// launch authorization, dispatch, response inspection, release
// authorization. Request scoring and response scoring (E-31) are the
// observation probes, mandatory filters that run after every other filter
// of the request and response chains (FR-4.3, TestStageOrder).
func (g *Gateway) toolHandler(sess session.Session, ref *backend.ToolRef) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		received := time.Now()
		corr, _ := ctx.Value(ctxCorrelation).(string)
		if corr == "" {
			corr = ids.New()
		}
		// FR-2.11: ending the session cancels this call.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		defer g.trackCall(sess.ID, cancel)()
		// SR-7.12-1: the harness closing the response stream (or the
		// connection) cancels the call; the dispatcher then cancels it
		// southbound (FR-5.26).
		if rc, ok := ctx.Value(ctxRequest).(context.Context); ok {
			defer context.AfterFunc(rc, cancel)()
		}

		c := &callRun{g: g, corr: corr, base: audit.Event{CorrelationID: corr, SessionID: sess.ID, PrincipalID: sess.PrincipalID,
			ServerRevision: ref.Server.Revision, ToolRevision: ref.Revision}}
		// FR-10.2: one span per stage, with thread CPU time, emitted to
		// the Observation Collector when the call ends.
		if g.spans != nil {
			c.spans = pipeline.NewSpanTimer(corr)
			if a, ok := ctx.Value(ctxAuthSpan).(pipeline.StageSpan); ok {
				c.spans.Add(a)
			}
			defer func() { g.spans(c.spans.Finish()) }()
		}
		channel.From(ctx).Apply(&c.base) // FR-16.8
		side, trust := toolClasses(ref)
		// The requested event carries the canonical request (FR-4.1): the
		// correlation, session and principal IDs and the server and tool
		// revisions are the event's own fields; the public name, the digest
		// of the canonicalized arguments and the receipt time are in its
		// detail. The arguments themselves are not journaled. Policy
		// simulation replays recorded calls from it (FR-3.5).
		if err := g.evidence.Record(c.event("call", audit.PhaseRequested, "E-02", "", "", "not_evaluated", map[string]any{
			"server": ref.Server.Alias, "tool": ref.Tool.Name, "template": sess.Template, "profile": sess.Profile,
			"side_effect": side, "source_trust": trust, "public_name": ref.Public,
			"arguments_sha256": argumentsDigest(req.Params.Arguments), "received_at": received.UTC().Format(time.RFC3339Nano)})); err != nil {
			return nil, c.auditFailure(err)
		}

		// Session check: the request was authenticated, but the session may
		// have ended since.
		endCheck := c.stage(pipeline.SpanSessionCheck)
		active, closed := g.store.IsActive(sess.ID), g.failClosed()
		endCheck()
		if !active {
			return nil, c.refuse(gatewayError(CodeSessionInvalid, "session invalid", ReasonSessionState, corr, "", nil),
				"call", audit.PhaseDenied, "E-04", "deny", ReasonSessionState, "not_evaluated")
		}
		if reason := closed; reason != "" {
			return nil, c.refuse(gatewayError(CodeGatewayFailClosed, "gateway fail-closed", reason, corr, "", nil),
				"call", audit.PhaseDenied, "E-12", "deny", reason, "unavailable")
		}

		// Decision (SR-5.5-1: every call is evaluated).
		endDecision := c.stage(pipeline.SpanDecision)
		c.dec = g.decider.Decide(g.policyRequest(sess, ref, side, trust, req.Params.Arguments))
		endDecision()
		c.decided()
		dec := c.dec
		if dec.Outcome != policy.Permit {
			var e *jsonrpc.Error
			switch dec.ReasonCode {
			case policy.ReasonRateLimited:
				e = gatewayError(CodeRateLimited, "rate limited", dec.ReasonCode, corr, dec.ID, map[string]any{"callsPerMinute": dec.Obligations.CallsPerMinute, "burst": dec.Obligations.Burst})
			case policy.ReasonQuota:
				e = gatewayError(CodeRateLimited, "session quota exhausted", dec.ReasonCode, corr, dec.ID, map[string]any{"callsPerSession": dec.Obligations.CallsPerSession})
			case policy.ReasonNoSnapshot:
				e = gatewayError(CodeGatewayFailClosed, "gateway fail-closed", dec.ReasonCode, corr, dec.ID, nil)
			case policy.ReasonSessionState: // Appendix B: -31006
				e = gatewayError(CodeSessionInvalid, "session not active", dec.ReasonCode, corr, dec.ID, nil)
			default:
				e = gatewayError(CodePolicyDenied, "policy denied", dec.ReasonCode, corr, dec.ID, map[string]any{"decisiveRules": dec.DecisiveRules})
			}
			return nil, c.refuse(e, "decision", audit.PhaseDenied, "E-06", "deny", dec.ReasonCode, "evaluated")
		}

		call := &pipeline.Call{CorrelationID: corr, SessionID: sess.ID, PrincipalID: sess.PrincipalID, Template: sess.Template,
			Purpose: sess.Purpose, Project: sess.Project, EndUser: sess.EndUser, Server: ref.Server.Alias, Tool: ref.Tool.Name,
			PublicName: ref.Public, ServerRevision: ref.Server.Revision, ToolRevision: ref.Revision, ManifestSource: ref.Server.ManifestSource,
			DecisionID: dec.ID, PolicyRevision: dec.PolicyRevision, Obligations: dec.Obligations, DecisiveRules: dec.DecisiveRules,
			InputSchema: ref.Tool.InputSchema, OutputSchema: ref.Tool.OutputSchema,
			Channel: c.base.Channel, ClientID: c.base.ClientID, ClientAddress: c.base.ClientAddress}
		call.TraceParent, call.ClientInfo = selfAsserted(req.Params.Meta) // FR-1.44, FR-1.45
		c.call = call
		c.prog = g.newProgress(ctx, req, call)
		defer c.prog.stop()

		// Request inspection (E-09).
		endInspect := c.stage(pipeline.SpanRequestInspection)
		// The filters run on their own goroutines; their CPU time is
		// added to the stage by filterSpans.
		var args json.RawMessage
		var reqApplied []string
		var verdict *pipeline.RequestVerdict
		c.spans.Wait(func() { args, reqApplied, verdict = g.filters.RunRequest(ctx, call, req.Params.Arguments) })
		endInspect()
		c.filterSpans(pipeline.StageRequest)
		if verdict != nil && ctx.Err() != nil && !g.store.IsActive(sess.ID) {
			// FR-2.11: the session ended while the filters ran; their
			// cancellation verdict is not an inspection finding.
			return nil, c.refuse(gatewayError(CodeSessionInvalid, "session ended during the call", ReasonSessionEnded, corr, dec.ID, nil),
				"call", audit.PhaseIndeterminate, "E-04", "cancelled", ReasonSessionEnded, "evaluated")
		}
		if verdict != nil {
			var e *jsonrpc.Error
			if verdict.ReasonCode == pipeline.ReasonSchemaInvalid {
				raw, _ := json.Marshal(map[string]any{"reasonCode": verdict.ReasonCode, "correlationId": corr, "decisionId": dec.ID, "findings": verdict.Finding,
					"message": Message(jsonrpc.CodeInvalidParams, verdict.ReasonCode, nil)})
				e = &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "arguments do not match the tool schema", Data: raw}
			} else {
				e = gatewayError(CodePolicyDenied, "request blocked by inspection", verdict.ReasonCode, corr, dec.ID, map[string]any{"findings": verdict.Finding, "filters": reqApplied})
			}
			return nil, c.refuse(e, "filter", audit.PhaseFiltered, "E-09", "block", verdict.ReasonCode, "evaluated")
		}

		// SR-5.12-1: arguments a filter transformed are decided again
		// before launch (the call is not counted twice). The new decision
		// governs approval and launch; its record names the first one.
		if argumentsChanged(req.Params.Arguments, args) {
			first := c.dec
			endRecheck := c.stage(pipeline.SpanDecision)
			c.dec = g.decider.Recheck(g.policyRequest(sess, ref, side, trust, args))
			endRecheck()
			c.decided()
			c.superseded = first.ID
			dec = c.dec
			if dec.Outcome != policy.Permit {
				return nil, c.refuse(gatewayError(CodePolicyDenied, "policy denied", dec.ReasonCode, corr, dec.ID, map[string]any{"decisiveRules": dec.DecisiveRules}),
					"decision", audit.PhaseDenied, "E-06", "deny", dec.ReasonCode, "evaluated")
			}
			call.DecisionID, call.Obligations, call.DecisiveRules = dec.ID, dec.Obligations, dec.DecisiveRules
		}

		// Approval (E-07).
		if dec.Obligations.Approval || call.RequireApproval {
			endApproval := c.stage(pipeline.SpanApproval)
			var err error
			c.spans.Wait(func() { err = g.approve(ctx, c, call, args, req) })
			endApproval()
			if err != nil {
				return nil, err
			}
		}

		// Launch authorization under the barrier (FR-4.13, SR-1.17-1,
		// SR-6.2-1): the decision intent is committed before the capability
		// exists.
		binding := pipeline.Binding{CorrelationID: corr, DecisionID: dec.ID, PolicyRevision: dec.PolicyRevision, PublicName: ref.Public}
		if l := dec.Obligations.EgressLimits; l != nil { // FR-5.38
			binding.Egress = pipeline.EgressLimits{RequestBytes: l.RequestBytes, ResponseBytes: l.ResponseBytes, Timeout: l.Timeout()}
		}
		// Dispatch (FR-4.8, FR-4.9, FR-4.10) with the one-use capability.
		// The dispatched event is recorded under the same barrier hold as
		// the authorization, so that an emergency stop (or the backup's
		// drain stop) is ordered entirely before or after both: no call is
		// recorded as dispatched after the stop event (SR-7.7-1).
		endLaunch := c.stage(pipeline.SpanLaunchAuthorization)
		endDispatch := func() {}
		capID, err := g.authorizeLaunch(c, sess, ref, binding, func() error {
			endLaunch()
			endLaunch = func() {}
			endDispatch = c.stage(pipeline.SpanDispatch)
			if err := c.record("call", audit.PhaseDispatched, "E-10", "", "", "evaluated"); err != nil {
				endDispatch()
				return c.auditFailure(err)
			}
			return nil
		})
		endLaunch()
		if err != nil {
			return nil, err
		}
		cctx, ccancel := context.WithTimeout(ctx, g.cfg.Limits.ClientDeadline.Duration) // CP-13 client deadline (FR-1.43)
		defer ccancel()
		dispatch := backend.Dispatch{Principal: sess.PrincipalID, Ref: ref, Arguments: args, Capability: capID, Binding: binding}
		if c.prog.enabled() { // FR-1.39
			dispatch.Progress = c.prog.relay
		}
		var res *mcp.CallToolResult
		c.spans.Wait(func() { res, err = g.reg.Call(cctx, dispatch) })
		responded := time.Now()
		endDispatch()
		c.prog.stop() // FR-1.40: no progress after the final response
		if err != nil {
			return nil, g.mapDispatchError(c, sess.ID, err)
		}

		// Response inspection (E-11).
		endRespInspect := c.stage(pipeline.SpanResponseInspection)
		var respApplied []string
		var rv *pipeline.ResponseVerdict
		c.spans.Wait(func() { res, respApplied, rv = g.filters.RunResponse(ctx, call, res) })
		endRespInspect()
		c.filterSpans(pipeline.StageResponse)
		if rv != nil {
			return nil, c.refuse(gatewayError(CodeResponseWithheld, "response withheld", rv.ReasonCode, corr, dec.ID, map[string]any{"findings": rv.Finding}),
				"filter", audit.PhaseWithheld, "E-11", "withhold", rv.ReasonCode, "evaluated")
		}
		// Provenance (FR-4.12, SR-5.13-1) and release authorization.
		endRelease := c.stage(pipeline.SpanReleaseAuthorization)
		defer endRelease()
		if res.Meta == nil {
			res.Meta = mcp.Meta{}
		}
		applied := append(append([]string{}, reqApplied...), respApplied...)
		prov := map[string]any{
			"serverId": ref.Server.Alias, "serverRevision": ref.Server.Revision, "toolRevision": ref.Revision,
			"decisionId": dec.ID, "filters": applied, "manifest": ref.Server.ManifestSource, "untrusted": true,
			"disposition": call.Inspection.Disposition(), // FR-4.11
		}
		if tags := call.Inspection.Tags(); len(tags) > 0 { // FR-4.17
			prov["tags"] = tags
		}
		res.Meta[metaPrefix+"provenance"] = prov

		outcome := "ok"
		if res.IsError {
			outcome = "tool_error"
		}
		// The completed event follows response inspection; responded_at is
		// when the backend's response arrived, the end of server execution
		// (P-101) for P-213.
		if err := c.recordDetail("call", audit.PhaseCompleted, "E-10", outcome, "", "evaluated",
			map[string]any{"responded_at": responded.UTC().Format(time.RFC3339Nano)}); err != nil {
			return nil, c.auditFailure(err)
		}
		// Release authorization under the barrier (SR-1.17-2); the delivered
		// event is durable before the result leaves.
		if err := g.authorizeRelease(c, sess.ID); err != nil {
			return nil, err
		}
		if dec.TaintsSession { // SR-5.13-2: untrusted content reached the session
			g.decider.Taint(sess.ID)
		}
		return res, nil
	}
}

// approve runs the approval stage (FR-3.14 to FR-3.22). It returns nil when
// the call may continue. While the Approver holds the call, its Progress
// calls commit the response to an event stream and send keep-alives
// (stream.go).
func (g *Gateway) approve(ctx context.Context, c *callRun, call *pipeline.Call, args json.RawMessage, req *mcp.CallToolRequest) error {
	res, err := g.approver.Request(ctx, pipeline.ApprovalRequest{Call: *call, Arguments: args, Hold: g.cfg.Limits.ApprovalHold.Duration, Progress: g.keepAlive(ctx, c.prog)})
	if ctx.Err() != nil && g.stopped.Load() { // SR-7.6-2: the stop cancelled the held call
		return c.refuse(gatewayError(CodeGatewayFailClosed, "call cancelled by emergency stop", ReasonEmergencyStop, c.corr, c.dec.ID, nil),
			"call", audit.PhaseDenied, "E-12", "cancelled", ReasonEmergencyStop, "evaluated")
	}
	if err != nil {
		g.log.Warn("approval service failed; refusing the call", "err", err, "correlation", c.corr)
		res = pipeline.ApprovalResult{Outcome: pipeline.Pending, ReasonCode: ReasonApprovalNoSvc,
			RetryText: "The approval service is unavailable. Retry later or ask the operator."}
	}
	detail := map[string]any{"approval_id": res.ApprovalID, "approver": res.Approver}
	switch res.Outcome {
	case pipeline.Approved:
		if err := c.commit("approval", audit.PhaseAuthorized, "E-07", "approved", "APPROVED", "evaluated", detail); err != nil {
			return c.auditFailure(err)
		}
		return nil
	case pipeline.Denied:
		reason := res.ReasonCode
		if reason == "" {
			reason = ReasonApprovalDenied
		}
		extra := map[string]any{}
		if res.ApprovalID != "" {
			extra["approvalId"] = res.ApprovalID
		}
		return c.refuse(harnessVisible(gatewayError(CodePolicyDenied, "approval denied", reason, c.corr, c.dec.ID, extra)),
			"approval", audit.PhaseDenied, "E-07", "deny", reason, "evaluated")
	default:
		reason := res.ReasonCode
		if reason == "" || (reason == pipeline.ReasonApprovalRequired && call.Obligations.ApprovalReason != "") {
			reason = pipeline.ReasonApprovalRequired
			if call.Obligations.ApprovalReason != "" { // TAINT_APPROVAL
				reason = call.Obligations.ApprovalReason
			}
		}
		extra := map[string]any{"retry": res.RetryText}
		link := res.ConsoleURL
		if link == "" && g.consoleURL != "" {
			link = g.consoleURL + "/approvals?correlation=" + url.QueryEscape(c.corr)
		}
		if link != "" {
			extra["consoleUrl"] = link // retained for clients of the first slice
			extra["approvalUrl"] = link
		}
		if res.ApprovalID != "" {
			extra["approvalId"] = res.ApprovalID
		}
		if !res.ExpiresAt.IsZero() {
			extra["expiresAt"] = res.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return c.refuse(harnessVisible(gatewayError(CodeApprovalRequired, "approval required", reason, c.corr, c.dec.ID, extra)),
			"approval", audit.PhaseDenied, "E-07", "pending", reason, "evaluated")
	}
}

// harnessVisible appends the plain-language data.message to the JSON-RPC
// error message of an approval outcome. Claude Code 2.1.302 shows a failed
// tool call to the person as error.message only (FR-3.25 run,
// docs/verification/FR-3.25.md), so without this the denial text and the
// approval link of -31002 (FR-1.51) never reach the person.
func harnessVisible(e *jsonrpc.Error) *jsonrpc.Error {
	var data struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(e.Data, &data) == nil && data.Message != "" {
		e.Message += ": " + data.Message
	}
	return e
}

// authorizeLaunch rechecks state under the barrier, commits the decision
// intent ("authorized") durably and only then issues the capability;
// dispatched (which records the dispatch) runs under the barrier as well.
// SR-1.17-1: the recheck covers the policy revision, the session state,
// the principal and credential state and the server revision state, each
// as the gate sees it now, so a revocation completed after the decision
// refuses the launch.
func (g *Gateway) authorizeLaunch(c *callRun, sess session.Session, ref *backend.ToolRef, b pipeline.Binding, dispatched func() error) (string, error) {
	g.gate.RLock()
	defer g.gate.RUnlock()
	reason, code := "", int64(CodeGatewayFailClosed)
	switch {
	case g.stopped.Load():
		reason = ReasonEmergencyStop
	case g.decider.Snapshot() == nil || g.decider.Snapshot().Revision != b.PolicyRevision:
		reason = ReasonRevisionChanged
	case !g.store.IsActive(sess.ID):
		reason, code = ReasonSessionState, CodeSessionInvalid
	case g.principalDisabled(sess.PrincipalID):
		reason, code = policy.ReasonPrincipalDisabled, CodePolicyDenied
	case g.cfg.CredentialRevoked(sess.ClientID):
		reason, code = policy.ReasonCredentialInvalid, CodePolicyDenied
	case ref.Server.Suspended() || g.reg.Resolve(ref.Public) == nil || g.reg.Resolve(ref.Public).Server != ref.Server:
		reason, code = policy.ReasonRevisionNotEnabled, CodePolicyDenied
	case g.evidenceErr() != nil:
		reason = ReasonJournalUnavailable
	case len(g.healthGate()) > 0: // E-23 critical cause (SR-6.11-1, SR-7.10-1)
		reason = ReasonFailClosed
	}
	if reason != "" {
		return "", c.refuse(gatewayError(code, "launch refused", reason, c.corr, c.dec.ID, nil),
			"call", audit.PhaseDenied, "E-12", "deny", reason, "evaluated")
	}
	if err := c.commit("decision", audit.PhaseAuthorized, "E-12", "permit", c.dec.ReasonCode, "evaluated", c.decisionDetail()); err != nil {
		return "", c.auditFailure(err)
	}
	capID := g.caps.Issue(b)
	if err := dispatched(); err != nil {
		return "", err
	}
	return capID, nil
}

// authorizeRelease rechecks session and stop state under the barrier and
// commits the delivered event before the result is released.
func (g *Gateway) authorizeRelease(c *callRun, sessionID string) error {
	g.gate.RLock()
	defer g.gate.RUnlock()
	reason := ""
	switch {
	case g.stopped.Load() && !g.draining.Load(): // a drain (SR-7.7-1) lets calls in flight finish
		reason = ReasonEmergencyStop
	case !g.store.IsActive(sessionID):
		reason = ReasonSessionState
	}
	if reason != "" {
		// Table B.2: every failed release recheck is RELEASE_REFUSED; the
		// cause is in the event detail.
		if aerr := c.commit("call", audit.PhaseWithheld, "E-12", "withhold", ReasonReleaseRefused, "evaluated", map[string]any{"cause": reason}); aerr != nil {
			c.g.log.Error("evidence write failed", "err", aerr, "correlation", c.corr)
		}
		return gatewayError(CodeResponseWithheld, "response withheld", ReasonReleaseRefused, c.corr, c.dec.ID, nil)
	}
	if err := c.commit("call", audit.PhaseDelivered, "E-12", "release", "", "evaluated", nil); err != nil {
		// SR-6.3-1: without a durable outcome record the result is withheld.
		c.g.log.Error("evidence write failed; withholding result", "err", err, "correlation", c.corr)
		return gatewayError(CodeResponseWithheld, "response withheld: evidence unavailable", ReasonOutcomeUnrecorded, c.corr, c.dec.ID, nil)
	}
	return nil
}

// argumentsChanged reports whether request inspection changed the
// arguments, comparing canonical forms so that formatting is ignored.
func argumentsChanged(before, after json.RawMessage) bool {
	norm := func(b json.RawMessage) string {
		if len(bytes.TrimSpace(b)) == 0 || string(bytes.TrimSpace(b)) == "null" {
			return "{}"
		}
		c, err := policy.Canonical(b)
		if err != nil {
			return string(b)
		}
		return string(c)
	}
	return norm(before) != norm(after)
}

// argumentsDigest is the SHA-256 of a call's canonicalized arguments
// (FR-4.1): object keys sorted, insignificant whitespace removed. Absent or
// null arguments are the empty object; arguments that are not JSON are
// hashed as sent (the request filters refuse them).
func argumentsDigest(args json.RawMessage) string {
	b := bytes.TrimSpace(args)
	if len(b) == 0 || string(b) == "null" {
		b = []byte("{}")
	}
	if c, err := policy.Canonical(b); err == nil {
		b = c
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// policyRequest builds the request the Policy Decision Service evaluates:
// the canonical request subset, the arguments for rule predicates
// (SR-1.7-1), the prerequisites it checks (SR-1.5-1: principal enabled,
// session active, server revision enabled), the eligible routes
// (SR-1.11-1: the server alias, while the revision serves the tool) and
// the server's risk classes (SR-3.13-1). Credential revocation ends the
// credential's sessions, so it reaches the decision as an inactive
// session.
func (g *Gateway) policyRequest(sess session.Session, ref *backend.ToolRef, side, trust string, args json.RawMessage) policy.Request {
	r := policy.Request{PrincipalID: sess.PrincipalID, SessionID: sess.ID, Profile: sess.Profile, Template: sess.Template,
		Server: ref.Server.Alias, Tool: ref.Tool.Name, SideEffect: side, SourceTrust: trust, Arguments: args,
		SessionInactive: !g.store.IsActive(sess.ID), RevisionNotEnabled: ref.Server.Suspended(),
		RoutesKnown: true, RiskClasses: ref.Server.RiskClasses()}
	r.PrincipalDisabled = g.principalDisabled(sess.PrincipalID)
	if live := g.reg.Resolve(ref.Public); live != nil && live.Server == ref.Server && !ref.Server.Suspended() {
		r.Routes = []string{ref.Server.Alias}
	}
	return r
}

// principalDisabled reports whether the principal is disabled or suspended.
func (g *Gateway) principalDisabled(id string) bool {
	p := g.cfg.FindPrincipal(id)
	return p != nil && p.Enabled != nil && !*p.Enabled
}

// mapDispatchError maps a dispatcher error to an Appendix B error and
// writes the terminal event (failed, indeterminate, withheld or denied) for
// every path.
func (g *Gateway) mapDispatchError(c *callRun, sessionID string, err error) error {
	corr, dec := c.corr, c.dec
	var be *backend.BackendError
	var ce *backend.CapabilityError
	var we *jsonrpc.Error
	switch {
	case errors.As(err, &ce):
		return c.refuse(gatewayError(CodeGatewayFailClosed, "dispatch refused", ReasonCapability, corr, dec.ID, nil),
			"call", audit.PhaseDenied, "E-10", "deny", ReasonCapability, "evaluated")
	case errors.As(err, &be): // FR-1.32
		return c.refuse(gatewayError(CodeBackendError, "backend error", "BACKEND_ERROR", corr, dec.ID, map[string]any{"backendCode": be.Code}),
			"call", audit.PhaseFailed, "E-10", "backend_error", "BACKEND_ERROR", "evaluated")
	case errors.Is(err, backend.ErrQueueFull):
		return c.refuse(gatewayError(CodeRateLimited, "dispatch queue full", "QUEUE_FULL", corr, dec.ID, nil),
			"call", audit.PhaseDenied, "E-10", "deny", "QUEUE_FULL", "evaluated")
	case errors.Is(err, backend.ErrTimeout):
		return c.refuse(gatewayError(CodeIndeterminate, "upstream timeout", "UPSTREAM_TIMEOUT", corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-10", "timeout", "UPSTREAM_TIMEOUT", "evaluated")
	case errors.Is(err, backend.ErrTooLarge):
		return c.refuse(gatewayError(CodeResponseWithheld, "response withheld", "RESULT_TOO_LARGE", corr, dec.ID, nil),
			"call", audit.PhaseWithheld, "E-11", "withhold", "RESULT_TOO_LARGE", "evaluated")
	case errors.Is(err, backend.ErrInputRequired): // FR-5.24; the MRTR Relay Profile is not implemented
		return c.refuse(gatewayError(CodeInputRequired, "input required", "INPUT_REQUIRED_UNSUPPORTED", corr, dec.ID, nil),
			"call", audit.PhaseFailed, "E-10", "input_required", "INPUT_REQUIRED_UNSUPPORTED", "evaluated")
	case errors.Is(err, backend.ErrInvalidResult): // FR-5.23, SR-5.20-1: nothing of the result is released
		return c.refuse(gatewayError(CodeResponseWithheld, "response withheld", "RESULT_INVALID", corr, dec.ID, nil),
			"call", audit.PhaseWithheld, "E-11", "withhold", "RESULT_INVALID", "evaluated")
	case errors.Is(err, backend.ErrInvalidOutput): // FR-5.14: the instance is replaced
		phase := audit.PhaseFailed
		if policy.TaintGated(dec.SideEffect) { // the tool may have acted (SR-7.2-1)
			phase = audit.PhaseIndeterminate
		}
		return c.refuse(gatewayError(CodeBackendError, "backend protocol error", "BACKEND_OUTPUT_INVALID", corr, dec.ID, nil),
			"call", phase, "E-10", "failed", "BACKEND_OUTPUT_INVALID", "evaluated")
	case errors.Is(err, backend.ErrInstanceFailed) && policy.TaintGated(dec.SideEffect):
		// SR-7.2-1: a tool of side-effect class write, external or execute
		// (or unclassified) lost its outcome; it is not retried.
		return c.refuse(gatewayError(CodeIndeterminate, "instance failed", "INSTANCE_FAILED", corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-10", "indeterminate", "INSTANCE_FAILED", "evaluated")
	case errors.Is(err, context.DeadlineExceeded):
		return c.refuse(gatewayError(CodeTimeout, "client deadline expired", "CLIENT_DEADLINE", corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-10", "timeout", "CLIENT_DEADLINE", "evaluated")
	case errors.Is(err, context.Canceled) && g.stopped.Load():
		// SR-7.6-2: the emergency stop cancelled the call. As for a call
		// whose release the stop refuses (SR-1.17-2), nothing is released;
		// the backend may have acted before the cancellation reached it.
		return c.refuse(gatewayError(CodeResponseWithheld, "call cancelled by emergency stop", ReasonEmergencyStop, corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-12", "cancelled", ReasonEmergencyStop, "evaluated")
	case errors.Is(err, context.Canceled) && !g.store.IsActive(sessionID):
		return c.refuse(gatewayError(CodeSessionInvalid, "session ended during the call", ReasonSessionEnded, corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-04", "cancelled", ReasonSessionEnded, "evaluated")
	case errors.Is(err, context.Canceled):
		return c.refuse(gatewayError(CodeIndeterminate, "call cancelled", "CANCELLED", corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-10", "cancelled", "CANCELLED", "evaluated")
	case errors.As(err, &we):
		return c.refuse(we, "call", audit.PhaseFailed, "E-10", "failed", "INVALID_ARGUMENTS", "evaluated")
	}
	g.log.Warn("dispatch failed", "server_revision", c.base.ServerRevision, "err", err)
	return c.refuse(gatewayError(CodeBackendError, "dispatch failed", "DISPATCH_FAILED", corr, dec.ID, nil),
		"call", audit.PhaseFailed, "E-10", "failed", "DISPATCH_FAILED", "evaluated")
}

// toolClasses returns the side-effect class and source trust a verified
// manifest declares for the tool. An unverified (live) tool list is the
// server describing itself, so it classifies nothing.
func toolClasses(ref *backend.ToolRef) (side, trust string) {
	if !ref.Server.Verified || ref.Tool == nil {
		return "", ""
	}
	side, _ = ref.Tool.Meta[policy.MetaSideEffect].(string)
	trust, _ = ref.Tool.Meta[policy.MetaSourceTrust].(string)
	return side, trust
}
