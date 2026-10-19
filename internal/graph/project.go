package graph

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// mirrorLabels are the labels the evidence mirror writes. Rebuild removes
// exactly these.
var mirrorLabels = []string{"AuditEvent", "Session", "Principal", "Invocation", "Decision", "PolicyRevision", "PolicyControl",
	"ServerRevision", "ToolRevision", "Approval", "RuleRevision", "PolicyObject"}

// labelProps is the property allowlist per mirrored label (Appendix D key
// properties plus the mirror's bookkeeping). Community Edition has no
// property existence constraints, so the Data Access Service enforces
// these; id, firstSeen and lastSeen are maintained by the templates.
var labelProps = map[string]map[string]bool{
	"AuditEvent": set("ts", "time", "class", "phase", "origin", "originLabel", "outcome", "reasonCode", "policyStatus", "correlationId",
		"sessionId", "principalId", "decisionId", "serverRevision", "toolRevision", "policyRevision"),
	"Session":        set("principalId", "state", "revisionId", "endReason", "observationPolicyId", "contextKey"),
	"Principal":      set(),
	"Invocation":     set("sessionId", "principalId", "serverRevision", "toolRevision", "phase", "outcome", "reasonCode"),
	"Decision":       set("ts", "outcome", "reasonCode", "revisionId", "correlationId", "sessionId"),
	"PolicyRevision": set("activatedAt"),
	"PolicyControl":  set("activeRevisionId"),
	"ServerRevision": set(),
	"ToolRevision":   set("name"),
	"Approval":       set("sessionId", "state", "argsDigest", "expiresAt", "approver", "publicName", "correlationId"),
	"RuleRevision":   set("parentId"),
	"PolicyObject":   set("type"),
}

func set(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// nodeRow is one node upsert of a projection.
type nodeRow struct {
	label string
	id    string
	ts    int64
	props map[string]any
}

// linkRow is one relationship of a projection.
type linkRow struct {
	op       string // link.<From>.<REL>.<To>
	from, to string
}

// projection is the graph form of a batch of evidence events.
type projection struct {
	nodes []nodeRow
	links []linkRow
}

// eventTS is the event time in Unix nanoseconds, or 0 when unparsable.
func eventTS(ev audit.Event) int64 {
	t, err := time.Parse(time.RFC3339Nano, ev.Time)
	if err != nil {
		return 0
	}
	return t.UnixNano()
}

// strList reads a list of strings from a decoded or in-process detail
// value.
func strList(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// maxRuleLinks bounds the rule revisions one decision event projects.
const maxRuleLinks = 256

func detailMap(d any) map[string]any {
	if d == nil {
		return nil
	}
	if m, ok := d.(map[string]any); ok {
		return m
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

const maxPropString = 4096

// props builds a property map without empty values; long strings are cut.
func props(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		k := kv[i].(string)
		switch v := kv[i+1].(type) {
		case string:
			if len(v) > maxPropString {
				v = v[:maxPropString]
			}
			if v != "" {
				m[k] = v
			}
		case int64:
			m[k] = v
		case nil:
		default:
			m[k] = v
		}
	}
	return m
}

// callClasses are the event classes that belong to one tool call
// (invocation) when they carry a correlation ID.
var callClasses = map[string]bool{"call": true, "decision": true, "filter": true, "approval": true}

// add projects one event. It is deterministic in the event, so applying
// it again changes nothing (idempotent by event ID).
func (p *projection) add(ev audit.Event) {
	if ev.EventID == "" {
		return
	}
	ts := eventTS(ev)
	node := func(label, id string, pr map[string]any) {
		if id != "" && len(id) <= MaxStringParam {
			p.nodes = append(p.nodes, nodeRow{label: label, id: id, ts: ts, props: pr})
		}
	}
	link := func(op, from, to string) {
		if from != "" && to != "" && len(from) <= MaxStringParam && len(to) <= MaxStringParam {
			p.links = append(p.links, linkRow{op: op, from: from, to: to})
		}
	}
	node("AuditEvent", ev.EventID, props("ts", ts, "time", ev.Time, "class", ev.Class, "phase", string(ev.Phase), "origin", ev.Origin,
		"originLabel", audit.OriginLabel(ev), "outcome", ev.Outcome, "reasonCode", ev.ReasonCode, "policyStatus", ev.PolicyStatus, "correlationId", ev.CorrelationID,
		"sessionId", ev.SessionID, "principalId", ev.PrincipalID, "decisionId", ev.DecisionID, "serverRevision", ev.ServerRevision,
		"toolRevision", ev.ToolRevision, "policyRevision", ev.PolicyRevision))

	if ev.PrincipalID != "" {
		node("Principal", ev.PrincipalID, props())
	}
	if ev.SessionID != "" {
		sp := props("principalId", ev.PrincipalID)
		if ev.Class == "session" {
			sp = props("principalId", ev.PrincipalID, "state", ev.Outcome, "endReason", ev.ReasonCode, "revisionId", ev.PolicyRevision)
			if d := detailMap(ev.Detail); ev.Outcome == "created" && d != nil {
				// FR-2.13: the Observation Policy and baseline context key
				// recorded at creation.
				op, _ := d["observation_policy"].(string)
				ck, _ := d["context_key"].(string)
				sp = props("principalId", ev.PrincipalID, "state", ev.Outcome, "endReason", ev.ReasonCode, "revisionId", ev.PolicyRevision,
					"observationPolicyId", op, "contextKey", ck)
			}
		}
		node("Session", ev.SessionID, sp)
		link("link.AuditEvent.IN_SESSION.Session", ev.EventID, ev.SessionID)
		link("link.Session.OF_PRINCIPAL.Principal", ev.SessionID, ev.PrincipalID)
	}
	if ev.PolicyRevision != "" {
		pp := props()
		if ev.Class == "admin" && ev.ReasonCode == "POLICY_ACTIVATED" {
			pp = props("activatedAt", ts)
		}
		node("PolicyRevision", ev.PolicyRevision, pp)
		link("link.AuditEvent.RECORDED_UNDER.PolicyRevision", ev.EventID, ev.PolicyRevision)
		if (ev.Class == "admin" && ev.ReasonCode == "POLICY_ACTIVATED") || (ev.Class == "gateway" && ev.Outcome == "started") {
			node("PolicyControl", "control", props("activeRevisionId", ev.PolicyRevision))
		}
	}
	if ev.ServerRevision != "" {
		node("ServerRevision", ev.ServerRevision, props())
		// SR-6.5-1: a backend is linked as observed only by events of a
		// call the Gateway exchanged messages with it for.
		if audit.BackendObserved(ev) {
			link("link.AuditEvent.OBSERVED_FROM.ServerRevision", ev.EventID, ev.ServerRevision)
		}
	}
	if ev.ToolRevision != "" {
		name := ev.ToolRevision
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		node("ToolRevision", ev.ToolRevision, props("name", name))
		link("link.ToolRevision.BELONGS_TO.ServerRevision", ev.ToolRevision, ev.ServerRevision)
	}
	inv := ""
	if ev.CorrelationID != "" && callClasses[ev.Class] {
		inv = ev.CorrelationID
		node("Invocation", inv, props("sessionId", ev.SessionID, "principalId", ev.PrincipalID, "serverRevision", ev.ServerRevision,
			"toolRevision", ev.ToolRevision, "phase", string(ev.Phase), "outcome", ev.Outcome, "reasonCode", ev.ReasonCode))
		link("link.AuditEvent.FOR_INVOCATION.Invocation", ev.EventID, inv)
		link("link.Invocation.IN_SESSION.Session", inv, ev.SessionID)
		link("link.Invocation.INVOKED.ToolRevision", inv, ev.ToolRevision)
	}
	if ev.DecisionID != "" {
		dp := props("correlationId", ev.CorrelationID, "sessionId", ev.SessionID, "revisionId", ev.PolicyRevision)
		if ev.Class == "decision" {
			dp = props("correlationId", ev.CorrelationID, "sessionId", ev.SessionID, "revisionId", ev.PolicyRevision,
				"ts", ts, "outcome", ev.Outcome, "reasonCode", ev.ReasonCode)
		}
		node("Decision", ev.DecisionID, dp)
		link("link.AuditEvent.FOR_DECISION.Decision", ev.EventID, ev.DecisionID)
		link("link.Decision.IN_SESSION.Session", ev.DecisionID, ev.SessionID)
		link("link.Decision.EVALUATED_UNDER.PolicyRevision", ev.DecisionID, ev.PolicyRevision)
		link("link.Decision.TARGETED.ServerRevision", ev.DecisionID, ev.ServerRevision)
		if ev.Class == "decision" && ev.Phase == audit.PhaseAuthorized {
			link("link.Invocation.AUTHORIZED_BY.Decision", inv, ev.DecisionID)
		}
		if ev.Class == "decision" {
			p.decisionLinks(ev, node, link)
		}
	}
	if ev.Class == "approval" {
		d := detailMap(ev.Detail)
		id, _ := d["approval_id"].(string)
		if id != "" {
			approver, _ := d["approver"].(string)
			if approver == "" {
				approver, _ = d["actor"].(string)
			}
			pub, _ := d["public_name"].(string)
			digest, _ := d["arguments_digest"].(string)
			exp, _ := d["expires_at"].(string)
			node("Approval", id, props("sessionId", ev.SessionID, "state", ev.Outcome, "argsDigest", digest, "expiresAt", exp,
				"approver", approver, "publicName", pub, "correlationId", ev.CorrelationID))
			link("link.Approval.FOR_INVOCATION.Invocation", id, inv)
			link("link.Approval.IN_SESSION.Session", id, ev.SessionID)
		}
	}
}

// decisionLinks projects the decision record of a decision event (SR-6.4-1):
// the considered, applicable and decisive rule revisions of the decision,
// each contained in the decision's policy revision, and the effective
// Audit Profile revision the event was recorded under.
func (p *projection) decisionLinks(ev audit.Event, node func(string, string, map[string]any), link func(string, string, string)) {
	d := detailMap(ev.Detail)
	if d == nil {
		return
	}
	for _, k := range []struct{ key, rel string }{
		{"considered_rules", "CONSIDERED_RULE"}, {"applicable_rules", "APPLICABLE_RULE"}, {"decisive_rules", "DECIDED_BY"},
	} {
		rules := strList(d[k.key])
		if len(rules) > maxRuleLinks {
			rules = rules[:maxRuleLinks]
		}
		for _, r := range rules {
			node("RuleRevision", r, props("parentId", ev.PolicyRevision))
			link("link.PolicyRevision.CONTAINS.RuleRevision", ev.PolicyRevision, r)
			link("link.Decision."+k.rel+".RuleRevision", ev.DecisionID, r)
		}
	}
	ob, _ := d["obligations"].(map[string]any)
	if ap, _ := ob["audit_profile"].(string); ap != "" {
		node("PolicyObject", ap, props("type", "audit_profile"))
		link("link.AuditEvent.RECORDED_UNDER.PolicyObject", ev.EventID, ap)
	}
}
