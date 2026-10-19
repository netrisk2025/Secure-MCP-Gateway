package library

import (
	"net/http"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// Reason codes of classification overrides (SR-3.11-1).
const (
	ReasonOverridden   = "CLASSIFICATION_OVERRIDDEN"
	ReasonLoosening    = "CLASSIFICATION_LOOSENING_REFUSED"
	ReasonOverrideTool = "CLASSIFICATION_TOOL_UNKNOWN"
)

// ToolOverride is an operator's classification of one tool of a revision.
// Each field may only make the manifest's classification more restrictive
// (SR-3.11-1); empty fields keep the manifest's value.
type ToolOverride struct {
	SideEffect  string `json:"side_effect,omitempty"`
	SourceTrust string `json:"source_trust,omitempty"`
	RiskClass   string `json:"risk_class,omitempty"`
	By          string `json:"by,omitempty"`
}

var (
	sideRank = map[string]int{policy.SideRead: 0, policy.SideWrite: 1, policy.SideExternal: 2, policy.SideExecute: 3}
	riskRank = map[string]int{"low": 0, "moderate": 1, "high": 2}
)

// SetOverride records a classification override for a tool of a revision.
// The manifest's classification stays as signed; an override that would
// loosen any of side-effect class, source trust or risk class is refused
// (SR-3.11-1). The new classification applies when the revision's tools
// are next presented (at the next start of its instance).
func (l *Library) SetOverride(id, rev, tool string, ov ToolOverride) (ToolOverride, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.find(id, rev)
	if r == nil {
		return ToolOverride{}, errf(ReasonUnknown, "no revision %s@%s", id, rev)
	}
	m, _, err := l.Manifest(id, rev)
	if err != nil {
		return ToolOverride{}, err
	}
	mt := m.Find(tool)
	if mt == nil {
		return ToolOverride{}, errf(ReasonOverrideTool, "revision %s@%s has no tool %q", id, rev, tool)
	}
	refuse := func(field, from, to string) (ToolOverride, error) {
		_ = l.evidence(audit.Event{Origin: "E-14", Outcome: "refused", ReasonCode: ReasonLoosening, ServerRevision: r.Key(),
			Detail: map[string]any{"tool": tool, "field": field, "manifest": from, "requested": to, "actor": ov.By}})
		return ToolOverride{}, errf(ReasonLoosening, "%s of %s may only become more restrictive: the manifest says %q, the override %q", field, tool, from, to)
	}
	if ov.SideEffect != "" {
		if _, ok := sideRank[ov.SideEffect]; !ok || sideRank[ov.SideEffect] < sideRank[mt.SideEffect] {
			return refuse("side_effect", mt.SideEffect, ov.SideEffect)
		}
	}
	if ov.SourceTrust != "" && (ov.SourceTrust != policy.TrustTrusted && ov.SourceTrust != policy.TrustUntrusted ||
		ov.SourceTrust == policy.TrustTrusted && mt.SourceTrust == policy.TrustUntrusted) {
		return refuse("source_trust", mt.SourceTrust, ov.SourceTrust)
	}
	if ov.RiskClass != "" {
		base := mt.RiskClass
		if base == "" {
			base = m.RiskClass
		}
		if _, ok := riskRank[ov.RiskClass]; !ok || riskRank[ov.RiskClass] < riskRank[base] {
			return refuse("risk_class", base, ov.RiskClass)
		}
	}
	if r.Overrides == nil {
		r.Overrides = map[string]ToolOverride{}
	}
	r.Overrides[tool] = ov
	if err := l.save(); err != nil {
		return ToolOverride{}, err
	}
	if err := l.evidence(audit.Event{Origin: "E-14", Outcome: "overridden", ReasonCode: ReasonOverridden, ServerRevision: r.Key(),
		Detail: map[string]any{"tool": tool, "side_effect": ov.SideEffect, "source_trust": ov.SourceTrust, "risk_class": ov.RiskClass, "actor": ov.By}}); err != nil {
		return ToolOverride{}, err
	}
	return ov, nil
}

// applyClassification puts each tool's effective side-effect class and
// source trust (the manifest's, tightened by any override) on its
// metadata, where the decision reads them (SR-3.11-1, SR-1.18-1).
func applyClassification(tools []*mcp.Tool, r *Revision, find func(string) (side, trust string, ok bool)) {
	for _, t := range tools {
		side, trust, ok := find(t.Name)
		if !ok {
			continue
		}
		if ov, has := r.Overrides[t.Name]; has {
			side = policy.EffectiveSideEffect(side, ov.SideEffect)
			trust = policy.EffectiveSourceTrust(trust, ov.SourceTrust)
		}
		if t.Meta == nil {
			t.Meta = mcp.Meta{}
		}
		t.Meta[policy.MetaSideEffect], t.Meta[policy.MetaSourceTrust] = side, trust
	}
}

// apiOverride serves POST /api/v1/packages/{id}/{rev}/classification:
// {"tool", "side_effect"?, "source_trust"?, "risk_class"?}.
func (rt *Runtime) apiOverride(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tool        string `json:"tool"`
		SideEffect  string `json:"side_effect"`
		SourceTrust string `json:"source_trust"`
		RiskClass   string `json:"risk_class"`
	}
	if err := decodeBody(r, &body); err != nil || body.Tool == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "bad_request",
			"message": "body must be {tool, side_effect?, source_trust?, risk_class?}"}})
		return
	}
	ov, err := rt.lib.SetOverride(r.PathValue("id"), r.PathValue("rev"), body.Tool,
		ToolOverride{SideEffect: body.SideEffect, SourceTrust: body.SourceTrust, RiskClass: body.RiskClass, By: adminapi.Actor(r)})
	if err != nil {
		writeErr(w, err)
		return
	}
	got, _ := rt.lib.Get(r.PathValue("id"), r.PathValue("rev"))
	tools := make([]string, 0, len(got.Overrides))
	for t := range got.Overrides {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	writeJSON(w, http.StatusOK, map[string]any{"tool": body.Tool, "override": ov, "overridden_tools": tools, "restart_required": true})
}
