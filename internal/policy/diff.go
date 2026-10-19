package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Change is one semantic difference between two revisions.
//
// Kind is one of profile_added, profile_removed, profile_changed,
// template_added, template_removed, template_changed, grant_added,
// grant_removed, grant_changed, deny_added, deny_removed. Before and After
// are short human-readable renderings of the changed object.
type Change struct {
	Kind     string `json:"kind"`
	Profile  string `json:"profile,omitempty"`
	Template string `json:"template,omitempty"`
	Server   string `json:"server,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

// DiffReport compares two revisions. Widening is true when the change set
// adds authority: a new grant, a removed deny rule, a removed approval
// obligation, a raised rate or quota bound, a removed filter, or a relaxed
// taint action.
type DiffReport struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Same     bool     `json:"same"`
	Widening bool     `json:"widening"`
	Changes  []Change `json:"changes"`
}

func renderProfile(p FrameworkProfile) string {
	s := fmt.Sprintf("templates=%s default=%s", strings.Join(p.Templates, ","), p.DefaultTemplate)
	if p.CallsPerMinute > 0 {
		s += fmt.Sprintf(" calls_per_minute=%d", p.CallsPerMinute)
	}
	if len(p.RemoteAllowed) > 0 {
		s += " remote_allowed=" + strings.Join(p.RemoteAllowed, ",")
	}
	return s
}

func renderTemplate(t *Template) string {
	ta := t.TaintAction
	if ta == "" {
		ta = TaintApprove
	}
	s := "taint_action=" + ta
	if t.CallsPerMinute > 0 {
		s += fmt.Sprintf(" calls_per_minute=%d", t.CallsPerMinute)
	}
	if t.CallsPerSession > 0 {
		s += fmt.Sprintf(" calls_per_session=%d", t.CallsPerSession)
	}
	return s
}

func renderRule(r *Rule) string {
	parts := []string{"rule=" + r.ID}
	if r.Approval {
		parts = append(parts, "approval")
	}
	if r.CallsPerMinute > 0 {
		parts = append(parts, fmt.Sprintf("calls_per_minute=%d", r.CallsPerMinute))
	}
	if r.CallsPerSession > 0 {
		parts = append(parts, fmt.Sprintf("calls_per_session=%d", r.CallsPerSession))
	}
	if r.SideEffect != "" {
		parts = append(parts, "side_effect="+r.SideEffect)
	}
	if r.SourceTrust != "" {
		parts = append(parts, "source_trust="+r.SourceTrust)
	}
	if len(r.Filters) > 0 {
		f := slices.Clone(r.Filters)
		sort.Strings(f)
		parts = append(parts, "filters="+strings.Join(f, ","))
	}
	if l := r.EgressLimits; l != nil {
		parts = append(parts, fmt.Sprintf("egress_limits=%d/%d/%dms", l.RequestBytes, l.ResponseBytes, l.TimeoutMS))
	}
	return strings.Join(parts, " ")
}

// obligations of a rule without its ID, so a renamed rule with the same
// obligations is not reported as changed.
func ruleObligations(r *Rule) string {
	c := *r
	c.ID = ""
	return renderRule(&c)
}

// looser reports whether bound b (0 = none) is looser than a.
func looser(a, b int) bool { return (a > 0 && b == 0) || (a > 0 && b > a) }

// egressLooser reports whether egress limits b are looser than a in any
// bound (nil sets none).
func egressLooser(a, b *EgressLimits) bool {
	if a == nil {
		return false
	}
	var z EgressLimits
	if b == nil {
		b = &z
	}
	l64 := func(x, y int64) bool { return (x > 0 && y == 0) || (x > 0 && y > x) }
	return l64(a.RequestBytes, b.RequestBytes) || l64(a.ResponseBytes, b.ResponseBytes) || l64(a.TimeoutMS, b.TimeoutMS)
}

func ruleWidens(a, b *Rule) bool {
	if a.Approval && !b.Approval {
		return true
	}
	if looser(a.CallsPerMinute, b.CallsPerMinute) || looser(a.CallsPerSession, b.CallsPerSession) {
		return true
	}
	if egressLooser(a.EgressLimits, b.EgressLimits) {
		return true
	}
	for _, f := range a.Filters {
		if !slices.Contains(b.Filters, f) {
			return true
		}
	}
	if sideRank[b.SideEffect] < sideRank[a.SideEffect] || (a.SideEffect != "" && b.SideEffect == "") {
		return true
	}
	return a.SourceTrust == TrustUntrusted && b.SourceTrust != TrustUntrusted
}

// Diff compares revision a (before) with revision b (after). Either may be
// nil, which compares against an empty policy.
func Diff(a, b *Snapshot) DiffReport {
	if a == nil {
		a = &Snapshot{}
	}
	if b == nil {
		b = &Snapshot{}
	}
	rep := DiffReport{From: a.Revision, To: b.Revision, Changes: []Change{}}
	add := func(c Change, widens bool) {
		rep.Changes = append(rep.Changes, c)
		rep.Widening = rep.Widening || widens
	}
	for _, name := range unionKeys(a.Profiles, b.Profiles) {
		pa, inA := a.Profiles[name]
		pb, inB := b.Profiles[name]
		switch {
		case !inA:
			add(Change{Kind: "profile_added", Profile: name, After: renderProfile(pb)}, true)
		case !inB:
			add(Change{Kind: "profile_removed", Profile: name, Before: renderProfile(pa)}, false)
		case renderProfile(pa) != renderProfile(pb):
			widens := looser(pa.CallsPerMinute, pb.CallsPerMinute)
			for _, t := range pb.Templates {
				widens = widens || !slices.Contains(pa.Templates, t)
			}
			for _, t := range pb.RemoteAllowed {
				widens = widens || !slices.Contains(pa.RemoteAllowed, t)
			}
			add(Change{Kind: "profile_changed", Profile: name, Before: renderProfile(pa), After: renderProfile(pb)}, widens)
		}
	}
	for _, name := range unionKeys(a.templates, b.templates) {
		ta, tb := a.templates[name], b.templates[name]
		switch {
		case ta == nil:
			add(Change{Kind: "template_added", Template: name, After: renderTemplate(tb)}, len(b.Grants(name)) > 0)
		case tb == nil:
			add(Change{Kind: "template_removed", Template: name, Before: renderTemplate(ta)}, false)
		case renderTemplate(ta) != renderTemplate(tb):
			widens := looser(ta.CallsPerMinute, tb.CallsPerMinute) || looser(ta.CallsPerSession, tb.CallsPerSession) ||
				(ta.TaintAction == TaintDeny && tb.TaintAction != TaintDeny)
			add(Change{Kind: "template_changed", Template: name, Before: renderTemplate(ta), After: renderTemplate(tb)}, widens)
		}
		ga, gb := grantMap(a, name), grantMap(b, name)
		for _, k := range unionKeys(ga, gb) {
			ra, rb := ga[k], gb[k]
			server, tool, _ := strings.Cut(k, "/")
			switch {
			case ra == nil:
				add(Change{Kind: "grant_added", Template: name, Server: server, Tool: tool, Rule: rb.ID, After: renderRule(rb)}, true)
			case rb == nil:
				add(Change{Kind: "grant_removed", Template: name, Server: server, Tool: tool, Rule: ra.ID, Before: renderRule(ra)}, false)
			case ruleObligations(ra) != ruleObligations(rb):
				add(Change{Kind: "grant_changed", Template: name, Server: server, Tool: tool, Rule: rb.ID, Before: renderRule(ra), After: renderRule(rb)}, ruleWidens(ra, rb))
			}
		}
		da, db := denyMap(a, name), denyMap(b, name)
		for _, k := range unionKeys(da, db) {
			server, tool, _ := strings.Cut(k, "/")
			switch {
			case da[k] == "":
				add(Change{Kind: "deny_added", Template: name, Server: server, Tool: tool, Rule: db[k]}, false)
			case db[k] == "":
				add(Change{Kind: "deny_removed", Template: name, Server: server, Tool: tool, Rule: da[k]}, true)
			}
		}
	}
	rep.Same = len(rep.Changes) == 0
	return rep
}

// grantMap returns "server/tool" -> permit rule of a template, before deny
// rules are applied (deny changes are reported separately).
func grantMap(s *Snapshot, template string) map[string]*Rule {
	out := map[string]*Rule{}
	for server, tools := range s.grants[template] {
		for tool, r := range tools {
			out[server+"/"+tool] = r
		}
	}
	return out
}

func denyMap(s *Snapshot, template string) map[string]string {
	out := map[string]string{}
	for server, rules := range s.denies[template] {
		for _, r := range rules {
			for _, t := range r.Tools {
				out[server+"/"+t] = r.ID
			}
		}
	}
	return out
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	var out []string
	for k := range a {
		seen[k] = true
		out = append(out, k)
	}
	for k := range b {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
