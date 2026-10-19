// Package perf is the reference workload of SRS FR-11.1 and the
// measurements of the FR-11 performance requirements: it generates the
// reference dataset (a policy with 10,000 rule and registry nodes and 256
// candidate rules per decision, and an Evidence Journal of 100,000 events
// over 30 days), drives real smcpd instances with eight concurrent callers,
// and measures decision latency, capture overhead, gateway-added overhead,
// console query latency and idle memory. cmd/smcp-workload is its command;
// the CI job "perf" runs it and publishes the results in the status data.
package perf

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// Reference dataset sizes (SRS FR-11.1, SEC Appendix A).
const (
	// RefNodes is the number of rule and registry nodes.
	RefNodes = 10000
	// RefRegistryNodes are the registry nodes of the reference instance:
	// the reference server revision and its four tool revisions.
	RefRegistryNodes = 5
	// RefRules is the number of policy rules: the nodes that are not
	// registry nodes.
	RefRules = RefNodes - RefRegistryNodes
	// RefCandidates is the number of rules of the decision template that
	// name the called server (the CP-12 candidate-rule bound).
	RefCandidates = 256
	// RefEvents is the number of journal events.
	RefEvents = 100000
	// RefDays is the span of the journal.
	RefDays = 30
	// RefCallers is the number of concurrent callers.
	RefCallers = 8
)

// RefTools are the reference server's tools; the decision template's
// candidate rules include one rule for each.
var RefTools = []string{"echo", "time_now", "list_files", "read_file"}

// Dataset describes a generated dataset.
type Dataset struct {
	Rules         int `json:"rules"`
	RegistryNodes int `json:"registryNodes"`
	Candidates    int `json:"candidateRules"`
	Events        int `json:"events"`
	Days          int `json:"days"`
	Callers       int `json:"callers"`
}

// Nodes is the number of rule and registry nodes.
func (d Dataset) Nodes() int { return d.Rules + d.RegistryNodes }

// ReferencePolicy returns a policy document with rules rules in total.
// Template "read-only" (the default template of profile "dev") has
// candidates rules naming server "ref": one for each RefTools entry and
// synthetic tools for the rest, so every decision for that server
// considers candidates rules. Template "approval-demo" keeps the bootstrap
// approval rule. The remaining rules are spread over "bulk-NN" templates
// of at most 256 rules each, used by profile "bulk".
func ReferencePolicy(revision string, rules, candidates int) ([]byte, error) {
	if candidates < len(RefTools) || rules < candidates+2 {
		return nil, fmt.Errorf("perf: %d rules cannot hold %d candidates", rules, candidates)
	}
	type rule struct {
		ID       string   `json:"id"`
		Server   string   `json:"server"`
		Tools    []string `json:"tools"`
		Approval bool     `json:"approval,omitempty"`
	}
	type template struct {
		Description string `json:"description,omitempty"`
		Rules       []rule `json:"rules"`
	}
	type profile struct {
		Templates       []string `json:"templates"`
		DefaultTemplate string   `json:"default_template"`
	}
	templates := map[string]template{}
	ro := template{Description: "Reference workload decision template"}
	for i := 0; i < candidates; i++ {
		tool := fmt.Sprintf("synthetic_%04d", i)
		if i < len(RefTools) {
			tool = RefTools[i]
		}
		ro.Rules = append(ro.Rules, rule{ID: fmt.Sprintf("ro-%04d", i), Server: "ref", Tools: []string{tool}})
	}
	templates["read-only"] = ro
	templates["approval-demo"] = template{Rules: []rule{
		{ID: "demo-free", Server: "ref", Tools: []string{"echo"}},
		{ID: "demo-approve", Server: "ref", Tools: []string{"read_file"}, Approval: true},
	}}
	left := rules - candidates - 2
	var bulk []string
	for n := 0; left > 0; n++ {
		name := fmt.Sprintf("bulk-%02d", n)
		t := template{}
		for i := 0; i < 256 && left > 0; i++ {
			t.Rules = append(t.Rules, rule{ID: fmt.Sprintf("b%02d-%03d", n, i), Server: fmt.Sprintf("bulk%02d", i%16), Tools: []string{fmt.Sprintf("bulk_tool_%03d", i)}})
			left--
		}
		templates[name] = t
		bulk = append(bulk, name)
	}
	profiles := map[string]profile{"dev": {Templates: []string{"read-only", "approval-demo"}, DefaultTemplate: "read-only"}}
	if len(bulk) > 0 {
		profiles["bulk"] = profile{Templates: bulk, DefaultTemplate: bulk[0]}
	}
	doc := map[string]any{"revision": revision, "framework_profiles": profiles, "templates": templates}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return nil, err
	}
	if _, err := policy.Compile(b); err != nil {
		return nil, fmt.Errorf("perf: reference policy does not compile: %w", err)
	}
	return b, nil
}

// CountRules returns the number of rules of a policy document and the
// number of rules of template that name server.
func CountRules(doc []byte, template, server string) (total, candidates int, err error) {
	var p struct {
		Templates map[string]struct {
			Rules []struct {
				Server string `json:"server"`
			} `json:"rules"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(doc, &p); err != nil {
		return 0, 0, err
	}
	for name, t := range p.Templates {
		total += len(t.Rules)
		if name == template {
			for _, r := range t.Rules {
				if r.Server == server {
					candidates++
				}
			}
		}
	}
	return total, candidates, nil
}

// WriteJournal writes events reference events into the Evidence Journal
// of stateDir, signed with the instance's evidence key, with times spread
// evenly over the days before now: tool calls of eight principals (the
// requested, decision, dispatched, completed and delivered events of each),
// with one call in ten denied before dispatch. It must run before smcpd
// first opens the journal. It returns the number of events written.
func WriteJournal(stateDir string, events, days int, now time.Time) (int, error) {
	key, err := keys.LoadEvidenceKey(stateDir)
	if err != nil {
		return 0, err
	}
	start := now.Add(-time.Duration(days) * 24 * time.Hour)
	step := time.Duration(int64(time.Duration(days)*24*time.Hour) / int64(max(events, 1)))
	// The journal reads the clock from its own goroutines as well.
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	j, err := audit.Open(filepath.Join(stateDir, "journal"), key, audit.Options{MaxEvents: 1000, MaxAge: time.Hour,
		Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() }})
	if err != nil {
		return 0, err
	}
	rng := rand.New(rand.NewPCG(1, 2)) // #nosec G404 -- synthetic workload, not security relevant
	written := 0
	emit := func(ev audit.Event) error {
		clock.Add(int64(step))
		written++
		return j.Record(ev)
	}
	for n := 0; written < events; n++ {
		principal := fmt.Sprintf("workload-%d", n%RefCallers)
		session := fmt.Sprintf("session-%d-%d", n%RefCallers, n/500)
		corr := fmt.Sprintf("corr-%07d", n)
		dec := fmt.Sprintf("dec-%07d", n)
		tool := RefTools[rng.IntN(len(RefTools))]
		base := audit.Event{CorrelationID: corr, SessionID: session, PrincipalID: principal, ServerRevision: "smcp-ref-filesystem@ref",
			ToolRevision: "smcp-ref-filesystem@ref/" + tool, PolicyStatus: "evaluated"}
		evs := []audit.Event{}
		req := base
		req.Class, req.Phase, req.Origin, req.PolicyStatus = "call", audit.PhaseRequested, "E-02", "not_evaluated"
		req.Detail = map[string]any{"server": "ref", "tool": tool, "template": "read-only", "public_name": "ref_" + tool}
		evs = append(evs, req)
		d := base
		d.Class, d.Origin, d.DecisionID, d.PolicyRevision = "decision", "E-06", dec, "workload-r1"
		if n%10 == 9 {
			d.Phase, d.Outcome, d.ReasonCode = audit.PhaseDenied, "deny", "NO_PERMIT"
			evs = append(evs, d)
		} else {
			d.Phase, d.Outcome, d.ReasonCode = audit.PhaseAuthorized, "permit", "PERMIT"
			d.Detail = map[string]any{"decisive_rules": []any{"workload-r1/read-only/ro-0000"}, "template": "read-only"}
			evs = append(evs, d)
			for _, ph := range []audit.Phase{audit.PhaseDispatched, audit.PhaseCompleted, audit.PhaseDelivered} {
				e := base
				e.Class, e.Phase, e.Origin, e.DecisionID, e.PolicyRevision = "call", ph, "E-10", dec, "workload-r1"
				if ph != audit.PhaseDispatched {
					e.Outcome = "ok"
				}
				evs = append(evs, e)
			}
		}
		for _, e := range evs {
			if written >= events {
				break
			}
			if err := emit(e); err != nil {
				_ = j.Close()
				return written, err
			}
		}
	}
	return written, j.Close()
}
