// Package policy is the slice of the Policy Administration Service (E-05) and
// Policy Decision Service (E-06): a schema-validated policy document
// (FR-3.2) compiled into an in-memory decision snapshot (FR-3.10), evaluated
// deterministically with default deny (SR-1.3-1), deny precedence and a
// decision record (FR-3.11). Only two of the nine policy object types exist
// in the slice: Framework Profiles and Session Allow Policy Templates.
package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

//go:embed policy.schema.json
var schemaJSON []byte

// Document is the policy file as written.
type Document struct {
	Revision          string                      `json:"revision"`
	FrameworkProfiles map[string]FrameworkProfile `json:"framework_profiles"`
	Templates         map[string]Template         `json:"templates"`
}

// FrameworkProfile binds a framework instance to the templates it may use
// (ARCH §7.1 layer 2).
type FrameworkProfile struct {
	Templates       []string `json:"templates"`
	DefaultTemplate string   `json:"default_template"`
	CallsPerMinute  int      `json:"calls_per_minute,omitempty"`
}

// Template is a Session Allow Policy Template (ARCH §7.1 layer 3).
type Template struct {
	Description    string `json:"description,omitempty"`
	CallsPerMinute int    `json:"calls_per_minute,omitempty"`
	Rules          []Rule `json:"rules"`
}

// Rule permits the named backend tools of one server alias. Everything not
// named by a rule is denied.
type Rule struct {
	ID             string   `json:"id"`
	Server         string   `json:"server"`
	Tools          []string `json:"tools"`
	Approval       bool     `json:"approval,omitempty"`
	CallsPerMinute int      `json:"calls_per_minute,omitempty"`
}

// Snapshot is the compiled, immutable decision snapshot of one revision.
type Snapshot struct {
	Revision string
	Digest   string
	Profiles map[string]FrameworkProfile
	// grants[template][server][tool] -> rule
	grants map[string]map[string]map[string]*Rule
	// rulesByTemplate keeps the declared order for considered-rule reporting.
	rulesByTemplate map[string][]*Rule
	templateRate    map[string]int
}

// Grant is one permitted (server, tool) pair of a template with its rule.
type Grant struct {
	Server string
	Tool   string
	Rule   *Rule
}

// Load reads and compiles the policy file.
func Load(path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := Compile(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Compile validates the document against the schema and the publication
// invariants the slice can check (ARCH §7.3), then compiles it.
func Compile(raw []byte) (*Snapshot, error) {
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("policy.schema.json", schemaDoc); err != nil {
		return nil, err
	}
	sch, err := c.Compile("policy.schema.json")
	if err != nil {
		return nil, err
	}
	if err := sch.Validate(generic); err != nil {
		return nil, fmt.Errorf("policy does not match schema: %w", err)
	}
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	for name, p := range doc.FrameworkProfiles {
		found := false
		for _, t := range p.Templates {
			if _, ok := doc.Templates[t]; !ok {
				return nil, fmt.Errorf("framework profile %q names unknown template %q", name, t)
			}
			if t == p.DefaultTemplate {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("framework profile %q: default_template %q is not in its templates", name, p.DefaultTemplate)
		}
	}
	digest := sha256.Sum256(raw)
	s := &Snapshot{
		Revision:        doc.Revision,
		Digest:          hex.EncodeToString(digest[:]),
		Profiles:        doc.FrameworkProfiles,
		grants:          map[string]map[string]map[string]*Rule{},
		rulesByTemplate: map[string][]*Rule{},
		templateRate:    map[string]int{},
	}
	for tname, t := range doc.Templates {
		s.templateRate[tname] = t.CallsPerMinute
		byServer := map[string]map[string]*Rule{}
		ruleIDs := map[string]bool{}
		for i := range t.Rules {
			r := &t.Rules[i]
			if ruleIDs[r.ID] {
				return nil, fmt.Errorf("template %q: duplicate rule id %q", tname, r.ID)
			}
			ruleIDs[r.ID] = true
			s.rulesByTemplate[tname] = append(s.rulesByTemplate[tname], r)
			tools := byServer[r.Server]
			if tools == nil {
				tools = map[string]*Rule{}
				byServer[r.Server] = tools
			}
			for _, tool := range r.Tools {
				if prev, dup := tools[tool]; dup {
					// Overlapping permits are rejected at publication (ARCH §7.3).
					return nil, fmt.Errorf("template %q: rules %q and %q both permit %s/%s", tname, prev.ID, r.ID, r.Server, tool)
				}
				tools[tool] = r
			}
		}
		s.grants[tname] = byServer
	}
	return s, nil
}

// HasTemplate reports whether the snapshot defines the template.
func (s *Snapshot) HasTemplate(name string) bool { _, ok := s.grants[name]; return ok }

// Grants lists every (server, tool) a template permits, sorted.
func (s *Snapshot) Grants(template string) []Grant {
	var out []Grant
	for server, tools := range s.grants[template] {
		for tool, rule := range tools {
			out = append(out, Grant{server, tool, rule})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// Outcome of a decision.
const (
	Permit = "permit"
	Deny   = "deny"
)

// Reason codes (Appendix B data.reasonCode values used by this slice).
const (
	ReasonPermit       = "PERMIT"
	ReasonNoPermit     = "NO_PERMIT" // SR-1.3-1
	ReasonNoTemplate   = "NO_TEMPLATE"
	ReasonRateLimited  = "RATE_LIMITED"
	ReasonNoSnapshot   = "NO_SNAPSHOT" // SR-1.2-1
	ReasonSessionState = "SESSION_STATE"
)

// Obligations the slice can express (FR-3.12 subset).
type Obligations struct {
	Approval       bool
	CallsPerMinute int
}

// Decision is the FR-3.11 record.
type Decision struct {
	ID              string
	Outcome         string
	ReasonCode      string
	ConsideredRules []string
	ApplicableRules []string
	DecisiveRules   []string
	Obligations     Obligations
	Route           string // server alias
	PolicyRevision  string
	Duration        time.Duration
}

// Request is the canonical request subset E-06 evaluates.
type Request struct {
	PrincipalID string
	SessionID   string
	Template    string
	Server      string
	Tool        string
}

// Decider evaluates requests against the current snapshot and keeps the
// sliding-window rate counters of FR-3.13.
type Decider struct {
	mu       sync.RWMutex
	snap     *Snapshot
	now      func() time.Time
	counters map[string][]time.Time
	defRate  int
}

// NewDecider returns a decider with the given snapshot (may be nil, which
// denies everything with NO_SNAPSHOT) and CP-11 default principal rate.
func NewDecider(snap *Snapshot, defaultCallsPerMinute int) *Decider {
	return &Decider{snap: snap, now: time.Now, counters: map[string][]time.Time{}, defRate: defaultCallsPerMinute}
}

// SetNow replaces the clock (tests).
func (d *Decider) SetNow(f func() time.Time) { d.mu.Lock(); d.now = f; d.mu.Unlock() }

// Snapshot returns the active snapshot.
func (d *Decider) Snapshot() *Snapshot { d.mu.RLock(); defer d.mu.RUnlock(); return d.snap }

// Activate swaps in a new snapshot atomically (FR-3.10).
func (d *Decider) Activate(s *Snapshot) { d.mu.Lock(); d.snap = s; d.mu.Unlock() }

// Decide evaluates one request. It is deterministic given the snapshot and
// the counter state; it never consults anything but the snapshot.
func (d *Decider) Decide(req Request) Decision {
	start := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	dec := Decision{ID: ids.New(), Outcome: Deny}
	if d.snap == nil {
		dec.ReasonCode = ReasonNoSnapshot
		dec.Duration = time.Since(start)
		return dec
	}
	dec.PolicyRevision = d.snap.Revision
	rules := d.snap.rulesByTemplate[req.Template]
	if _, ok := d.snap.grants[req.Template]; !ok {
		dec.ReasonCode = ReasonNoTemplate
		dec.Duration = time.Since(start)
		return dec
	}
	for _, r := range rules {
		dec.ConsideredRules = append(dec.ConsideredRules, r.ID)
	}
	rule := d.snap.grants[req.Template][req.Server][req.Tool]
	if rule == nil {
		dec.ReasonCode = ReasonNoPermit
		dec.Duration = time.Since(start)
		return dec
	}
	dec.ApplicableRules = []string{rule.ID}
	// Rate bound: smallest applicable of rule, template, profile and CP-11.
	limit := d.defRate
	for _, v := range []int{rule.CallsPerMinute, d.snap.templateRate[req.Template]} {
		if v > 0 && v < limit {
			limit = v
		}
	}
	if !d.allowLocked("p:"+req.PrincipalID, limit) || !d.allowLocked("s:"+req.SessionID, limit) || !d.allowLocked("t:"+req.SessionID+"/"+req.Server+"/"+req.Tool, limit) {
		dec.ReasonCode = ReasonRateLimited
		dec.DecisiveRules = []string{rule.ID}
		dec.Obligations.CallsPerMinute = limit
		dec.Duration = time.Since(start)
		return dec
	}
	dec.Outcome = Permit
	dec.ReasonCode = ReasonPermit
	dec.DecisiveRules = []string{rule.ID}
	dec.Obligations = Obligations{Approval: rule.Approval, CallsPerMinute: limit}
	dec.Route = req.Server
	dec.Duration = time.Since(start)
	return dec
}

// allowLocked implements a one-minute sliding window per key and records the
// call when within the limit.
func (d *Decider) allowLocked(key string, limit int) bool {
	now := d.now()
	cut := now.Add(-time.Minute)
	ts := d.counters[key]
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	ts = ts[i:]
	if len(ts) >= limit {
		d.counters[key] = ts
		return false
	}
	d.counters[key] = append(ts, now)
	return true
}
