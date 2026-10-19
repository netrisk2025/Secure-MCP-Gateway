// Package policy is the policy model of the Policy Administration Service
// (E-05) and the evaluator of the Policy Decision Service (E-06): a
// schema-validated policy document (FR-3.2) compiled into an in-memory
// decision snapshot (FR-3.10), evaluated deterministically with default deny
// (SR-1.3-1), deny precedence (SR-1.4-1), a decision record (FR-3.11), rate
// and burst windows (FR-3.13, CP-11), per-session quotas, evaluation bounds
// (SR-1.20-1) and the restrict-only session taint obligation (SR-5.13-2).
// Two of the nine policy object types exist: Framework Profiles and Session
// Allow Policy Templates.
//
// The signed Policy Store (D-01) that holds published revisions is the
// policystore package; this package only validates, compiles, compares
// (Diff) and replays (Simulate) documents.
//
// The active snapshot is the policy authority. Replace swaps it atomically
// after validation; callers that must order the swap against in-flight
// launch authorizations (the Enforcement Coordinator) do so under their own
// barrier.
package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

//go:embed policy.schema.json
var schemaJSON []byte

// SchemaJSON returns the published policy schema.
func SchemaJSON() []byte { return append([]byte(nil), schemaJSON...) }

// SchemaVersion is the version of policy.schema.json; EvaluatorVersion is
// the version of the decision semantics in this file. Both are recorded with
// every published revision (FR-3.4).
const (
	SchemaVersion    = "1"
	EvaluatorVersion = "5"
)

var compiledSchema = func() *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		panic("embedded policy schema: " + err.Error())
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("policy.schema.json", doc); err != nil {
		panic(err)
	}
	s, err := c.Compile("policy.schema.json")
	if err != nil {
		panic("compile policy schema: " + err.Error())
	}
	return s
}()

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
	// Servers, when set, is the profile's authority ceiling: the server
	// aliases its sessions may reach through any of its templates. A
	// template granting a server that no profile using it permits is
	// rejected at publication (SR-1-3), and a session of this profile is
	// denied other servers even when its template names them (SR-1-2).
	Servers []string `json:"servers,omitempty"`
	// HighRisk lists the high-risk tool classes (general-sql,
	// code-execution, cad-scripting, browser-automation) the profile's
	// sessions may be granted; a grant of a server in such a class needs
	// the flag here and on the template (SR-3.13-1).
	HighRisk []string `json:"high_risk,omitempty"`
	// RemoteAllowed lists the profile's templates that sessions created
	// through the Remote Access listener may use (FR-16.12). A template
	// not listed is refused there; an empty list allows no remote session.
	RemoteAllowed []string `json:"remote_allowed,omitempty"`
}

// Template is a Session Allow Policy Template (ARCH §7.1 layer 3).
type Template struct {
	Description    string `json:"description,omitempty"`
	CallsPerMinute int    `json:"calls_per_minute,omitempty"`
	// CallsPerSession bounds the permitted calls of one session under this
	// template over its whole lifetime (quota state, ARCH §7.1 layer 5).
	CallsPerSession int `json:"calls_per_session,omitempty"`
	// TaintAction is what a tainted session gets for tools of a gated
	// side-effect class: "approve" (default) adds an approval obligation,
	// "deny" refuses the call (SR-5.13-2).
	TaintAction string `json:"taint_action,omitempty"`
	// HighRisk lists the high-risk tool classes this template may grant
	// (SR-3.13-1); see FrameworkProfile.HighRisk.
	HighRisk []string `json:"high_risk,omitempty"`
	Rules    []Rule   `json:"rules"`
}

// Rule permits (or, with effect "deny", forbids) the named backend tools of
// one server alias. Everything not named by a permit rule is denied, and a
// deny rule wins over every permit (SR-1.4-1). A deny rule may name "*" to
// cover every tool of the server. Filters names optional request and
// response filters (by filter ID) that must run on calls the rule permits;
// mandatory filters always run.
//
// SideEffect and SourceTrust classify the rule's tools for session taint.
// They combine with the verified manifest's classes restrict-only: the more
// restrictive side-effect class and "untrusted" over "trusted" win.
type Rule struct {
	ID              string   `json:"id"`
	Effect          string   `json:"effect,omitempty"`
	Server          string   `json:"server"`
	Tools           []string `json:"tools"`
	Approval        bool     `json:"approval,omitempty"`
	CallsPerMinute  int      `json:"calls_per_minute,omitempty"`
	CallsPerSession int      `json:"calls_per_session,omitempty"`
	SideEffect      string   `json:"side_effect,omitempty"`
	SourceTrust     string   `json:"source_trust,omitempty"`
	Filters         []string `json:"filters,omitempty"`
	// EgressLimits bounds each egress operation of the calls the rule
	// permits (FR-5.38); the Egress Broker applies the smallest of these,
	// the manifest's and the configuration's.
	EgressLimits *EgressLimits `json:"egress_limits,omitempty"`
	// When holds the rule's argument predicates (FR-3.6, SR-1.7-1): a
	// permit rule applies only when every one holds.
	When []Predicate `json:"when,omitempty"`
}

// EgressLimits is the egress-limit part of the egress grants obligation
// (FR-3.12, FR-5.38): request size, response size and duration of each
// outbound operation an instance makes while serving the call. Zero sets
// no bound.
type EgressLimits struct {
	RequestBytes  int64 `json:"request_bytes,omitempty"`
	ResponseBytes int64 `json:"response_bytes,omitempty"`
	TimeoutMS     int64 `json:"timeout_ms,omitempty"`
}

// Timeout returns the duration bound (0 when none).
func (l *EgressLimits) Timeout() time.Duration {
	if l == nil {
		return 0
	}
	return time.Duration(l.TimeoutMS) * time.Millisecond
}

// Rule effects, taint actions, side-effect classes and source-trust values
// (CP-44).
const (
	EffectPermit = "permit"
	EffectDeny   = "deny"

	TaintApprove = "approve"
	TaintDeny    = "deny"

	SideRead     = "read"
	SideWrite    = "write"
	SideExternal = "external"
	SideExecute  = "execute"

	TrustTrusted   = "trusted"
	TrustUntrusted = "untrusted"

	// AnyTool is the wildcard a deny rule may use in tools.
	AnyTool = "*"
)

// Meta keys a verified ManifestSource (E-13) sets on a tool to carry the
// manifest's side-effect class and source trust. The edge reads them only
// from verified manifests; a live, unverified tool list cannot classify
// itself.
const (
	MetaSideEffect  = "local.smcpgw/sideEffect"
	MetaSourceTrust = "local.smcpgw/sourceTrust"
	// MetaToolClass carries the manifest's tool class; ClassGatewayAdmin
	// tools are never presented (SR-3.12-1).
	MetaToolClass     = "local.smcpgw/toolClass"
	ClassGatewayAdmin = "gateway-admin"
)

// Evaluation bounds (CP-12).
const (
	DefaultCandidateBound = 256
	DefaultDeadline       = 500 * time.Millisecond
)

// Snapshot is the compiled, immutable decision snapshot of one revision.
type Snapshot struct {
	Revision string
	Digest   string // SHA-256 of Raw
	Profiles map[string]FrameworkProfile
	// Raw is the canonical JSON of the document (keys sorted, no
	// insignificant whitespace). Digest and signatures cover these bytes.
	Raw []byte

	doc Document
	// grants[template][server][tool] -> permit rule
	grants map[string]map[string]map[string]*Rule
	// denies[template][server] -> deny rules
	denies map[string]map[string][]*Rule
	// rulesByTemplate keeps the declared order for considered-rule reporting.
	rulesByTemplate map[string][]*Rule
	templates       map[string]*Template
}

// Document returns a copy of the compiled document.
func (s *Snapshot) Document() Document {
	var d Document
	_ = json.Unmarshal(s.Raw, &d)
	return d
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

// Canonical returns the canonical JSON form of a JSON document: object keys
// sorted, numbers kept as written, no HTML escaping and no insignificant
// whitespace. Two documents with the same content have the same canonical
// bytes (FR-3.8).
func Canonical(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("parse: trailing data after the document")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Compile validates the document against the schema and the publication
// invariants that can be checked from the document alone (ARCH §7.3), then
// compiles it.
func Compile(raw []byte) (*Snapshot, error) {
	canon, err := Canonical(raw)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(canon, &generic); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := compiledSchema.Validate(generic); err != nil {
		return nil, fmt.Errorf("policy does not match schema: %w", err)
	}
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(canon))
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
		for _, t := range p.RemoteAllowed {
			if !slices.Contains(p.Templates, t) {
				return nil, fmt.Errorf("framework profile %q: remote_allowed template %q is not in its templates", name, t)
			}
		}
	}
	if err := checkProfileCeilings(doc); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canon)
	s := &Snapshot{
		Revision:        doc.Revision,
		Digest:          hex.EncodeToString(digest[:]),
		Profiles:        doc.FrameworkProfiles,
		Raw:             canon,
		doc:             doc,
		grants:          map[string]map[string]map[string]*Rule{},
		denies:          map[string]map[string][]*Rule{},
		rulesByTemplate: map[string][]*Rule{},
		templates:       map[string]*Template{},
	}
	for tname := range doc.Templates {
		t := doc.Templates[tname]
		s.templates[tname] = &t
		byServer := map[string]map[string]*Rule{}
		denyByServer := map[string][]*Rule{}
		ruleIDs := map[string]bool{}
		for i := range t.Rules {
			r := &t.Rules[i]
			if ruleIDs[r.ID] {
				return nil, fmt.Errorf("template %q: duplicate rule id %q", tname, r.ID)
			}
			ruleIDs[r.ID] = true
			s.rulesByTemplate[tname] = append(s.rulesByTemplate[tname], r)
			for j := range r.When {
				if err := r.When[j].compile(); err != nil {
					return nil, fmt.Errorf("template %q rule %q: %w", tname, r.ID, err)
				}
			}
			if r.Effect == EffectDeny {
				if r.Approval || r.CallsPerMinute > 0 || r.CallsPerSession > 0 || len(r.Filters) > 0 || r.EgressLimits != nil || r.SideEffect != "" || r.SourceTrust != "" || len(r.When) > 0 {
					return nil, fmt.Errorf("template %q: deny rule %q carries obligations or classes; a deny rule has none", tname, r.ID)
				}
				denyByServer[r.Server] = append(denyByServer[r.Server], r)
				continue
			}
			tools := byServer[r.Server]
			if tools == nil {
				tools = map[string]*Rule{}
				byServer[r.Server] = tools
			}
			for _, tool := range r.Tools {
				if tool == AnyTool {
					return nil, fmt.Errorf("template %q: permit rule %q uses %q; only deny rules may name every tool", tname, r.ID, AnyTool)
				}
				if prev, dup := tools[tool]; dup {
					// Overlapping permits are rejected at publication (SR-1.9-1).
					return nil, fmt.Errorf("template %q: rules %q and %q both permit %s/%s", tname, prev.ID, r.ID, r.Server, tool)
				}
				tools[tool] = r
			}
		}
		s.grants[tname] = byServer
		s.denies[tname] = denyByServer
	}
	return s, nil
}

// checkProfileCeilings rejects a template that grants a server absent from
// every framework profile permitted to use it (SR-1-3). A profile without
// servers is unrestricted; a template no profile uses grants nothing.
func checkProfileCeilings(doc Document) error {
	names := make([]string, 0, len(doc.Templates))
	for n := range doc.Templates {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, tname := range names {
		var users []string
		open := false
		allowed := map[string]bool{}
		for pname, p := range doc.FrameworkProfiles {
			if !slices.Contains(p.Templates, tname) {
				continue
			}
			users = append(users, pname)
			if len(p.Servers) == 0 {
				open = true
			}
			for _, sv := range p.Servers {
				allowed[sv] = true
			}
		}
		if open || len(users) == 0 {
			continue
		}
		sort.Strings(users)
		for _, r := range doc.Templates[tname].Rules {
			if r.Effect != EffectDeny && !allowed[r.Server] {
				return fmt.Errorf("template %q rule %q grants server %q, which no framework profile using the template permits (%s) (SR-1-3)",
					tname, r.ID, r.Server, strings.Join(users, ", "))
			}
		}
	}
	return nil
}

// RuleRevisionID names a rule within a published revision: rules are not
// versioned on their own, so a rule's revision is the policy revision, the
// template and the rule ID (SR-1.19-1, SR-6.4-1).
func RuleRevisionID(revision, template, rule string) string {
	return revision + "/" + template + "/" + rule
}

// HighRiskClasses are the tool classes that need explicit high-risk flags
// on a template and its framework profile (SR-3.13-1).
var HighRiskClasses = []string{"general-sql", "code-execution", "cad-scripting", "browser-automation"}

// CheckHighRisk rejects a revision that grants a server of a high-risk
// class from a template, or to a framework profile, that does not flag the
// class (SR-3.13-1). classes maps server aliases to their declared tool
// classes.
func (s *Snapshot) CheckHighRisk(classes map[string][]string) error {
	names := make([]string, 0, len(s.doc.Templates))
	for n := range s.doc.Templates {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, tname := range names {
		t := s.doc.Templates[tname]
		for _, r := range t.Rules {
			if r.Effect == EffectDeny {
				continue
			}
			for _, c := range classes[r.Server] {
				if !slices.Contains(HighRiskClasses, c) {
					continue
				}
				if !slices.Contains(t.HighRisk, c) {
					return fmt.Errorf("template %q rule %q grants server %q of high-risk class %q, which the template does not flag in high_risk (SR-3.13-1)", tname, r.ID, r.Server, c)
				}
				for pname, p := range s.doc.FrameworkProfiles {
					if slices.Contains(p.Templates, tname) && !slices.Contains(p.HighRisk, c) {
						return fmt.Errorf("framework profile %q uses template %q, which grants server %q of high-risk class %q, without flagging the class in high_risk (SR-3.13-1)", pname, tname, r.Server, c)
					}
				}
			}
		}
	}
	return nil
}

// ApprovalFloor reports whether a tool of manifest side-effect class c
// always needs approval, whatever the policy says (SR-1.18-1): the write,
// external and execute classes cover the approval triggers of the security
// SRS (file and repository mutation, external transmission, code
// execution).
func ApprovalFloor(c string) bool { return c == SideWrite || c == SideExternal || c == SideExecute }

// HasTemplate reports whether the snapshot defines the template.
func (s *Snapshot) HasTemplate(name string) bool { _, ok := s.grants[name]; return ok }

// denyRule returns the first deny rule of the template that covers the tool.
func (s *Snapshot) denyRule(template, server, tool string) *Rule {
	for _, r := range s.denies[template][server] {
		for _, t := range r.Tools {
			if t == tool || t == AnyTool {
				return r
			}
		}
	}
	return nil
}

// Grants lists every (server, tool) a template permits and no deny rule
// forbids, sorted.
func (s *Snapshot) Grants(template string) []Grant {
	var out []Grant
	for server, tools := range s.grants[template] {
		for tool, rule := range tools {
			if s.denyRule(template, server, tool) != nil {
				continue
			}
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

// Reason codes (Appendix B data.reasonCode values produced by E-06).
const (
	ReasonPermit        = "PERMIT"
	ReasonNoPermit      = "NO_PERMIT" // SR-1.3-1
	ReasonNoTemplate    = "NO_TEMPLATE"
	ReasonDenyRule      = "DENY_RULE" // SR-1.4-1
	ReasonRateLimited   = "RATE_LIMITED"
	ReasonQuota         = "QUOTA_EXHAUSTED"
	ReasonEvalBound     = "EVAL_BOUND"  // SR-1.20-1
	ReasonNoSnapshot    = "NO_SNAPSHOT" // SR-1.2-1
	ReasonSessionState  = "SESSION_STATE"
	ReasonTaintDenied   = "TAINT_DENIED"   // SR-5.13-2
	ReasonTaintApproval = "TAINT_APPROVAL" // SR-5.13-2
	// SR-1.5-1 prerequisites, SR-1.11-1 routes and SR-3.13-1 high-risk
	// flags.
	ReasonPrincipalDisabled  = "PRINCIPAL_DISABLED"
	ReasonCredentialInvalid  = "CREDENTIAL_INVALID"
	ReasonRevisionNotEnabled = "REVISION_NOT_ENABLED"
	ReasonNoRoute            = "NO_ROUTE"
	ReasonAmbiguousRoute     = "AMBIGUOUS_ROUTE"
	ReasonHighRisk           = "HIGH_RISK_UNFLAGGED"
)

// Obligations the evaluator can express (FR-3.12 subset).
type Obligations struct {
	Approval bool
	// ApprovalReason is the reason code to report when the approval
	// obligation is not satisfied: "" (APPROVAL_REQUIRED) or TAINT_APPROVAL.
	ApprovalReason string
	CallsPerMinute int
	Burst          int
	// CallsPerSession is the session quota that applied (0 when none).
	CallsPerSession int
	Filters         []string // optional filter IDs that must run (request and response chains)
	// The obligations of FR-3.12 that come from objects outside the policy
	// document, as the Decider's context provides them for the server.
	AuditProfile      string        `json:",omitempty"` // effective Audit Profile revision
	ObservationPolicy string        `json:",omitempty"` // Observation Policy ID
	AnomalyResponse   string        `json:",omitempty"` // Anomaly Response Policy revision
	SizeLimit         int64         `json:",omitempty"` // result bound in bytes (CP-08)
	Timeout           time.Duration `json:",omitempty"` // upstream timeout (CP-13)
	EgressGrants      []string      `json:",omitempty"` // granted egress destinations of the server
	// EgressLimits are the permit rule's egress bounds for the call
	// (FR-5.38), nil when the rule sets none.
	EgressLimits   *EgressLimits `json:",omitempty"`
	SecretGrants   []string      `json:",omitempty"` // secret slots granted to the server
	RuntimeProfile string        `json:",omitempty"` // launcher and sandbox profile of the instance
}

// ObligationContext is what the Decider adds to every permit's obligations
// for a server (FR-3.12): the parts of the effective policy that live in
// other objects (observation objects, Secret Use Policy, egress grants,
// limits, runtime).
type ObligationContext struct {
	AuditProfile, ObservationPolicy, AnomalyResponse string
	SizeLimit                                        int64
	Timeout                                          time.Duration
	EgressGrants, SecretGrants                       []string
	RuntimeProfile                                   string
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
	Template        string // the session template the decision evaluated
	Duration        time.Duration
	// BaselineSnapshot is the behavior baseline snapshot loaded by the
	// Anomaly Scorer when the decision was made ("" when none is loaded or
	// observation is off), part of the FR-3.11 decision record.
	BaselineSnapshot string
	// SideEffect and SourceTrust are the effective classes of the tool
	// ("" when unclassified). Tainted reports that the session was tainted
	// when the decision was made; TaintsSession that releasing this call's
	// result taints the session (SR-5.13-2).
	SideEffect    string
	SourceTrust   string
	Tainted       bool
	TaintsSession bool
	// FailedPredicate names the predicate of the decisive permit rule that
	// did not hold (a NO_PERMIT decision), for the decision record.
	FailedPredicate string
}

// Request is the canonical request subset E-06 evaluates.
type Request struct {
	PrincipalID string
	SessionID   string
	Profile     string // the principal's framework profile
	Template    string
	Server      string
	Tool        string
	// SideEffect and SourceTrust are the classes the verified manifest
	// declares for the tool ("" when the manifest is unverified or silent).
	SideEffect  string
	SourceTrust string
	// Arguments are the call's arguments, for rule predicates (SR-1.7-1).
	Arguments json.RawMessage
	// Prerequisites (SR-1.5-1), set by the caller; the zero value means
	// satisfied.
	PrincipalDisabled  bool
	CredentialInvalid  bool
	SessionInactive    bool
	RevisionNotEnabled bool
	// Routes are the routes eligible for the server and tool revision
	// (SR-1.11-1); RoutesKnown false skips the check (replays).
	Routes      []string
	RoutesKnown bool
	// RiskClasses are the server's declared tool classes (SR-3.13-1).
	RiskClasses []string
}

// Decider evaluates requests against the current snapshot and keeps the
// sliding-window rate counters of FR-3.13, the session quotas and the
// session taint marks.
type Decider struct {
	mu       sync.RWMutex
	snap     *Snapshot
	now      func() time.Time
	counters map[string][]time.Time
	defRate  int
	burst    int
	calls    int
	quota    map[string]map[string]int // session -> quota key -> permitted calls
	tainted  map[string]bool
	bound    int
	deadline time.Duration
	evalHook func() // tests: runs inside evaluation, before the deadline check
	context  func(server string) ObligationContext
	baseline func() string
}

// SetBaseline sets the source of the baseline snapshot ID recorded on
// every decision (FR-3.11). The function is called once per decision and
// must not block.
func (d *Decider) SetBaseline(f func() string) {
	d.mu.Lock()
	d.baseline = f
	d.mu.Unlock()
}

// SetContext sets the source of the FR-3.12 obligations that live outside
// the policy document.
func (d *Decider) SetContext(f func(server string) ObligationContext) {
	d.mu.Lock()
	d.context = f
	d.mu.Unlock()
}

// NewDecider returns a decider with the given snapshot (may be nil, which
// denies everything with NO_SNAPSHOT) and CP-11 default principal rate.
func NewDecider(snap *Snapshot, defaultCallsPerMinute int) *Decider {
	return &Decider{snap: snap, now: time.Now, counters: map[string][]time.Time{}, defRate: defaultCallsPerMinute,
		quota: map[string]map[string]int{}, tainted: map[string]bool{}, bound: DefaultCandidateBound, deadline: DefaultDeadline}
}

// SetNow replaces the clock (tests).
func (d *Decider) SetNow(f func() time.Time) { d.mu.Lock(); d.now = f; d.mu.Unlock() }

// SetBurst sets the CP-11 burst: at most n calls in any window of
// n/limit minutes, for every rate window. 0 disables the burst window.
func (d *Decider) SetBurst(n int) { d.mu.Lock(); d.burst = n; d.mu.Unlock() }

// SetBounds replaces the CP-12 candidate-rule bound and decision deadline.
func (d *Decider) SetBounds(candidates int, deadline time.Duration) {
	d.mu.Lock()
	d.bound, d.deadline = candidates, deadline
	d.mu.Unlock()
}

// Snapshot returns the active snapshot.
func (d *Decider) Snapshot() *Snapshot { d.mu.RLock(); defer d.mu.RUnlock(); return d.snap }

// Activate swaps in a new snapshot atomically (FR-3.10) without checks.
// Prefer Replace.
func (d *Decider) Activate(s *Snapshot) { d.mu.Lock(); d.snap = s; d.mu.Unlock() }

// ErrRevisionReused is returned by Replace when a changed document keeps
// the active revision ID; catalogs and decisions are keyed by revision, so
// the revision must change whenever the content does.
var ErrRevisionReused = errors.New("policy content changed but the revision ID did not")

// Replace validates and activates a compiled snapshot. Reloading the same
// content is a no-op that reports unchanged.
func (d *Decider) Replace(s *Snapshot) (changed bool, err error) {
	if s == nil {
		return false, errors.New("nil snapshot")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.snap != nil && d.snap.Revision == s.Revision {
		if d.snap.Digest != s.Digest {
			return false, fmt.Errorf("%w (%s)", ErrRevisionReused, s.Revision)
		}
		return false, nil
	}
	d.snap = s
	return true, nil
}

// Taint marks a session tainted until it ends (SR-5.13-2). The edge calls
// it when a result from an untrusted-source tool is released.
func (d *Decider) Taint(sessionID string) {
	d.mu.Lock()
	d.tainted[sessionID] = true
	d.mu.Unlock()
}

// Tainted reports whether the session is tainted.
func (d *Decider) Tainted(sessionID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.tainted[sessionID]
}

// EndSession drops the taint mark and quota state of an ended session.
func (d *Decider) EndSession(sessionID string) {
	d.mu.Lock()
	delete(d.tainted, sessionID)
	delete(d.quota, sessionID)
	d.mu.Unlock()
}

var sideRank = map[string]int{SideRead: 0, SideWrite: 1, SideExternal: 2, SideExecute: 3}

// EffectiveSideEffect combines two side-effect classes restrict-only: the
// more restrictive one wins; "" is unknown.
func EffectiveSideEffect(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case sideRank[b] > sideRank[a]:
		return b
	}
	return a
}

// EffectiveSourceTrust combines two source-trust values restrict-only:
// "untrusted" wins over "trusted"; "" is unknown.
func EffectiveSourceTrust(a, b string) string {
	if a == TrustUntrusted || b == TrustUntrusted {
		return TrustUntrusted
	}
	if a == TrustTrusted || b == TrustTrusted {
		return TrustTrusted
	}
	return ""
}

// TaintGated reports whether a tool of side-effect class c is restricted in
// a tainted session. Unclassified tools are treated as gated, because the
// Gateway cannot show they do not write.
func TaintGated(c string) bool { return c != SideRead }

// Decide evaluates one request. It is deterministic given the snapshot, the
// counter state and the session's taint mark; it never consults anything
// else (SR-1.12-1).
func (d *Decider) Decide(req Request) Decision { return d.decide(req, true) }

// Recheck evaluates a request again without counting it against rate
// windows or quotas: the call was already counted by its first decision.
// The Request Inspection Pipeline uses it when a filter transformed the
// arguments (SR-5.12-1). The result is a new decision with its own ID.
func (d *Decider) Recheck(req Request) Decision { return d.decide(req, false) }

func (d *Decider) decide(req Request, consume bool) Decision {
	start := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	dec := Decision{ID: ids.New(), Outcome: Deny, Template: req.Template}
	if d.baseline != nil {
		dec.BaselineSnapshot = d.baseline()
	}
	done := func() Decision { dec.Duration = time.Since(start); return dec }
	if d.snap == nil {
		dec.ReasonCode = ReasonNoSnapshot
		return done()
	}
	dec.PolicyRevision = d.snap.Revision
	// SR-1.5-1: prerequisites, before any rule is evaluated.
	switch {
	case req.PrincipalDisabled:
		dec.ReasonCode = ReasonPrincipalDisabled
		return done()
	case req.CredentialInvalid:
		dec.ReasonCode = ReasonCredentialInvalid
		return done()
	case req.SessionInactive:
		dec.ReasonCode = ReasonSessionState
		return done()
	case req.RevisionNotEnabled:
		dec.ReasonCode = ReasonRevisionNotEnabled
		return done()
	}
	tmpl := d.snap.templates[req.Template]
	if tmpl == nil {
		dec.ReasonCode = ReasonNoTemplate
		return done()
	}
	// Layer intersection (SR-1-2): the framework profile must still permit
	// the session's template under this revision.
	if req.Profile != "" {
		p, ok := d.snap.Profiles[req.Profile]
		if !ok || !slices.Contains(p.Templates, req.Template) {
			dec.ReasonCode = ReasonNoTemplate
			return done()
		}
		// SR-1-2: the profile's server ceiling bounds every template.
		if len(p.Servers) > 0 && !slices.Contains(p.Servers, req.Server) {
			dec.ReasonCode = ReasonNoPermit
			return done()
		}
	}
	candidates := 0
	for _, r := range d.snap.rulesByTemplate[req.Template] {
		dec.ConsideredRules = append(dec.ConsideredRules, r.ID)
		if r.Server == req.Server {
			candidates++
		}
	}
	if d.bound > 0 && candidates > d.bound { // SR-1.20-1
		dec.ReasonCode = ReasonEvalBound
		return done()
	}
	// SR-1.11-1: exactly one route bound to the server and tool revision.
	if req.RoutesKnown {
		switch len(req.Routes) {
		case 0:
			dec.ReasonCode = ReasonNoRoute
			return done()
		case 1:
		default:
			dec.ReasonCode = ReasonAmbiguousRoute
			return done()
		}
	}
	rule := d.snap.grants[req.Template][req.Server][req.Tool]
	deny := d.snap.denyRule(req.Template, req.Server, req.Tool)
	if rule != nil {
		dec.ApplicableRules = append(dec.ApplicableRules, rule.ID)
	}
	if deny != nil { // SR-1.4-1: deny wins regardless of permits
		dec.ApplicableRules = append(dec.ApplicableRules, deny.ID)
		dec.DecisiveRules = []string{deny.ID}
		dec.ReasonCode = ReasonDenyRule
		return done()
	}
	if rule == nil {
		dec.ReasonCode = ReasonNoPermit
		return done()
	}
	// SR-1.7-1, SR-1.7-2: the permit applies only when its predicates
	// hold; a missing or malformed argument does not match.
	matched, failed, predApproval := matchPredicates(rule.When, req.Arguments, d.now())
	if !matched {
		dec.ApplicableRules = slices.DeleteFunc(dec.ApplicableRules, func(id string) bool { return id == rule.ID })
		dec.FailedPredicate = failed
		dec.ReasonCode = ReasonNoPermit
		return done()
	}
	// SR-3.13-1: a server in a high-risk class needs the class flagged on
	// the template and on the framework profile.
	for _, c := range req.RiskClasses {
		if !slices.Contains(HighRiskClasses, c) {
			continue
		}
		if !slices.Contains(tmpl.HighRisk, c) || (req.Profile != "" && !slices.Contains(d.snap.Profiles[req.Profile].HighRisk, c)) {
			dec.DecisiveRules = []string{rule.ID}
			dec.ReasonCode = ReasonHighRisk
			return done()
		}
	}
	dec.DecisiveRules = []string{rule.ID}
	if BrokenBuild { // deliberate defect, smcp_broken builds only (FR-15.8)
		dec.Outcome, dec.ReasonCode, dec.Route = Permit, ReasonPermit, req.Server
		return done()
	}
	dec.SideEffect = EffectiveSideEffect(rule.SideEffect, req.SideEffect)
	dec.SourceTrust = EffectiveSourceTrust(rule.SourceTrust, req.SourceTrust)
	dec.TaintsSession = dec.SourceTrust == TrustUntrusted
	dec.Tainted = d.tainted[req.SessionID]

	ob := Obligations{Approval: rule.Approval || predApproval, Filters: slices.Clone(rule.Filters)}
	if rule.EgressLimits != nil {
		l := *rule.EgressLimits
		ob.EgressLimits = &l
	}
	if d.context != nil { // FR-3.12
		c := d.context(req.Server)
		ob.AuditProfile, ob.ObservationPolicy, ob.AnomalyResponse = c.AuditProfile, c.ObservationPolicy, c.AnomalyResponse
		ob.SizeLimit, ob.Timeout, ob.RuntimeProfile = c.SizeLimit, c.Timeout, c.RuntimeProfile
		ob.EgressGrants, ob.SecretGrants = slices.Clone(c.EgressGrants), slices.Clone(c.SecretGrants)
	}
	// SR-1.18-1: the manifest's write, external and execute classes always
	// need approval; a policy can add approvals but not remove this floor.
	if ApprovalFloor(req.SideEffect) {
		ob.Approval = true
	}
	// Session taint (SR-5.13-2): restrict-only, decided before any counter
	// is touched so that a refusal consumes nothing.
	if dec.Tainted && TaintGated(dec.SideEffect) {
		if tmpl.TaintAction == TaintDeny {
			dec.ReasonCode = ReasonTaintDenied
			return done()
		}
		if !ob.Approval {
			ob.Approval, ob.ApprovalReason = true, ReasonTaintApproval
		}
	}

	// Rate bound: the smallest applicable of rule, template, framework
	// profile and the CP-11 default, applied to the principal, session and
	// session-tool windows.
	limit := d.defRate
	for _, v := range []int{rule.CallsPerMinute, tmpl.CallsPerMinute, d.snap.Profiles[req.Profile].CallsPerMinute} {
		if v > 0 && v < limit {
			limit = v
		}
	}
	burst := d.burst
	if burst > limit {
		burst = limit
	}
	ob.CallsPerMinute, ob.Burst = limit, burst
	// Quota: the smallest of the rule's and the template's per-session
	// bounds, each counted in its own scope.
	type quotaKey struct {
		key   string
		limit int
	}
	var quotas []quotaKey
	if tmpl.CallsPerSession > 0 {
		quotas = append(quotas, quotaKey{"t:" + req.Template, tmpl.CallsPerSession})
	}
	if rule.CallsPerSession > 0 {
		quotas = append(quotas, quotaKey{"r:" + req.Template + "/" + rule.ID, rule.CallsPerSession})
	}
	for _, q := range quotas {
		if ob.CallsPerSession == 0 || q.limit < ob.CallsPerSession {
			ob.CallsPerSession = q.limit
		}
	}
	if d.evalHook != nil {
		d.evalHook()
	}
	if d.deadline > 0 && time.Since(start) > d.deadline { // SR-1.20-1
		dec.ReasonCode = ReasonEvalBound
		return done()
	}
	if !consume {
		dec.Outcome, dec.ReasonCode, dec.Obligations, dec.Route = Permit, ReasonPermit, ob, req.Server
		return done()
	}
	used := d.quota[req.SessionID]
	for _, q := range quotas {
		if used[q.key] >= q.limit {
			dec.ReasonCode = ReasonQuota
			dec.Obligations.CallsPerSession = ob.CallsPerSession
			return done()
		}
	}
	keys := []string{"p:" + req.PrincipalID, "s:" + req.SessionID, "t:" + req.SessionID + "/" + req.Server + "/" + req.Tool}
	if !d.allowLocked(keys, limit, burst) {
		dec.ReasonCode = ReasonRateLimited
		dec.Obligations.CallsPerMinute, dec.Obligations.Burst = limit, burst
		return done()
	}
	if len(quotas) > 0 {
		if used == nil {
			used = map[string]int{}
			d.quota[req.SessionID] = used
		}
		for _, q := range quotas {
			used[q.key]++
		}
	}
	dec.Outcome = Permit
	dec.ReasonCode = ReasonPermit
	dec.Obligations = ob
	dec.Route = req.Server
	return done()
}

// allowLocked applies a one-minute sliding window, and when burst > 0 a
// burst window of burst/limit minutes, to every key, and records the call
// in all of them only when every window has room, so a refused call
// consumes nothing.
func (d *Decider) allowLocked(keys []string, limit, burst int) bool {
	now := d.now()
	cut := now.Add(-time.Minute)
	var burstCut time.Time
	if burst > 0 && burst < limit {
		burstCut = now.Add(-time.Minute * time.Duration(burst) / time.Duration(limit))
	}
	d.calls++
	if d.calls%1024 == 0 {
		d.pruneLocked(cut)
	}
	ok := true
	for _, k := range keys {
		ts := d.counters[k]
		i := 0
		for i < len(ts) && !ts[i].After(cut) {
			i++
		}
		ts = ts[i:]
		d.counters[k] = ts
		if len(ts) >= limit {
			ok = false
		}
		if !burstCut.IsZero() {
			n := 0
			for j := len(ts) - 1; j >= 0 && ts[j].After(burstCut); j-- {
				n++
			}
			if n >= burst {
				ok = false
			}
		}
	}
	if !ok {
		return false
	}
	for _, k := range keys {
		d.counters[k] = append(d.counters[k], now)
	}
	return true
}

// pruneLocked drops windows with no call inside the last minute, so ended
// sessions do not keep counters forever.
func (d *Decider) pruneLocked(cut time.Time) {
	for k, ts := range d.counters {
		if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
			delete(d.counters, k)
		}
	}
}

// Counters returns the number of rate windows held (tests).
func (d *Decider) Counters() int { d.mu.RLock(); defer d.mu.RUnlock(); return len(d.counters) }
