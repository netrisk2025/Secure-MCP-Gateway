// Package filters implements the built-in filters of the Request Inspection
// Pipeline (E-09, FR-4.5) and the Response Inspection Pipeline (E-11,
// FR-4.6), the optional untrusted-content delimiting obligation (FR-4.18)
// and the tool metadata scan at import and presentation (SR-5.9-2,
// FR-1.52). Detection rules are versioned data files under rules/, each
// checked against the SHA-256 digest in rules/index.json (FR-4.16), and each
// rule set has a labelled corpus under testdata/corpus with measured
// false-positive and false-negative rates (FR-19.5).
//
// Filters plug into pipeline.Filters; the tool metadata scan plugs in as a
// pipeline.ManifestSource decorator and a pipeline.ToolScreen. Findings
// never contain matched content.
package filters

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Options configure an Inspector.
type Options struct {
	Config    config.Filters
	ConfigDir string // relative rules_dir and roots resolve against it
	// RequestBodyBytes (CP-07) and ResultBytes (CP-08) are the size-limit
	// defaults.
	RequestBodyBytes int64
	ResultBytes      int64
	Evidence         audit.Recorder
	Log              *slog.Logger
	// Trust returns a tool's manifest source_trust ("trusted" or
	// "untrusted"); nil or anything else is untrusted.
	Trust func(*pipeline.Call) string
	// Names lists the backend tool names of every enabled server, for the
	// cross-server shadowing check at presentation.
	Names func() map[string][]string
}

// OptionsFrom builds Options from a loaded configuration.
func OptionsFrom(cfg *config.Config) Options {
	return Options{Config: cfg.Filters, ConfigDir: cfg.Dir, RequestBodyBytes: cfg.Limits.RequestBodyBytes, ResultBytes: cfg.Limits.ResultBytes}
}

// DefaultMandatoryRequest are the request filters that run on every call
// unless [filters] mandatory_request says otherwise. schema-validate is
// always mandatory.
var DefaultMandatoryRequest = []string{IDSizeLimit, IDUnicodeControl, IDSecretFingerprint, IDPathCanonicalize, IDURLCanonicalize, IDInjectionDetect}

// DefaultMandatoryResponse are the response filters that run on every call.
// pii-detect (request and response) and delimit-untrusted run when a
// policy rule names them.
var DefaultMandatoryResponse = []string{IDSizeLimit, IDOutputSchema, IDContentTypeGate, IDSecretFingerprint, IDUnicodeControl, IDInjectionMarker}

// Request and response filter IDs with their chain order.
var requestOrder = map[string]int{IDSizeLimit: 50, IDUnicodeControl: 110, IDSecretFingerprint: 120, IDPIIDetect: 125, IDPathCanonicalize: 130, IDURLCanonicalize: 140, IDInjectionDetect: 150}
var responseOrder = map[string]int{IDSizeLimit: 10, IDOutputSchema: 20, IDContentTypeGate: 30, IDSecretFingerprint: 40, IDUnicodeControl: 50, IDPIIDetect: 60, IDInjectionMarker: 70, IDDelimitUntrusted: 90}

// Inspector owns the loaded rule sets, the fingerprint set, the metadata
// scan state and the built-in filters.
type Inspector struct {
	lib          *Library
	sets         atomic.Pointer[map[string]*RuleSet]
	fps          *FingerprintSet
	evidence     audit.Recorder
	log          *slog.Logger
	trust        func(*pipeline.Call) string
	names        func() map[string][]string
	metadataScan bool
	meta         metadataState

	size      SizeOptions
	paths     *pathFilter
	urls      *urlFilter
	ct        ContentTypeOptions
	mandReq   []string
	mandResp  []string
	deadline  time.Duration
	installed atomic.Bool
}

// New loads the rule sets and builds the filters. A rule-set file whose
// digest does not match the index, an unknown pinned version or an
// unknown filter ID in the mandatory lists refuses to start.
func New(o Options) (*Inspector, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	c := o.Config
	rel := func(p string) string {
		if p != "" && !filepath.IsAbs(p) && o.ConfigDir != "" {
			return filepath.Join(o.ConfigDir, p)
		}
		return p
	}
	var lib *Library
	var err error
	if c.RulesDir != "" {
		lib, err = LoadDir(rel(c.RulesDir))
	} else {
		lib, err = LoadEmbedded()
	}
	if err != nil {
		return nil, err
	}
	in := &Inspector{lib: lib, fps: NewFingerprintSet(), evidence: o.Evidence, log: o.Log, trust: o.Trust, names: o.Names,
		metadataScan: c.MetadataScan == nil || *c.MetadataScan, deadline: c.Deadline.Duration,
		meta: metadataState{imported: map[string][]string{}, suspended: map[string]SuspendedTool{}, reported: map[string]bool{}}}
	sets := map[string]*RuleSet{}
	for _, id := range RequiredRuleSets {
		rs, err := lib.Get(id, c.RuleVersions[id])
		if err != nil {
			return nil, err
		}
		sets[id] = rs
	}
	for id := range c.RuleVersions {
		if !slices.Contains(RequiredRuleSets, id) {
			return nil, fmt.Errorf("filters.rule_versions names unknown rule set %q", id)
		}
	}
	in.sets.Store(&sets)

	in.size = SizeOptions{ArgumentBytes: c.Size.ArgumentBytes, ArgumentDepth: c.Size.ArgumentDepth, StringBytes: c.Size.StringBytes,
		ResultBytes: o.ResultBytes, ResultDepth: c.Size.ResultDepth}
	if in.size.ArgumentBytes <= 0 {
		in.size.ArgumentBytes = o.RequestBodyBytes
	}
	if in.size.ArgumentBytes <= 0 {
		in.size.ArgumentBytes = 1 << 20
	}
	if in.size.ResultBytes <= 0 {
		in.size.ResultBytes = 8 << 20
	}
	if in.size.ArgumentDepth <= 0 {
		in.size.ArgumentDepth = 32
	}
	if in.size.ResultDepth <= 0 {
		in.size.ResultDepth = 32
	}
	roots := make([]string, 0, len(c.Paths.Roots))
	for _, r := range c.Paths.Roots {
		roots = append(roots, rel(r))
	}
	serverRoots := map[string][]string{}
	for alias, list := range c.Paths.ServerRoots {
		for _, r := range list {
			serverRoots[alias] = append(serverRoots[alias], rel(r))
		}
	}
	if in.paths, err = newPathFilter(PathOptions{Roots: roots, ServerRoots: serverRoots, Names: c.Paths.Names, IgnoreNames: c.Paths.IgnoreNames,
		Rewrite: c.Paths.Rewrite == nil || *c.Paths.Rewrite}); err != nil {
		return nil, fmt.Errorf("filters.paths: %w", err)
	}
	if in.urls, err = newURLFilter(URLOptions{Schemes: slices.Clone(c.URLs.Schemes), Hosts: c.URLs.Hosts, DenyHosts: c.URLs.DenyHosts,
		AllowPrivate: c.URLs.AllowPrivate, Names: c.URLs.Names, IgnoreNames: c.URLs.IgnoreNames, Rewrite: c.URLs.Rewrite == nil || *c.URLs.Rewrite}); err != nil {
		return nil, fmt.Errorf("filters.urls: %w", err)
	}
	in.ct = ContentTypeOptions{Allow: c.ContentTypes.Allow, MaxBytes: c.ContentTypes.MaxBytes}
	if in.ct.MaxBytes <= 0 {
		in.ct.MaxBytes = 1 << 20
	}
	in.mandReq, in.mandResp = DefaultMandatoryRequest, DefaultMandatoryResponse
	if c.MandatoryRequest != nil {
		in.mandReq = c.MandatoryRequest
	}
	if c.MandatoryResponse != nil {
		in.mandResp = c.MandatoryResponse
	}
	for _, id := range in.mandReq {
		if _, ok := requestOrder[id]; !ok && id != "schema-validate" {
			return nil, fmt.Errorf("filters.mandatory_request names unknown request filter %q", id)
		}
	}
	for _, id := range in.mandResp {
		if _, ok := responseOrder[id]; !ok {
			return nil, fmt.Errorf("filters.mandatory_response names unknown response filter %q", id)
		}
	}
	return in, nil
}

// Library returns every loaded rule-set version.
func (in *Inspector) Library() *Library { return in.lib }

// Fingerprints is the set E-20 registers delivered secrets with.
func (in *Inspector) Fingerprints() *FingerprintSet { return in.fps }

func (in *Inspector) ruleSet(id string) *RuleSet { return (*in.sets.Load())[id] }

// RuleSet returns the version of rule set id in effect.
func (in *Inspector) RuleSet(id string) *RuleSet { return in.ruleSet(id) }

// UseRuleSet switches rule set id to another version listed in the index.
// Calls already inside a filter finish with the version they started with;
// catalogs built afterwards are screened with the new version (FR-1.52).
func (in *Inspector) UseRuleSet(id, version string) error {
	rs, err := in.lib.Get(id, version)
	if err != nil {
		return err
	}
	for {
		old := in.sets.Load()
		next := make(map[string]*RuleSet, len(*old))
		for k, v := range *old {
			next[k] = v
		}
		next[id] = rs
		if in.sets.CompareAndSwap(old, &next) {
			return nil
		}
	}
}

func (in *Inspector) source(id string) ruleSource { return func() *RuleSet { return in.ruleSet(id) } }

func (in *Inspector) fingerprintCheck(ss []surface) *pipeline.Finding {
	if in.fps.Len() == 0 {
		return nil
	}
	for _, s := range ss {
		if _, ok := in.fps.Match(s.get()); ok {
			return &pipeline.Finding{Filter: IDSecretFingerprint, RuleSet: "registered-fingerprints", Rule: "registered-secret", Location: s.loc, Score: 1}
		}
	}
	return nil
}

// RequestFilters returns the built-in request filters by ID.
func (in *Inspector) RequestFilters() map[string]pipeline.RequestFilter {
	return map[string]pipeline.RequestFilter{
		IDSizeLimit:         sizeRequest{in.size},
		IDUnicodeControl:    &ruleRequestFilter{id: IDUnicodeControl, rules: in.source(RuleSetUnicode), reason: ReasonUnicodeControl},
		IDSecretFingerprint: &ruleRequestFilter{id: IDSecretFingerprint, rules: in.source(RuleSetSecrets), reason: ReasonSecretInArguments, extra: in.fingerprintCheck},
		// The data-class rules (the pii rule set) apply to every argument
		// string with each rule's request action when the call's effective
		// obligations name pii-detect (SR-5.8-1).
		IDPIIDetect:        &ruleRequestFilter{id: IDPIIDetect, rules: in.source(RuleSetPII), reason: ReasonDataClass},
		IDPathCanonicalize: in.paths,
		IDURLCanonicalize:  in.urls,
		IDInjectionDetect:  &ruleRequestFilter{id: IDInjectionDetect, rules: in.source(RuleSetInjection), forceTag: true},
	}
}

// ResponseFilters returns the built-in response filters by ID.
func (in *Inspector) ResponseFilters() map[string]pipeline.ResponseFilter {
	return map[string]pipeline.ResponseFilter{
		IDSizeLimit:         sizeResponse{in.size},
		IDOutputSchema:      outputSchema{},
		IDContentTypeGate:   contentTypeGate{in.ct},
		IDSecretFingerprint: &ruleResponseFilter{id: IDSecretFingerprint, rules: in.source(RuleSetSecrets), reason: ReasonSecretLeak, extra: in.fingerprintCheck, extraWhy: ReasonSecretLeak},
		IDUnicodeControl:    &ruleResponseFilter{id: IDUnicodeControl, rules: in.source(RuleSetUnicode), reason: ReasonFilterBlocked},
		IDPIIDetect:         &ruleResponseFilter{id: IDPIIDetect, rules: in.source(RuleSetPII), reason: ReasonFilterBlocked},
		IDInjectionMarker:   &ruleResponseFilter{id: IDInjectionMarker, rules: in.source(RuleSetInjection), forceTag: true},
		IDDelimitUntrusted:  delimitUntrusted{trust: in.trust},
	}
}

// Register adds every built-in filter to f, mandatory as configured, sets
// the CP-14 deadline and attaches the evidence observer. It may be called
// once per Inspector.
func (in *Inspector) Register(f *pipeline.Filters) error {
	if !in.installed.CompareAndSwap(false, true) {
		return fmt.Errorf("filters already registered")
	}
	for id, rf := range in.RequestFilters() {
		if err := f.RegisterRequest(rf, pipeline.Registration{Order: requestOrder[id], Mandatory: slices.Contains(in.mandReq, id)}); err != nil {
			return err
		}
	}
	for id, rf := range in.ResponseFilters() {
		if err := f.RegisterResponse(rf, pipeline.Registration{Order: responseOrder[id], Mandatory: slices.Contains(in.mandResp, id)}); err != nil {
			return err
		}
	}
	if in.deadline > 0 {
		f.SetDeadline(in.deadline)
	}
	in.Observe(f)
	return nil
}

// Observe attaches the evidence observer only: one "filter" event per chain
// run with every filter's outcome, findings and duration (FR-4.7) and the
// P-043, P-044 and P-140 to P-144 parameter values. Evidence observers
// (E-29) receive it from the journal fan-out.
func (in *Inspector) Observe(f *pipeline.Filters) {
	if in.evidence == nil {
		return
	}
	f.Observe(in.record)
}

func (in *Inspector) record(call *pipeline.Call, stage string, runs []pipeline.FilterRun) {
	if len(runs) == 0 {
		return
	}
	origin := "E-09"
	if stage == pipeline.StageResponse {
		origin = "E-11"
	}
	outcome, reason := "pass", ""
	var injection float64
	unicodeHits, redactions, secretHits, piiHits := 0, 0, 0, 0
	hits := map[string]int{}
	entries := make([]map[string]any, 0, len(runs))
	for _, r := range runs {
		switch {
		case r.Action == pipeline.Block:
			outcome, reason = "block", r.ReasonCode
		case r.Action == pipeline.Transform && outcome == "pass":
			outcome = "transform"
		}
		if r.Action == pipeline.Transform && r.ReasonCode != "" {
			redactions++
		}
		for _, f := range r.Findings {
			hits[r.Filter]++
			switch r.Filter {
			case IDInjectionDetect, IDInjectionMarker:
				injection = max(injection, f.Score)
			case IDUnicodeControl:
				unicodeHits++
			case IDSecretFingerprint:
				secretHits++
			case IDPIIDetect:
				piiHits++
			}
		}
		e := map[string]any{"id": r.Filter, "version": r.Version, "action": r.Action.String(), "duration_us": r.Duration.Microseconds()}
		if r.ReasonCode != "" {
			e["reason_code"] = r.ReasonCode
		}
		if len(r.Findings) > 0 {
			e["findings"] = r.Findings
		}
		entries = append(entries, e)
	}
	params := map[string]any{}
	if stage == pipeline.StageRequest {
		params["P-043"], params["P-044"] = injection, unicodeHits
	} else {
		params["P-140"], params["P-141"], params["P-142"], params["P-143"], params["P-144"] = hits, redactions, secretHits, injection, piiHits
	}
	ev := audit.Event{Class: "filter", Origin: origin, CorrelationID: call.CorrelationID, SessionID: call.SessionID, PrincipalID: call.PrincipalID,
		DecisionID: call.DecisionID, PolicyRevision: call.PolicyRevision, ServerRevision: call.ServerRevision, ToolRevision: call.ToolRevision,
		Outcome: outcome, ReasonCode: reason, PolicyStatus: "evaluated",
		Detail: map[string]any{"stage": stage, "filters": entries, "parameters": params}}
	if call.Channel != "" { // FR-16.8
		ev.Channel, ev.ClientID, ev.ClientAddress = call.Channel, call.ClientID, call.ClientAddress
		if call.ClientAddress != "" {
			ev.ClientAddressSource = "server-asserted"
		}
	}
	if err := in.evidence.Record(ev); err != nil {
		// The journal's sticky error fails the Gateway closed for later
		// calls; this call's own terminal events will fail the same way.
		in.log.Error("evidence write failed for filter run", "err", err, "correlation", call.CorrelationID)
	}
}
