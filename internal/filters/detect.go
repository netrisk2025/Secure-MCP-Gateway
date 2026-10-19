package filters

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Filter IDs (FR-4.5, FR-4.6, FR-4.18).
const (
	IDSizeLimit         = "size-limit"
	IDUnicodeControl    = "unicode-control"
	IDSecretFingerprint = "secret-fingerprint"
	IDPathCanonicalize  = "path-canonicalize"
	IDURLCanonicalize   = "url-canonicalize"
	IDInjectionDetect   = "injection-detect"
	IDOutputSchema      = "output-schema"
	IDContentTypeGate   = "content-type-gate"
	IDPIIDetect         = "pii-detect"
	IDInjectionMarker   = "injection-marker"
	IDDelimitUntrusted  = "delimit-untrusted"
)

// filterVersion is the version of the filter code; detection filters
// append the rule-set version in effect.
const filterVersion = "1.0.0"

// Reason codes of the built-in filters. Response-side codes reuse the
// Appendix B codes of -31003.
const (
	ReasonArgumentsInvalid  = "ARGUMENTS_INVALID"
	ReasonArgumentsTooLarge = "ARGUMENTS_TOO_LARGE"
	ReasonArgumentsTooDeep  = "ARGUMENTS_TOO_DEEP"
	ReasonUnicodeControl    = "UNICODE_CONTROL"
	ReasonSecretInArguments = "SECRET_IN_ARGUMENTS"
	ReasonDataClass         = "DATA_CLASS_IN_ARGUMENTS"
	ReasonPathInvalid       = "PATH_INVALID"
	ReasonPathOutsideRoots  = "PATH_OUTSIDE_ROOTS"
	ReasonURLInvalid        = "URL_INVALID"
	ReasonURLNotAllowed     = "URL_NOT_ALLOWED"
	ReasonURLPrivate        = "URL_PRIVATE_ADDRESS"
	ReasonRedacted          = "REDACTED"
	ReasonResultTooLarge    = "RESULT_TOO_LARGE"
	ReasonFilterBlocked     = "FILTER_BLOCKED"
	ReasonSecretLeak        = "SECRET_LEAK"
	ReasonMetadataBlocked   = "METADATA_BLOCKED"
)

// maxFindings bounds the findings one filter reports for one call.
const maxFindings = 64

// ruleSource gives a filter the rule set currently in effect.
type ruleSource func() *RuleSet

func ruleVersion(rs *RuleSet) string { return filterVersion + "+" + rs.ID + "." + rs.Version }

func finding(filter string, rs *RuleSet, r *Rule, loc string, tag bool) pipeline.Finding {
	return pipeline.Finding{Filter: filter, RuleSet: rs.ID, RuleSetVersion: rs.Version, Rule: r.ID, Location: loc, Score: r.Score, Tag: tag}
}

// scanResult is the outcome of applying a rule set to a list of surfaces.
type scanResult struct {
	findings []pipeline.Finding
	block    *pipeline.Finding // first blocking finding
	redact   map[int][]Match   // surface index -> matches to redact
}

// scanSurfaces applies rs to ss using the stage's rule actions. forceTag
// turns every finding into a tag (the injection filters, FR-4.17).
func scanSurfaces(filter string, rs *RuleSet, stage string, ss []surface, forceTag bool) scanResult {
	var out scanResult
	for i, s := range ss {
		for _, m := range rs.Scan(s.get()) {
			action := m.Rule.RequestAction
			if stage == pipeline.StageResponse {
				action = m.Rule.ResponseAction
			}
			if forceTag {
				action = ActionTag
			}
			f := finding(filter, rs, m.Rule, s.loc, action == ActionTag)
			if len(out.findings) < maxFindings {
				out.findings = append(out.findings, f)
			}
			switch action {
			case ActionBlock:
				if out.block == nil {
					b := f
					out.block = &b
				}
			case ActionRedact:
				if s.set == nil || rs.Normalize {
					if out.block == nil {
						b := f
						out.block = &b
					}
					continue
				}
				if out.redact == nil {
					out.redact = map[int][]Match{}
				}
				out.redact[i] = append(out.redact[i], m)
			}
		}
	}
	return out
}

// redactString replaces each matched span: code-point rules are removed,
// other rules are replaced by a "[REDACTED:<rule>]" marker (FR-4.11).
func redactString(s string, ms []Match) string {
	slices.SortFunc(ms, func(a, b Match) int { return a.Start - b.Start })
	var b strings.Builder
	pos := 0
	for _, m := range ms {
		if m.End <= pos {
			continue
		}
		start := max(m.Start, pos)
		b.WriteString(s[pos:start])
		if m.Rule.Kind != "codepoints" {
			b.WriteString("[REDACTED:" + m.Rule.ID + "]")
		}
		pos = m.End
	}
	b.WriteString(s[pos:])
	return b.String()
}

func applyRedactions(ss []surface, red map[int][]Match) {
	for i, ms := range red {
		ss[i].set(redactString(ss[i].get(), ms))
	}
}

func invalidArguments() pipeline.RequestVerdict {
	return pipeline.RequestVerdict{Action: pipeline.Block, ReasonCode: ReasonArgumentsInvalid, Finding: "arguments are not valid JSON"}
}

func blockText(f *pipeline.Finding) string {
	return fmt.Sprintf("rule %s of %s %s matched at %s", f.Rule, f.RuleSet, f.RuleSetVersion, locOrRoot(f.Location))
}

func locOrRoot(l string) string {
	if l == "" {
		return "/"
	}
	return l
}

// ruleRequestFilter applies a rule set to every argument string.
type ruleRequestFilter struct {
	id       string
	rules    ruleSource
	reason   string
	forceTag bool
	extra    func(ss []surface) *pipeline.Finding // registered fingerprints
}

func (f *ruleRequestFilter) ID() string      { return f.id }
func (f *ruleRequestFilter) Version() string { return ruleVersion(f.rules()) }

func (f *ruleRequestFilter) FilterRequest(_ context.Context, _ *pipeline.Call, args json.RawMessage) (pipeline.RequestVerdict, error) {
	rs := f.rules()
	v, ss, ok := argSurfaces(args)
	if !ok {
		return invalidArguments(), nil
	}
	sr := scanSurfaces(f.id, rs, pipeline.StageRequest, ss, f.forceTag)
	if f.extra != nil {
		if fp := f.extra(ss); fp != nil {
			sr.findings = append(sr.findings, *fp)
			if sr.block == nil {
				sr.block = fp
			}
		}
	}
	if sr.block != nil {
		return pipeline.RequestVerdict{Action: pipeline.Block, ReasonCode: f.reason, Finding: blockText(sr.block), Findings: sr.findings}, nil
	}
	if len(sr.redact) > 0 {
		applyRedactions(ss, sr.redact)
		raw, err := json.Marshal(v)
		if err != nil {
			return pipeline.RequestVerdict{}, err
		}
		return pipeline.RequestVerdict{Action: pipeline.Transform, Arguments: raw, ReasonCode: ReasonRedacted, Findings: sr.findings}, nil
	}
	return pipeline.RequestVerdict{Action: pipeline.Pass, Findings: sr.findings}, nil
}

// ruleResponseFilter applies a rule set to every text surface of a result.
type ruleResponseFilter struct {
	id       string
	rules    ruleSource
	reason   string // withhold reason
	forceTag bool
	extra    func(ss []surface) *pipeline.Finding
	extraWhy string // withhold reason for an extra finding
}

func (f *ruleResponseFilter) ID() string      { return f.id }
func (f *ruleResponseFilter) Version() string { return ruleVersion(f.rules()) }

func (f *ruleResponseFilter) FilterResponse(_ context.Context, _ *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	rs := f.rules()
	ss := resultSurfaces(res)
	if f.extra != nil {
		if fp := f.extra(ss); fp != nil {
			return pipeline.ResponseVerdict{Action: pipeline.Block, ReasonCode: f.extraWhy, Finding: "a registered secret fingerprint matched at " + fp.Location, Findings: []pipeline.Finding{*fp}}, nil
		}
	}
	sr := scanSurfaces(f.id, rs, pipeline.StageResponse, ss, f.forceTag)
	if sr.block != nil {
		return pipeline.ResponseVerdict{Action: pipeline.Block, ReasonCode: f.reason, Finding: blockText(sr.block), Findings: sr.findings}, nil
	}
	if len(sr.redact) == 0 {
		return pipeline.ResponseVerdict{Action: pipeline.Pass, Findings: sr.findings}, nil
	}
	out, err := cloneResult(res)
	if err != nil {
		return pipeline.ResponseVerdict{}, err
	}
	css := resultSurfaces(out)
	if len(css) != len(ss) {
		return pipeline.ResponseVerdict{}, fmt.Errorf("result surfaces changed while cloning")
	}
	applyRedactions(css, sr.redact)
	return pipeline.ResponseVerdict{Action: pipeline.Transform, Result: out, ReasonCode: ReasonRedacted, Findings: sr.findings}, nil
}
