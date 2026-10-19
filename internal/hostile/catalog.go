package hostile

import "strings"

// Row is one row of SRS Appendix L (hostile backend fixture suite). The
// text is copied from srs_build/appendix2.md; TestCatalogMatchesSRS keeps
// the two in step.
type Row struct {
	ID           string
	Attack       string
	Behavior     string
	Expected     string
	Profiles     string // "Both", "Enforced", or a split description
	Requirements []string
}

// EnforcedOnly reports whether the row is asserted only in the Enforced
// profile. In the Standalone profile such rows are limitations listed in
// docs/security-limitations.md.
func (r Row) EnforcedOnly() bool { return r.Profiles == "Enforced" }

// Rows lists every Appendix L row in order.
var Rows = []Row{
	{ID: "HF-01", Attack: "Poisoned tool description", Behavior: "A description containing instructions to the model to call another tool or reveal data", Expected: "Blocking metadata rule matches; the tool is suspended at import, not presented, and `metadata_blocked` is recorded", Profiles: "Both", Requirements: []string{"SR-5.9-2", "FR-1.52"}},
	{ID: "HF-02", Attack: "Poisoned schema property description", Behavior: "The same text inside a nested `properties.*.description`", Expected: "As HF-01", Profiles: "Both", Requirements: []string{"SR-5.9-2"}},
	{ID: "HF-03", Attack: "Rug pull through `list_changed`", Behavior: "After enablement, sends `notifications/tools/list_changed` and returns a changed description and an added tool", Expected: "The server revision is suspended for drift; the changed and added tools never appear in a catalog", Profiles: "Both", Requirements: []string{"SR-3.8-1", "SR-3.10-1", "FR-5.31"}},
	{ID: "HF-04", Attack: "Prompt injection in text content", Behavior: "Result text with injection phrases", Expected: "Released with an injection-marker tag; P-143 recorded; the session is tainted if the tool's `source_trust` is `untrusted`", Profiles: "Both", Requirements: []string{"FR-4.17", "SR-5.13-2"}},
	{ID: "HF-05", Attack: "Prompt injection in structured content", Behavior: "The same phrases inside `structuredContent` string fields", Expected: "As HF-04", Profiles: "Both", Requirements: []string{"SR-5.9-1", "FR-4.17"}},
	{ID: "HF-06", Attack: "Prompt injection in an error result", Behavior: "`isError` result whose text carries the phrases", Expected: "As HF-04; the error is filtered before release", Profiles: "Both", Requirements: []string{"SR-5.9-1"}},
	{ID: "HF-07", Attack: "Prompt injection in progress messages", Behavior: "`notifications/progress` messages carrying the phrases", Expected: "Progress messages are filtered and tagged before relay", Profiles: "Both", Requirements: []string{"SR-5.9-1", "FR-1.39"}},
	{ID: "HF-08", Attack: "Secret exfiltration in a result", Behavior: "Echoes a value registered as a secret fingerprint", Expected: "Result withheld with `-31003` `SECRET_LEAK`; secret grant suspended", Profiles: "Both", Requirements: []string{"FR-6.10", "SR-5.11-1"}},
	{ID: "HF-09", Attack: "Secret exfiltration in arguments", Behavior: "The agent passes a registered secret value as an argument", Expected: "Request blocked before dispatch by the outbound argument filter", Profiles: "Both", Requirements: []string{"SR-5.8-1"}},
	{ID: "HF-10", Attack: "Schema smuggling: remote `$ref`", Behavior: "`inputSchema` with `$ref` to an external URL", Expected: "Tool definition refused at import; no network request", Profiles: "Both", Requirements: []string{"SR-1.8-2", "SR-1.8-3"}},
	{ID: "HF-11", Attack: "Schema smuggling: deep nesting", Behavior: "Schema nested beyond the CP-36 depth", Expected: "Tool definition refused at import", Profiles: "Both", Requirements: []string{"SR-1.8-3"}},
	{ID: "HF-12", Attack: "Schema smuggling: huge enum", Behavior: "Enum with more subschemas or members than CP-36 allows", Expected: "Tool definition refused at import", Profiles: "Both", Requirements: []string{"SR-1.8-3"}},
	{ID: "HF-13", Attack: "Schema smuggling: `additionalProperties` games", Behavior: "Runtime schema loosens `additionalProperties` or adds `patternProperties` compared with the manifest", Expected: "Drift suspension; arguments are validated against the packaged schema only", Profiles: "Both", Requirements: []string{"SR-3.7-1", "SR-3.8-1", "SR-1.8-1"}},
	{ID: "HF-14", Attack: "Public-name collision", Behavior: "Two tools of one server whose names map to the same public name under FR-1.26 (for example `a.b` and `a_b`)", Expected: "The revision is not enabled; the reason names both backend tool names", Profiles: "Both", Requirements: []string{"FR-1.49"}},
	{ID: "HF-15", Attack: "Cross-server shadowing", Behavior: "Descriptions that reference another server's public tool names or redefine their behavior", Expected: "Blocking metadata rule matches; tool suspended", Profiles: "Both", Requirements: []string{"SR-5.9-2"}},
	{ID: "HF-16", Attack: "Oversized result", Behavior: "A result larger than CP-08", Expected: "Withheld with `-31003` `RESULT_TOO_LARGE`; nothing partial released", Profiles: "Both", Requirements: []string{"SR-5.11-1", "FR-4.10"}},
	{ID: "HF-17", Attack: "Slow-drip response", Behavior: "Writes one byte per second", Expected: "Call ends at the CP-13 deadline with `-31009` `UPSTREAM_TIMEOUT`; instance restarted", Profiles: "Both", Requirements: []string{"FR-4.9", "SR-7.2-1"}},
	{ID: "HF-18", Attack: "Invalid stdout", Behavior: "Non-JSON lines on standard output", Expected: "Instance terminated; call fails with `-31007`; event recorded", Profiles: "Both", Requirements: []string{"FR-5.14"}},
	{ID: "HF-19", Attack: "Never responding", Behavior: "Accepts the call and never answers", Expected: "As HF-17", Profiles: "Both", Requirements: []string{"FR-4.9"}},
	{ID: "HF-20", Attack: "Fork bomb", Behavior: "Spawns processes without limit", Expected: "PID limit stops growth; instance killed; host unaffected", Profiles: "Enforced", Requirements: []string{"SR-4.7-2", "FR-5.35"}},
	{ID: "HF-21", Attack: "Memory blow-up", Behavior: "Allocates without limit", Expected: "cgroup memory limit kills the instance; Gateway unaffected", Profiles: "Enforced", Requirements: []string{"SR-4.7-2"}},
	{ID: "HF-22", Attack: "Symlink and path escape", Behavior: "Arguments with `../` and a symlink created to `/etc` inside its mount", Expected: "Path arguments outside the grant are denied before dispatch; reads through the symlink fail inside the sandbox", Profiles: "Both (argument check); Enforced (mount)", Requirements: []string{"SR-1.8-4", "SR-4.6-1"}},
	{ID: "HF-23", Attack: "Direct network escape", Behavior: "Opens TCP connections to the Internet, the LAN and loopback services", Expected: "Every connection fails; only broker endpoints are reachable", Profiles: "Enforced", Requirements: []string{"SR-4.5-1"}},
	{ID: "HF-24", Attack: "DNS escape and rebinding", Behavior: "Resolves attacker names directly and through the broker with a rebinding answer", Expected: "Direct resolution fails; the broker refuses the rebound private address", Profiles: "Enforced", Requirements: []string{"SR-5.15-1", "SR-5.15-2"}},
	{ID: "HF-25", Attack: "Unsolicited client-input request", Behavior: "Returns `InputRequiredResult` asking for elicitation", Expected: "`-31010` without the MRTR profile", Profiles: "Both", Requirements: []string{"FR-5.24"}},
	{ID: "HF-26", Attack: "Legacy server-initiated request", Behavior: "Sends `roots/list` or `sampling/createMessage` to the Gateway", Expected: "Rejected; nothing relayed northbound", Profiles: "Both", Requirements: []string{"FR-5.20", "SR-5.6-2"}},
	{ID: "HF-27", Attack: "Unicode control and bidirectional text", Behavior: "Result text with bidi overrides and zero-width characters", Expected: "`unicode-control` filter finding per the versioned corpus", Profiles: "Both", Requirements: []string{"SR-5.14-1"}},
}

// Lookup returns the row with the given ID (case-insensitive).
func Lookup(id string) (Row, bool) {
	id = strings.ToUpper(id)
	for _, r := range Rows {
		if r.ID == id {
			return r, true
		}
	}
	return Row{}, false
}
