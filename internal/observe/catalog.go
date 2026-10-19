package observe

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ethan03805/secure-mcp-gateway/docs"
)

// Param is one Parameter Catalog entry (ArchitectureV2 §10.1).
type Param struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Unit          string `json:"unit"`
	DataType      string `json:"dataType"` // string, integer, number, array, object
	SourceElement string `json:"sourceElement"`
	CapturePoint  string `json:"capturePoint"`
	Derivation    string `json:"derivation"`
	Sensitivity   string `json:"sensitivity"` // S0 to S3
	Baselinable   bool   `json:"baselinable"`
	CostClass     string `json:"costClass"`
}

// Numeric reports whether the parameter holds a number that can be
// baselined and scored.
func (p Param) Numeric() bool { return p.DataType == "integer" || p.DataType == "number" }

// Catalog is a parsed Parameter Catalog.
type Catalog struct {
	Version string  `json:"catalogVersion"`
	Params  []Param `json:"parameters"`

	byKey map[string]*Param
}

// ParseCatalog parses a catalog document and indexes it by ID and name.
func ParseCatalog(raw []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parameter catalog: %w", err)
	}
	if c.Version == "" || len(c.Params) == 0 {
		return nil, fmt.Errorf("parameter catalog: no version or no parameters")
	}
	c.byKey = map[string]*Param{}
	for i := range c.Params {
		p := &c.Params[i]
		if p.ID == "" || p.Name == "" {
			return nil, fmt.Errorf("parameter catalog: entry %d has no id or name", i)
		}
		if _, dup := c.byKey[p.ID]; dup {
			return nil, fmt.Errorf("parameter catalog: duplicate %s", p.ID)
		}
		if _, dup := c.byKey[p.Name]; dup {
			return nil, fmt.Errorf("parameter catalog: duplicate name %s", p.Name)
		}
		c.byKey[p.ID], c.byKey[p.Name] = p, p
	}
	return &c, nil
}

var (
	defaultCatalog     *Catalog
	defaultCatalogErr  error
	defaultCatalogOnce sync.Once
)

// DefaultCatalog is the catalog shipped with the release (docs/parameters.json).
func DefaultCatalog() *Catalog {
	defaultCatalogOnce.Do(func() { defaultCatalog, defaultCatalogErr = ParseCatalog(docs.ParametersJSON) })
	if defaultCatalogErr != nil {
		panic(defaultCatalogErr) // the embedded file is checked by the SRS build and by tests
	}
	return defaultCatalog
}

// Lookup finds a parameter by ID ("P-024") or name ("request_bytes").
func (c *Catalog) Lookup(key string) (Param, bool) {
	p, ok := c.byKey[strings.TrimSpace(key)]
	if !ok {
		return Param{}, false
	}
	return *p, true
}

// Resolve maps IDs or names to parameter names, rejecting unknown keys.
func (c *Catalog) Resolve(keys []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, k := range keys {
		p, ok := c.Lookup(k)
		if !ok {
			return nil, fmt.Errorf("unknown parameter %q (not in Parameter Catalog %s)", k, c.Version)
		}
		if !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p.Name)
		}
	}
	return out, nil
}

// Periodic lists the system meta-metric parameters (capture point
// "periodic", P-240 to P-250).
func (c *Catalog) Periodic() []Param {
	var out []Param
	for _, p := range c.Params {
		if p.CapturePoint == "periodic" {
			out = append(out, p)
		}
	}
	return out
}

// PerCall lists the parameters captured per call (every capture point
// except "periodic"), in catalog order.
func (c *Catalog) PerCall() []Param {
	var out []Param
	for _, p := range c.Params {
		if p.CapturePoint != "periodic" {
			out = append(out, p)
		}
	}
	return out
}

// Identifiers are the parameters every record carries regardless of the
// Observation Policy (FR-10.4): P-001, P-004, P-022, P-023, P-080, P-087.
var Identifiers = []string{"principal_id", "session_id", "server_revision", "tool_name", "decision_outcome", "baseline_snapshot_id"}

// Computed lists the per-call parameters this release derives. Every other
// catalog parameter is stored as a null column (FR-9.7) until an
// instrumented element supplies it. See docs/observation.md.
var Computed = []string{
	"principal_id", "session_template", "calls_in_session", "end_user_claim",
	"harness_adapter_version", "trace_parent", "mcp_method", "server_revision", "tool_name",
	"request_bytes", "argument_count", "argument_max_depth", "argument_string_lengths", "argument_entropy",
	"path_argument_count", "url_argument_count", "argument_value_hashes", "unicode_control_count", "injection_detect_score",
	"previous_tool", "transition_surprise", "inter_call_interval", "calls_per_minute_session",
	"calls_per_minute_principal", "distinct_tools_in_session", "repeated_identical_calls",
	"decision_outcome", "decisive_rule_ids", "obligations_applied", "approval_state",
	"anomaly_band", "max_abs_z", "baseline_snapshot_id",
	"server_execution_time",
	"response_bytes", "content_parts_by_type", "output_schema_conformance", "response_entropy",
	"response_token_estimate", "is_error", "structured_field_count", "embedded_url_count",
	"filter_hits", "redaction_count", "secret_fingerprint_matches", "injection_marker_score", "pii_hits",
	"release_outcome", "delivery_confirmation", "end_to_end_latency", "t_request_filters", "t_response_filters",
	"t_approval_wait", "t_scoring", "t_capture", "gateway_overhead",
	"session_id",
}

// DefaultParameters is the parameter set of the default Observation Policy:
// every computed S0 and S1 parameter.
func (c *Catalog) DefaultParameters() []string {
	var out []string
	for _, n := range Computed {
		if p, ok := c.Lookup(n); ok && (p.Sensitivity == "S0" || p.Sensitivity == "S1") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
