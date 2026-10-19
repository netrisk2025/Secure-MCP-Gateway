package config

// Observation configures SS-10 Observation & Analytics and the Observation
// Store (E-27, E-29 to E-32). Every key is optional; internal/analytics
// applies the defaults (docs/observation.md) to absent keys. This table is
// the Gateway's default Observation Policy until observation policies are
// published through the Policy Administration Service (E-05).
type Observation struct {
	// Enabled turns observation on (default true). Observation never gates
	// enforcement: when the store cannot be opened the Gateway runs
	// without analytics and health reports it.
	Enabled *bool `toml:"enabled" json:"enabled"`
	// Store selects the backend: "auto" (DuckDB when the binary has cgo,
	// otherwise JSON Lines), "duckdb" or "jsonl".
	Store string `toml:"store" json:"store"`
	// Dir is the store directory (default <state>/observation).
	Dir string `toml:"dir" json:"dir"`
	// ExportDir receives research exports (default <state>/exports, CP-46).
	ExportDir string `toml:"export_dir" json:"export_dir"`
	// PolicyID names this Observation Policy in records and spans.
	PolicyID string `toml:"policy_id" json:"policy_id"`
	// Parameters are the captured parameters (IDs or names); default every
	// computed S0 and S1 parameter.
	Parameters []string `toml:"parameters" json:"parameters"`
	// EscalationParameters are added for calls whose band is elevated or
	// worse.
	EscalationParameters []string `toml:"escalation_parameters" json:"escalation_parameters"`
	// SamplingRate is the normal-band capture rate (CP-31: 0.1).
	SamplingRate *float64 `toml:"sampling_rate" json:"sampling_rate"`
	// Retention is how long observation partitions are kept (CP-25
	// metadata: 90 days, "2160h").
	Retention Duration `toml:"retention" json:"retention"`
	// Queue bounds the collector input queue (default 4096).
	Queue int `toml:"queue" json:"queue"`
	// FlushRecords and FlushInterval bound a store batch (defaults 1000
	// records, 200ms).
	FlushRecords  int      `toml:"flush_records" json:"flush_records"`
	FlushInterval Duration `toml:"flush_interval" json:"flush_interval"`
	// MetricsInterval is the meta-metrics sampling interval (default 10s).
	MetricsInterval Duration `toml:"metrics_interval" json:"metrics_interval"`
	// MemoryLimitBytes bounds DuckDB memory (CP-33: 512 MiB).
	MemoryLimitBytes int64 `toml:"memory_limit_bytes" json:"memory_limit_bytes"`
	// StorageQuotaBytes is the Observation Store's storage quota (default
	// 10 GiB); health warns at 80% (FR-9.15).
	StorageQuotaBytes int64 `toml:"storage_quota_bytes" json:"storage_quota_bytes"`
	// Scoring selects "async" (default: scored after release, alert and
	// capture escalation only), "sync" (scored in the inspection stages
	// before launch and release authorization) or "off".
	Scoring string `toml:"scoring" json:"scoring"`
	// RequireApprovalBand: with sync scoring, a call whose request band is
	// at least this band needs approval (E-07). "off" (default),
	// "elevated", "abnormal" or "critical".
	RequireApprovalBand string `toml:"require_approval_band" json:"require_approval_band"`
	// WithholdBand: with sync scoring, a result whose response band is at
	// least this band is withheld. "off" (default) or a band.
	WithholdBand string `toml:"withhold_band" json:"withhold_band"`
	// EscalateCaptureBand is the lowest band whose calls get capture
	// escalation; lower bands alert only (FR-8.14). "elevated" (default),
	// "abnormal", "critical" or "off" (alert only at every band).
	EscalateCaptureBand string `toml:"escalate_capture_band" json:"escalate_capture_band"`
	// UncharacterizedAction is the restrict-only action for a call whose
	// context has no baseline yet: "record" (default), "escalate" (capture
	// escalation) or "approve" (escalation and, with sync scoring, an
	// approval obligation).
	UncharacterizedAction string `toml:"uncharacterized_action" json:"uncharacterized_action"`
	// EscalationBands adds escalation parameters per band (FR-8.10): the
	// parameters of a band are captured for escalated calls of that band
	// and every higher band, in addition to EscalationParameters.
	EscalationBands map[string][]string `toml:"escalation_bands" json:"escalation_bands"`
	// Scope limits the calls the Observation Policy samples and escalates
	// (FR-8.9); empty lists match every call. Research campaigns keep
	// their own scope.
	Scope ObservationScope `toml:"scope" json:"scope"`
	// Baseline configures the Behavior Baseline Engine and the bands.
	Baseline ObservationBaseline `toml:"baseline" json:"baseline"`
}

// ObservationScope selects calls by principal ID, framework type, session
// template, server alias and tool ("<server alias>/<backend tool name>").
// A call is in scope when it matches every non-empty list.
type ObservationScope struct {
	Principals []string `toml:"principals" json:"principals,omitempty"`
	Frameworks []string `toml:"frameworks" json:"frameworks,omitempty"`
	Templates  []string `toml:"templates" json:"templates,omitempty"`
	Servers    []string `toml:"servers" json:"servers,omitempty"`
	Tools      []string `toml:"tools" json:"tools,omitempty"`
}

// Empty reports whether the scope matches every call.
func (s ObservationScope) Empty() bool {
	return len(s.Principals)+len(s.Frameworks)+len(s.Templates)+len(s.Servers)+len(s.Tools) == 0
}

// ObservationBaseline configures E-30 and E-31.
type ObservationBaseline struct {
	// Contexts are the baseline context dimensions (default principal,
	// tool).
	Contexts []string `toml:"contexts" json:"contexts"`
	// Features are the baselined features (default: docs/observation.md).
	Features []ObservationFeature `toml:"feature" json:"feature"`
	// NMin is the sample count at which a context is characterized
	// (CP-30: 30).
	NMin int64 `toml:"n_min" json:"n_min"`
	// HalfLife enables exponential decay of earlier samples.
	HalfLife Duration `toml:"half_life" json:"half_life"`
	// LearningWindow excludes older records from learning (default 720h).
	LearningWindow Duration `toml:"learning_window" json:"learning_window"`
	// SnapshotInterval and SnapshotRecords trigger snapshot builds
	// (defaults 1h and 10000).
	SnapshotInterval Duration `toml:"snapshot_interval" json:"snapshot_interval"`
	SnapshotRecords  int64    `toml:"snapshot_records" json:"snapshot_records"`
	// AutoPromoteMaxShift and AutoPromoteMaxSigmaFactor enable automatic
	// promotion when every drift value is within them (default off).
	AutoPromoteMaxShift       float64 `toml:"auto_promote_max_shift" json:"auto_promote_max_shift"`
	AutoPromoteMaxSigmaFactor float64 `toml:"auto_promote_max_sigma_factor" json:"auto_promote_max_sigma_factor"`
	// Bands are the |z| lower bounds of elevated, abnormal and critical
	// (CP-30: [2, 3, 4]).
	Bands []float64 `toml:"bands" json:"bands"`
}

// ObservationFeature is one baselined feature.
type ObservationFeature struct {
	Parameter  string   `toml:"parameter" json:"parameter"`
	Kind       string   `toml:"kind" json:"kind"`           // numeric (default) or categorical
	Transform  string   `toml:"transform" json:"transform"` // none, log1p, box-cox(λ)
	Robust     bool     `toml:"robust" json:"robust"`
	SigmaFloor *float64 `toml:"sigma_floor" json:"sigma_floor"`
}
