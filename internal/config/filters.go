package config

// Filters configures the Request and Response Inspection Pipelines (E-09,
// E-11) and the tool metadata scan. Every key is optional; docs/filters.md
// describes each one and its default.
type Filters struct {
	// RulesDir holds an index.json and rule-set files that replace the
	// rule sets compiled into the binary.
	RulesDir string `toml:"rules_dir" json:"rules_dir"`
	// RuleVersions pins a rule set to a version listed in the index.
	RuleVersions map[string]string `toml:"rule_versions" json:"rule_versions"`
	// Deadline bounds one chain run (CP-14, default 2s).
	Deadline Duration `toml:"deadline" json:"deadline"`
	// MandatoryRequest and MandatoryResponse replace the default sets of
	// filters that run on every call; other registered filters run only
	// when a policy rule names them.
	MandatoryRequest  []string `toml:"mandatory_request" json:"mandatory_request"`
	MandatoryResponse []string `toml:"mandatory_response" json:"mandatory_response"`
	// MetadataScan scans tool metadata at import and presentation (default
	// true).
	MetadataScan *bool `toml:"metadata_scan" json:"metadata_scan"`

	Size         FilterSize         `toml:"size" json:"size"`
	Paths        FilterPaths        `toml:"paths" json:"paths"`
	URLs         FilterURLs         `toml:"urls" json:"urls"`
	ContentTypes FilterContentTypes `toml:"content_types" json:"content_types"`
}

// FilterSize configures size-limit. Zero values take the defaults.
type FilterSize struct {
	ArgumentBytes int64 `toml:"argument_bytes" json:"argument_bytes"`
	ArgumentDepth int   `toml:"argument_depth" json:"argument_depth"`
	StringBytes   int64 `toml:"string_bytes" json:"string_bytes"`
	ResultDepth   int   `toml:"result_depth" json:"result_depth"`
}

// FilterPaths configures path-canonicalize.
type FilterPaths struct {
	Roots       []string            `toml:"roots" json:"roots"`
	ServerRoots map[string][]string `toml:"server_roots" json:"server_roots"`
	Names       []string            `toml:"argument_names" json:"argument_names"`
	IgnoreNames []string            `toml:"ignore_names" json:"ignore_names"`
	Rewrite     *bool               `toml:"rewrite" json:"rewrite"`
}

// FilterURLs configures url-canonicalize.
type FilterURLs struct {
	Schemes      []string `toml:"schemes" json:"schemes"`
	Hosts        []string `toml:"hosts" json:"hosts"`
	DenyHosts    []string `toml:"deny_hosts" json:"deny_hosts"`
	AllowPrivate bool     `toml:"allow_private" json:"allow_private"`
	Names        []string `toml:"argument_names" json:"argument_names"`
	IgnoreNames  []string `toml:"ignore_names" json:"ignore_names"`
	Rewrite      *bool    `toml:"rewrite" json:"rewrite"`
}

// FilterContentTypes configures content-type-gate.
type FilterContentTypes struct {
	Allow    []string `toml:"allow" json:"allow"`
	MaxBytes int64    `toml:"max_bytes" json:"max_bytes"`
}
