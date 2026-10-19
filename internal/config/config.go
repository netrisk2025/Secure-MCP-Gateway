// Package config loads the Gateway configuration from a TOML file validated
// against the published JSON Schema (FR-12.6) and applies the controlled
// parameter defaults of SRS Appendix A.
package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed config.schema.json
var schemaJSON []byte

// SchemaJSON returns the published configuration schema.
func SchemaJSON() []byte { return append([]byte(nil), schemaJSON...) }

// Config is the validated Gateway configuration. Relative paths are resolved
// against the directory holding the configuration file.
type Config struct {
	Listener      Listener      `toml:"listener" json:"listener"`
	AdminListener AdminListener `toml:"admin_listener" json:"admin_listener"`
	State         State         `toml:"state" json:"state"`
	Admin         Admin         `toml:"admin" json:"admin"`
	Approvers     []Approver    `toml:"approver" json:"approver"`
	Approvals     Approvals     `toml:"approvals" json:"approvals"`
	Console       Console       `toml:"console" json:"console"` // E-24 role accounts (console.go)
	Policy        Policy        `toml:"policy" json:"policy"`
	Limits        Limits        `toml:"limits" json:"limits"`
	Profile       Profile       `toml:"profile" json:"profile"`
	Log           Log           `toml:"log" json:"log"`
	Principals    []Principal   `toml:"principal" json:"principal"`
	Clients       []Client      `toml:"client" json:"client"`
	// ClientMetadata is the CP-52 Client ID Metadata Document allowlist
	// (FR-2.18).
	ClientMetadata []ClientMetadata `toml:"client_metadata" json:"client_metadata"`
	Servers        []Server         `toml:"server" json:"server"`
	Runtime        Runtime          `toml:"runtime" json:"runtime"` // E-15, E-16, E-17 (runtime.go)
	Egress         Egress           `toml:"egress" json:"egress"`
	Filters        Filters          `toml:"filters" json:"filters"` // E-09, E-11 (filters.go)
	Graph          Graph            `toml:"graph" json:"graph"`
	Observation    Observation      `toml:"observation" json:"observation"`
	// Secrets enables the Secret Vault and Broker (E-19, E-20) when present.
	Secrets *Secrets `toml:"secrets" json:"secrets"`

	// directory adds principals and clients managed at run time
	// (SetDirectory); not part of the file.
	directory Directory
	Remote    Remote   `toml:"remote" json:"remote"`
	UDS       UDS      `toml:"uds" json:"uds"` // UDS Harness Profile (uds.go)
	Packages  Packages `toml:"packages" json:"packages"`

	// Operations (E-21 export, E-22, E-23); see ops.go.
	SchemaVersion int      `toml:"schema_version" json:"schema_version"`
	Metrics       Metrics  `toml:"metrics" json:"metrics"`
	Evidence      Evidence `toml:"evidence" json:"evidence"`
	Backup        Backup   `toml:"backup" json:"backup"`

	// Dir is the directory of the configuration file; set by Load.
	Dir string `toml:"-" json:"-"`
}

// Listener configures the harness listener (E-01), CP-01 to CP-03.
type Listener struct {
	Address        string   `toml:"address" json:"address"`
	PublicURL      string   `toml:"public_url" json:"public_url"`
	MCPPath        string   `toml:"mcp_path" json:"mcp_path"`
	TLSCert        string   `toml:"tls_cert" json:"tls_cert"`
	TLSKey         string   `toml:"tls_key" json:"tls_key"`
	AllowedOrigins []string `toml:"allowed_origins" json:"allowed_origins"`
}

// AdminListener configures the loopback control API listener (E-24, CP-03).
// It is separate from the harness listener so that session tokens are never
// accepted for administrative actions (SR-2.5-1).
type AdminListener struct {
	Address string `toml:"address" json:"address"`
}

// Profile selects the deployment profile. "auto" runs the enforced profile
// when the host and launcher support it and the standalone (unconfined)
// profile otherwise; "enforced" refuses to start without confinement;
// "standalone" never attempts confinement.
type Profile struct {
	Mode string `toml:"mode" json:"mode"`
}

// Log configures the diagnostic logger. Diagnostic logs are separate from
// the evidence journal and are never evidence.
type Log struct {
	Level  string `toml:"level" json:"level"`
	Format string `toml:"format" json:"format"` // standard error format; the file is always JSON Lines
	// File is the diagnostic log file (D-14), rotated at MaxBytes keeping
	// MaxFiles rotated files (CP-50). Default <state.dir>/log/smcpd.log.
	File     string `toml:"file" json:"file"`
	MaxBytes int64  `toml:"max_bytes" json:"max_bytes"`
	MaxFiles int    `toml:"max_files" json:"max_files"`
}

// State names the directory that holds keys and the evidence journal.
type State struct {
	Dir string `toml:"dir" json:"dir"`
}

// Admin is the administrator account of the control API (E-24). Either a
// password hash or a pending one-use bootstrap token is configured. The
// bootstrap token is redeemed once on the admin listener to set the
// password, which is then kept in the state directory.
type Admin struct {
	Username              string `toml:"username" json:"username"`
	PasswordHash          string `toml:"password_hash" json:"password_hash"`
	BootstrapTokenSHA256  string `toml:"bootstrap_token_sha256" json:"bootstrap_token_sha256"`
	BootstrapTokenExpires string `toml:"bootstrap_token_expires" json:"bootstrap_token_expires"`
}

// Approver is a Session Approver account. It may approve harness sign-ins at
// the OAuth authorization endpoint (FR-2.19) and nothing else; the
// administrator account is not accepted there.
type Approver struct {
	Username     string `toml:"username" json:"username"`
	PasswordHash string `toml:"password_hash" json:"password_hash"`
}

// Graph configures the graph mirror (E-25, E-26, E-28). Defaults are
// applied by internal/graph; see docs/graph.md.
type Graph struct {
	Enabled           bool     `toml:"enabled" json:"enabled"`
	URI               string   `toml:"uri" json:"uri"`
	Username          string   `toml:"username" json:"username"`
	PasswordFile      string   `toml:"password_file" json:"password_file"`
	Database          string   `toml:"database" json:"database"`
	Retention         Duration `toml:"retention" json:"retention"`
	RetentionInterval Duration `toml:"retention_interval" json:"retention_interval"`
	CatchUpInterval   Duration `toml:"catchup_interval" json:"catchup_interval"`
	MemoryInterval    Duration `toml:"memory_interval" json:"memory_interval"`
	BatchSize         int      `toml:"batch_size" json:"batch_size"`
	Queue             int      `toml:"queue" json:"queue"`
	HeapBytes         int64    `toml:"heap_bytes" json:"heap_bytes"`
	PageCacheBytes    int64    `toml:"page_cache_bytes" json:"page_cache_bytes"`
	RequireHardening  bool     `toml:"require_hardening" json:"require_hardening"`
}

// Policy points at the policy document (E-05 draft in this slice).
type Policy struct {
	File string `toml:"file" json:"file"`
}

// Limits holds controlled parameters from SRS Appendix A that the Gateway
// enforces. A key absent from the file takes the Appendix A default; a key
// present with an explicit value, including 0 where the schema allows it,
// keeps that value.
type Limits struct {
	RequestBodyBytes       int64    `toml:"request_body_bytes" json:"request_body_bytes"`                         // CP-07
	ResultBytes            int64    `toml:"result_bytes" json:"result_bytes"`                                     // CP-08
	ToolConcurrencyPerUser int      `toml:"tool_concurrency_per_principal" json:"tool_concurrency_per_principal"` // CP-10
	ToolConcurrencyTotal   int      `toml:"tool_concurrency_total" json:"tool_concurrency_total"`                 // CP-10
	ToolQueue              int      `toml:"tool_queue" json:"tool_queue"`                                         // CP-10
	PrincipalCallsPerMin   int      `toml:"principal_calls_per_minute" json:"principal_calls_per_minute"`         // CP-11
	PrincipalCallBurst     int      `toml:"principal_call_burst" json:"principal_call_burst"`                     // CP-11 burst
	UpstreamTimeout        Duration `toml:"upstream_timeout" json:"upstream_timeout"`                             // CP-13
	ClientDeadline         Duration `toml:"client_deadline" json:"client_deadline"`                               // CP-13
	SessionMaxLifetime     Duration `toml:"session_max_lifetime" json:"session_max_lifetime"`                     // CP-18
	SessionIdleTimeout     Duration `toml:"session_idle_timeout" json:"session_idle_timeout"`                     // CP-18
	SessionsPerPrincipal   int      `toml:"sessions_per_principal" json:"sessions_per_principal"`                 // CP-18
	CatalogTTLMs           int      `toml:"catalog_ttl_ms" json:"catalog_ttl_ms"`                                 // CP-19
	CatalogPageSize        int      `toml:"catalog_page_size" json:"catalog_page_size"`                           // CP-19
	ListenStreamsPerSess   int      `toml:"listen_streams_per_session" json:"listen_streams_per_session"`         // CP-20
	ApprovalHold           Duration `toml:"approval_hold" json:"approval_hold"`                                   // approval hold-mode bound
}

// LimitDefault is one Appendix A default applied to a [limits] key.
type LimitDefault struct {
	Key   string
	Value any // int, int64 or time.Duration
	field func(*Limits) any
}

// LimitDefaults lists the defaults by configuration key. A test checks that
// this list and the schema's limits properties name the same keys.
var LimitDefaults = []LimitDefault{
	{"request_body_bytes", int64(1 << 20), func(m *Limits) any { return &m.RequestBodyBytes }},
	{"result_bytes", int64(8 << 20), func(m *Limits) any { return &m.ResultBytes }},
	{"tool_concurrency_per_principal", 4, func(m *Limits) any { return &m.ToolConcurrencyPerUser }},
	{"tool_concurrency_total", 16, func(m *Limits) any { return &m.ToolConcurrencyTotal }},
	{"tool_queue", 32, func(m *Limits) any { return &m.ToolQueue }},
	{"principal_calls_per_minute", 60, func(m *Limits) any { return &m.PrincipalCallsPerMin }},
	{"principal_call_burst", 10, func(m *Limits) any { return &m.PrincipalCallBurst }},
	{"upstream_timeout", 45 * time.Second, func(m *Limits) any { return &m.UpstreamTimeout }},
	{"client_deadline", 60 * time.Second, func(m *Limits) any { return &m.ClientDeadline }},
	{"session_max_lifetime", 8 * time.Hour, func(m *Limits) any { return &m.SessionMaxLifetime }},
	{"session_idle_timeout", 30 * time.Minute, func(m *Limits) any { return &m.SessionIdleTimeout }},
	{"sessions_per_principal", 8, func(m *Limits) any { return &m.SessionsPerPrincipal }},
	{"catalog_ttl_ms", 60000, func(m *Limits) any { return &m.CatalogTTLMs }},
	{"catalog_page_size", 100, func(m *Limits) any { return &m.CatalogPageSize }},
	{"listen_streams_per_session", 2, func(m *Limits) any { return &m.ListenStreamsPerSess }},
	{"approval_hold", 120 * time.Second, func(m *Limits) any { return &m.ApprovalHold }},
}

// Principal is a framework instance record (FR-2.1).
type Principal struct {
	ID          string `toml:"id" json:"id"`
	Framework   string `toml:"framework" json:"framework"`
	DisplayName string `toml:"display_name" json:"display_name"`
	Profile     string `toml:"profile" json:"profile"`
	Enabled     *bool  `toml:"enabled" json:"enabled"`
}

// Client is an OAuth client registration bound to exactly one principal
// (FR-2.18). ClientID is either an opaque issued ID or a Client ID Metadata
// Document URL. ClientSecretHash is empty for public clients.
type Client struct {
	ClientID         string   `toml:"client_id" json:"client_id"`
	ClientSecretHash string   `toml:"client_secret_hash" json:"client_secret_hash"`
	Principal        string   `toml:"principal" json:"principal"`
	RedirectURIs     []string `toml:"redirect_uris" json:"redirect_uris"`
}

// ClientMetadata is one CP-52 allowlist entry: an HTTPS Client ID Metadata
// Document URL that the Gateway may fetch when a client presents it as its
// client_id, and the one principal that client binds to (FR-2.18). The
// document supplies the redirect URIs; the URL must match exactly.
type ClientMetadata struct {
	URL       string `toml:"url" json:"url"`
	Principal string `toml:"principal" json:"principal"`
}

// FindClientMetadata returns the allowlist entry for a client ID, or nil.
func (c *Config) FindClientMetadata(id string) *ClientMetadata {
	for i := range c.ClientMetadata {
		if c.ClientMetadata[i].URL == id {
			return &c.ClientMetadata[i]
		}
	}
	return nil
}

// Server is a backend MCP server launched over stdio. Signed packages
// (E-13) are not built yet; until they are, the tool list is taken from the
// live server at startup and flagged as unverified.
//
// RiskClasses names the high-risk classes of the server's tools; a server in
// any high-risk class is refused under the standalone (unconfined) profile.
// SecretEnv maps environment variable names to secret references that the
// Secret Broker (E-20) resolves at launch.
type Server struct {
	Alias       string            `toml:"alias" json:"alias"`
	Command     string            `toml:"command" json:"command"`
	Args        []string          `toml:"args" json:"args"`
	Env         map[string]string `toml:"env" json:"env"`
	SecretEnv   map[string]string `toml:"secret_env" json:"secret_env"`
	Dir         string            `toml:"dir" json:"dir"`
	RiskClasses []string          `toml:"risk_classes" json:"risk_classes"`
	// CommandSHA256 optionally pins the hex SHA-256 of the command file of
	// a command-configured server. Without it the Gateway records the
	// content address of the command (and of file arguments) at the first
	// launch and refuses a relaunch whose files changed (SR-3.6-1).
	CommandSHA256 string `toml:"command_sha256" json:"command_sha256"`
	// Package names a signed server package (E-13/E-14) instead of a
	// command: the enabled revision of that server ID is launched from the
	// content-addressed store. PackageSHA256 optionally pins its artifact
	// digest; Slots bind the manifest's filesystem slots to host paths.
	Package       string            `toml:"package" json:"package"`
	PackageSHA256 string            `toml:"package_sha256" json:"package_sha256"`
	Slots         map[string]string `toml:"slots" json:"slots"`

	// Set by the package library when it resolves a packaged entry, never
	// read from the file: the manifest's launch runtime ("native", "node",
	// "python", "oci"), the unpacked artifact tree, and the filesystem
	// slots the verified manifest declares, bound to host paths (nil for a
	// configured command). The Execution Sandbox mounts only grants that
	// intersect Roots (SR-4.6-1).
	Runtime      string     `toml:"-" json:"-"`
	ArtifactRoot string     `toml:"-" json:"-"`
	Roots        []SlotRoot `toml:"-" json:"-"`
}

// SlotRoot is one manifest-declared filesystem slot bound to a host path;
// Write is true when the manifest declares the slot read-write.
type SlotRoot struct {
	Slot  string
	Path  string
	Write bool
}

// Packages configures the Library Trust Verifier and Local Server
// Registry (E-13, E-14; docs/packaging.md).
type Packages struct {
	Library       string   `toml:"library" json:"library"`             // default <state>/library
	ScanInterval  Duration `toml:"scan_interval" json:"scan_interval"` // FR-5.3, default 300s
	RequireSigned bool     `toml:"require_signed" json:"require_signed"`
	Node          string   `toml:"node" json:"node"`
	Python        string   `toml:"python" json:"python"`
	Podman        string   `toml:"podman" json:"podman"`
}

// Secrets configures the Secret Vault (E-19) and Secret Broker (E-20).
// Defaults and path resolution are applied by internal/secrets.
type Secrets struct {
	VaultDir        string   `toml:"vault_dir" json:"vault_dir"`
	KeySource       string   `toml:"key_source" json:"key_source"`
	PassphraseFile  string   `toml:"passphrase_file" json:"passphrase_file"`
	UsePolicyFile   string   `toml:"use_policy_file" json:"use_policy_file"`
	RuntimeDir      string   `toml:"runtime_dir" json:"runtime_dir"`
	RotationOverlap Duration `toml:"rotation_overlap" json:"rotation_overlap"`
}

// HighRiskClasses are the tool classes that need confinement: general SQL,
// code execution, CAD scripting and browser automation.
var HighRiskClasses = []string{"general-sql", "code-execution", "cad-scripting", "browser-automation"}

// HighRisk reports whether the server declares any high-risk class.
func (s Server) HighRisk() bool {
	for _, c := range s.RiskClasses {
		if slices.Contains(HighRiskClasses, c) {
			return true
		}
	}
	return false
}

// Duration is a time.Duration that reads from a TOML string such as "45s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.Duration.String()), nil }

// Load reads, validates and defaults the configuration file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cfg.Dir = filepath.Dir(abs)
	cfg.resolvePaths()
	return cfg, nil
}

// Parse validates raw TOML against the schema and applies defaults. Paths are
// left as written.
func Parse(raw []byte) (*Config, error) {
	var generic map[string]any
	if err := toml.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	// The version is checked before the schema: a newer file may use keys
	// this release does not know (FR-13.13).
	if err := checkSchemaVersion(generic); err != nil {
		return nil, err
	}
	if err := validate(generic); err != nil {
		return nil, err
	}
	var cfg Config
	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	cfg.applyDefaults(presentKeys(generic, "limits"))
	cfg.Egress.applyDefaults(presentKeys(generic, "egress"))
	if err := cfg.applyOpsDefaults(); err != nil {
		return nil, err
	}
	cfg.Remote.applyDefaults(cfg.AdminListener.Address)
	cfg.UDS.applyDefaults()
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// presentKeys returns the keys written in the named table of the document.
func presentKeys(doc map[string]any, table string) map[string]bool {
	out := map[string]bool{}
	if t, ok := doc[table].(map[string]any); ok {
		for k := range t {
			out[k] = true
		}
	}
	return out
}

var compiledSchema = func() *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		panic("embedded config schema: " + err.Error())
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("config.schema.json", doc); err != nil {
		panic(err)
	}
	s, err := c.Compile("config.schema.json")
	if err != nil {
		panic("compile config schema: " + err.Error())
	}
	return s
}()

func validate(doc map[string]any) error {
	// The schema is validated against the JSON form of the TOML document so
	// that one published schema serves both the file and any future API.
	js, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var jsonDoc any
	if err := json.Unmarshal(js, &jsonDoc); err != nil {
		return err
	}
	if err := compiledSchema.Validate(jsonDoc); err != nil {
		return fmt.Errorf("configuration does not match schema: %w", err)
	}
	return nil
}

func (c *Config) applyDefaults(limitsSet map[string]bool) {
	l := &c.Listener
	if l.Address == "" {
		l.Address = "127.0.0.1:8443"
	}
	if l.PublicURL == "" {
		l.PublicURL = "https://" + l.Address
	}
	if l.MCPPath == "" {
		l.MCPPath = "/mcp"
	}
	if l.TLSCert == "" {
		l.TLSCert = "tls/server.crt"
	}
	if l.TLSKey == "" {
		l.TLSKey = "tls/server.key"
	}
	if c.AdminListener.Address == "" {
		c.AdminListener.Address = "127.0.0.1:8444"
	}
	if c.Profile.Mode == "" {
		c.Profile.Mode = "auto"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.State.Dir == "" {
		c.State.Dir = "state"
	}
	if c.Policy.File == "" {
		c.Policy.File = "policy.json"
	}
	if c.Packages.ScanInterval.Duration == 0 {
		c.Packages.ScanInterval.Duration = 300 * time.Second
	}
	for _, d := range LimitDefaults {
		if limitsSet[d.Key] {
			continue
		}
		switch v := d.Value.(type) {
		case int:
			*d.field(&c.Limits).(*int) = v
		case int64:
			*d.field(&c.Limits).(*int64) = v
		case time.Duration:
			d.field(&c.Limits).(*Duration).Duration = v
		}
	}
	c.Runtime.applyDefaults(c.Profile.Mode)
	for i := range c.Principals {
		if c.Principals[i].Enabled == nil {
			t := true
			c.Principals[i].Enabled = &t
		}
	}
}

// checkVerifiers refuses password and client secret verifiers weaker than
// CP-28 (SR-2.7-1).
func (c *Config) checkVerifiers() error {
	type entry struct{ key, hash string }
	list := []entry{{"admin.password_hash", c.Admin.PasswordHash}}
	for _, a := range c.Approvers {
		list = append(list, entry{fmt.Sprintf("approver %q password_hash", a.Username), a.PasswordHash})
	}
	for _, a := range c.Approvals.Accounts {
		list = append(list, entry{fmt.Sprintf("approvals.account %q password_hash", a.Username), a.PasswordHash})
	}
	for _, a := range c.Console.Accounts {
		list = append(list, entry{fmt.Sprintf("console.account %q password_hash", a.Username), a.PasswordHash})
	}
	for _, cl := range c.Clients {
		list = append(list, entry{fmt.Sprintf("client %q client_secret_hash", cl.ClientID), cl.ClientSecretHash})
	}
	for _, e := range list {
		if err := keys.CheckVerifier(e.hash); err != nil {
			return fmt.Errorf("%s: %w", e.key, err)
		}
	}
	return nil
}

// check enforces cross-field rules the schema cannot express.
func (c *Config) check() error {
	for _, d := range []struct {
		key string
		v   Duration
	}{{"upstream_timeout", c.Limits.UpstreamTimeout}, {"client_deadline", c.Limits.ClientDeadline},
		{"session_max_lifetime", c.Limits.SessionMaxLifetime}, {"session_idle_timeout", c.Limits.SessionIdleTimeout}} {
		if d.v.Duration <= 0 {
			return fmt.Errorf("limits.%s must be a positive duration", d.key)
		}
	}
	if c.Limits.ApprovalHold.Duration < 0 || c.Limits.ApprovalHold.Duration > 600*time.Second {
		return fmt.Errorf("limits.approval_hold must be between 0s and 600s (CP-45)")
	}
	if c.Admin.PasswordHash == "" && c.Admin.BootstrapTokenSHA256 == "" {
		return fmt.Errorf("admin needs password_hash or bootstrap_token_sha256")
	}
	if err := c.checkVerifiers(); err != nil {
		return err
	}
	if c.Admin.BootstrapTokenExpires != "" {
		if _, err := time.Parse(time.RFC3339, c.Admin.BootstrapTokenExpires); err != nil {
			return fmt.Errorf("admin.bootstrap_token_expires: %w", err)
		}
	}
	if sameHostPort(c.AdminListener.Address, c.Listener.Address) {
		return fmt.Errorf("admin_listener.address must differ from listener.address")
	}
	approvers := map[string]bool{}
	for _, a := range c.Approvers {
		if approvers[a.Username] {
			return fmt.Errorf("duplicate approver %q", a.Username)
		}
		if a.Username == c.Admin.Username {
			return fmt.Errorf("approver %q reuses the administrator username", a.Username)
		}
		approvers[a.Username] = true
	}
	principals := map[string]bool{}
	for _, p := range c.Principals {
		if principals[p.ID] {
			return fmt.Errorf("duplicate principal id %q", p.ID)
		}
		principals[p.ID] = true
	}
	clients := map[string]bool{}
	for _, cl := range c.Clients {
		if clients[cl.ClientID] {
			return fmt.Errorf("duplicate client_id %q", cl.ClientID)
		}
		clients[cl.ClientID] = true
		if !principals[cl.Principal] {
			return fmt.Errorf("client %q names unknown principal %q", cl.ClientID, cl.Principal)
		}
	}
	for _, m := range c.ClientMetadata { // FR-2.18: one principal per client ID
		u, err := url.Parse(m.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Path == "" || u.Path == "/" {
			return fmt.Errorf("client_metadata %q: an HTTPS URL with a path, no user information and no fragment is required (CP-52)", m.URL)
		}
		if clients[m.URL] {
			return fmt.Errorf("duplicate client_id %q (client and client_metadata)", m.URL)
		}
		clients[m.URL] = true
		if !principals[m.Principal] {
			return fmt.Errorf("client_metadata %q names unknown principal %q", m.URL, m.Principal)
		}
	}
	if err := c.Runtime.check(c); err != nil {
		return err
	}
	aliases := map[string]bool{}
	for _, s := range c.Servers {
		if aliases[s.Alias] {
			return fmt.Errorf("duplicate server alias %q", s.Alias)
		}
		aliases[s.Alias] = true
		if (s.Command == "") == (s.Package == "") {
			return fmt.Errorf("server %q: set exactly one of command and package", s.Alias)
		}
		if s.Package == "" && (s.PackageSHA256 != "" || len(s.Slots) > 0) {
			return fmt.Errorf("server %q: package_sha256 and slots apply only to a package", s.Alias)
		}
		if s.Package != "" && s.CommandSHA256 != "" {
			return fmt.Errorf("server %q: command_sha256 applies only to a command; pin a package with package_sha256", s.Alias)
		}
		for k := range s.SecretEnv {
			if _, dup := s.Env[k]; dup {
				return fmt.Errorf("server %q: %s is in both env and secret_env", s.Alias, k)
			}
		}
	}
	if err := c.checkRemote(); err != nil {
		return err
	}
	if err := c.checkUDS(); err != nil {
		return err
	}
	return c.Egress.check(aliases)
}

func sameHostPort(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return ap == bp && (ah == bh || ah == "localhost" || bh == "localhost")
}

func (c *Config) resolvePaths() {
	res := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(c.Dir, *p)
		}
	}
	res(&c.State.Dir)
	res(&c.Policy.File)
	res(&c.UDS.Path)
	// TLS paths default relative to the state directory.
	for _, p := range []*string{&c.Listener.TLSCert, &c.Listener.TLSKey} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(c.State.Dir, *p)
		}
	}
	for i := range c.Servers {
		res(&c.Servers[i].Dir)
		for k, v := range c.Servers[i].Slots {
			res(&v)
			c.Servers[i].Slots[k] = v
		}
	}
	c.Runtime.resolvePaths(c.Dir)
	c.resolveOpsPaths(res)
	res(&c.Packages.Library)
}

// ResourceURI is the CP-41 resource indicator: the public URL of the MCP
// endpoint.
func (c *Config) ResourceURI() string { return c.Listener.PublicURL + c.Listener.MCPPath }

// AdminURL is the base URL of the control API.
func (c *Config) AdminURL() string { return "https://" + c.AdminListener.Address }

// FindPrincipal returns the principal record with the given ID.
func (c *Config) FindPrincipal(id string) *Principal {
	for i := range c.Principals {
		if c.Principals[i].ID == id {
			if c.directory != nil && c.directory.Suspended(id) {
				p, off := c.Principals[i], false
				p.Enabled = &off
				return &p
			}
			return &c.Principals[i]
		}
	}
	if c.directory != nil {
		if p, ok := c.directory.Principal(id); ok {
			return &p
		}
	}
	return nil
}

// FindClient returns the client registration with the given client ID.
func (c *Config) FindClient(id string) *Client {
	for i := range c.Clients {
		if c.Clients[i].ClientID == id {
			return &c.Clients[i]
		}
	}
	if c.directory != nil {
		if cl, ok := c.directory.Client(id); ok {
			return &cl
		}
	}
	return nil
}

// Directory holds principals and OAuth clients managed at run time from the
// control API (internal/principals), in addition to those of the file, and
// can suspend a file principal. FindPrincipal and FindClient consult it
// after the file, so every element sees the same principals.
type Directory interface {
	Principal(id string) (Principal, bool)
	Client(id string) (Client, bool)
	Suspended(id string) bool
}

// CredentialRevoked reports whether the run-time directory holds the
// client credential id as revoked. Clients of the configuration file are
// never revoked there (they are removed from the file instead), and
// clients the directory does not know are not reported.
func (c *Config) CredentialRevoked(id string) bool {
	r, ok := c.directory.(interface{ CredentialRevoked(string) bool })
	return ok && id != "" && r.CredentialRevoked(id)
}

// SetDirectory attaches the run-time directory. Call it before the
// listeners start; the configuration is read without locks.
func (c *Config) SetDirectory(d Directory) { c.directory = d }

// ApproverDirectory is implemented by a Directory that also holds Session
// Approver accounts created from the control API (FR-2.23).
type ApproverDirectory interface {
	Approvers() []Approver
}

// SessionApprovers returns every Session Approver account: the [[approver]]
// entries of the file, then those of the run-time directory. Every element
// that verifies a Session Approver sign-in reads this list.
func (c *Config) SessionApprovers() []Approver {
	out := append([]Approver(nil), c.Approvers...)
	if d, ok := c.directory.(ApproverDirectory); ok {
		out = append(out, d.Approvers()...)
	}
	return out
}

// FindApprover returns the Session Approver with the given username.
func (c *Config) FindApprover(username string) *Approver {
	for _, a := range c.SessionApprovers() {
		if a.Username == username {
			return &a
		}
	}
	return nil
}
