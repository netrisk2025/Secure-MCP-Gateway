// Package config loads the Gateway configuration from a TOML file validated
// against the published JSON Schema (FR-12.6) and applies the controlled
// parameter defaults of SRS Appendix A.
package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed config.schema.json
var schemaJSON []byte

// Config is the validated Gateway configuration. Relative paths are resolved
// against the directory holding the configuration file.
type Config struct {
	Listener   Listener    `toml:"listener" json:"listener"`
	State      State       `toml:"state" json:"state"`
	Admin      Admin       `toml:"admin" json:"admin"`
	Policy     Policy      `toml:"policy" json:"policy"`
	Limits     Limits      `toml:"limits" json:"limits"`
	Principals []Principal `toml:"principal" json:"principal"`
	Clients    []Client    `toml:"client" json:"client"`
	Servers    []Server    `toml:"server" json:"server"`

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

// State names the directories that hold keys and the evidence journal.
type State struct {
	Dir string `toml:"dir" json:"dir"`
}

// Admin is the administrative sign-in used by the OAuth authorization
// endpoint (FR-2.19) in this slice.
type Admin struct {
	Username     string `toml:"username" json:"username"`
	PasswordHash string `toml:"password_hash" json:"password_hash"`
}

// Policy points at the policy document (E-05 draft in this slice).
type Policy struct {
	File string `toml:"file" json:"file"`
}

// Limits holds controlled parameters from SRS Appendix A that this slice
// enforces. Zero values are replaced by the appendix defaults.
type Limits struct {
	RequestBodyBytes       int64    `toml:"request_body_bytes" json:"request_body_bytes"`                         // CP-07
	ResultBytes            int64    `toml:"result_bytes" json:"result_bytes"`                                     // CP-08
	ToolConcurrencyPerUser int      `toml:"tool_concurrency_per_principal" json:"tool_concurrency_per_principal"` // CP-10
	ToolConcurrencyTotal   int      `toml:"tool_concurrency_total" json:"tool_concurrency_total"`                 // CP-10
	ToolQueue              int      `toml:"tool_queue" json:"tool_queue"`                                         // CP-10
	PrincipalCallsPerMin   int      `toml:"principal_calls_per_minute" json:"principal_calls_per_minute"`         // CP-11
	UpstreamTimeout        Duration `toml:"upstream_timeout" json:"upstream_timeout"`                             // CP-13
	ClientDeadline         Duration `toml:"client_deadline" json:"client_deadline"`                               // CP-13
	SessionMaxLifetime     Duration `toml:"session_max_lifetime" json:"session_max_lifetime"`                     // CP-18
	SessionIdleTimeout     Duration `toml:"session_idle_timeout" json:"session_idle_timeout"`                     // CP-18
	SessionsPerPrincipal   int      `toml:"sessions_per_principal" json:"sessions_per_principal"`                 // CP-18
	CatalogTTLMs           int      `toml:"catalog_ttl_ms" json:"catalog_ttl_ms"`                                 // CP-19
	CatalogPageSize        int      `toml:"catalog_page_size" json:"catalog_page_size"`                           // CP-19
	ListenStreamsPerSess   int      `toml:"listen_streams_per_session" json:"listen_streams_per_session"`         // CP-20
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

// Server is a backend MCP server this slice launches over stdio. The signed
// package path (E-13) is not part of the slice; the tool list is taken from
// the live server at startup and recorded by the registry.
type Server struct {
	Alias   string            `toml:"alias" json:"alias"`
	Command string            `toml:"command" json:"command"`
	Args    []string          `toml:"args" json:"args"`
	Env     map[string]string `toml:"env" json:"env"`
	Dir     string            `toml:"dir" json:"dir"`
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
	if err := validate(generic); err != nil {
		return nil, err
	}
	var cfg Config
	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

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
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return fmt.Errorf("embedded schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("config.schema.json", schemaDoc); err != nil {
		return err
	}
	sch, err := c.Compile("config.schema.json")
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	if err := sch.Validate(jsonDoc); err != nil {
		return fmt.Errorf("configuration does not match schema: %w", err)
	}
	return nil
}

func (c *Config) applyDefaults() {
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
	if c.State.Dir == "" {
		c.State.Dir = "state"
	}
	if c.Policy.File == "" {
		c.Policy.File = "policy.json"
	}
	m := &c.Limits
	def := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	def64 := func(p *int64, v int64) {
		if *p == 0 {
			*p = v
		}
	}
	defD := func(p *Duration, v time.Duration) {
		if p.Duration == 0 {
			p.Duration = v
		}
	}
	def64(&m.RequestBodyBytes, 1<<20)
	def64(&m.ResultBytes, 8<<20)
	def(&m.ToolConcurrencyPerUser, 4)
	def(&m.ToolConcurrencyTotal, 16)
	def(&m.ToolQueue, 32)
	def(&m.PrincipalCallsPerMin, 60)
	defD(&m.UpstreamTimeout, 45*time.Second)
	defD(&m.ClientDeadline, 60*time.Second)
	defD(&m.SessionMaxLifetime, 8*time.Hour)
	defD(&m.SessionIdleTimeout, 30*time.Minute)
	def(&m.SessionsPerPrincipal, 8)
	def(&m.CatalogTTLMs, 60000)
	def(&m.CatalogPageSize, 100)
	def(&m.ListenStreamsPerSess, 2)
	for i := range c.Principals {
		if c.Principals[i].Enabled == nil {
			t := true
			c.Principals[i].Enabled = &t
		}
	}
}

// check enforces cross-field rules the schema cannot express.
func (c *Config) check() error {
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
	aliases := map[string]bool{}
	for _, s := range c.Servers {
		if aliases[s.Alias] {
			return fmt.Errorf("duplicate server alias %q", s.Alias)
		}
		aliases[s.Alias] = true
	}
	return nil
}

func (c *Config) resolvePaths() {
	res := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(c.Dir, *p)
		}
	}
	res(&c.State.Dir)
	res(&c.Policy.File)
	// TLS paths default relative to the state directory.
	for _, p := range []*string{&c.Listener.TLSCert, &c.Listener.TLSKey} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(c.State.Dir, *p)
		}
	}
	for i := range c.Servers {
		res(&c.Servers[i].Dir)
	}
}

// ResourceURI is the CP-41 resource indicator: the public URL of the MCP
// endpoint.
func (c *Config) ResourceURI() string { return c.Listener.PublicURL + c.Listener.MCPPath }

// FindPrincipal returns the principal record with the given ID.
func (c *Config) FindPrincipal(id string) *Principal {
	for i := range c.Principals {
		if c.Principals[i].ID == id {
			return &c.Principals[i]
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
	return nil
}
