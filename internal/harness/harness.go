// Package harness generates and checks client (harness) configuration for
// the Gateway (E-33, FR-15): connection settings and CA trust per client
// (`smcpctl clients setup`, FR-15.7), lockdown profiles that restrict a
// client to the Gateway and deny its file tools the Gateway's paths
// (`smcpctl lockdown`, FR-15.1, FR-15.2, FR-15.6), and the inventory and
// path checks of `smcpctl doctor` (FR-15.3 to FR-15.5, SR-4.9-1,
// SR-4.11-1).
//
// Every change is planned first (Plan) so that --dry-run shows exactly
// what would be written; applying a plan copies each existing file to a
// timestamped backup and records a manifest that `remove` uses to restore
// the files byte for byte.
package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

// GatewayName is the server name the Gateway gets in client configuration.
const GatewayName = "smcp"

// Gateway describes the Gateway a client is pointed at.
type Gateway struct {
	MCPURL      string   // https://127.0.0.1:8443/mcp
	CAFile      string   // Gateway server CA
	Credentials string   // CP-43 credential file
	Paths       []string // CP-46 Gateway paths: configuration, state, logs
	// Origins identify the Gateway in other configuration (scheme://host:port).
	Origins []string
	// Standalone is true when the Gateway runs the Standalone profile, in
	// which clients run under the Gateway's own identity.
	Standalone bool
}

// Env is where client configuration lives.
type Env struct {
	Home string
	CWD  string // project scope
	OS   string // runtime.GOOS
	// Root prefixes system-wide (managed) paths; "" is the real root. Tests
	// point it at a temporary directory.
	Root string
	Gateway
}

// NewEnv returns the environment of the current user.
func NewEnv(gw Gateway) (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return Env{}, err
	}
	return Env{Home: home, CWD: cwd, OS: runtime.GOOS, Gateway: gw}, nil
}

func (e Env) home(p ...string) string { return filepath.Join(append([]string{e.Home}, p...)...) }
func (e Env) sys(p string) string {
	if e.Root == "" {
		return p
	}
	return filepath.Join(e.Root, p)
}

// Options select how a client connects.
type Options struct {
	// Stdio connects through smcp-stdio even where the client supports
	// Streamable HTTP (no CA trust needed in the client).
	Stdio bool
	// Helper uses smcp-session as a header helper (Claude Code) instead of
	// the client's OAuth sign-in.
	Helper bool
	// NoLockdown leaves the lockdown profile out of setup.
	NoLockdown bool
}

// Purposes of a change.
const (
	PurposeConnection = "connection"
	PurposeCATrust    = "ca-trust"
	PurposeLockdown   = "lockdown"
)

// Change is one file the plan writes.
type Change struct {
	Path    string `json:"path"`
	Scope   string `json:"scope"` // user, project, managed
	Purpose string `json:"purpose"`
	Before  []byte `json:"-"` // nil when the file does not exist
	After   []byte `json:"-"`
	Mode    os.FileMode
}

// Plan is what setup or lockdown would do for one client.
type Plan struct {
	Client   string     `json:"client"`
	Changes  []Change   `json:"changes"`
	Commands [][]string `json:"commands,omitempty"` // to run with the operator's consent (system trust)
	Notes    []string   `json:"notes,omitempty"`
}

// Server is an MCP server configured in a client.
type Server struct {
	Client    string `json:"client"`
	Scope     string `json:"scope"`
	File      string `json:"file"`
	Name      string `json:"name"`
	Transport string `json:"transport"` // http, stdio, unknown
	Target    string `json:"target"`    // URL or command line
	Gateway   bool   `json:"gateway"`
}

// Client is one harness of Appendix K.
type Client struct {
	ID   string
	Name string
	// Installed reports whether the client appears to be installed for the
	// user (configuration directory or binary present).
	Installed func(Env) bool
	Setup     func(Env, Options) (Plan, error)
	Lockdown  func(Env) (Plan, error)
	Inventory func(Env) ([]Server, []string) // servers, unreadable-file notes
	// SettingsFiles are the client's MCP and permission settings files in
	// user and project scope (SR-4.11-1).
	SettingsFiles func(Env) []string
	// Protected reports whether the lockdown denies the client's own file
	// tools write access to its settings files.
	Protected func(Env) bool
	CATrust   func(Env) (bool, string)
	// LockdownMechanism is empty when the client offers none (Appendix K).
	LockdownMechanism string
}

var registry = map[string]*Client{}

func register(c *Client) { registry[c.ID] = c }

// Lookup returns a client by ID or a common alias.
func Lookup(id string) (*Client, bool) {
	id = strings.ToLower(id)
	switch id {
	case "claude", "claudecode":
		id = "claude-code"
	case "codex-cli":
		id = "codex"
	case "gemini":
		id = "gemini-cli"
	case "grok":
		id = "grok-build"
	}
	c, ok := registry[id]
	return c, ok
}

// Clients returns every client in a stable order.
func Clients() []*Client {
	out := make([]*Client, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IDs lists the client IDs.
func IDs() []string {
	var ids []string
	for _, c := range Clients() {
		ids = append(ids, c.ID)
	}
	return ids
}

func readOrNil(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// IsGatewayURL reports whether u is the Gateway's MCP endpoint (any of its
// origins).
func (g Gateway) IsGatewayURL(u string) bool {
	pu, err := url.Parse(u)
	if err != nil {
		return false
	}
	origin := strings.ToLower(pu.Scheme + "://" + pu.Host)
	for _, o := range g.Origins {
		if strings.EqualFold(strings.TrimSuffix(o, "/"), origin) {
			return true
		}
	}
	return false
}

// IsGatewayCommand reports whether a stdio command line is an adapter of
// the Gateway (smcp-stdio, smcp-connect directly or through npx).
func IsGatewayCommand(cmd string, args []string) bool {
	base := filepath.Base(cmd)
	if base == "smcp-stdio" || base == "smcp-connect" {
		return true
	}
	if base == "npx" || base == "bunx" || base == "pnpm" {
		for _, a := range args {
			if a == "smcp-connect" || strings.HasPrefix(a, "smcp-connect@") {
				return true
			}
		}
	}
	return false
}

// jsonEdit loads a JSON object file (empty when absent), applies f, and
// returns the change. Files that are not JSON objects are refused rather
// than overwritten.
func jsonEdit(path, scope, purpose string, f func(map[string]any) error) (Change, error) {
	before, err := readOrNil(path)
	if err != nil {
		return Change{}, err
	}
	doc := map[string]any{}
	if len(bytes.TrimSpace(before)) > 0 {
		if err := json.Unmarshal(before, &doc); err != nil {
			return Change{}, fmt.Errorf("%s is not a JSON object (comments are not supported); edit it by hand: %w", path, err)
		}
	}
	if err := f(doc); err != nil {
		return Change{}, err
	}
	after, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return Change{}, err
	}
	return Change{Path: path, Scope: scope, Purpose: purpose, Before: before, After: append(after, '\n'), Mode: 0o600}, nil
}

func obj(doc map[string]any, key string) map[string]any {
	m, ok := doc[key].(map[string]any)
	if !ok {
		m = map[string]any{}
		doc[key] = m
	}
	return m
}

func appendUnique(list []any, items ...any) []any {
	for _, it := range items {
		dup := false
		for _, x := range list {
			a, _ := json.Marshal(x)
			b, _ := json.Marshal(it)
			if bytes.Equal(a, b) {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, it)
		}
	}
	return list
}

// Markers delimit the block smcpctl manages in TOML and YAML files.
const (
	markBegin = "# BEGIN smcp (managed by smcpctl; remove with smcpctl)"
	markEnd   = "# END smcp"
)

// blockEdit appends (or replaces) the managed block in a text file.
// conflict reports text outside the block that already defines what the
// block would; the edit is then refused.
func blockEdit(path, scope, purpose, block string, conflict func(outside string) string) (Change, error) {
	before, err := readOrNil(path)
	if err != nil {
		return Change{}, err
	}
	text := string(before)
	outside := text
	if i := strings.Index(text, markBegin); i >= 0 {
		j := strings.Index(text[i:], markEnd)
		if j < 0 {
			return Change{}, fmt.Errorf("%s has an unterminated smcp block", path)
		}
		end := i + j + len(markEnd)
		if end < len(text) && text[end] == '\n' {
			end++
		}
		outside = text[:i] + text[end:]
	}
	if msg := conflict(outside); msg != "" {
		return Change{}, fmt.Errorf("%s: %s; add this by hand instead:\n%s", path, msg, block)
	}
	after := outside
	if after != "" && !strings.HasSuffix(after, "\n") {
		after += "\n"
	}
	after += markBegin + "\n" + strings.TrimRight(block, "\n") + "\n" + markEnd + "\n"
	return Change{Path: path, Scope: scope, Purpose: purpose, Before: before, After: []byte(after), Mode: 0o600}, nil
}

// yamlChildren returns the child keys of a top-level YAML mapping key and
// the text of each child's block. It understands block-style mappings
// only, which is what the clients write.
func yamlChildren(text, key string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(text, "\n")
	in, indent, cur := false, -1, ""
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lead := len(l) - len(strings.TrimLeft(l, " "))
		if lead == 0 {
			in = strings.HasPrefix(l, key+":")
			indent, cur = -1, ""
			continue
		}
		if !in {
			continue
		}
		if indent < 0 {
			indent = lead
		}
		if lead == indent {
			name, _, _ := strings.Cut(trimmed, ":")
			name = strings.Trim(strings.TrimPrefix(name, "- "), `"'`)
			cur = name
			out[cur] = ""
			continue
		}
		if cur != "" {
			out[cur] += trimmed + "\n"
		}
	}
	return out
}

func hasTopKey(text, key string) bool {
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, key+":") {
			return true
		}
	}
	return false
}

// denyRules are Claude Code style permission rules for the Gateway paths.
func (g Gateway) protectedPaths() []string {
	var out []string
	for _, p := range append(slices.Clone(g.Paths), g.Credentials) {
		if p != "" {
			out = append(out, filepath.Clean(p))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Manifest records an applied plan so that it can be removed.
type Manifest struct {
	Client  string          `json:"client"`
	Purpose string          `json:"purpose"` // setup or lockdown
	Applied time.Time       `json:"applied"`
	Files   []ManifestEntry `json:"files"`
}

// ManifestEntry is one changed file.
type ManifestEntry struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Backup  string `json:"backup,omitempty"`
}

// ManifestPath is where the manifest of a client's setup or lockdown is
// kept: ~/.config/smcp/harness/<client>-<kind>.json.
func ManifestPath(home, client, kind string) string {
	return filepath.Join(home, ".config", "smcp", "harness", client+"-"+kind+".json")
}

// Apply writes the plan's changes. Each existing file is first copied to
// <file>.smcp-backup-<timestamp> (FR-15.6). A previous manifest of the
// same kind must be removed first, so that the recorded originals are
// never overwritten.
func Apply(p Plan, manifestPath, kind string, now time.Time) (Manifest, error) {
	if exists(manifestPath) {
		return Manifest{}, fmt.Errorf("%s %s is already applied (%s); remove it first", p.Client, kind, manifestPath)
	}
	m := Manifest{Client: p.Client, Purpose: kind, Applied: now.UTC()}
	stamp := now.UTC().Format("20060102T150405Z")
	seen := map[string]bool{}
	for _, c := range p.Changes {
		if seen[c.Path] {
			return m, fmt.Errorf("plan changes %s twice", c.Path)
		}
		seen[c.Path] = true
		e := ManifestEntry{Path: c.Path}
		if cur, err := readOrNil(c.Path); err != nil {
			return m, err
		} else if cur != nil {
			e.Existed = true
			e.Backup = c.Path + ".smcp-backup-" + stamp
			fi, err := os.Stat(c.Path)
			if err != nil {
				return m, err
			}
			if err := os.WriteFile(e.Backup, cur, fi.Mode().Perm()); err != nil {
				return m, err
			}
		}
		m.Files = append(m.Files, e)
	}
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		return m, err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(manifestPath, b, 0o600); err != nil {
		return m, err
	}
	for _, c := range p.Changes {
		mode := c.Mode
		if fi, err := os.Stat(c.Path); err == nil {
			mode = fi.Mode().Perm()
		}
		if mode == 0 {
			mode = 0o600
		}
		if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
			return m, err
		}
		if err := os.WriteFile(c.Path, c.After, mode); err != nil {
			return m, fmt.Errorf("%s: %w (restore with remove)", c.Path, err)
		}
	}
	return m, nil
}

// Remove restores the files of an applied manifest: backups are copied
// back byte for byte and files that did not exist are deleted. The backups
// and the manifest are deleted afterwards.
func Remove(manifestPath string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	var errs []error
	for _, e := range m.Files {
		if !e.Existed {
			if err := os.Remove(e.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		orig, err := os.ReadFile(e.Backup)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		fi, err := os.Stat(e.Backup)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.WriteFile(e.Path, orig, fi.Mode().Perm()); err != nil {
			errs = append(errs, err)
			continue
		}
		_ = os.Chmod(e.Path, fi.Mode().Perm())
		_ = os.Remove(e.Backup)
	}
	if len(errs) > 0 {
		return m, errors.Join(errs...)
	}
	return m, os.Remove(manifestPath)
}

// SystemTrustCommands add the Gateway CA to the operating-system trust
// store. They run only with --system-trust (FR-15.7).
func SystemTrustCommands(goos, home, caFile string) [][]string {
	switch goos {
	case "darwin":
		return [][]string{{"security", "add-trusted-cert", "-r", "trustRoot", "-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"), caFile}}
	case "linux":
		return [][]string{{"sudo", "cp", caFile, "/usr/local/share/ca-certificates/smcp-gateway.crt"}, {"sudo", "update-ca-certificates"}}
	}
	return nil
}

// Describe renders a plan for --dry-run.
func Describe(p Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", p.Client)
	if len(p.Changes) == 0 {
		b.WriteString("  no files to change\n")
	}
	for _, c := range p.Changes {
		state := "create"
		if c.Before != nil {
			state = "update"
		}
		fmt.Fprintf(&b, "  %s %s (%s, %s scope)\n", state, c.Path, c.Purpose, c.Scope)
		for _, l := range strings.Split(strings.TrimRight(string(c.After), "\n"), "\n") {
			fmt.Fprintf(&b, "    | %s\n", l)
		}
	}
	for _, cmd := range p.Commands {
		fmt.Fprintf(&b, "  run: %s\n", strings.Join(cmd, " "))
	}
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "  note: %s\n", n)
	}
	return b.String()
}
