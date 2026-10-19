package harness

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func testEnv(t *testing.T) Env {
	t.Helper()
	d := t.TempDir()
	e := Env{Home: filepath.Join(d, "home"), CWD: filepath.Join(d, "proj"), OS: "darwin", Root: filepath.Join(d, "root"),
		Gateway: Gateway{MCPURL: "https://127.0.0.1:8443/mcp", CAFile: filepath.Join(d, "state", "tls", "ca.crt"),
			Credentials: filepath.Join(d, "home", ".config", "smcp", "credentials.toml"),
			Paths:       []string{filepath.Join(d, "state"), filepath.Join(d, "conf")},
			Origins:     []string{"https://127.0.0.1:8443", "https://gw.example.ts.net"}, Standalone: true}}
	for _, p := range []string{e.Home, e.CWD, e.Root, filepath.Join(d, "state", "tls"), filepath.Join(d, "conf")} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixtures writes, for each client with a known configuration format, one
// Gateway entry and one other server in each scope the client has.
func fixtures(t *testing.T, e Env) map[string][]string {
	gwHTTP := `{"type":"http","url":"https://127.0.0.1:8443/mcp"}`
	write(t, e.home(".claude.json"), `{"mcpServers":{"smcp":`+gwHTTP+`,"github":{"type":"http","url":"https://api.githubcopilot.com/mcp/"}},
 "projects":{"/p":{"mcpServers":{"local-fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","."]}}}}}`)
	write(t, filepath.Join(e.CWD, ".mcp.json"), `{"mcpServers":{"proj-db":{"command":"db-mcp"},"gw":{"command":"smcp-stdio"}}}`)
	write(t, claudeManaged(e, "managed-mcp.json"), `{"mcpServers":{"corp":{"type":"http","url":"https://corp.example/mcp"},"remote-gw":{"type":"http","url":"https://gw.example.ts.net/mcp"}}}`)
	write(t, e.home(".codex", "config.toml"), "[mcp_servers.smcp]\ncommand = \"smcp-stdio\"\n\n[mcp_servers.figma]\nurl = \"https://figma.example/mcp\"\n")
	write(t, filepath.Join(e.CWD, ".codex", "config.toml"), "[mcp_servers.projtool]\ncommand = \"tool\"\n[mcp_servers.gw]\ncommand = \"npx\"\nargs = [\"-y\", \"smcp-connect\"]\n")
	write(t, e.home(".hermes", "config.yaml"), "model: x\nmcp_servers:\n  smcp:\n    url: \"https://127.0.0.1:8443/mcp\"\n  web:\n    command: web-mcp\n")
	write(t, e.home(".config", "opencode", "opencode.json"), `{"mcp":{"smcp":{"type":"local","command":["smcp-stdio"]},"browser":{"type":"local","command":["browser-mcp","--x"]}}}`)
	write(t, filepath.Join(e.CWD, "opencode.json"), `{"mcp":{"projremote":{"type":"remote","url":"https://x.example/mcp"}}}`)
	write(t, e.home(".gemini", "settings.json"), `{"mcpServers":{"smcp":{"command":"smcp-stdio"},"maps":{"httpUrl":"https://maps.example/mcp"}}}`)
	write(t, filepath.Join(e.CWD, ".gemini", "settings.json"), `{"mcpServers":{"projgem":{"command":"gem-tool"}}}`)
	write(t, e.sys("/Library/Application Support/GeminiCli/settings.json"), `{"mcpServers":{"sysgem":{"command":"sys-tool"}}}`)
	write(t, e.home(".config", "goose", "config.yaml"), "extensions:\n  smcp:\n    type: stdio\n    cmd: smcp-stdio\n  developer:\n    type: builtin\n    cmd: goose-dev\n")
	return map[string][]string{
		"claude-code": {"github", "local-fs", "proj-db", "corp"},
		"codex":       {"figma", "projtool"},
		"hermes":      {"web"},
		"opencode":    {"browser", "projremote"},
		"gemini-cli":  {"maps", "projgem", "sysgem"},
		"goose":       {"developer"},
	}
}

func TestDoctorInventory(t *testing.T) {
	reqtest.Partial(t, "FR-15.3", "SR-4.9-1")
	// Partial: fixtures for every client whose configuration format is
	// known; Grok Build's location is not known yet, and SR-4.9-1's
	// "start the client and list its servers" needs the pinned clients.
	e := testEnv(t)
	want := fixtures(t, e)
	r := Doctor(e, IDs(), nil)
	flagged := map[string][]string{}
	for _, f := range r.Findings {
		if f.Kind == KindServer {
			for _, s := range r.Servers {
				if s.Client == f.Client && strings.Contains(f.Message, `"`+s.Name+`"`) {
					flagged[f.Client] = append(flagged[f.Client], s.Name)
				}
			}
		}
	}
	for client, names := range want {
		got := flagged[client]
		slices.Sort(got)
		slices.Sort(names)
		if !slices.Equal(got, names) {
			t.Errorf("%s: flagged %v, want %v", client, got, names)
		}
	}
	gw := 0
	for _, s := range r.Servers {
		if s.Gateway {
			gw++
		}
	}
	if gw != 9 { // smcp entries plus gw/remote-gw aliases
		t.Errorf("gateway entries recognised: %d", gw)
	}
	if !r.Failed() {
		t.Fatal("findings did not fail")
	}
}

func TestDoctorReadablePathsStandalone(t *testing.T) {
	reqtest.Partial(t, "FR-15.4")
	// Partial: run on a Standalone host as the Gateway user; the Enforced
	// host case (no findings for the key directory as the harness user)
	// needs the Enforced profile's service identities.
	e := testEnv(t)
	write(t, e.Credentials, "x")
	locked := filepath.Join(e.Paths[1])
	if err := os.Chmod(locked, 0o100); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o700)
	r := Doctor(e, []string{"hermes"}, nil)
	var readable []string
	standalone := false
	for _, f := range r.Findings {
		if f.Kind == KindReadable {
			readable = append(readable, f.Path)
		}
		if f.Kind == KindInfo && strings.Contains(f.Message, "Gateway's own user identity") {
			standalone = true
		}
	}
	slices.Sort(readable)
	want := []string{e.Credentials, e.Paths[0]}
	slices.Sort(want)
	if os.Geteuid() == 0 {
		t.Skip("root reads every path")
	}
	if !slices.Equal(readable, want) || !standalone {
		t.Fatalf("readable %v (want %v), standalone statement %v", readable, want, standalone)
	}
}

func TestLockdownReversible(t *testing.T) {
	reqtest.Verifies(t, "FR-15.6")
	e := testEnv(t)
	fixtures(t, e)
	// One pre-existing managed file so both the "existed" and "created"
	// paths are exercised.
	write(t, claudeManaged(e, "managed-settings.json"), "{\n  \"model\": \"opus\"\n}\n")
	for _, c := range Clients() {
		p, err := c.Lockdown(e)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		orig := map[string][]byte{}
		for _, ch := range p.Changes {
			b, err := readOrNil(ch.Path)
			if err != nil {
				t.Fatal(err)
			}
			orig[ch.Path] = b
		}
		mp := ManifestPath(e.Home, c.ID, "lockdown")
		if _, err := Apply(p, mp, "lockdown", time.Now()); err != nil {
			t.Fatalf("%s apply: %v", c.ID, err)
		}
		for _, ch := range p.Changes {
			now, _ := os.ReadFile(ch.Path)
			if !bytes.Equal(now, ch.After) {
				t.Fatalf("%s: %s not written", c.ID, ch.Path)
			}
		}
		if _, err := Apply(p, mp, "lockdown", time.Now()); err == nil {
			t.Fatalf("%s: second apply accepted", c.ID)
		}
		if len(p.Changes) == 0 {
			if _, err := os.Stat(mp); err != nil {
				t.Fatalf("%s: no manifest", c.ID)
			}
		}
		if _, err := Remove(mp); err != nil {
			t.Fatalf("%s remove: %v", c.ID, err)
		}
		for path, b := range orig {
			now, err := readOrNil(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(now, b) || (b == nil) != (now == nil) {
				t.Fatalf("%s: %s differs after remove", c.ID, path)
			}
			matches, _ := filepath.Glob(path + ".smcp-backup-*")
			if len(matches) != 0 {
				t.Fatalf("%s: backups left: %v", c.ID, matches)
			}
		}
	}
}

func TestClaudeCodeLockdownProfile(t *testing.T) {
	reqtest.Partial(t, "FR-15.2", "FR-15.1", "SR-4.11-1")
	// Partial: the generated managed settings are checked; that the pinned
	// Claude Code refuses a user-added server and the Read is part of the
	// client matrix job (FR-15.8), not run here.
	e := testEnv(t)
	p, err := registry["claude-code"].Lockdown(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 1 || p.Changes[0].Path != filepath.Join(e.Root, "/Library/Application Support/ClaudeCode/managed-settings.json") {
		t.Fatalf("changes %+v", p.Changes)
	}
	var doc struct {
		AllowManagedOnly bool             `json:"allowManagedMcpServersOnly"`
		Allowed          []map[string]any `json:"allowedMcpServers"`
		Permissions      struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(p.Changes[0].After, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowManagedOnly || len(doc.Allowed) != 2 || doc.Allowed[0]["serverUrl"] != e.MCPURL {
		t.Fatalf("allowlist %+v", doc)
	}
	for _, p := range append(e.Paths, e.Credentials) {
		for _, tool := range []string{"Read", "Edit"} {
			rule := tool + "(/" + p + "/**)"
			alt := tool + "(/" + p + ")"
			if !slices.Contains(doc.Permissions.Deny, rule) && !slices.Contains(doc.Permissions.Deny, alt) {
				t.Errorf("missing deny %s", rule)
			}
		}
	}
	for _, f := range []string{"Edit(~/.claude.json)", "Edit(~/.claude/settings.json)", "Edit(./.mcp.json)"} {
		if !slices.Contains(doc.Permissions.Deny, f) {
			t.Errorf("missing %s", f)
		}
	}
	// Doctor: settings files writable without the profile, protected with it.
	write(t, e.home(".claude.json"), `{"mcpServers":{"smcp":{"type":"http","url":"https://127.0.0.1:8443/mcp"}}}`)
	writable := func() bool {
		for _, f := range Doctor(e, []string{"claude-code"}, nil).Findings {
			if f.Kind == KindWritable {
				return true
			}
		}
		return false
	}
	if !writable() {
		t.Fatal("writable settings not reported before lockdown")
	}
	if _, err := Apply(p, ManifestPath(e.Home, "claude-code", "lockdown"), "lockdown", time.Now()); err != nil {
		t.Fatal(err)
	}
	if writable() {
		t.Fatal("writable settings reported after lockdown")
	}
}

func TestSetupCATrustAndConnection(t *testing.T) {
	reqtest.Partial(t, "FR-15.7")
	// Partial: the per-client trust settings and the --system-trust gate
	// are checked; connecting each pinned client over TLS is the matrix
	// job's.
	e := testEnv(t)
	p, err := registry["claude-code"].Setup(e, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	for _, c := range p.Changes {
		if c.Purpose == PurposeCATrust {
			_ = json.Unmarshal(c.After, &settings)
		}
	}
	if asMap(settings["env"])["NODE_EXTRA_CA_CERTS"] != e.CAFile {
		t.Fatalf("CA trust %v", settings)
	}
	if len(p.Commands) != 0 {
		t.Fatal("system trust store change planned without --system-trust")
	}
	h, err := registry["hermes"].Setup(e, Options{})
	if err != nil || !strings.Contains(string(h.Changes[0].After), e.CAFile) {
		t.Fatalf("hermes ssl_verify: %v %s", err, h.Changes[0].After)
	}
	// Clients without a confirmed trust mechanism default to smcp-stdio.
	for _, id := range []string{"codex", "opencode", "gemini-cli", "goose"} {
		p, err := registry[id].Setup(e, Options{})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if len(p.Changes) == 0 || !strings.Contains(string(p.Changes[0].After), "smcp-stdio") {
			t.Fatalf("%s does not use smcp-stdio: %+v", id, p)
		}
	}
	if cmds := SystemTrustCommands("darwin", e.Home, e.CAFile); len(cmds) != 1 || cmds[0][0] != "security" {
		t.Fatalf("system trust %v", cmds)
	}
	// Existing configuration outside the managed block is refused, not
	// overwritten.
	write(t, e.home(".codex", "config.toml"), "[mcp_servers.smcp]\nurl = \"x\"\n")
	if _, err := registry["codex"].Setup(e, Options{}); err == nil {
		t.Fatal("conflicting codex entry overwritten")
	}
	// Setup twice replaces its own block.
	os.Remove(e.home(".codex", "config.toml"))
	p1, _ := registry["codex"].Setup(e, Options{})
	write(t, p1.Changes[0].Path, string(p1.Changes[0].After))
	p2, err := registry["codex"].Setup(e, Options{})
	if err != nil || strings.Count(string(p2.Changes[0].After), markBegin) != 1 {
		t.Fatalf("re-setup: %v %s", err, p2.Changes[0].After)
	}
}
