package acceptance

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// ctlAsUser runs smcpctl for a user whose home directory is home, from the
// project directory proj.
func (g *gateway) ctlAsUser(home, proj string, args ...string) (string, error) {
	g.t.Helper()
	args = append(args, "--config", g.cfg)
	cmd := exec.Command(filepath.Join(binDir, "smcpctl"), args...)
	cmd.Dir = proj
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "USERPROFILE="+home)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

type doctorReport struct {
	Clients []string `json:"clients_checked"`
	Servers []struct {
		Client, Scope, Name string
		Gateway             bool
	} `json:"servers"`
	Findings []struct {
		Kind, Client, Message string
	} `json:"findings"`
}

func (g *gateway) doctor(home, proj string) doctorReport {
	g.t.Helper()
	out, _ := g.ctlAsUser(home, proj, "doctor", "--json") // exits 1 when there are findings
	i, j := strings.Index(out, "{"), strings.LastIndex(out, "}")
	var r doctorReport
	if i < 0 || j < i || json.Unmarshal([]byte(out[i:j+1]), &r) != nil {
		g.t.Fatalf("doctor output:\n%s", out)
	}
	return r
}

// insertAfter inserts text after the first line equal to line.
func insertAfter(t *testing.T, path, line, text string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, line+"\n")
	if i < 0 {
		t.Fatalf("%s has no line %q:\n%s", path, line, s)
	}
	i += len(line) + 1
	if err := os.WriteFile(path, []byte(s[:i]+text+s[i:]), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAT16HarnessLockdown is acceptance scenario AT-16 with the real
// smcpctl for a fresh user home and project directory, for every local
// client of Appendix K:
//
//   - clients setup configures the Gateway as the client's only MCP
//     server, and doctor recognizes it as the Gateway;
//   - the lockdown profile is applied where the client has a mechanism the
//     user can write (Codex requirements file, Goose allowlist); for Claude
//     Code and Gemini CLI, whose mechanism is a managed file under
//     /Library or /etc, the profile is shown with --dry-run and names only
//     the Gateway;
//   - a second MCP server added in project or user scope is flagged by
//     doctor for every client;
//   - doctor reports each client without a lockdown mechanism, each
//     settings file the client's own tools can write, and the Gateway paths
//     readable by the user;
//   - Grok Build's configuration location and mechanism are not confirmed
//     (Appendix K), and setup and lockdown say so.
//
// Partial: the clients are not started at their pinned versions (FR-15.1,
// SR-4.9-1, SR-4.11-1 need the client matrix job), and the managed
// profiles are not installed (they need administrator rights).
func TestAT16HarnessLockdown(t *testing.T) {
	g := newGateway(t, options{})
	g.start()
	g.scenario("AT-16")
	reqtest.Partial(t, "FR-15.1", "FR-15.3", "SR-4.9-1", "SR-4.11-1")
	home, proj := t.TempDir(), t.TempDir()

	// Clients whose lockdown is a managed file, and what the profile must
	// contain: an allowlist naming the Gateway (and, for Claude Code, deny
	// rules on the Gateway paths and the client's own settings files).
	managed := map[string][]string{"claude-code": {"allowManagedMcpServersOnly", "allowedMcpServers", "smcp-stdio", "Edit(~/.claude.json)", "Read(/"},
		"gemini-cli": {`"allowed"`, `"smcp"`}}
	clients := []string{"claude-code", "codex", "gemini-cli", "goose", "hermes", "opencode"}
	for _, c := range clients {
		args := []string{"clients", "setup", c}
		if managed[c] != nil {
			args = append(args, "--no-lockdown")
		}
		if out, err := g.ctlAsUser(home, proj, args...); err != nil {
			t.Fatalf("setup %s: %v\n%s", c, err, out)
		}
		if want := managed[c]; want != nil {
			out, err := g.ctlAsUser(home, proj, "lockdown", "apply", c, "--dry-run")
			if err != nil || !strings.Contains(out, "managed scope") {
				t.Fatalf("lockdown %s --dry-run: %v\n%s", c, err, out)
			}
			for _, w := range want {
				if !strings.Contains(out, w) {
					t.Fatalf("lockdown %s profile lacks %q:\n%s", c, w, out)
				}
			}
		}
	}
	grok, _ := g.ctlAsUser(home, proj, "clients", "setup", "grok-build")
	if !strings.Contains(grok, "to be confirmed at pinning") {
		t.Fatalf("grok-build setup does not state the unconfirmed mechanism:\n%s", grok)
	}

	r := g.doctor(home, proj)
	for _, c := range clients {
		n := 0
		for _, s := range r.Servers {
			if s.Client == c {
				n++
				if !s.Gateway {
					t.Fatalf("%s: server %q is not the Gateway after setup", c, s.Name)
				}
			}
		}
		if n != 1 {
			t.Fatalf("%s: %d servers after setup, want the Gateway only", c, n)
		}
	}
	findings := func(r doctorReport, kind, client string) []string {
		var out []string
		for _, f := range r.Findings {
			if f.Kind == kind && f.Client == client {
				out = append(out, f.Message)
			}
		}
		return out
	}
	for _, c := range clients {
		if len(findings(r, "non-gateway-server", c)) != 0 {
			t.Fatalf("%s: server findings with the Gateway only: %v", c, findings(r, "non-gateway-server", c))
		}
	}
	for _, c := range []string{"hermes", "opencode"} {
		if !strings.Contains(strings.Join(findings(r, "info", c), "\n"), "no lockdown mechanism") {
			t.Fatalf("%s: doctor does not report the missing lockdown mechanism", c)
		}
	}

	// A second server for every client.
	writeFile(t, proj, ".mcp.json", `{"mcpServers":{"rogue-claude":{"command":"rogue-mcp"}}}`, 0o600)
	writeFile(t, proj, filepath.Join(".codex", "config.toml"), "[mcp_servers.rogue-codex]\ncommand = \"rogue-mcp\"\n", 0o600)
	writeFile(t, proj, filepath.Join(".gemini", "settings.json"), `{"mcpServers":{"rogue-gemini":{"command":"rogue-mcp"}}}`, 0o600)
	writeFile(t, proj, "opencode.json", `{"mcp":{"rogue-opencode":{"type":"local","command":["rogue-mcp"]}}}`, 0o600)
	insertAfter(t, filepath.Join(home, ".config", "goose", "config.yaml"), "extensions:", "  rogue-goose:\n    type: stdio\n    cmd: rogue-mcp\n")
	insertAfter(t, filepath.Join(home, ".hermes", "config.yaml"), "mcp_servers:", "  rogue-hermes:\n    command: rogue-mcp\n")
	r = g.doctor(home, proj)
	for _, c := range clients {
		want := "rogue-" + strings.TrimSuffix(c, "-cli")
		if c == "claude-code" {
			want = "rogue-claude"
		}
		if !strings.Contains(strings.Join(findings(r, "non-gateway-server", c), "\n"), want) {
			t.Errorf("%s: doctor did not flag %s: %v", c, want, findings(r, "non-gateway-server", c))
		}
		if len(findings(r, "settings-writable", c)) == 0 {
			t.Errorf("%s: doctor does not report its writable settings files", c)
		}
	}
	readable := 0
	for _, f := range r.Findings {
		if f.Kind == "readable-path" {
			readable++
		}
	}
	if readable == 0 {
		t.Fatal("doctor does not report the Gateway paths readable by the client user")
	}
	g.stop()
}
