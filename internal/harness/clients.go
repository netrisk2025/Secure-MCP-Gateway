package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

func installed(dirs func(Env) []string, bins ...string) func(Env) bool {
	return func(e Env) bool {
		for _, d := range dirs(e) {
			if exists(d) {
				return true
			}
		}
		for _, b := range bins {
			if _, err := exec.LookPath(b); err == nil {
				return true
			}
		}
		return false
	}
}

// jsonServers lists the servers of a JSON object map (mcpServers, mcp).
func jsonServers(e Env, client, scope, file string, m map[string]any) []Server {
	var out []Server
	for name, v := range m {
		s := Server{Client: client, Scope: scope, File: file, Name: name, Transport: "unknown"}
		def, _ := v.(map[string]any)
		u, _ := def["url"].(string)
		if u == "" {
			u, _ = def["httpUrl"].(string)
		}
		var cmd string
		var args []string
		switch c := def["command"].(type) {
		case string:
			cmd = c
		case []any: // OpenCode: command is an array
			for i, x := range c {
				if i == 0 {
					cmd = fmt.Sprint(x)
				} else {
					args = append(args, fmt.Sprint(x))
				}
			}
		}
		if cmd == "" {
			cmd, _ = def["cmd"].(string)
		}
		if a, ok := def["args"].([]any); ok {
			for _, x := range a {
				args = append(args, fmt.Sprint(x))
			}
		}
		switch {
		case u != "":
			s.Transport, s.Target, s.Gateway = "http", u, e.IsGatewayURL(u)
		case cmd != "":
			s.Transport, s.Target, s.Gateway = "stdio", strings.TrimSpace(cmd+" "+strings.Join(args, " ")), IsGatewayCommand(cmd, args)
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Server) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func readJSON(path string) (map[string]any, bool, error) {
	b, err := readOrNil(path)
	if err != nil || b == nil {
		return nil, false, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, true, fmt.Errorf("%s: %w", path, err)
	}
	return doc, true, nil
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// stdioEntry is the command clients run for smcp-stdio.
func stdioEntry() map[string]any { return map[string]any{"command": "smcp-stdio", "args": []any{}} }

func credentialNote(e Env) string {
	if e.Credentials != "" && exists(e.Credentials) {
		return ""
	}
	return fmt.Sprintf("smcp-stdio and smcp-session read the credential file %s (mode 0600): create it with `smcpctl clients credentials` (see docs/adapters.md) before starting the client", e.Credentials)
}

func addNote(p *Plan, n string) {
	if n != "" {
		p.Notes = append(p.Notes, n)
	}
}

// ---- Claude Code (FR-15.2) ----

func claudeManaged(e Env, file string) string {
	if e.OS == "darwin" {
		return e.sys(filepath.Join("/Library/Application Support/ClaudeCode", file))
	}
	return e.sys(filepath.Join("/etc/claude-code", file))
}

func claudeDeny(e Env) []any {
	var rules []any
	for _, p := range e.protectedPaths() {
		pat := "/" + p // Claude Code: //path is absolute
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			pat += "/**"
		}
		rules = append(rules, "Read("+pat+")", "Edit("+pat+")")
	}
	// SR-4.11-1: the client's own MCP and permission settings.
	for _, f := range []string{"~/.claude.json", "~/.claude/settings.json", "~/.claude/settings.local.json", "./.mcp.json", "./.claude/settings.json", "./.claude/settings.local.json"} {
		rules = append(rules, "Edit("+f+")")
	}
	return rules
}

func init() {
	register(&Client{
		ID: "claude-code", Name: "Claude Code",
		LockdownMechanism: "managed-settings.json: allowedMcpServers (serverUrl and serverCommand), allowManagedMcpServersOnly, permissions.deny",
		Installed:         installed(func(e Env) []string { return []string{e.home(".claude"), e.home(".claude.json")} }, "claude"),
		Setup: func(e Env, o Options) (Plan, error) {
			p := Plan{Client: "claude-code"}
			c, err := jsonEdit(e.home(".claude.json"), "user", PurposeConnection, func(doc map[string]any) error {
				var entry map[string]any
				if o.Stdio {
					entry = stdioEntry()
					entry["type"] = "stdio"
				} else {
					entry = map[string]any{"type": "http", "url": e.MCPURL}
					if o.Helper {
						entry["headersHelper"] = "smcp-session"
					}
				}
				obj(doc, "mcpServers")[GatewayName] = entry
				return nil
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			if !o.Stdio {
				c, err := jsonEdit(e.home(".claude", "settings.json"), "user", PurposeCATrust, func(doc map[string]any) error {
					obj(doc, "env")["NODE_EXTRA_CA_CERTS"] = e.CAFile
					return nil
				})
				if err != nil {
					return p, err
				}
				p.Changes = append(p.Changes, c)
			}
			if o.Stdio || o.Helper {
				addNote(&p, credentialNote(e))
			} else {
				addNote(&p, "Claude Code signs in through the Gateway's OAuth endpoint; register its client ID (or allowlisted metadata document) in [[client]] first")
			}
			return p, nil
		},
		Lockdown: func(e Env) (Plan, error) {
			p := Plan{Client: "claude-code"}
			c, err := jsonEdit(claudeManaged(e, "managed-settings.json"), "managed", PurposeLockdown, func(doc map[string]any) error {
				doc["allowManagedMcpServersOnly"] = true
				doc["allowedMcpServers"] = []any{map[string]any{"serverUrl": e.MCPURL}, map[string]any{"serverCommand": []any{"smcp-stdio"}}}
				perms := obj(doc, "permissions")
				deny, _ := perms["deny"].([]any)
				perms["deny"] = appendUnique(deny, claudeDeny(e)...)
				return nil
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			addNote(&p, "the managed settings path is system-wide; run lockdown apply with sudo (or deploy the file through MDM)")
			addNote(&p, "allowManagedMcpServersOnly is read from managed settings by Claude Code v2.1.273 and later")
			return p, nil
		},
		Inventory: func(e Env) ([]Server, []string) {
			var out []Server
			var notes []string
			if doc, ok, err := readJSON(e.home(".claude.json")); err != nil {
				notes = append(notes, err.Error())
			} else if ok {
				out = append(out, jsonServers(e, "claude-code", "user", e.home(".claude.json"), asMap(doc["mcpServers"]))...)
				for proj, v := range asMap(doc["projects"]) {
					out = append(out, jsonServers(e, "claude-code", "local:"+proj, e.home(".claude.json"), asMap(asMap(v)["mcpServers"]))...)
				}
			}
			if doc, ok, err := readJSON(filepath.Join(e.CWD, ".mcp.json")); err != nil {
				notes = append(notes, err.Error())
			} else if ok {
				out = append(out, jsonServers(e, "claude-code", "project", filepath.Join(e.CWD, ".mcp.json"), asMap(doc["mcpServers"]))...)
			}
			if doc, ok, err := readJSON(claudeManaged(e, "managed-mcp.json")); err != nil {
				notes = append(notes, err.Error())
			} else if ok {
				out = append(out, jsonServers(e, "claude-code", "managed", claudeManaged(e, "managed-mcp.json"), asMap(doc["mcpServers"]))...)
			}
			if doc, ok, _ := readJSON(claudeManaged(e, "managed-settings.json")); ok {
				out = append(out, jsonServers(e, "claude-code", "managed", claudeManaged(e, "managed-settings.json"), asMap(doc["managedMcpServers"]))...)
			}
			return out, notes
		},
		SettingsFiles: func(e Env) []string {
			return []string{e.home(".claude.json"), e.home(".claude", "settings.json"), filepath.Join(e.CWD, ".mcp.json"), filepath.Join(e.CWD, ".claude", "settings.json")}
		},
		Protected: func(e Env) bool {
			doc, ok, _ := readJSON(claudeManaged(e, "managed-settings.json"))
			if !ok {
				return false
			}
			deny, _ := asMap(doc["permissions"])["deny"].([]any)
			return slices.Contains(deny, any("Edit(~/.claude.json)")) && slices.Contains(deny, any("Edit(~/.claude/settings.json)"))
		},
		CATrust: func(e Env) (bool, string) {
			if doc, ok, _ := readJSON(e.home(".claude", "settings.json")); ok {
				if v, _ := asMap(doc["env"])["NODE_EXTRA_CA_CERTS"].(string); v != "" {
					return v == e.CAFile, "NODE_EXTRA_CA_CERTS in ~/.claude/settings.json is " + v
				}
			}
			if v := os.Getenv("NODE_EXTRA_CA_CERTS"); v != "" {
				return v == e.CAFile, "NODE_EXTRA_CA_CERTS in the environment is " + v
			}
			return false, "NODE_EXTRA_CA_CERTS is not set (not needed when the client uses smcp-stdio)"
		},
	})

	// ---- Codex CLI ----
	register(&Client{
		ID: "codex", Name: "Codex CLI",
		LockdownMechanism: "requirements.toml [mcp_server_allowlist] (to confirm at pinning)",
		Installed:         installed(func(e Env) []string { return []string{e.home(".codex")} }, "codex"),
		Setup: func(e Env, o Options) (Plan, error) {
			p := Plan{Client: "codex"}
			block := fmt.Sprintf("[mcp_servers.%s]\ncommand = \"smcp-stdio\"\nargs = []\n", GatewayName)
			if !o.Stdio && o.Helper {
				block = fmt.Sprintf("[mcp_servers.%s]\nurl = %q\n", GatewayName, e.MCPURL)
				addNote(&p, "Codex CLI over HTTP needs the Gateway CA trusted by Codex (mechanism to confirm at pinning) and `codex mcp login smcp`; smcp-stdio (the default) needs neither")
			}
			c, err := blockEdit(e.home(".codex", "config.toml"), "user", PurposeConnection, block, func(outside string) string {
				if strings.Contains(outside, "[mcp_servers."+GatewayName+"]") {
					return "already defines [mcp_servers." + GatewayName + "]"
				}
				return ""
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			addNote(&p, credentialNote(e))
			return p, nil
		},
		Lockdown: func(e Env) (Plan, error) {
			p := Plan{Client: "codex"}
			body := fmt.Sprintf("# Codex CLI administrator requirements generated by smcpctl lockdown.\n[mcp_server_allowlist.%s]\ncommand = \"smcp-stdio\"\n", GatewayName)
			before, _ := readOrNil(e.home(".config", "smcp", "codex-requirements.toml"))
			p.Changes = append(p.Changes, Change{Path: e.home(".config", "smcp", "codex-requirements.toml"), Scope: "user", Purpose: PurposeLockdown, Before: before, After: []byte(body), Mode: 0o644})
			addNote(&p, "Codex reads administrator requirements from managed configuration (on macOS the com.openai.codex requirements_toml_base64 preference); deploy this file there. Key names are taken from Codex PR #9101 and are to be confirmed at pinning")
			addNote(&p, "Codex has no rule that denies its own file tools the Gateway paths; smcpctl doctor reports readable paths")
			return p, nil
		},
		Inventory: func(e Env) ([]Server, []string) {
			var out []Server
			var notes []string
			for _, f := range []struct{ scope, path string }{{"user", e.home(".codex", "config.toml")}, {"project", filepath.Join(e.CWD, ".codex", "config.toml")}} {
				b, err := readOrNil(f.path)
				if err != nil || b == nil {
					continue
				}
				var doc map[string]any
				if err := toml.Unmarshal(b, &doc); err != nil {
					notes = append(notes, fmt.Sprintf("%s: %v", f.path, err))
					continue
				}
				out = append(out, jsonServers(e, "codex", f.scope, f.path, asMap(doc["mcp_servers"]))...)
			}
			return out, notes
		},
		SettingsFiles: func(e Env) []string { return []string{e.home(".codex", "config.toml")} },
		Protected:     func(Env) bool { return false },
		CATrust: func(Env) (bool, string) {
			return false, "Codex CLI CA trust mechanism is to be confirmed at pinning; use smcp-stdio"
		},
	})

	// ---- Hermes Agent ----
	register(&Client{
		ID: "hermes", Name: "Hermes Agent",
		Installed: installed(func(e Env) []string { return []string{e.home(".hermes")} }, "hermes"),
		Setup: func(e Env, o Options) (Plan, error) {
			p := Plan{Client: "hermes"}
			var block string
			if o.Stdio {
				block = fmt.Sprintf("mcp_servers:\n  %s:\n    command: smcp-stdio\n    args: []\n", GatewayName)
				addNote(&p, credentialNote(e))
			} else {
				block = fmt.Sprintf("mcp_servers:\n  %s:\n    url: %q\n    auth: oauth\n    ssl_verify: %q\n", GatewayName, e.MCPURL, e.CAFile)
			}
			c, err := blockEdit(e.home(".hermes", "config.yaml"), "user", PurposeConnection, block, func(outside string) string {
				if hasTopKey(outside, "mcp_servers") {
					return "already has an mcp_servers section"
				}
				return ""
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			return p, nil
		},
		Lockdown: func(Env) (Plan, error) {
			p := Plan{Client: "hermes"}
			addNote(&p, "Hermes Agent offers no administrator MCP allowlist and no file-tool deny rule (Appendix K); smcpctl doctor reports other servers and readable paths")
			return p, nil
		},
		Inventory: func(e Env) ([]Server, []string) {
			b, err := readOrNil(e.home(".hermes", "config.yaml"))
			if err != nil || b == nil {
				return nil, nil
			}
			return yamlServers(e, "hermes", "user", e.home(".hermes", "config.yaml"), yamlChildren(string(b), "mcp_servers")), nil
		},
		SettingsFiles: func(e Env) []string { return []string{e.home(".hermes", "config.yaml")} },
		Protected:     func(Env) bool { return false },
		CATrust: func(e Env) (bool, string) {
			b, _ := readOrNil(e.home(".hermes", "config.yaml"))
			if strings.Contains(string(b), e.CAFile) {
				return true, "ssl_verify names the Gateway CA"
			}
			return false, "ssl_verify does not name the Gateway CA"
		},
	})

	// ---- OpenCode ----
	register(&Client{
		ID: "opencode", Name: "OpenCode",
		Installed: installed(func(e Env) []string { return []string{e.home(".config", "opencode")} }, "opencode"),
		Setup: func(e Env, o Options) (Plan, error) {
			p := Plan{Client: "opencode"}
			c, err := jsonEdit(e.home(".config", "opencode", "opencode.json"), "user", PurposeConnection, func(doc map[string]any) error {
				entry := map[string]any{"type": "local", "command": []any{"smcp-stdio"}, "enabled": true}
				if !o.Stdio && o.Helper {
					entry = map[string]any{"type": "remote", "url": e.MCPURL, "enabled": true}
					addNote(&p, "OpenCode over HTTP needs NODE_EXTRA_CA_CERTS set to the Gateway CA in its environment (to confirm at pinning)")
				}
				obj(doc, "mcp")[GatewayName] = entry
				return nil
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			addNote(&p, credentialNote(e))
			return p, nil
		},
		Lockdown: func(Env) (Plan, error) {
			p := Plan{Client: "opencode"}
			addNote(&p, "OpenCode has no configuration scope that the user and agent cannot write (to confirm at pinning); smcpctl doctor reports other servers and readable paths")
			return p, nil
		},
		Inventory: func(e Env) ([]Server, []string) {
			var out []Server
			var notes []string
			for _, f := range []struct{ scope, path string }{{"user", e.home(".config", "opencode", "opencode.json")}, {"project", filepath.Join(e.CWD, "opencode.json")}} {
				doc, ok, err := readJSON(f.path)
				if err != nil {
					notes = append(notes, err.Error())
				} else if ok {
					out = append(out, jsonServers(e, "opencode", f.scope, f.path, asMap(doc["mcp"]))...)
				}
			}
			return out, notes
		},
		SettingsFiles: func(e Env) []string {
			return []string{e.home(".config", "opencode", "opencode.json"), filepath.Join(e.CWD, "opencode.json")}
		},
		Protected: func(Env) bool { return false },
		CATrust: func(Env) (bool, string) {
			return false, "not needed with smcp-stdio; NODE_EXTRA_CA_CERTS for HTTP is to be confirmed at pinning"
		},
	})

	// ---- Gemini CLI ----
	geminiSystem := func(e Env) string {
		if e.OS == "darwin" {
			return e.sys("/Library/Application Support/GeminiCli/settings.json")
		}
		return e.sys("/etc/gemini-cli/settings.json")
	}
	register(&Client{
		ID: "gemini-cli", Name: "Gemini CLI",
		LockdownMechanism: "system settings.json: mcpServers and mcp.allowed (the vendor states name allowlists are not a security boundary)",
		Installed:         installed(func(e Env) []string { return []string{e.home(".gemini")} }, "gemini"),
		Setup: func(e Env, o Options) (Plan, error) {
			p := Plan{Client: "gemini-cli"}
			c, err := jsonEdit(e.home(".gemini", "settings.json"), "user", PurposeConnection, func(doc map[string]any) error {
				entry := stdioEntry()
				if !o.Stdio && o.Helper {
					entry = map[string]any{"httpUrl": e.MCPURL}
					addNote(&p, "Gemini CLI over HTTP needs NODE_EXTRA_CA_CERTS set to the Gateway CA in its environment")
				}
				obj(doc, "mcpServers")[GatewayName] = entry
				return nil
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			addNote(&p, credentialNote(e))
			return p, nil
		},
		Lockdown: func(e Env) (Plan, error) {
			p := Plan{Client: "gemini-cli"}
			c, err := jsonEdit(geminiSystem(e), "managed", PurposeLockdown, func(doc map[string]any) error {
				obj(doc, "mcpServers")[GatewayName] = stdioEntry()
				obj(doc, "mcp")["allowed"] = []any{GatewayName}
				return nil
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			addNote(&p, "system settings are system-wide; run with sudo. Google states the name allowlist is not a security boundary, so Gemini CLI stays gateway-available")
			return p, nil
		},
		Inventory: func(e Env) ([]Server, []string) {
			var out []Server
			var notes []string
			for _, f := range []struct{ scope, path string }{{"user", e.home(".gemini", "settings.json")}, {"project", filepath.Join(e.CWD, ".gemini", "settings.json")}, {"managed", geminiSystem(e)}} {
				doc, ok, err := readJSON(f.path)
				if err != nil {
					notes = append(notes, err.Error())
				} else if ok {
					out = append(out, jsonServers(e, "gemini-cli", f.scope, f.path, asMap(doc["mcpServers"]))...)
				}
			}
			return out, notes
		},
		SettingsFiles: func(e Env) []string {
			return []string{e.home(".gemini", "settings.json"), filepath.Join(e.CWD, ".gemini", "settings.json")}
		},
		Protected: func(Env) bool { return false },
		CATrust: func(Env) (bool, string) {
			if os.Getenv("NODE_EXTRA_CA_CERTS") != "" {
				return true, "NODE_EXTRA_CA_CERTS is set in the environment"
			}
			return false, "not needed with smcp-stdio; HTTP needs NODE_EXTRA_CA_CERTS"
		},
	})

	// ---- Goose ----
	register(&Client{
		ID: "goose", Name: "Goose",
		LockdownMechanism: "GOOSE_ALLOWLIST YAML allowlist matched on the extension command (to confirm at pinning)",
		Installed:         installed(func(e Env) []string { return []string{e.home(".config", "goose")} }, "goose"),
		Setup: func(e Env, _ Options) (Plan, error) {
			p := Plan{Client: "goose"}
			block := fmt.Sprintf("extensions:\n  %s:\n    name: %s\n    type: stdio\n    cmd: smcp-stdio\n    args: []\n    enabled: true\n    timeout: 300\n", GatewayName, GatewayName)
			c, err := blockEdit(e.home(".config", "goose", "config.yaml"), "user", PurposeConnection, block, func(outside string) string {
				if hasTopKey(outside, "extensions") {
					return "already has an extensions section"
				}
				return ""
			})
			if err != nil {
				return p, err
			}
			p.Changes = append(p.Changes, c)
			addNote(&p, credentialNote(e))
			return p, nil
		},
		Lockdown: func(e Env) (Plan, error) {
			p := Plan{Client: "goose"}
			path := e.home(".config", "smcp", "goose-allowlist.yaml")
			before, _ := readOrNil(path)
			p.Changes = append(p.Changes, Change{Path: path, Scope: "user", Purpose: PurposeLockdown, Before: before, Mode: 0o644,
				After: []byte("# Goose extension allowlist generated by smcpctl lockdown.\nextensions:\n  - id: " + GatewayName + "\n    command: smcp-stdio\n")})
			addNote(&p, "set GOOSE_ALLOWLIST="+path+" in the environment Goose starts from (the allowlist is checked when an extension is installed)")
			return p, nil
		},
		Inventory: func(e Env) ([]Server, []string) {
			b, err := readOrNil(e.home(".config", "goose", "config.yaml"))
			if err != nil || b == nil {
				return nil, nil
			}
			return yamlServers(e, "goose", "user", e.home(".config", "goose", "config.yaml"), yamlChildren(string(b), "extensions")), nil
		},
		SettingsFiles: func(e Env) []string { return []string{e.home(".config", "goose", "config.yaml")} },
		Protected:     func(Env) bool { return false },
		CATrust:       func(Env) (bool, string) { return false, "not needed with smcp-stdio" },
	})

	// ---- Grok Build ----
	register(&Client{
		ID: "grok-build", Name: "Grok Build",
		Installed: installed(func(e Env) []string { return []string{e.home(".grok")} }, "grok"),
		Setup: func(e Env, _ Options) (Plan, error) {
			p := Plan{Client: "grok-build"}
			addNote(&p, "Grok Build's MCP configuration location is to be confirmed at pinning; configure a stdio MCP server whose command is smcp-stdio (no arguments)")
			addNote(&p, credentialNote(e))
			return p, nil
		},
		Lockdown: func(Env) (Plan, error) {
			p := Plan{Client: "grok-build"}
			addNote(&p, "Grok Build's lockdown mechanism is to be confirmed at pinning")
			return p, nil
		},
		Inventory: func(Env) ([]Server, []string) {
			return nil, []string{"Grok Build configuration location is not known; servers are not listed"}
		},
		SettingsFiles: func(Env) []string { return nil },
		Protected:     func(Env) bool { return false },
		CATrust:       func(Env) (bool, string) { return false, "not needed with smcp-stdio" },
	})
}

func yamlServers(e Env, client, scope, file string, children map[string]string) []Server {
	var out []Server
	for name, body := range children {
		s := Server{Client: client, Scope: scope, File: file, Name: name, Transport: "unknown"}
		for _, l := range strings.Split(body, "\n") {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.TrimSpace(k) {
			case "url", "uri":
				s.Transport, s.Target, s.Gateway = "http", v, e.IsGatewayURL(v)
			case "command", "cmd":
				s.Transport, s.Target, s.Gateway = "stdio", v, IsGatewayCommand(v, nil)
			}
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Server) int { return strings.Compare(a.Name, b.Name) })
	return out
}
