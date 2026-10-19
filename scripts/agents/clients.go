package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Model endpoints. The Vercel AI Gateway serves both the Anthropic Messages
// API (Claude Code) and the OpenAI-compatible APIs (everything else) with
// one key, AI_GATEWAY_API_KEY.
const (
	aiGatewayAnthropic = "https://ai-gateway.vercel.sh"
	aiGatewayOpenAI    = "https://ai-gateway.vercel.sh/v1"
	modelClaude        = "anthropic/claude-haiku-5.5"
	modelCodex         = "openai/gpt-5.1-codex-mini"
	tokenEnv           = "SMCP_SESSION_TOKEN"
	aiKeyEnv           = "AI_GATEWAY_API_KEY"
)

// Run modes recorded in agents.json.
const (
	modeAIGateway = "ai-gateway"
	modeLocal     = "local-login"
	modeScripted  = "scripted"
)

// runEnv is what a driver needs to run one prompt.
type runEnv struct {
	g        *gateway
	dir      string // per-client working directory, also the agent's cwd
	token    string // session bearer token (passed only through tokenEnv)
	local    bool   // use the user's subscription login instead of the AI Gateway
	caBundle string // system roots plus the Gateway CA, for clients that replace roots
	maxTurns int
	bin      string // resolved executable
}

// client describes one agent CLI of the Appendix K matrix.
type client struct {
	ID        string // short identifier, used in -clients and principal names
	Name      string // matrix.json "client" value
	Framework string // config [[principal]] framework
	Bins      []string
	// LocalLogin is true when the CLI can use the user's subscription login
	// (-local); other clients always use the AI Gateway.
	LocalLogin bool
	// NeedsKey names the environment variable that must be set for the
	// model in AI Gateway mode ("" for none).
	NeedsKey string
	// localRefusal, when set, reports whether the client's output shows it
	// refused the approval-obligated call itself, before sending it,
	// because it had no way to ask the person (FR-1.50).
	localRefusal func(output []byte) bool
	// NotRunReason, when set, records the client as not-run without trying.
	NotRunReason string
	setup        func(c *client, e *runEnv) error
	command      func(c *client, e *runEnv, prompt string) *exec.Cmd
	// session, when set, drives a command whose prompt goes to stdin and
	// whose stdout carries requests the suite must answer.
	session func(stdin io.WriteCloser, stdout io.Reader, log io.Writer, prompt string) error
	// run replaces setup/command for the in-process reference client.
	run func(ctx context.Context, e *runEnv, s scenario) (string, error)
}

func (c *client) mode(local bool) string {
	if c.run != nil {
		return modeScripted
	}
	if local && c.LocalLogin {
		return modeLocal
	}
	return modeAIGateway
}

// baseEnv is the environment of every agent process: the caller's
// environment, the session token, and the Gateway CA for Node-based CLIs.
func baseEnv(e *runEnv, extra ...string) []string {
	env := append(os.Environ(), tokenEnv+"="+e.token, "NODE_EXTRA_CA_CERTS="+e.g.ca)
	return append(env, extra...)
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func mcpToolNames(prefix string) string {
	var names []string
	for _, t := range append(grantedTools(), publicName(toolUngranted)) {
		names = append(names, prefix+t)
	}
	return strings.Join(names, ",")
}

// allClients is the Appendix K local-client matrix in matrix.json order.
func allClients() []*client {
	return []*client{
		claudeCode(), codex(), hermes(), opencode(), gemini(), goose(),
		{ID: "grok-build", Name: "Grok Build", Framework: "grok-build",
			NotRunReason: "no publicly installable Grok Build CLI; connection mode is to be confirmed at pinning"},
	}
}

func claudeCode() *client {
	return &client{
		ID: "claude-code", Name: "Claude Code", Framework: "claude-code", Bins: []string{"claude"},
		LocalLogin: true, NeedsKey: aiKeyEnv,
		// Claude Code asks the person before every call to a tool marked
		// anthropic/requiresUserInteraction (FR-1.50), even when allowed. A
		// plain `claude -p` has nobody to ask and refuses such calls, and
		// --permission-prompt-tool with an MCP tool is refused too. The SDK
		// control protocol (stream-json with --permission-prompt-tool stdio)
		// asks its host, so the suite runs Claude Code that way and answers
		// each permission request as the person would. The refusal check
		// stays for builds that refuse even there.
		localRefusal: func(out []byte) bool { return deniedInResult(out, "mcp__smcp__"+publicName(toolApproval)) },
		session: func(stdin io.WriteCloser, stdout io.Reader, log io.Writer, prompt string) error {
			return streamJSONSession(stdin, stdout, log, prompt, "mcp__smcp__")
		},
		setup: func(c *client, e *runEnv) error {
			// Streamable HTTP with a static bearer header; Claude Code expands
			// ${VAR} in MCP configuration, so the token never touches disk.
			return writeJSONFile(filepath.Join(e.dir, "mcp.json"), map[string]any{
				"mcpServers": map[string]any{"smcp": map[string]any{
					"type": "http", "url": e.g.endpoint,
					"headers": map[string]string{"Authorization": "Bearer ${" + tokenEnv + "}"},
				}},
			})
		},
		command: func(c *client, e *runEnv, prompt string) *exec.Cmd {
			model := modelClaude
			env := []string{"DISABLE_AUTOUPDATER=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "MCP_TIMEOUT=30000", "MCP_TOOL_TIMEOUT=180000"}
			if e.local {
				model = "haiku"
			} else {
				env = append(env,
					"CLAUDE_CONFIG_DIR="+filepath.Join(e.dir, "claude-config"),
					"ANTHROPIC_BASE_URL="+aiGatewayAnthropic,
					"ANTHROPIC_AUTH_TOKEN="+os.Getenv(aiKeyEnv),
					"ANTHROPIC_API_KEY=")
			}
			// The prompt goes to stdin as a stream-json user message
			// (streamJSONSession); permission requests come back on stdout.
			cmd := exec.Command(e.bin, "-p",
				"--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
				"--permission-prompt-tool", "stdio",
				"--mcp-config", filepath.Join(e.dir, "mcp.json"), "--strict-mcp-config",
				"--tools", "", // no built-in tools: only the Gateway's MCP tools
				"--allowedTools", mcpToolNames("mcp__smcp__"),
				"--max-turns", fmt.Sprint(e.maxTurns),
				"--model", model, "--no-session-persistence",
				"--debug-file", filepath.Join(e.dir, "claude-debug.txt"))
			cmd.Env = baseEnv(e, env...)
			return cmd
		},
	}
}

func codex() *client {
	return &client{
		ID: "codex", Name: "Codex CLI", Framework: "codex", Bins: []string{"codex"},
		LocalLogin: true, NeedsKey: aiKeyEnv,
		setup: func(c *client, e *runEnv) error {
			if e.local {
				return nil
			}
			return os.MkdirAll(filepath.Join(e.dir, "codex-home"), 0o700)
		},
		command: func(c *client, e *runEnv, prompt string) *exec.Cmd {
			args := []string{"exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--ignore-rules",
				"-s", "read-only", "-C", e.dir}
			if !e.local {
				// Without a model catalog entry for this ID Codex falls back to
				// reasoning effort "none"; low makes its tool choice steadier.
				args = append(args, "-m", modelCodex, "-c", `model_reasoning_effort="low"`)
			} else if m := codexUserModel(); m != "" {
				// A ChatGPT login offers its own model set, so local mode uses
				// the model of the user's config.toml (the rest of that file is
				// ignored) with low reasoning effort.
				args = append(args, "-m", m, "-c", `model_reasoning_effort="low"`)
			}
			args = append(args,
				"-c", fmt.Sprintf("mcp_servers.smcp={url=%q,bearer_token_env_var=%q,tool_timeout_sec=180,startup_timeout_sec=30,default_tools_approval_mode=\"approve\"}", e.g.endpoint, tokenEnv))
			// Codex reads extra trust roots from CODEX_CA_CERTIFICATE; the
			// bundle keeps the public roots for the model endpoint.
			env := []string{"CODEX_CA_CERTIFICATE=" + e.caBundle}
			if !e.local {
				args = append(args,
					"-c", "model_provider=\"aigw\"",
					"-c", fmt.Sprintf("model_providers.aigw={name=\"Vercel AI Gateway\",base_url=%q,env_key=%q,wire_api=\"responses\"}", aiGatewayOpenAI, aiKeyEnv))
				env = append(env, "CODEX_HOME="+filepath.Join(e.dir, "codex-home"))
			}
			cmd := exec.Command(e.bin, append(args, prompt)...)
			cmd.Env = baseEnv(e, env...)
			return cmd
		},
	}
}

var (
	codexModelRe = regexp.MustCompile(`(?m)^model\s*=\s*"([^"]+)"`)
	tomlTableRe  = regexp.MustCompile(`(?m)^\[`)
)

// codexUserModel returns the top-level model of $CODEX_HOME/config.toml
// (default ~/.codex), or "".
func codexUserModel() string {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		h, _ := os.UserHomeDir()
		home = filepath.Join(h, ".codex")
	}
	b, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil {
		return ""
	}
	// Only the part before the first table header is top level.
	if i := tomlTableRe.FindIndex(b); i != nil {
		b = b[:i[0]]
	}
	if m := codexModelRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

func opencode() *client {
	return &client{
		ID: "opencode", Name: "OpenCode", Framework: "opencode", Bins: []string{"opencode"}, NeedsKey: aiKeyEnv,
		setup: func(c *client, e *runEnv) error {
			off := map[string]bool{}
			for _, t := range []string{"bash", "edit", "write", "read", "grep", "glob", "list", "patch", "webfetch", "websearch", "todowrite", "todoread", "task", "skill", "codesearch", "lsp"} {
				off[t] = false
			}
			return writeJSONFile(filepath.Join(e.dir, "opencode.json"), map[string]any{
				"$schema":    "https://opencode.ai/config.json",
				"model":      "vercel/" + modelClaude,
				"autoupdate": false,
				"share":      "disabled",
				"tools":      off,
				"permission": map[string]string{"edit": "deny", "bash": "deny", "webfetch": "deny"},
				"mcp": map[string]any{"smcp": map[string]any{
					"type": "remote", "url": e.g.endpoint, "enabled": true, "oauth": false, "timeout": 180000,
					"headers": map[string]string{"Authorization": "Bearer {env:" + tokenEnv + "}"},
				}},
			})
		},
		command: func(c *client, e *runEnv, prompt string) *exec.Cmd {
			cmd := exec.Command(e.bin, "run", "--pure", "--print-logs", "--log-level", "DEBUG", "--format", "json", "-m", "vercel/"+modelClaude, prompt)
			cmd.Env = baseEnv(e,
				"OPENCODE_CONFIG="+filepath.Join(e.dir, "opencode.json"),
				"XDG_CONFIG_HOME="+filepath.Join(e.dir, "xdg-config"),
				"XDG_DATA_HOME="+filepath.Join(e.dir, "xdg-data"),
				"XDG_STATE_HOME="+filepath.Join(e.dir, "xdg-state"),
				"OPENCODE_DISABLE_AUTOUPDATE=1", "OPENCODE_DISABLE_LSP_DOWNLOAD=true")
			return cmd
		},
	}
}

func hermes() *client {
	return &client{
		ID: "hermes", Name: "Hermes Agent", Framework: "hermes", Bins: []string{"hermes"}, NeedsKey: aiKeyEnv,
		setup: func(c *client, e *runEnv) error {
			home := filepath.Join(e.dir, "hermes-home")
			if err := os.MkdirAll(home, 0o700); err != nil {
				return err
			}
			// YAML is a superset of JSON. Hermes expands ${VAR} in values.
			return writeJSONFile(filepath.Join(home, "config.yaml"), map[string]any{
				"model": map[string]any{"default": modelClaude, "provider": "custom", "base_url": aiGatewayOpenAI, "api_key": "${" + aiKeyEnv + "}"},
				"mcp_servers": map[string]any{"smcp": map[string]any{
					"url": e.g.endpoint, "ssl_verify": e.g.ca, "timeout": 180, "connect_timeout": 30,
					"headers": map[string]string{"Authorization": "Bearer ${" + tokenEnv + "}"},
					"tools":   map[string]any{"resources": false, "prompts": false},
				}},
			})
		},
		command: func(c *client, e *runEnv, prompt string) *exec.Cmd {
			cmd := exec.Command(e.bin, "-z", prompt, "--ignore-rules", "-t", "smcp") // -z takes the MCP server name as a toolset
			cmd.Env = baseEnv(e, "HERMES_HOME="+filepath.Join(e.dir, "hermes-home"))
			return cmd
		},
	}
}

func gemini() *client {
	return &client{
		ID: "gemini", Name: "Gemini CLI", Framework: "gemini-cli", Bins: []string{"gemini"}, NeedsKey: "GEMINI_API_KEY",
		setup: func(c *client, e *runEnv) error {
			// System settings take precedence over user and workspace
			// settings. Gemini CLI expands $VAR in settings values.
			return writeJSONFile(filepath.Join(e.dir, "gemini-system-settings.json"), map[string]any{
				"mcpServers": map[string]any{"smcp": map[string]any{
					"httpUrl": e.g.endpoint, "trust": true, "timeout": 180000,
					"headers": map[string]string{"Authorization": "Bearer $" + tokenEnv},
				}},
				"mcp":      map[string]any{"allowed": []string{"smcp"}},
				"security": map[string]any{"auth": map[string]any{"selectedType": "gemini-api-key"}},
			})
		},
		command: func(c *client, e *runEnv, prompt string) *exec.Cmd {
			cmd := exec.Command(e.bin, "-p", prompt, "-m", "gemini-2.5-flash", "--yolo")
			cmd.Env = baseEnv(e,
				"GEMINI_CLI_SYSTEM_SETTINGS_PATH="+filepath.Join(e.dir, "gemini-system-settings.json"),
				"GEMINI_CLI_HOME="+e.dir)
			return cmd
		},
	}
}

func goose() *client {
	reason := ""
	if runtime.GOOS == "darwin" {
		// rustls-platform-verifier uses only the macOS keychain there; on
		// Linux it reads SSL_CERT_FILE. The suite never edits the keychain.
		reason = "on macOS Goose verifies TLS only against the system keychain; the suite does not add the Gateway CA to it (runs on Linux)"
	}
	return &client{
		ID: "goose", Name: "Goose", Framework: "goose", Bins: []string{"goose"}, NeedsKey: aiKeyEnv, NotRunReason: reason,
		setup: func(c *client, e *runEnv) error {
			dir := filepath.Join(e.dir, "xdg-config", "goose")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			// Goose does not expand variables in extension headers, so the
			// session token is written into this temporary, owner-only file;
			// it dies with the Gateway at the end of the run.
			return writeJSONFile(filepath.Join(dir, "config.yaml"), map[string]any{
				"GOOSE_PROVIDER": "openai",
				"GOOSE_MODEL":    modelClaude,
				"OPENAI_HOST":    "https://ai-gateway.vercel.sh",
				"GOOSE_MODE":     "auto",
				"extensions": map[string]any{"smcp": map[string]any{
					"enabled": true, "type": "streamable_http", "name": "smcp", "uri": e.g.endpoint, "timeout": 300,
					"headers": map[string]string{"Authorization": "Bearer " + e.token},
				}},
			})
		},
		command: func(c *client, e *runEnv, prompt string) *exec.Cmd {
			cmd := exec.Command(e.bin, "run", "--no-session", "--quiet", "--max-turns", fmt.Sprint(e.maxTurns), "-t", prompt)
			cmd.Env = baseEnv(e,
				"XDG_CONFIG_HOME="+filepath.Join(e.dir, "xdg-config"),
				"OPENAI_API_KEY="+os.Getenv(aiKeyEnv),
				"OPENAI_BASE_PATH=v1/chat/completions",
				"SSL_CERT_FILE="+e.caBundle,
				"GOOSE_DISABLE_KEYRING=1")
			return cmd
		},
	}
}

// findBin returns the first candidate on PATH or in the usual per-user
// install directories.
func findBin(names []string) string {
	home, _ := os.UserHomeDir()
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
		for _, d := range []string{".local/bin", ".opencode/bin", ".npm-global/bin", "go/bin"} {
			p := filepath.Join(home, d, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				return p
			}
		}
	}
	return ""
}

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+[0-9A-Za-z.+-]*`)

// clientVersion runs `<bin> --version` and extracts the first version number.
func clientVersion(ctx context.Context, bin string) string {
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	if m := versionRe.Find(out); m != nil {
		return string(m)
	}
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// caBundle writes the system trust roots followed by the Gateway CA, for
// clients whose CA setting replaces rather than extends the roots.
func caBundle(dst, gatewayCA string) error {
	ca, err := os.ReadFile(gatewayCA)
	if err != nil {
		return err
	}
	var sys []byte
	for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"} {
		if b, err := os.ReadFile(p); err == nil {
			sys = b
			break
		}
	}
	return os.WriteFile(dst, append(append(sys, '\n'), ca...), 0o644)
}
