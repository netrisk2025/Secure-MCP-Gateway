# Claude Code

Status: configuration generated and unit-tested; the setup it writes has not been run by the matrix job. The real-agent suite (`docs/agents-conformance.md`) ran Claude Code 2.1.302 over HTTPS on 2026-10-16 and it failed: the native build (Bun runtime, BoringSSL) rejects the iPAddress name constraints of the CP-53 local CA with "unsupported name constraint type" and does not connect. Option C (`smcp-stdio`) avoids this.

## Connect

Option A, OAuth sign-in (default). Claude Code discovers the Gateway's OAuth metadata, opens a browser, and a Session Approver signs in. Claude Code's client ID (or its Client ID Metadata Document URL) must be a `[[client]]` with `redirect_uris = ["http://localhost:*/callback"]`.

```
smcpctl clients setup claude-code --dry-run
smcpctl clients setup claude-code --no-lockdown
```

This writes `mcpServers.smcp = {"type": "http", "url": "https://127.0.0.1:8443/mcp"}` to `~/.claude.json` and `env.NODE_EXTRA_CA_CERTS = <state>/tls/ca.crt` to `~/.claude/settings.json`. The manual equivalent:

```
export NODE_EXTRA_CA_CERTS=<state dir>/tls/ca.crt
claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
```

Option B, header helper (no browser step): `smcpctl clients credentials --client-id <id> --secret-file <file>`, then `smcpctl clients setup claude-code --helper`, which adds `"headersHelper": "smcp-session"`.

Option C, stdio: `smcpctl clients setup claude-code --stdio` configures `smcp-stdio`; no CA trust is needed in Claude Code.

Tools appear as `mcp__smcp__<alias>_<tool>`. Tools that require approval carry `anthropic/requiresUserInteraction`, so Claude Code also asks locally.

## Lockdown (FR-15.2)

```
smcpctl lockdown show claude-code
sudo --preserve-env=HOME smcpctl lockdown apply claude-code --config <config>
```

The managed settings file (`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS, `/etc/claude-code/managed-settings.json` on Linux) sets `allowManagedMcpServersOnly: true`, allows only the Gateway URL and the `smcp-stdio` command, and denies Claude Code's `Read` and `Edit` tools on the Gateway's state and configuration directories and the credential file, and `Edit` on Claude Code's own MCP and settings files. Claude Code's managed settings cannot be overridden from user or project settings. Remove with `sudo --preserve-env=HOME smcpctl lockdown remove claude-code`.

## Verify

```
smcpctl doctor --client claude-code
claude mcp list
```

Doctor lists every MCP server in user (`~/.claude.json`), local (`projects.*`), project (`.mcp.json`) and managed scope and flags each one that is not the Gateway. With the lockdown applied, `claude mcp add --transport http other https://example.com/mcp` should be refused by Claude Code ("not allowed by enterprise policy").
