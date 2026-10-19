# Gemini CLI

Status: configuration generated and unit-tested; not run at a pinned version (matrix `not-run`). The real-agent suite installs Gemini CLI in CI (0.64.0 on 2026-10-16) and records it `not-run`, because it needs `GEMINI_API_KEY` (the Vercel AI Gateway that serves the other clients' models does not serve the Gemini API) and no such key is configured. Labelled `gateway-available`.

## Connect

```
smcpctl clients credentials --client-id <id> --secret-file <file>
smcpctl clients setup gemini-cli --dry-run
smcpctl clients setup gemini-cli --no-lockdown
```

Sets `mcpServers.smcp = {"command": "smcp-stdio", "args": []}` in `~/.gemini/settings.json`. `--helper` writes `{"httpUrl": "https://127.0.0.1:8443/mcp"}` instead; Gemini CLI then needs `NODE_EXTRA_CA_CERTS` set to the Gateway CA in the environment it starts from.

## Lockdown

`sudo --preserve-env=HOME smcpctl lockdown apply gemini-cli` writes the system settings file (`/Library/Application Support/GeminiCli/settings.json` on macOS, `/etc/gemini-cli/settings.json` on Linux) with `mcpServers.smcp` and `mcp.allowed = ["smcp"]`. Google states that name-based allowlisting is not an airtight security mechanism, so Gemini CLI stays `gateway-available` until bypass tests pass. Gemini CLI has no rule that keeps its own file tools from the Gateway's paths.

## Verify

`smcpctl doctor --client gemini-cli` lists `mcpServers` in user, project (`.gemini/settings.json`) and system settings and flags servers that are not the Gateway.
