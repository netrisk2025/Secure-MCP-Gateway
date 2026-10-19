# Codex CLI

Status: configuration generated and unit-tested; the setup it writes has not been run by the matrix job. The real-agent suite (`docs/agents-conformance.md`) ran Codex CLI 0.142.2 over Streamable HTTP with a pre-issued session token on 2026-10-16 and it passed. Codex is treated as a 2025-11-25 era client.

## Connect

Default: `smcp-stdio`, which holds the session and trusts the Gateway CA itself, so Codex needs no CA configuration.

```
smcpctl clients credentials --client-id <id> --secret-file <file>
smcpctl clients setup codex --dry-run
smcpctl clients setup codex --no-lockdown
```

This adds a managed block to `~/.codex/config.toml`:

```toml
# BEGIN smcp (managed by smcpctl; remove with smcpctl)
[mcp_servers.smcp]
command = "smcp-stdio"
args = []
# END smcp
```

`--helper` writes `url = "https://127.0.0.1:8443/mcp"` instead, for Codex's own OAuth (`codex mcp login smcp`); Codex must then trust the Gateway CA: the real-agent suite uses `CODEX_CA_CERTIFICATE` set to a PEM bundle of the system roots plus the Gateway CA (the public roots are needed for the model endpoint). Codex 0.142.2 has no `http_headers_helper`; with `--helper` it can instead send the header that `smcp-session --env SMCP_AUTHORIZATION` exports, through `env_http_headers = {Authorization = "SMCP_AUTHORIZATION"}` (docs/adapters.md). Setup does not write that entry.

## Lockdown

`smcpctl lockdown apply codex` writes `~/.config/smcp/codex-requirements.toml`:

```toml
[mcp_server_allowlist.smcp]
command = "smcp-stdio"
```

Codex matches the allowlist on name and transport. It reads administrator requirements from managed configuration (on macOS the `com.openai.codex` `requirements_toml_base64` preference), so deploy the file there. The key names are taken from Codex pull request #9101 and are to be confirmed at pinning. Codex has no rule that keeps its own file tools from the Gateway's paths.

## Verify

`smcpctl doctor --client codex` lists `[mcp_servers]` in `~/.codex/config.toml` and `./.codex/config.toml` and flags any server that is not the Gateway.
