# X-12 Framework Adapter Interface: interface control document

Interface: X-12, agentic framework to the Harness Adapter Kit (E-33: `smcp-session`, `smcp-stdio`, `smcp-connect`, `smcpctl clients setup`, `smcpctl lockdown`, `smcpctl doctor`). Requirement: FR-1.48 (with FR-12.12, FR-12.13, FR-15, FR-16.9). The framework is untrusted. The Gateway side of every adapter is X-01 (`x-01-harness-interface.md`); the adapters add no framework-specific logic to the Gateway.

Detail per client: `docs/clients/<client>.md`; machine-readable matrix with pinned versions and results: `docs/clients/matrix.json`; adapter behavior: `docs/adapters.md`.

## 1. Hooks the adapters provide

| Hook | Adapter | Contract |
|---|---|---|
| Header-helper command | `smcp-session` | Prints exactly one JSON object of headers, `{"Authorization": "Bearer <token>"}`, on standard output and exits 0 within 9 seconds; exit status 1 with a message on standard error when no session can be obtained. `--env NAME` prints `NAME=Bearer <token>` for clients that only expand environment variables (FR-12.12) |
| Stdio MCP server command | `smcp-stdio` | Speaks newline-delimited JSON-RPC on standard input and output; forwards each message unchanged to the TLS listener (or the UDS socket when `[gateway] socket` is set) with the session credential, preserving the framework's protocol era; requests run concurrently; a request that cannot be delivered gets a JSON-RPC error so the framework is never left waiting; standard error carries failures only (FR-12.13) |
| Stdio MCP server command (remote) | `smcp-connect` | As `smcp-stdio`, against a Remote Access URL, signing in with the OAuth device grant; release binary and npm package (FR-16.9) |
| Native OAuth | none (the framework's own client) | The framework discovers the protected resource metadata from the 401 and runs the authorization-code flow with PKCE against X-01 section 3 |

## 2. Credential file (CP-43)

- Path: `--credentials FILE`, else `$SMCP_CREDENTIALS`, else `$XDG_CONFIG_HOME/smcp/credentials.toml`, else `~/.config/smcp/credentials.toml`.
- Mode 0600, directory 0700; a file readable or writable by group or others stops the adapter with status 1 before any connection (SR-2.3-2). Written atomically.
- Contents: `[gateway] url`, `ca_file` (the only trust root when set), `socket` and `uds_key` (UDS Harness Profile); `[client] id`, `secret`, optional `template`, `purpose`, `project`, `end_user`; `[session]` tokens written by the adapters.
- Session handling: the access token is reused until half of `expires_in` has passed, then refreshed with the refresh-token grant (rotation, FR-2.22); without a refresh token, or when refresh fails, a confidential client creates a session through the session API. A 401 from the Gateway drops the token, obtains a new one and retries once, then answers `-31006`.
- No session means no tools: the adapters never cache tool lists or results and never fall back to a direct backend connection.

## 3. Hooks per supported framework

| Framework | Primary connection | Hook that carries the credential | CA trust for HTTP | Lockdown written by `smcpctl lockdown` | Quick start |
|---|---|---|---|---|---|
| Claude Code | Streamable HTTP | OAuth, or `headersHelper: "smcp-session"` (`smcpctl clients setup claude-code --helper`); fallback stdio `command: smcp-stdio` | `NODE_EXTRA_CA_CERTS` | `managed-settings.json`: `allowManagedMcpServersOnly`, `allowedMcpServers`, `permissions.deny` Read and Edit on Gateway paths | `docs/clients/claude-code.md` |
| Codex CLI | stdio `command = "smcp-stdio"` (default setup) | `smcp-stdio`; or Streamable HTTP with Codex OAuth or `env_http_headers` carrying the value `smcp-session --env` exports (Codex 0.142.2 has no `http_headers_helper` hook) | `CODEX_CA_CERTIFICATE` | `requirements.toml` MCP server allowlist matched by name and transport | `docs/clients/codex.md` |
| Hermes Agent | Streamable HTTP | OAuth with PKCE, or a static header from `smcp-session --env`; fallback `command: smcp-stdio` | `ssl_verify` CA bundle path | none offered by the client | `docs/clients/hermes.md` |
| OpenCode | stdio `"command": ["smcp-stdio"]` | `smcp-stdio`; or a remote server entry with OAuth or headers | `NODE_EXTRA_CA_CERTS` | `opencode.json` `mcp` and `permission` settings | `docs/clients/opencode.md` |
| Gemini CLI | stdio `mcpServers.smcp.command = "smcp-stdio"` | `smcp-stdio`; or `httpUrl` with OAuth or headers | `NODE_EXTRA_CA_CERTS` | system settings `mcpServers` and server allowlist | `docs/clients/gemini-cli.md` |
| Goose | stdio extension running `smcp-stdio` | `smcp-stdio`; or Streamable HTTP with headers from `smcp-session` | `SSL_CERT_FILE` on Linux, system keychain on macOS | `GOOSE_ALLOWLIST` YAML allowlist matched on the extension command | `docs/clients/goose.md` |
| Grok Build | stdio `command: smcp-stdio` | `smcp-stdio` | not needed (the adapter holds the CA) | none offered by the client | `docs/clients/grok-build.md` |
| Grok Bot, ChatGPT agent, Meta Muse (vendor cloud) | Remote Access URL through a tunnel | OAuth with operator-approved dynamic registration or a pre-registered client; `smcp-connect` where the vendor runs a local command | public TLS at the tunnel provider | vendor admin MCP or connector allowlists, where offered | `docs/clients/cloud-agents.md` |

Every entry's mechanism, pinned version and last result are in `docs/clients/matrix.json`; mechanisms marked `confirm: true` there come from vendor documentation and were not all exercised.

## 4. Setup, lockdown and doctor

- `smcpctl clients setup <client> [--dry-run] [--stdio] [--helper] [--no-lockdown] [--system-trust]` writes the client's MCP configuration (server name `smcp`), its CA trust setting and the lockdown profile, keeping the original bytes; `--remove` restores every file. Details: `docs/harness.md`.
- `smcpctl lockdown show|apply|remove <client> [--dry-run]` manages the client's allowlist so that only the Gateway entry is usable; system-wide files need administrator rights.
- `smcpctl doctor --client <client>` reads the client's settings and reports every MCP server that is not a Gateway adapter or endpoint, readable Gateway paths, and the CA trust; each finding names its fix.

## 5. Failure behavior

| Condition | Adapter behavior |
|---|---|
| Credential file missing or with wrong mode | exit 1 before connecting, naming the file |
| No session and no client secret | exit 1, "no session; sign in first" |
| Gateway answers 401 after one refresh | the request gets `-31006` with a plain-language message |
| Gateway unreachable or answers without a JSON-RPC body | the request gets `-32000` with the reason |
| UDS socket refuses the peer or key | `smcp-stdio` exits 1, "the Gateway refused the socket session" |
| Session revoked by an operator | later requests get `-31006`; the framework shows the Gateway's `data.message` |
