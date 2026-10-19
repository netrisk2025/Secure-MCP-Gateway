# Harness adapters: smcp-session, smcp-stdio, smcp-connect

Three small programs of the Harness Adapter Kit (E-33) connect clients that cannot, or should not, talk to the Gateway's OAuth endpoint directly. All three read and write one credential file (CP-43).

| Program | Requirement | Use |
|---|---|---|
| `smcp-session` | FR-12.12 | Header helper: prints `{"Authorization": "Bearer <token>"}` for Claude Code `headersHelper`, or `NAME=Bearer <token>` with `--env NAME` for Codex `env_http_headers` and Hermes |
| `smcp-stdio` | FR-12.13 | Stdio MCP server that relays to the local Gateway; for clients that only launch commands, or to avoid configuring CA trust in the client |
| `smcp-connect` | FR-16.9 | Stdio MCP server that relays to a Remote Access URL with OAuth device sign-in; release binary and npm package (`npx smcp-connect`) |

## Credential file (CP-43)

Default path: `$SMCP_CREDENTIALS`, else `$XDG_CONFIG_HOME/smcp/credentials.toml`, else `~/.config/smcp/credentials.toml`. Every program takes `--credentials FILE`.

The file must have mode 0600. When group or other users can read or write it, the program exits with status 1 before making any connection, naming the file: `<file> (mode 0644): credential file is readable or writable by other users; run chmod 600 on it` (SR-2.3-2). The programs write it atomically with mode 0600 and create its directory with mode 0700.

```toml
[gateway]
url = "https://127.0.0.1:8443/mcp"        # MCP endpoint (local), or https://<public name>/mcp (remote)
ca_file = "/path/to/state/tls/ca.crt"     # when set, the only trust root; leave empty for a public tunnel
# socket = "/run/smcp/harness.sock"       # UDS harness socket, when the UDS Harness Profile is enabled (smcp-stdio)
# uds_key = "..."                         # bearer key registered for this user in [[uds.peer]]

[client]
id = "helper"                             # [[client]] ID
secret = "..."                            # confidential client secret (session API)
template = "ro"                           # optional session claims
purpose = ""
project = ""
end_user = ""

[session]                                 # written by the adapters
id = "..."
access_token = "..."
refresh_token = "..."
issued_at = 2026-10-17T14:00:00Z
expires_in = 1800
```

Create it for a confidential client with:

```
smcpctl clients credentials --client-id helper --secret-file secret.txt [--template ro] [--out FILE]
```

The client must be a `[[client]]` with `client_secret_hash` (generate the hash with `smcpctl hash-password`).

### Session handling

- The access token is reused until half its lifetime (`expires_in`) has passed (CP-43).
- Then the refresh-token grant runs at the token endpoint (`/oauth/token`, FR-2.20, FR-2.22). Refresh keeps the session and rotates both tokens.
- When there is no refresh token, or refresh fails, `smcp-session` and `smcp-stdio` create a new session through the session API (`POST /smcp/v1/sessions`, FR-2.2) with the client secret. Without a secret they stop with "no session; sign in first".
- When the Gateway answers a relayed request with 401, the relay drops the access token, obtains a new one and retries once. If that fails it answers the request with JSON-RPC error `-31006` "the Gateway refused the session (HTTP 401) after a refresh; sign in again".

## smcp-session

```
smcp-session [--credentials FILE] [--env NAME]
```

Prints one JSON object of headers on standard output and exits 0. It finishes within 9 seconds (Claude Code allows a helper 10). `--env NAME` prints `NAME=Bearer <token>` instead, for clients that only support static headers with variable expansion (Hermes): `export $(smcp-session --env SMCP_AUTHORIZATION)`.

Claude Code (`~/.claude.json` or `.mcp.json`):

```json
{"mcpServers": {"smcp": {"type": "http", "url": "https://127.0.0.1:8443/mcp", "headersHelper": "smcp-session"}}}
```

Claude Code also needs `NODE_EXTRA_CA_CERTS` set to the Gateway CA for HTTP; `smcpctl clients setup claude-code --helper` writes both.

Codex CLI 0.142.2 has no header-helper hook. It sends a header whose value it reads from an environment variable, so run the helper first and point `env_http_headers` at the variable:

```
export "$(smcp-session --env SMCP_AUTHORIZATION)"
codex -c 'mcp_servers.smcp={url="https://127.0.0.1:8443/mcp",env_http_headers={Authorization="SMCP_AUTHORIZATION"}}' ...
```

Codex must also trust the Gateway CA (`CODEX_CA_CERTIFICATE`, a PEM bundle of the system roots plus the Gateway CA). The token is valid for the access-token lifetime (CP-43); run the helper again before starting a new Codex process. `docs/verification/FR-12.12.md` records both clients connecting this way.

## smcp-stdio

```
smcp-stdio [--credentials FILE] [-v]
```

Reads newline-delimited JSON-RPC messages on standard input and POSTs each one, unchanged, to `[gateway] url` with the session's bearer token. Responses (JSON, or each event of an event stream) are written to standard output, one message per line. Standard error carries only failures (`-v` adds debug detail).

- The protocol era is the framework's: `Mcp-Protocol-Version` comes from the message's `_meta["io.modelcontextprotocol/protocolVersion"]` (2026-07-28 era) or from the version the `initialize` result negotiated (2025-11-25 era). `Mcp-Method` and, for `tools/call`, `prompts/get` and `resources/read`, `Mcp-Name` are taken from the message. Tools that declare `x-mcp-header` parameter headers are not supported by the relay.
- Requests are relayed concurrently; notifications get no output.
- A request the Gateway answers without a JSON-RPC body (for example plain HTTP 400), or that cannot be delivered, gets JSON-RPC error `-32000` with the reason, so the framework is never left waiting.
- TLS 1.3; when `ca_file` is set it is the only trust root.
- When `socket` is set, smcp-stdio connects to the Gateway's UDS harness socket instead of the URL (see `docs/harness.md`, UDS Harness Profile): it authenticates once with `uds_key`, then copies lines unchanged in both directions. When standard input ends it waits for the replies to the requests it sent, then closes the socket, which ends the session. A refused key or peer exits with status 1 and "the Gateway refused the socket session".
- Messages longer than 16 MiB are refused.

Any client: configure a stdio MCP server whose command is `smcp-stdio` with no arguments.

## smcp-connect

```
smcp-connect [--url URL] [--credentials FILE] [--ca FILE] [--client-id ID] [--scope SCOPE] [-v]
smcp-connect login [same flags]
smcp-connect logout [--credentials FILE]
npx smcp-connect --url https://<public name>/mcp
```

Environment: `SMCP_URL` (default for `--url`), `SMCP_CREDENTIALS`, `SMCP_CLIENT_SECRET` (secret of a pre-registered confidential client).

On first use (no tokens in the credential file) it signs in, then relays exactly like `smcp-stdio`:

1. Discovers the protected-resource and authorization-server metadata of the URL. The authorization server and every endpoint must be on the same origin as the MCP URL; otherwise it stops.
2. Without `[client] id` (or `--client-id`), registers itself as a public client (`client_name` "smcp-connect on <host>", device-code and refresh grants). The registration waits for operator approval; smcp-connect prints the `smcpctl clients approve <client-id>` command and retries every 10 seconds.
3. Runs the device authorization grant: prints `to sign in, open https://<name>/oauth/device and enter the code XXXX-XXXX` on standard error and polls. A Session Approver opens the page, enters the code, signs in and approves.
4. Stores the tokens in the credential file (mode 0600) and refreshes them at half their lifetime.

A credential file holds one Gateway URL; `smcp-connect` refuses `--url` for a different Gateway than the one stored and asks for another `--credentials` file. `login` signs in and exits; `logout` removes the tokens. `--ca` trusts a private CA (testing a tunnel with the Gateway's own certificate); with Tailscale Funnel or Cloudflare the public certificate is trusted by the system roots.

The npm package (`packaging/npm/smcp-connect`, Node 18 or later, no dependencies) behaves the same and reads and writes the same credential file format.

## Exit status

| Status | Meaning |
|---|---|
| 0 | Helper printed headers; relay ended because standard input closed |
| 1 | Credential file missing, unsafe or invalid; no session could be obtained; sign-in failed |
| 2 | Invalid arguments |
