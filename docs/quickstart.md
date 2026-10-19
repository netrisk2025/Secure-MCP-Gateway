# Quick start

From an installed `smcpctl` to a coding agent calling a tool through the Gateway, in the Standalone profile on macOS or Linux. Install first: [install.md](install.md). Every command below was run against this repository's build; ports and paths are the defaults.

## 1. Bootstrap an instance

```sh
smcpctl bootstrap --dir ~/smcp
```

`bootstrap` asks for two passwords, each entered twice and at least 12 characters:

| Account | Used for |
|---|---|
| Administrator (`admin`) | The control API and the console at `https://127.0.0.1:8444/` |
| Session Approver (`approver`) | Approving a harness sign-in in the browser. The Administrator account is refused there |

Passwords are never read from the command line or the environment. Without a terminal, pass `--admin-password-file` and `--approver-password-file`. With `--bootstrap-token`, no Administrator password is set: a one-use token valid for 24 hours is printed, and `smcpctl admin redeem` sets the password once `smcpd` runs.

It writes:

| Path | Contents |
|---|---|
| `~/smcp/smcp.toml` | Listeners (`127.0.0.1:8443` harness, `127.0.0.1:8444` control API), accounts, a principal and OAuth client for Claude Code, one backend server |
| `~/smcp/policy.json` | Framework profile `dev` with the templates `read-only` and `approval-demo` |
| `~/smcp/state/` | Local CA and listener certificate, evidence key, operator token (`keys/admin.token`), installation ID, the package library |
| `~/smcp/sandbox/` | The directory the reference server may read |

The backend is `smcp-refserver`, packaged and signed by `bootstrap` with a one-time key enrolled as a trust anchor for risk class `low`, and enabled under the alias `ref`. Its tools are `echo`, `time_now`, `list_files` and `read_file`, presented as `ref_echo`, `ref_time_now`, `ref_list_files` and `ref_read_file`.

Other ports: `--port` and `--admin-port`.

## 2. Start the Gateway

```sh
smcpd --config ~/smcp/smcp.toml
```

The log line `smcpd listening` gives the MCP URL, the admin URL, the policy revision, the profile and the release label. On macOS it reports `profile=standalone release_label="not enforced"`.

In a second terminal:

```sh
smcpctl health --config ~/smcp/smcp.toml
```

Expected: `health: degraded; causes: unconfined; release label: not enforced`. `degraded: unconfined` is permanent in the Standalone profile: backends run as ordinary processes. See [security-limitations.md](security-limitations.md).

To silence desktop notifications for approvals while trying things out, add to `smcp.toml` and restart:

```toml
[approvals]
notify = "off"
```

## 3. Connect a client

### Claude Code, OAuth sign-in

```sh
export NODE_EXTRA_CA_CERTS=~/smcp/state/tls/ca.crt
claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
```

Claude Code discovers the Gateway's OAuth metadata and opens a browser. Sign in as `approver`. The tools Claude Code lists are those of the session's template, named `mcp__smcp__ref_<tool>`. `smcpctl clients setup claude-code --no-lockdown` writes the same configuration (`--dry-run` shows it first; without `--no-lockdown` it also applies the lockdown profile, which needs `sudo`).

Known issue: the native Claude Code build (Bun runtime) rejects the IP name constraints of the Gateway's local CA ("unsupported name constraint type") and does not connect over HTTPS. Until that is resolved, use the stdio adapter below (`smcpctl clients setup claude-code --stdio`). See [clients/claude-code.md](clients/claude-code.md).

### Codex CLI (or any client) through smcp-stdio

`smcp-stdio` is a stdio MCP server that holds the Gateway session and trusts the Gateway CA itself, so the client needs no TLS configuration. It authenticates with a confidential OAuth client.

1. Create a client secret and hash it:

   ```sh
   umask 077
   head -c 24 /dev/urandom | base64 > ~/smcp/codex-secret.txt
   smcpctl hash-password --password-file ~/smcp/codex-secret.txt
   ```

2. Add a principal and the client to `~/smcp/smcp.toml`, then restart `smcpd`:

   ```toml
   [[principal]]
   id = "codex-local"
   framework = "codex"
   display_name = "Codex CLI on this machine"
   profile = "dev"

   [[client]]
   client_id = "codex-local"
   principal = "codex-local"
   client_secret_hash = "<output of hash-password>"
   redirect_uris = ["http://127.0.0.1/unused"]
   ```

3. Write the adapter credential file (`~/.config/smcp/credentials.toml`, mode 0600) and configure Codex:

   ```sh
   smcpctl clients credentials --config ~/smcp/smcp.toml --client-id codex-local --secret-file ~/smcp/codex-secret.txt
   smcpctl clients setup codex --config ~/smcp/smcp.toml --dry-run
   smcpctl clients setup codex --config ~/smcp/smcp.toml --no-lockdown
   ```

   This adds `[mcp_servers.smcp]` with `command = "smcp-stdio"` to `~/.codex/config.toml`.

Per-client details (Hermes, OpenCode, Gemini CLI, Goose, Grok Build, cloud agents) are in [clients/](clients/README.md).

## 4. Make calls

Ask the agent to echo a word with the `ref_echo` tool, or to list the files it may read. Each call goes through the decision, the request filters, dispatch to the reference server and the response filters, and every step is journaled.

Try an approval. In `policy.json` set `"default_template": "approval-demo"` in the `dev` profile and change `"revision"` to a new ID (`"r2"`; a changed document under an already published revision ID is refused), then publish it:

```sh
smcpctl policy reload --config ~/smcp/smcp.toml
smcpctl policy history --config ~/smcp/smcp.toml
```

Sessions keep the template they were created with, so start a new session (restart the client, or sign in again), then ask for `ref_read_file` on a file in `~/smcp/sandbox`. The call is held for up to 120 s. Approve it from another terminal:

```sh
smcpctl approvals --config ~/smcp/smcp.toml
smcpctl approvals approve <approval id> --config ~/smcp/smcp.toml
```

or in the console at `https://127.0.0.1:8444/approvals`. The held call then returns its result. See [approvals.md](approvals.md).

## 5. Check the evidence

```sh
smcpctl journal verify --config ~/smcp/smcp.toml
```

Expected: `journal OK` with the number of segments and events. The console's Audit view (`https://127.0.0.1:8444/audit`) shows each call with its decision, filters and outcome.

## 6. Emergency stop

```sh
smcpctl stop --reason "trying it" --config ~/smcp/smcp.toml   # every tool call is refused
smcpctl resume --config ~/smcp/smcp.toml
```

## 7. Check the client configuration

```sh
smcpctl doctor --config ~/smcp/smcp.toml
```

Doctor lists every MCP server configured in each installed client that is not the Gateway, files the client's own tools could use to change its MCP settings, and whether the client trusts the Gateway CA. Servers configured outside the Gateway bypass it; `smcpctl lockdown apply <client>` writes the client's managed settings so only the Gateway is allowed ([harness.md](harness.md)).

## Next

- [Operator guide](operator-guide.md): accounts, policy publication, packages, secrets, backups, keys, upgrades, remote access.
- [Policy reference](policy-reference.md): the policy document.
- [Packaging guide](packaging-guide.md): admit your own MCP servers.
- [Troubleshooting](troubleshooting.md): every error and reason code.
