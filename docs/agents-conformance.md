# Real-agent conformance suite

The suite in `scripts/agents` checks that real agent CLIs work through the Gateway (SRS FR-15.8). It starts a fresh Gateway with the bundled reference server in a temporary directory and signs each agent in without a browser. It then drives the agent CLI with one short scripted prompt per scenario. Every result is decided from the Gateway's evidence journal. What the model says is never used as evidence: a model can claim to have called a tool it never called, and the suite has seen that happen.

The results go to `build/agents.json`, the `agents` array of the published status data, and to `build/agents-report.json`, which holds the per-scenario detail.

## Clients

The clients are the local clients of SRS Appendix K, read from [clients/matrix.json](clients/matrix.json) (FR-15.10).

| ID | Client | How it connects | CA trust | Model (default mode) |
|---|---|---|---|---|
| `claude-code` | Claude Code | `--mcp-config` with a Streamable HTTP server and an `Authorization: Bearer ${SMCP_SESSION_TOKEN}` header; `--strict-mcp-config`; `--tools ""` (no built-in tools); SDK control protocol (`--input-format stream-json --output-format stream-json --permission-prompt-tool stdio`, see below) | `NODE_EXTRA_CA_CERTS` | `anthropic/claude-haiku-5.5` via the Vercel AI Gateway (`ANTHROPIC_BASE_URL=https://ai-gateway.vercel.sh`, `ANTHROPIC_AUTH_TOKEN`) |
| `codex` | Codex CLI | `-c mcp_servers.smcp={url=…, bearer_token_env_var="SMCP_SESSION_TOKEN", default_tools_approval_mode="approve"}` | `CODEX_CA_CERTIFICATE` with a bundle of the system roots plus the Gateway CA | `openai/gpt-5.1-codex-mini` at `model_reasoning_effort="low"` through a custom provider (`base_url=https://ai-gateway.vercel.sh/v1`, `env_key="AI_GATEWAY_API_KEY"`, `wire_api="responses"`) |
| `hermes` | Hermes Agent | `HERMES_HOME` with `mcp_servers.smcp` (`url`, `headers`, `ssl_verify`); `hermes -z … -t smcp` | `ssl_verify: <ca.crt>` | `anthropic/claude-haiku-5.5`, custom OpenAI-compatible provider |
| `opencode` | OpenCode | `OPENCODE_CONFIG` with a `remote` MCP server and `{env:SMCP_SESSION_TOKEN}`; built-in tools off | `NODE_EXTRA_CA_CERTS` | `vercel/anthropic/claude-haiku-5.5` |
| `gemini` | Gemini CLI | `GEMINI_CLI_SYSTEM_SETTINGS_PATH` with `mcpServers.smcp.httpUrl` and headers | `NODE_EXTRA_CA_CERTS` | `gemini-2.5-flash`; needs `GEMINI_API_KEY` (the AI Gateway does not serve the Gemini API) |
| `goose` | Goose | `XDG_CONFIG_HOME/goose/config.yaml` with a `streamable_http` extension | `SSL_CERT_FILE` (Linux only) | `anthropic/claude-haiku-5.5`, OpenAI-compatible provider |
| `grok-build` | Grok Build | none | none | Always `not-run`: no publicly installable CLI |
| `reference` | the suite's own scripted MCP client | Go SDK client | Go TLS | none; never runs unless named |

A client whose CLI is not installed, or which lacks model credentials, is recorded as `not-run` with the reason.

## Scenarios

Each client gets its own principal (`agents-<id>`, framework set to the client), its own pre-registered OAuth client (`smcp-agents-<id>`) and its own session. The policy has one template, `conformance`:

| Rule | Tool | Purpose |
|---|---|---|
| `conf-allow` | `ref_echo` | allowed call |
| `conf-limited` | `ref_time_now`, `calls_per_minute: 1` | denied call |
| `conf-approve` | `ref_read_file`, `approval: true` | approval-obligated call |
| none | `ref_list_files` | ungranted tool, never presented |

| Scenario | What happens | Pass condition (journal unless stated) |
|---|---|---|
| `signin` | The suite runs the OAuth 2.1 authorization-code flow with PKCE through the sign-in form, as the Session Approver, with the agent's registered client ID and a loopback redirect. The agent receives only the resulting bearer token, through the environment variable `SMCP_SESSION_TOKEN`. | A `session` event with outcome `created`, reason `OAUTH_CODE`, the agent's principal and template `conformance` |
| `catalog` | The suite's probe lists the session's tools with the agent's token. The agent is asked to list its tools and to call `ref_list_files` if present. | The catalog is exactly `ref_echo`, `ref_read_file`, `ref_time_now` (checked on the session's `tools/list`, not on model text) |
| `allowed` | The agent is asked to call `ref_echo` once. | A call to `echo` with `requested`, `authorized` (`permit`) and `delivered` (`release`) phases in this session |
| `denied` | The probe makes one `ref_time_now` call with the agent's token, which uses up the one-call-per-minute window. The agent is then asked to call `ref_time_now` once. | A `denied` event with outcome `deny` and reason `RATE_LIMITED` for `time_now`, and no `dispatched` phase |
| `approval` | The suite watches `smcpctl approvals list --json` and approves the agent's pending approval with `smcpctl approvals approve <id> --yes` while the agent asks to call `ref_read_file`. | `approval` events `requested`, `approved` and `consumed` for `read_file`, and the call `delivered` |
| `ungranted` | Evaluated at the end. | No call to `list_files` ever reached the call pipeline for this session, and the `allowed` scenario passed. Without a successful call, the absence of calls proves nothing. |

After every client has run, the suite stops `smcpd` with SIGTERM and runs `smcpctl journal verify`. A failed verification fails every client that ran.

Every prompt ends with a sentence saying that the Gateway's tools are MCP tools, not MCP resources. Codex CLI offers the model its own `list_mcp_resources` and `read_mcp_resource` tools next to the server's tools, and without that sentence `gpt-5.1-codex-mini` sometimes answered the approval prompt with `read_mcp_resource`, which the Gateway answers with "method not found" because it offers no resources.

### Approval-obligated calls per client

In the `approval` scenario the agent calls `ref_read_file`, the Gateway holds the call, and the suite approves it with `smcpctl approvals approve` while the agent waits. Clients differ in what happens before the call reaches the Gateway:

| Client | Before the call is sent | Observed result |
|---|---|---|
| Claude Code | Asks the person before every call to a tool marked `anthropic/requiresUserInteraction` (FR-1.50), even when `--allowedTools` allows it. The suite runs Claude Code with the SDK control protocol, receives the `can_use_tool` request on stdout and answers `allow` on stdin, as a person approving the local prompt would. Only tools whose name starts with `mcp__smcp__` are allowed. | Held and approved with smcpctl (2.1.302, Haiku 5.5 through the AI Gateway and local login, 2026-10-16) |
| Codex CLI | Runs the call without asking (`default_tools_approval_mode="approve"`). | Held and approved with smcpctl |
| Hermes Agent, OpenCode, Goose | Run the call without asking. | Held and approved with smcpctl |

A plain `claude -p` has nobody to ask and refuses the call itself ("tool requires user interaction; no prompt available in headless mode"). `--permission-prompt-tool` with an MCP tool is refused too ("MCP tool requires user interaction; not supported via --permission-prompt-tool"). Either refusal is listed in `permission_denials` of the result. The suite treats such a refusal as a failure of the `approval` scenario, because the Gateway hold was not exercised.

This covers one of the four FR-3.25 cases with Claude Code (a held call approved with `smcpctl approvals`). `go run ./scripts/agents -approval-acceptance <transcript.md>` runs all four with Claude Code only: a held call approved from the Approvals view (G-13) in a real browser (`console/e2e/approve-held.mjs`, which needs `npm ci` in `console`), one approved with `smcpctl approvals approve`, one denied from G-13, and one that reaches a 60 s hold bound. It decides each case from the journal and writes the tool result Claude Code received and its final reply to the transcript. The recorded run is [verification/FR-3.25.md](verification/FR-3.25.md).

## Running it

Prerequisites: Go, the agent CLIs you want to test, and model credentials.

```
set -a; . ~/.config/smcp-dev/ai-gateway.env; set +a   # provides AI_GATEWAY_API_KEY; never print it
go run ./scripts/agents                               # every client of the matrix
go run ./scripts/agents -clients claude-code,codex
go run ./scripts/agents -clients reference            # no model, no CLI: checks the harness itself
go run ./scripts/agents -local -clients claude-code,codex
```

| Flag | Default | Meaning |
|---|---|---|
| `-clients` | all matrix clients | Comma-separated IDs from the table above |
| `-local` | off | Claude Code and Codex use your own subscription logins (`claude` with model `haiku`; `codex` with your ChatGPT login, `--ignore-user-config`, and the top-level `model` of `~/.codex/config.toml` at low reasoning effort, because a ChatGPT login accepts only some models) instead of the AI Gateway. Recorded as mode `local-login`. |
| `-out` | `build/agents.json` | Status-data results |
| `-report` | `build/agents-report.json` | Per-scenario report with durations, agent exit status and session IDs |
| `-work` | a new temporary directory | Work directory; kept when given |
| `-keep` | off | Keep the temporary work directory |
| `-matrix` | `docs/clients/matrix.json` | Matrix with the pinned versions; a different installed version is noted in `detail` |
| `-timeout` | `4m` | Time limit for one agent prompt |
| `-max-turns` | `4` | Turn limit per prompt where the client has one (Claude Code, Goose) |
| `-dns-only-ca` | off | Diagnostic only: see below. Adds `+dns-only-ca` to the recorded mode. |
| `-broken-gateway` | off | Broken-build check (FR-15.8): see below. Adds `+broken-gateway` to the recorded mode and inverts the exit status. |

The exit status is 1 when any client failed, 2 when the suite itself could not run, and 0 otherwise (`not-run` does not fail).

Without `-local`, Claude Code runs with a temporary `CLAUDE_CONFIG_DIR` and Codex with a temporary `CODEX_HOME`, so your own settings, MCP servers and logins are not used or changed. With `-local` they use your normal configuration directories. The work directory holds, per client, the configuration the suite wrote and `<scenario>.log` with the agent's output, in which the session token and the model key are replaced by `[REDACTED]`. It also holds `smcpd.log` and the instance (`instance/state/journal`).

### Secrets

- The model key reaches each agent only through its environment. The session token travels the same way, and configuration files reference it with `${SMCP_SESSION_TOKEN}`, `{env:SMCP_SESSION_TOKEN}` or `bearer_token_env_var`. Goose is the exception: it does not expand variables in extension headers, so its temporary config file (mode 0600) holds the token. Neither secret ever appears on a command line.
- The Session Approver and administrator passwords are generated per run and stored in owner-only files in the work directory.
- Keep each run small: one short prompt per scenario, four scenario prompts per client, Haiku-class models. A full run of the five installable clients through the AI Gateway, plus the one Claude Code run of the broken-build check, costs well under one US dollar.

## Results format

`build/agents.json` follows the status contract (`site/src/lib/status.ts`, `AgentResult`):

```json
[
  {"client": "Codex CLI", "version": "0.142.2", "mode": "ai-gateway", "result": "pass",
   "detail": "passed: signin, catalog, allowed, denied, approval, ungranted (approval: held and approved 1 with smcpctl); journal verify ok"}
]
```

| Field | Values |
|---|---|
| `result` | `pass`, `fail`, `not-run` |
| `mode` | `ai-gateway`, `local-login`, `scripted` (reference client); `+dns-only-ca` is appended for diagnostic runs and `+broken-gateway` for the broken-build check |
| `detail` | Passed scenarios with notes, or each failed scenario with its reason, then `diagnosis:` when a known cause was found in the agent's logs, then the journal verification result |

## Known findings

| Finding | Clients | Effect | Status |
|---|---|---|---|
| BoringSSL rejects iPAddress name constraints ("unsupported name constraint type"). CP-53 used to put `IP 127.0.0.0/8` and `::1/128` constraints on the local CA. | Claude Code (native build, Bun runtime), OpenCode (Bun) | The client never connected to the Gateway, so its tools were missing and every scenario failed. | Resolved: CP-53 now has dNSName constraints only, and the Claude Code driver passes without `-dns-only-ca` (2.1.302, local login, 2026-10-16). An installation whose CA predates the change still has the IP constraints; `smcpd` warns at startup until `smcpctl keys rotate ca` replaces it. The suite's `detail` still names the cause when it finds the error in the agent's logs. |
| Goose on macOS verifies TLS only against the system keychain | Goose | The Gateway CA cannot be trusted without changing the keychain, which the suite does not do | Goose is `not-run` on macOS and runs in CI on Linux |
| Claude Code refuses FR-1.50-marked tools in plain headless mode | Claude Code | The Gateway's approval hold cannot be exercised with a plain `claude -p` | Resolved in the suite: Claude Code runs with the SDK control protocol and the suite answers its permission request. See "Approval-obligated calls per client". |
| Codex offers its own MCP resource tools | Codex CLI | `gpt-5.1-codex-mini` sometimes called `read_mcp_resource` instead of `ref_read_file`, and the approval scenario failed (CI, 2026-10-16) | Resolved: the prompts say the tools are not resources, and Codex runs at low reasoning effort |
| The Hermes main-line installer cannot install the pinned tag | Hermes Agent | `install.sh --branch v2026.6.19` from hermes-agent.nousresearch.com fails with "No module named 'pm'", so Hermes was not installed in CI | Resolved: `install-clis.sh` uses the installer from the pinned tag |

### The broken-build check

FR-15.8 asks that a deliberately broken Gateway build turn the results to `fail`. `smcpd` built with `-tags smcp_broken` has such a defect in the policy decider (`internal/policy/broken_on.go`): once a rule grants a tool, it permits the call without the rate limit and without the approval obligation. Ungranted tools stay denied, so agents still connect and call tools. The binary logs "DELIBERATELY BROKEN BUILD" at startup. Release builds never set the tag, and `TestBrokenBuildTag` checks both builds.

```
go run ./scripts/agents -clients claude-code -broken-gateway -out build/agents-broken.json -report build/agents-broken-report.json
```

With `-broken-gateway` the suite builds that binary and exits 0 only when at least one client ran and every client that ran reached the Gateway (its `allowed` scenario passed) and failed. A client that fails without reaching the Gateway proves nothing and fails the check. The expected detail is `failed: denied (call … to ref_time_now was dispatched; want a refusal); approval (no approval requested event for ref_read_file)`. `TestBrokenGatewayRun` runs the same check with the scripted reference client.

### The `-dns-only-ca` diagnostic

`-dns-only-ca` replaces the instance's server CA and listener certificate before `smcpd` starts. The replacement CA's name constraints permit only DNS `localhost`, with no iPAddress subtrees. CP-53 CAs no longer carry iPAddress subtrees either, so the option now only narrows the DNS names; it is kept for diagnosing an older CA. The results are labelled `+dns-only-ca`. Use it only to confirm that the CA is the one thing keeping a client from connecting. Never publish its results as the client's status.

## Continuous integration

The workflow `.github/workflows/agents.yml` (name "Real agents") runs on pushes to main, nightly and on manual dispatch, where it takes an optional client list. It is not a required check.

1. `scripts/agents/install-clis.sh` installs the CLIs at the versions pinned in `docs/clients/matrix.json`: the npm packages for Claude Code, Codex, OpenCode and Gemini CLI, the Goose release script and the Hermes installer of the release tag mapped from the pinned version. A client without a pin gets the latest release. A failed install prints the installer's last lines and leaves the client `not-run`.
2. `go run ./scripts/agents` runs with the repository secrets `AI_GATEWAY_API_KEY` and, optionally, `GEMINI_API_KEY`.
3. The broken-build check runs Claude Code against `smcpd` built with `-tags smcp_broken` (see above) and fails the job unless Claude Code reaches the Gateway and fails. It runs when the dispatch input includes `claude-code` or is empty and the AI Gateway key is set. Its results, `build/agents-broken.json`, are uploaded but never published.
4. The results, `smcpd.log` and the redacted agent output are uploaded as the artifact `agents-results`. Debug logs and per-client configuration files are not uploaded.
5. On main, the `publish` job commits `agents.json` to the `site-data` branch with `scripts/agents/publish.sh` and replaces the `agents` field of the published `status.json`. The CI `status` job reads `site-data/agents.json` whenever it publishes a new `status.json`, so the results stay on the site between agent runs.

To update a pin, change `pinnedVersion` in `docs/clients/matrix.json`, run the suite locally for that client, and record `lastResult` and `lastRun`.

## Troubleshooting

| Symptom in `detail` | Likely cause | What to do |
|---|---|---|
| `the agent made no call to ref_echo`, `diagnosis: … name constraints …` | BoringSSL client and the CP-53 CA | See Known findings; confirm with `-dns-only-ca` |
| `the agent made no call to …` with no diagnosis | The client did not connect or did not use the tool | Read `<work>/agents/<id>/allowed.log`. For Claude Code, `claude-debug.txt` has the MCP connection log. For OpenCode the output includes debug logs. For Codex, look for `read_mcp_resource` or `list_mcp_resources` in the log: the model picked a resource tool. |
| `approval (the client refused the call itself …)` | Claude Code refused the approval-obligated call instead of sending a `can_use_tool` request | Check that the command line still has `--permission-prompt-tool stdio` and stream-json input and output; a new Claude Code release may have changed the control protocol |
| `broken-build check FAILED: … passed against the broken Gateway` | The suite no longer detects missing enforcement | Treat as a suite defect: a check in `journal.go` stopped looking at the evidence it should |
| `ungranted (not proven …)` | No successful call in this run | Fix the `allowed` scenario first |
| `AI_GATEWAY_API_KEY is not set` | No model credentials | Source the key file, or use `-local` for Claude Code and Codex |
| `version X differs from pinned Y` | The installed CLI is not the pinned one | Install the pinned version or update the pin |
| `journal verify FAILED` | The evidence journal did not verify after the run | Treat as a Gateway defect; keep the work directory (`-keep`) and inspect `instance/state/journal` |
