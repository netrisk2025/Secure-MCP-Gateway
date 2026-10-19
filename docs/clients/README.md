# Client quick starts

How to connect each client of the SRS Appendix K matrix to the Gateway (FR-18.3). The machine-readable matrix, with pinned versions and the latest results, is `matrix.json` in this directory (FR-15.10).

**Status.** `smcp-session`, `smcp-stdio`, `smcp-connect` (binary and npm package), `smcpctl clients setup`, `smcpctl lockdown`, `smcpctl doctor` and the Remote Access Profile are implemented (see `docs/adapters.md`, `docs/harness.md`, `docs/remote-access.md`). The real-agent suite (`docs/agents-conformance.md`, FR-15.8) ran Claude Code, Codex CLI, Hermes Agent, OpenCode and Goose at pinned versions on 2026-10-16 over Streamable HTTP with a pre-issued session token; `matrix.json` records the results. It does not exercise `clients setup`, `lockdown` or the adapters, so every entry stays labelled `gateway-available`. The native Claude Code build and OpenCode (Bun runtime, BoringSSL) used to reject the iPAddress name constraints of the CP-53 local CA with "unsupported name constraint type". CP-53 now has DNS-only constraints and both clients pass; an instance whose CA predates the change needs `smcpctl keys rotate ca`. Mechanisms marked "to confirm at pinning" come from vendor documentation or third-party sources and have not been tested.

| Client | Runs on | Quick start |
|---|---|---|
| Claude Code | your computer | [claude-code.md](claude-code.md) |
| Codex CLI | your computer | [codex.md](codex.md) |
| Hermes Agent | your computer | [hermes.md](hermes.md) |
| OpenCode | your computer | [opencode.md](opencode.md) |
| Gemini CLI | your computer | [gemini-cli.md](gemini-cli.md) |
| Goose | your computer | [goose.md](goose.md) |
| Grok Build | your computer | [grok-build.md](grok-build.md) |
| Grok Bot, ChatGPT agent "dots" and custom connectors, Meta Muse | the vendor's computer | [cloud-agents.md](cloud-agents.md) |

## Common steps for local clients

1. Install and start the Gateway (README, "Running the first slice", until `docs/install.md` is published).
2. Create a Session Approver account for sign-ins (`[[approver]]`, FR-2.23).
3. For clients that use `smcp-stdio` or `smcp-session`, add a confidential `[[client]]` (secret hashed with `smcpctl hash-password`) and write the credential file: `smcpctl clients credentials --client-id <id> --secret-file <file>`.
4. Preview, then apply the client configuration, CA trust and lockdown: `smcpctl clients setup <client> --dry-run`, then without `--dry-run`. System-wide lockdown files (Claude Code, Gemini CLI) need administrator rights.
5. Run `smcpctl doctor --client <client>` and resolve every finding. In the Standalone profile the `readable-path` findings cannot be resolved: the client runs as the Gateway's user.
6. Start the client and check that the Gateway's tools are listed (`<alias>_<tool>`).

Undo with `smcpctl clients setup <client> --remove` (restores the original files byte for byte).
