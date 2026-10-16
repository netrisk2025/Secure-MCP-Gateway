# Secure MCP Gateway — Client Compatibility Brief

**Date:** 2026-10-15 (America/New_York)
**Question:** What do the agentic frameworks that will sit in front of the Gateway expect today, and does the implementation SRS (V1.0 draft) meet them?
**Method:** Primary documentation and release notes fetched on 2026-10-15 for Claude Code, Codex CLI, Hermes Agent, and the official MCP SDKs, read against `Secure_MCP_Gateway_SRS.md` FR-1, FR-2 and FR-5 and `ArchitectureV2.md` X-01. Third-party trackers are cited only where no primary source exists and are marked as such.

---

## 1. Summary

The protocol baseline is right. All four Tier 1 MCP SDKs ship protocol revision 2026-07-28, Claude Code negotiates it by default on current builds, and Hermes probes for it. The gap is not the protocol. It is the **harness interface** (X-01). The SRS asks the harness to call a Gateway-specific session API, carry a Gateway-specific session header, and present an mTLS client certificate. No shipping client does the first two, and only Hermes does the third. Each client does, however, offer a standard hook the Gateway can use instead.

| Gap in the SRS | Clients affected | Recommended change |
|---|---|---|
| Session creation through `POST /smcp/v1/sessions` plus the `Smcp-Session` header (FR-2.2, FR-2.5) | All three | Make OAuth 2.1 the primary session mechanism. The access token *is* the session. Keep the session API as the fallback behind a header helper. |
| mTLS client certificate as the recommended framework credential (OD-2, FR-2.14) | Claude Code, Codex | Demote mTLS to optional. Hermes can use it. The others cannot set a per-server client certificate. |
| Legacy Northbound Profile disabled in the baseline (CP-04, FR-1.46) | Codex, Cursor | Enable 2025-11-25 service in the baseline. Serving both eras on one endpoint is how the TypeScript and Python SDK servers behave. |
| Public tool name up to 128 characters with `.` separator (FR-1.26) | Claude Code, Hermes | Cap public names at 64 characters and use `_` as the separator. Clients prefix and sanitize names. |
| No per-client tool hints | Claude Code | Pass through or inject the `_meta` hints that Claude Code honours, in particular `anthropic/requiresUserInteraction` for approval-obligated tools. |

## 2. Protocol revision support, as of 2026-10-15

| Component | 2026-07-28 support | Evidence |
|---|---|---|
| MCP TypeScript SDK | Yes, v2 line (2.3.1 on Oct 5). v1.x stays on 2025-11-25 and will not add it. One v2 server serves both eras. | SDK releases, npm page, v2 migration guide |
| MCP Python SDK | Yes, 2.0.0 stable. Serves every earlier revision from the same server. | Release notes (mirrored) |
| MCP Go SDK | Yes, v1.7.0 on Jul 28, hardened in v1.8.0 on Sep 14. Streamable HTTP serves 2026-07-28 **only when `StreamableHTTPOptions.Stateless = true`**. The protocol doc does not describe one handler serving both eras. | `go-sdk` releases and `docs/protocol.md` |
| MCP C# SDK | Yes, 2.0, stateless by default. | .NET blog |
| MCP Rust SDK (used by Codex via `rmcp`) | Beta. | MCP blog GA post |
| Claude Code | Yes, through the v2 runtime (TypeScript SDK 2.x). Default on v2.1.232+ where feature flags are fetched and on v2.1.274+ elsewhere. Asks HTTP and stdio servers whether they support the newer revision and falls back to the legacy handshake if not. `MCP_SDK_GENERATION` and `MCP_PROTOCOL_NEGOTIATION` override. | Claude Code MCP docs, "MCP client runtimes" |
| Hermes Agent | Yes, probe mode. `protocol: auto` tries `initialize` first and falls back to `server/discover`; `protocol: stateless` probes `server/discover` first. Adopts Client ID Metadata Documents for OAuth. | Hermes `mcp-config-reference.md` |
| Codex CLI | No public claim. Config documentation has no protocol-version setting. Treat as 2025-11-25 until the Rust SDK leaves beta. | Codex MCP docs |
| Cursor | No public claim. Documentation still lists Roots and SSE. Treat as legacy. | Third-party tracker only |

**Consequence for the SRS.** CP-04 lists `2026-07-28` alone and makes `2025-11-25` a disabled profile. Two of the four clients the owner named would be unable to connect in the baseline configuration. The Go SDK note is a real risk to FR-1: if one stateless handler cannot also serve legacy clients, the Harness Edge needs either two endpoints or the project protocol layer that `front.md` §3.3 already names as the fallback.

## 3. How each client authenticates to an HTTP MCP server

| Capability | Claude Code | Codex CLI | Hermes Agent |
|---|---|---|---|
| Static headers | `headers` with `${VAR}` expansion | `http_headers`, `env_http_headers`, `bearer_token_env_var` | `headers` with `${VAR}` or `${env:VAR}` |
| Dynamic headers from a local command | `headersHelper` (prints JSON, 10 s limit, receives server name and URL in the environment) | `http_headers_helper` (prints JSON) | Not documented |
| OAuth 2.1 | Yes, native. Discovery via RFC 9728 then RFC 8414. DCR and Client ID Metadata Documents. Pre-registered client ID and secret supported. Token endpoint must be HTTPS or `localhost`/`127.0.0.1`/`::1`. | Yes, `auth = "oauth"` is the default for `url` servers. `codex mcp login`. CIMD, DCR or auto. | Yes, `auth: oauth`, PKCE, device-code flow, CIMD or DCR. |
| Per-server mTLS client certificate | No. `CLAUDE_CODE_CLIENT_CERT` and `CLAUDE_CODE_CLIENT_KEY` exist for the Anthropic API path. Their applicability to MCP connections is undocumented, and an open feature request reports an MCP gateway behind a device-certificate policy is unreachable. | No. | Yes. `client_cert`, `client_key`, and `ssl_verify` with a CA bundle path. |
| Unix domain socket | Not for HTTP servers. stdio only. | Not documented. stdio only. | Not documented. stdio only. |
| stdio launch of a local process | Yes | Yes | Yes |
| Trust or approval controls on the client | `_meta["anthropic/requiresUserInteraction"]` forces a prompt on every call; permission rules | `default_tools_approval_mode` and per-tool `approval_mode` | `trust: untrusted` prompts for tools without `readOnlyHint` |
| Tool-name handling | Exposes `mcp__<server>__<tool>`; drops tools whose full name exceeds 128 characters | Not documented | Exposes `mcp__<server>__<tool>`; replaces every character outside letters, digits and `_` with `_` |
| Tool schema constraints | Rejects root-level `anyOf`/`oneOf`/`allOf` (flattens them); property names 1–64 chars from `[A-Za-z0-9_.-]`; schema must validate against draft 2020-12 | Not documented | Not documented |
| Elicitation on 2026-07-28 | Declares `elicitation: {form: {}, url: {}}` client capability | Not documented | `elicitation.enabled` (default true); URL mode declined |

## 4. Where the SRS does not match, and how to close each gap

### 4.1 Session establishment (FR-2.2 to FR-2.5, X-01)

**Today:** the SRS requires the harness to call `POST /smcp/v1/sessions` with harness type, purpose, project root and template, then send the returned token in an `Smcp-Session` header on every MCP request. No client has a hook for a pre-flight REST call.

**Recommended primary path: OAuth 2.1, with the Gateway as a local authorization server.**

- All three clients implement MCP OAuth natively, including discovery of the protected-resource metadata the Gateway would publish on `127.0.0.1:8443`.
- The token request is the session-creation event. The Gateway mints the access token as the session key (E-04, F-06) and records the Framework Profile from the registered client ID (E-03, F-04).
- Session context claims (template, purpose, project root) travel as OAuth **scopes** or as resource indicators, which remain narrow-only exactly as ARCH §7.1 layer 4 requires.
- Token lifetime and refresh map directly onto CP-18 session lifetime and idle timeout. Revocation (F-09, F-32) is token revocation.
- Claude Code's v2 runtime validates the RFC 9207 `iss` parameter, so the Gateway's authorization server must emit it.
- Human sign-in at the browser step gives the operator an out-of-band binding of a framework instance to a person, which the end-user claim (OD-8) currently lacks.

This promotes the existing **OAuth Profile** (SR-2.11-1) from an optional profile to the baseline, and the current Session API becomes the fallback below.

**Fallback path: header helper.** Ship an `smcp-session` command. Claude Code's `headersHelper` and Codex's `http_headers_helper` run it before connecting; it creates or refreshes a session over the existing API and prints `{"Smcp-Session": "<token>"}`. Claude Code passes `CLAUDE_CODE_MCP_SERVER_NAME` and `CLAUDE_CODE_MCP_SERVER_URL` to the helper, so one helper serves several Gateway endpoints. Hermes has no helper hook; it uses OAuth or a static `${env:SMCP_SESSION}` header set by the same command run beforehand.

**Same-host path: stdio shim.** A `smcp-stdio` binary launched by the client's `command` key speaks newline-delimited MCP on stdin and stdout, holds the Gateway credential and session, and forwards over the UDS listener (FR-1.47). This is the Harness Adapter the architecture assumes, delivered as part of the release rather than left to each framework.

### 4.2 Framework credential (OD-2, FR-2.14, FR-2.15)

mTLS works only with Hermes. Make the baseline credential the OAuth client registration (pre-registered client ID plus secret where the client supports it, or Client ID Metadata Documents), bound to a principal in E-03. Keep mTLS as a hardening option, and keep UDS peer-UID plus key for same-host harnesses. SR-2.1-1 (per-request authentication) is still satisfied: every request carries the bearer token, which E-03 verifies against the session table.

### 4.3 Protocol eras on the northbound side (CP-04, FR-1.16, FR-1.17, FR-1.46)

Move `2025-11-25` into the baseline `CP-04` list. Serve both eras on one endpoint: accept `initialize` and mint an `Mcp-Session-Id` for legacy clients, and accept stateless `_meta`-versioned requests from modern ones. The TypeScript v2 and Python 2.0 servers already behave this way. For the Go implementation, confirm in the first prototype whether one `StreamableHTTPHandler` can do both. If it cannot, run the project protocol layer named in `front.md` §3.3 for the northbound side and keep the Go SDK for the southbound client.

### 4.4 Tool naming (FR-1.26)

Claude Code adds `mcp__<server>__` and drops any tool whose full name exceeds 128 characters. Hermes rewrites `.` and `-` to `_`, so `files.read` and `files_read` collide. Set the public name to `<alias>_<tool>` with aliases restricted to `[a-z0-9]` and a 64-character cap on the full public name.

### 4.5 Client-facing hints (new)

Claude Code honours `_meta` keys on `tools/list` entries. The Gateway should set `anthropic/requiresUserInteraction: true` on tools whose session policy carries an approval obligation, so the person sees a prompt in the harness as well as in the Approvals view. It should also normalize manifests that Claude Code would otherwise drop (root-level schema combinators, long property names). Both belong to E-08 F-19 as presentation rules and do not change authorization.

### 4.6 Things the SRS already gets right

- One POST endpoint, `server/discover`, `resultType`, `ttlMs` and `cacheScope: private`, deterministic tool order, `Mcp-Method` and `Mcp-Name` header checks. These match the 2026-07-28 text and the client behaviour above.
- Ignoring `Mcp-Session-Id` and `Last-Event-ID` on the modern path.
- `subscriptions/listen` limited to `toolsListChanged`. Claude Code's v2 runtime holds exactly this stream open.
- Rejecting `InputRequiredResult` relay unless the MRTR profile is on. Claude Code declares elicitation capability, so enabling the profile later has a working client.
- Self-asserted `clientInfo` recorded but never trusted (FR-1.45).

## 5. Open items for the owner

1. Approve OAuth 2.1 as the baseline harness authentication and session mechanism, which changes FR-2.2 to FR-2.5, FR-2.14, OD-2 and SR-2.11-1.
2. Approve enabling 2025-11-25 service in the baseline until Codex and Cursor publish 2026-07-28 support.
3. Approve shipping `smcp-session` and `smcp-stdio` as Gateway release components, which brings the Harness Adapter inside the system of interest.
4. Confirm in the first prototype whether the Go SDK can serve both protocol eras on one Streamable HTTP endpoint.

## 6. Disposition (2026-10-16)

The owner approved the recommendations in Section 4. They are applied in SRS V1.1 draft and Architecture V2.2 draft:

| Recommendation | Where it landed |
|---|---|
| OAuth 2.1 as the primary session mechanism | FR-2.2, FR-2.5, FR-2.17 to FR-2.22, SR-2.1-1, SR-2.1-2, SR-2.3-1, SR-2.11-1, CP-23, CP-41; ARCH OD-2 decided, X-01 revised |
| mTLS demoted to an optional profile | mTLS Harness Profile in SRS §1.5; FR-2.14 and SR-2.8-2 made conditional |
| 2025-11-25 era in the baseline | CP-04, FR-1.16, FR-1.17, FR-1.46, SR-5.1-1, SR-5.3-1; SRS §3.3 risk 1 |
| Adapters inside the system of interest | ARCH E-33 Harness Adapter Kit, F-94, F-95, X-12, A-2; FR-1.48, FR-12.12, FR-12.13, SR-2.3-2, CP-43 |
| Tool-name limits | FR-1.26, FR-1.49, CP-42 |
| Client-facing hints (§4.5) | FR-1.50 (approval hint); FR-5.22 (property-name drift rule). Root-level combinators are not normalized because Claude Code flattens them itself |
| Go SDK dual-era check (§4.3, open item 4) | Done 2026-10-16 in `spikes/go-sdk-dual-era/`: one handler serves both eras in stateless mode. SRS §3.3 risk 1 retired; FR-1.46 reworded so that no `Mcp-Session-Id` is required |

No items from this brief remain open.

## Sources

- [MCP blog: The 2026-07-28 Specification](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP blog: Beta SDKs for the 2026-07-28 release candidate](https://blog.modelcontextprotocol.io/posts/sdk-betas-2026-07-28/)
- [TypeScript SDK releases](https://github.com/modelcontextprotocol/typescript-sdk/releases), [v2 migration guide](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28), [npm page](https://www.npmjs.com/package/@modelcontextprotocol/sdk)
- [Go SDK releases](https://github.com/modelcontextprotocol/go-sdk/releases), [Go SDK protocol notes](https://github.com/modelcontextprotocol/go-sdk/blob/main/docs/protocol.md)
- [Python SDK 2.0.0 release](https://newreleases.io/project/github/modelcontextprotocol/python-sdk/release/v2.0.0)
- [Announcing v2.0 of the official MCP C# SDK](https://devblogs.microsoft.com/dotnet/announcing-v20-of-the-official-mcp-csharp-sdk/)
- [Claude Code: Connect to tools via MCP](https://code.claude.com/docs/en/mcp), [Claude Code: Enterprise network configuration](https://code.claude.com/docs/en/network-config)
- [Claude Code issue #57152: OAuth flow and mTLS settings](https://github.com/anthropics/claude-code/issues/57152), [issue #100914: client-certificate mTLS for http MCP servers](https://github.com/anthropics/claude-code/issues/100914)
- [Codex: MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Hermes Agent: MCP config reference](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/reference/mcp-config-reference.md)
- Third-party trackers used only for Cursor: [DEV Community: which MCP clients will break your server](https://dev.to/manoj07ar/handshake-which-mcp-clients-will-break-your-server-after-the-2026-07-28-spec-split-12ga)
