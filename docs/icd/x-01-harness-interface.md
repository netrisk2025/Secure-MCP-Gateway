# X-01 Harness Interface: interface control document

Interface: X-01, agent harness (framework) to the Harness Edge (E-01 Harness Interface Endpoint, E-02 Protocol Mediator, E-03 Identity & Authentication Service, E-04 Session Manager). Requirement: FR-1.48. The harness is untrusted. This document states the contract as release 1.0 implements it; where it and the SRS differ, the SRS governs and the difference is a defect.

Related documents: SRS FR-1 and FR-2 (Section 4), Appendix A (CP parameters), Appendix B (error and reason codes); `docs/harness.md` (UDS Harness Profile), `docs/adapters.md` (adapters), `docs/remote-access.md` (Remote Access Profile, X-13); X-12 in `x-12-adapter-hooks.md`.

## 1. Transports and listeners

| Listener | Address (CP-02) | Framing | Authentication |
|---|---|---|---|
| TLS harness listener | `https://127.0.0.1:8443/mcp` (loopback only, SR-2.9-3) | MCP Streamable HTTP, POST only (FR-1.3) | OAuth 2.1 bearer access token (section 3) |
| UDS harness socket (optional, UDS Harness Profile) | `/run/smcp/harness.sock`, mode 0660, group `smcp-harness` (SR-2.8-3) | Newline-delimited JSON-RPC as the MCP stdio binding defines it (FR-1.47) | Kernel peer UID registered in `[[uds.peer]]` plus that peer's bearer key (FR-2.15) |
| Remote Access listener (optional, X-13) | loopback, published through a tunnel | Streamable HTTP | OAuth with operator-approved registration or the device grant |

No other listener accepts harness connections (FR-1.1). The control API listener (CP-03, `127.0.0.1:8444`) refuses session tokens (SR-2.5-1).

TLS: version 1.3 only (SR-2.8-1). The server certificate chains to the local server CA in `<state>/tls/ca.crt` (CP-53, DNS name constraints only); harnesses trust that CA explicitly (X-12).

HTTP checks on the TLS listener: `Host` must be the listener address or the `public_url` host, else 421 (SR-2.9-2); an `Origin` header must be in `allowed_origins`, else 403 (SR-2.9-1); header block at most 16 KiB and 5 s (CP-06); body at most `request_body_bytes` (CP-07) else 413.

## 2. Protocol eras

Both eras are served on the same endpoint (CP-04: `2026-07-28`, `2025-11-25`).

| | 2026-07-28 (modern) | 2025-11-25 (legacy, FR-1.46) |
|---|---|---|
| Handshake | none; every request carries `_meta.io.modelcontextprotocol/protocolVersion` and `clientCapabilities` | `initialize`, then `notifications/initialized` |
| Version header | `MCP-Protocol-Version` equal to the body's version | `MCP-Protocol-Version` with the negotiated version after `initialize` |
| Methods | `server/discover`, `tools/list`, `tools/call`, `subscriptions/listen` (FR-1.11) | `initialize`, `tools/list`, `tools/call`, `ping` |
| Result fields | `resultType: "complete"` and `_meta.io.modelcontextprotocol/serverInfo` on every result (FR-1.14, FR-1.15) | `serverInfo` in the `initialize` result |
| Unknown or unsupported method | HTTP 404, `-32601` (FR-1.10) | HTTP 200, `-32601` |
| Session headers | `Mcp-Session-Id` and `Last-Event-ID` are ignored (FR-1.16) | not issued (stateless) |

A request is processed under legacy semantics only when it is a legacy `initialize` or carries the legacy version; an error never moves a request to the legacy path (SR-5.3-1).

## 3. OAuth 2.1 endpoints and scopes

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` | GET | RFC 9728 protected resource metadata; named in `WWW-Authenticate: Bearer resource_metadata="..."` on every 401 |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 metadata: `authorization_code` and `refresh_token` grants, PKCE `S256` only, `smcp_scope_patterns` |
| `/oauth/authorize` | GET, POST | Authorization code with PKCE; a Session Approver signs in (never the Administrator, FR-2.23) and approves the claims |
| `/oauth/token` | POST (form) | `grant_type=authorization_code` (code, `code_verifier`, `redirect_uri`, `resource`) or `grant_type=refresh_token` (rotation with reuse detection, FR-2.22, SR-2.11-4) |

Clients are pre-registered `[[client]]` entries or control-API principals (G-11); a `client_id` may be a Client ID Metadata Document URL. Confidential clients authenticate with `client_secret`.

Scopes (session claims, FR-2.3):

| Scope | Meaning |
|---|---|
| `smcp:template:<id>` | Session Allow Policy Template; must be one of the principal's Framework Profile templates; default is the profile's default template |
| `smcp:purpose:<tag>` | Declared purpose (recorded) |
| `smcp:project:<path>` | Project root (recorded) |
| `smcp:user:<claim>` | End-user claim (recorded; pseudonymized in research exports) |

Token response (also the session API's): `access_token`, `token_type: "Bearer"`, `expires_in` (CP-18 idle timeout), `refresh_token`, `scope`, `session_id`, `expires_at` (maximum lifetime), `template_id`, `policy_revision_id`, `observation_policy_id`.

A token is bound to the listener it was issued for; on another listener it gets 401 and `-31006` (SR-2.1-3). Sessions do not survive a Gateway restart in release 1.0 (FR-2.16 is deferred).

## 4. Session API

| Endpoint | Method | Purpose |
|---|---|---|
| `/smcp/v1/sessions` | POST | Create a session for a confidential client: JSON `client_id`, `client_secret`, optional `template_id`, `purpose`, `project_root`, `end_user`, `harness_version`; 201 with the token response (FR-2.2) |
| `/smcp/v1/sessions/{id}` | GET | The caller's own session (bearer of that session) |
| `/smcp/v1/sessions/{id}` | DELETE | End the caller's own session |

On the UDS socket the session is created by the first message instead:

```json
{"jsonrpc":"2.0","id":0,"method":"local.smcpgw/authenticate","params":{"key":"<bearer key>"}}
```

Its result carries `sessionId`, `principal` and `template`; the session ends when the connection closes.

## 5. Required request headers (2026-07-28)

| Header | Rule |
|---|---|
| `Authorization: Bearer <access token>` | Required on the MCP endpoint (header only, FR-2.5) |
| `Content-Type: application/json` | Required |
| `Accept` | Must allow `application/json` and `text/event-stream` |
| `MCP-Protocol-Version` | Required; equal to the body's `_meta` version |
| `Mcp-Method` | Required; equal to the body's `method` |
| `Mcp-Name` | Required for `tools/call`; equal to `params.name` |

A missing header or a header that disagrees with the body (including a `=?base64?...?=` encoded value) is refused with HTTP 400 and `-32020` before any processing (SR-5.2-1, SR-5.2-2). A header name or value with control characters, or a malformed header block, gets HTTP 400 with `-32020` and a null ID: the listener rewrites the HTTP layer's refusal, which happens before the body is read. The harness listener serves HTTP/1.1 only (a client that offers HTTP/2 falls back by ALPN). `x-mcp-header` parameter annotations are removed from presented schemas (FR-1.28), so no parameter headers are needed.

## 6. Message rules

- One JSON-RPC object per POST; batches and response objects get 400 and `-32600` (FR-1.4); invalid UTF-8 or JSON gets 400 and `-32700` (FR-1.22); a notification gets 202 with no body (FR-1.5).
- A request ID may not be reused while a request with that ID is in flight in the session (400, `-32600`, FR-1.21).
- Responses are JSON (FR-1.6); a `tools/call` with a progress token, a call held for approval and `subscriptions/listen` are answered as event streams. Held calls carry SSE comment keep-alives (FR-3.19). Progress uses the harness's token, is strictly increasing, at most 10 per second (CP-21), and stops at the result (FR-1.39, FR-1.40).
- Closing the event stream of a request cancels it, southbound too, within 1 second (FR-1.41); on the UDS socket `notifications/cancelled` does the same.
- `tools/list` pages hold at most CP-19 tools; `nextCursor` is HMAC-sealed to the session and the policy revision, and any other cursor gets `-32602` (FR-1.24, SR-5.7-2). Results carry `ttlMs` and `cacheScope: "private"` (FR-1.13).
- Presented tool names are `<server alias>_<tool>` (FR-1.26). Tools with an approval obligation carry `_meta.anthropic/requiresUserInteraction` and `_meta.local.smcpgw/approvalRequired` (FR-1.50).
- `subscriptions/listen` acknowledges only `toolsListChanged` (FR-1.33, FR-1.34); `notifications/tools/list_changed` carries the listen request ID as `subscriptionId` (FR-1.35); at most CP-20 listen streams per session (FR-1.38); the Gateway ends a stream with an empty complete result (FR-1.37).
- `CallToolResult` members (`content`, `structuredContent`, `isError`) are returned as response inspection left them (FR-1.31), with provenance in `_meta.local.smcpgw/provenance` (FR-4.12).
- `_meta.traceparent` (valid W3C format) and `_meta.io.modelcontextprotocol/clientInfo` are recorded as self-asserted observation attributes only; no harness `_meta` is sent to backends (FR-1.44, FR-1.45).
- Logging is not offered: no `logging` capability and no `notifications/message` (FR-1.42). Resources, prompts, completion, sampling, elicitation and roots are not relayed; server-initiated requests are refused southbound (FR-5.20).

## 7. Error codes

Reserved JSON-RPC codes are used only with their meaning in the MCP 2026-07-28 schema (FR-1.19): `-32700` parse error, `-32600` invalid request, `-32601` method not found, `-32602` invalid params (unknown tool, schema-invalid arguments with `reasonCode: SCHEMA_INVALID`, bad cursor), `-32603` internal error, `-32020` header mismatch, `-32022` unsupported protocol version. `-32002` and `-32042` are never emitted.

Gateway errors (Appendix B):

The HTTP column is Appendix B's. Errors raised before the MCP layer (`-31006` on authentication, `-31004` when fail-closed) use it; errors of a request that reached the MCP layer, a tool call among them, are JSON-RPC errors in an HTTP 200 response or event stream.

| Code | Name | HTTP | Meaning |
|---|---|---|---|
| `-31001` | PolicyDenied | 200 | The policy decision denied the request |
| `-31002` | ApprovalRequired | 200 | A human approval is pending; retry after approval (`data.approvalId`, `data.expiresAt`, `data.approvalUrl`) |
| `-31003` | ResponseWithheld | 200 | The response was withheld by response inspection, scoring or release checks |
| `-31004` | GatewayFailClosed | 503 | Enforcement dependencies are unavailable or the Gateway is stopped |
| `-31005` | RateLimited | 429 | A rate, concurrency, queue or stream limit was reached |
| `-31006` | SessionInvalid | 401 | Missing, invalid, expired, suspended or misbound session |
| `-31007` | BackendError | 200 | The backend failed or returned a protocol error (`data.backendCode`) |
| `-31008` | Timeout | 200 | The client deadline expired |
| `-31009` | IndeterminateOutcome | 200 | A possibly executed mutation lost its outcome; it is not retried |
| `-31010` | InputRequiredUnsupported | 200 | The backend requested client input and the MRTR Relay Profile is disabled |

Every Gateway error carries `data.reasonCode`, `data.correlationId`, `data.decisionId` when a decision was made, and `data.message`, a plain-language sentence from the Appendix B reason-code table (FR-1.20, FR-1.51). Every response echoes the request ID, including 401 and 503 (FR-1.18). Reason codes are listed in `docs/troubleshooting.md`.

## 8. Conformance fixtures

- `mcp-spec/2026-07-28/schema/examples` and `schema.json` are the fixtures. `internal/conformance` (FR-12.9) runs a full Gateway over a scripted backend, sends the example requests, validates every response and stream message against `schema.json`, serves the Tool, CallToolResult, InputRequiredResult, content-block and server-initiated request examples southbound, and reports a result for every example directory. `make conformance` writes the report to `build/conformance.md`.
- `internal/edge` and `internal/e2e` hold the per-requirement tests named in the requirement report (`make status`).
- `internal/hostile` runs the Appendix L hostile backend fixtures (`make hostile`).
- `docs/agents-conformance.md` records the real-agent runs.
