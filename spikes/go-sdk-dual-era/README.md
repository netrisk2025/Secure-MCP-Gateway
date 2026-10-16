# Spike: does the MCP Go SDK serve both protocol eras on one endpoint?

**Question (SRS §3.3 risk 1, Client-Compatibility-Brief §4.3 item 4):** can one
`mcp.NewStreamableHTTPHandler` serve 2026-07-28 stateless clients and
2025-11-25 `initialize` clients on the same URL, or must the northbound
JSON-RPC layer be project code?

**Answer (2026-10-16, `modelcontextprotocol/go-sdk` v1.8.0): yes, in stateless mode.**

| Request | `Stateless: false` (default) | `Stateless: true` |
|---|---|---|
| 2026-07-28 `server/discover` | 200, but `supportedVersions` lists only `2025-11-25` | 200, both versions advertised |
| 2026-07-28 `tools/list`, `tools/call` | 400 `-32022` UnsupportedProtocolVersion | 200 |
| 2026-07-28 request without `Mcp-Protocol-Version` header | 400 `-32022` | 400 `-32020` HeaderMismatch |
| 2025-11-25 `initialize` | 200 with `Mcp-Session-Id` | 200, no `Mcp-Session-Id` |
| 2025-11-25 `notifications/initialized`, `tools/list`, `tools/call` | 200 with the session header | 200 without any session header |
| `initialize` naming `2025-06-18` | answered with `protocolVersion: 2025-11-25` | same |
| 2026-07-28 request naming an unknown version | 400 `-32022`, `data.supported` and `data.requested` populated | same |
| `subscriptions/listen` with `toolsListChanged` | not tested | SSE stream; `acknowledged` first, then `tools/list_changed` when a tool is added |
| HTTP GET on the endpoint | 400 | 405 |

Consequences for the Gateway:

- Use `Stateless: true`. The default mode cannot serve modern clients at all.
- FR-1.46 does not need an `Mcp-Session-Id`: revision 2025-11-25 makes the
  transport session optional and the Gateway session is the bearer token.
- The SDK's defaults for `cacheScope` (`public`), `ttlMs` (`0`) and the
  `logging` capability do not meet FR-1.12, FR-1.13 and FR-1.42; the Gateway
  overrides them with `ServerOptions.SetCacheable` and `ServerOptions.Capabilities`.
- Unknown methods come back as JSON-RPC `-32601` with HTTP 200 from the SDK, not
  HTTP 404 as FR-1.10 states; this is handled in the Gateway or the requirement is
  revisited when the conformance suite is written.

Run: `go test -v ./...` in this directory. The tests only log what the handler
does; they do not assert, because the point of the spike is the table above.
