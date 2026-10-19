# OAuth sign-in

How a harness obtains a Gateway session through the Gateway's own OAuth 2.1 authorization server (FR-2.17 to FR-2.23, SR-2.11-1 to SR-2.11-5). The access token is the session (FR-2.20).

```mermaid
sequenceDiagram
  autonumber
  participant H as Harness
  participant W as Browser
  participant E01 as E-01 Endpoint
  participant E03 as E-03 Authorization server
  participant E04 as E-04 Session Manager
  participant E21 as E-21 Journal

  H->>E01: POST /mcp without a token
  E01-->>H: 401 with WWW-Authenticate resource_metadata URL
  H->>E03: GET /.well-known/oauth-protected-resource/mcp
  E03-->>H: resource URI, authorization server
  H->>E03: GET /.well-known/oauth-authorization-server
  E03-->>H: endpoints, S256 only, scopes, iss supported
  Note over H,E03: The client is a pre-registered client ID, an allowlisted metadata document URL (fetched only if on the CP-52 allowlist), or, on the Remote Access listener only, an operator-approved dynamic registration
  H->>W: open authorization URL with PKCE S256, resource, scope smcp:template
  W->>E03: GET /oauth/authorize
  E03->>E03: client, redirect URI, PKCE, resource and scope checks
  E03-->>W: sign-in page naming client, principal, template and scopes
  W->>E03: POST sign-in as Session Approver
  E03->>E21: sign-in event (approver, client, principal)
  E03-->>W: 302 to redirect URI with code, state and iss
  W->>H: authorization code on the loopback redirect
  H->>E03: POST /oauth/token with code and code_verifier
  E03->>E04: create session (principal, template, claims, approver)
  E04-->>H: access token, refresh token, expires_in
  H->>E01: POST /mcp with Authorization Bearer
  Note over H,E04: Refresh returns a new access token and a new refresh token and invalidates the old refresh token. Reuse of a rotated refresh token ends the session (SR-2.11-4).
```

## Implementation

`internal/session/oauth.go` implements the flow, with `internal/authguard` for rate limits and lockout. Differences from the diagram:

- Only Session Approver accounts (`[[approver]]`) can complete the sign-in; the Administrator account is refused (FR-2.19, FR-2.23).
- A Client ID Metadata Document is fetched only for a URL on the CP-52 allowlist (`[[client_metadata]]`: 5 s, 64 KiB, same-host redirects, public addresses only, cached 24 h) and bound to its principal; other metadata URLs are refused without a fetch, and the metadata does not advertise `client_id_metadata_document_supported` (FR-2.18, SR-2.11-5).
- Sessions are in memory and end when the Gateway restarts (session survival across restarts, FR-2.16, is deferred from release 1.0).
- Dynamic Client Registration and the device grant exist only on the Remote Access listener (`internal/remote`, [../remote-access.md](../remote-access.md)).
