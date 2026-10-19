# Cloud agent through a tunnel

How an agent that runs on a vendor's computer (Grok Bot, ChatGPT "dots", Meta Muse) reaches a Gateway that stays on the user's computer (FR-16, SR-2.9-3, SR-2.11-2, SR-4.14-1, SR-4.14-2; ARCH §18.9).

```mermaid
sequenceDiagram
  autonumber
  participant A as Cloud agent (vendor computer)
  participant T as Tunnel provider edge
  participant C as Tunnel connector (user computer)
  participant E01 as E-01 Remote listener 127.0.0.1:8444
  participant E03 as E-03 Authorization server
  participant P as Session Approver
  participant E04 as E-04 Session Manager
  participant E21 as E-21 Journal

  Note over C,E01: Operator ran smcpctl remote enable and remote check. No inbound port is open. nftables drops non-loopback connections (Enforced)
  A->>T: HTTPS to the public name
  T->>C: forward over the outbound tunnel
  C->>E01: TLS to the loopback remote listener
  E01->>E01: Host equals public name, remote bounds and rate limits
  E01-->>A: 401 with resource metadata (public URL)
  A->>E03: register client (RFC 7591)
  E03->>E21: registration pending event
  E03-->>A: client_id (pending)
  P->>E03: approve registration in G-11 or smcpctl clients approve
  A->>E03: authorization request with PKCE
  E03-->>P: sign-in page in the person's browser
  P->>E03: sign in as Session Approver
  A->>E03: token request
  E03->>E04: create session, template must be remote_allowed, remote lifetime
  E04-->>A: access token and refresh token
  A->>E01: tools/call with Bearer through the tunnel
  E01->>E21: every event carries channel remote, client ID, forwarded address (server-asserted)
  Note over A,E01: From here the call follows tool-call.md. Agents that accept only a command run smcp-connect, which bridges stdio to the public URL.
  Note over A,T: The tunnel provider terminates public TLS and can read the traffic. The agent's own browser, terminal and connectors do not pass through the Gateway (FR-18.2).
```

## Implementation

Implemented in `internal/remote` (listener, OAuth, registration, limits), `internal/channel` (remote origin on evidence), `internal/tunnel` and `cmd/smcpctl/remote.go` (tunnels), and `internal/adapter` plus `packaging/npm/smcp-connect` (`smcp-connect`). Differences from the diagram:

- Templates allowed for remote sessions are those the Framework Profile marks `remote_allowed`, narrowed by `remote.templates` in the configuration.
- `smcp-connect` signs in with the device authorization grant (`/oauth/device_authorization`, `/oauth/device`) instead of the authorization-code redirect, because it usually runs on a computer without the person's browser.
- In the Enforced profile, `smcpctl remote enable` installs the nftables table `inet smcp_remote` (SR-4.14-1), which drops non-loopback connections to the Gateway ports; macOS has no equivalent installed automatically.

Approval events of held remote calls carry the remote origin fields (channel, client ID, client address) like the call events.

See `docs/remote-access.md`.
