# Remote access: enable and device sign-in

How an operator opens the Remote Access Profile through a tunnel, and how `smcp-connect` on another computer registers, waits for approval and signs in with the device grant (FR-16.1 to FR-16.12, FR-12.13; ARCH §18.9). The browser-based authorization-code path of a cloud agent is the [cloud agent flow](cloud-agent-tunnel.md); configuration and limits are in the [Remote Access Profile guide](../remote-access.md).

The flow is drawn in three parts. Step numbers run on from one part to the next.

## 1. Enable and check (steps 1–10)

```mermaid
sequenceDiagram
  autonumber
  participant O as Operator (Gateway host)
  participant CTL as smcpctl remote
  participant TS as Tunnel CLI (tailscale or cloudflared)
  participant E24 as E-24 Control API
  participant E21 as E-21 Journal
  participant R as Remote listener (loopback)

  O->>CTL: remote enable --provider tailscale
  CTL->>TS: tailscale status --json for the MagicDNS name
  CTL->>E24: POST /api/v1/remote/enable with public URL and provider (operator token)
  E24->>E21: remote_access_enabled, committed
  E24->>R: open the loopback remote listener, state saved in state/remote/state.json
  CTL->>TS: tailscale funnel --bg to the remote listener
  CTL->>CTL: record what was started in state/remote/tunnel.json
  O->>CTL: remote check
  CTL->>R: protected-resource metadata through the public name
  R-->>CTL: metadata from the remote listener, not the harness listener
```

## 2. Client registration and device sign-in (steps 11–28)

```mermaid
sequenceDiagram
  autonumber 11
  participant C as smcp-connect (other computer)
  participant R as Remote listener (loopback)
  participant E03 as E-03 Authorization server (remote)
  participant E21 as E-21 Journal
  participant E24 as E-24 Control API
  participant O as Operator (Gateway host)
  participant P as Session Approver (browser)

  C->>R: discover metadata at the public URL
  C->>E03: POST /oauth/register (RFC 7591)
  E03->>E21: client_registration pending
  C->>E03: POST /oauth/device_authorization
  E03-->>C: 401 invalid_client, pending operator approval
  O->>E24: smcpctl clients approve client-id --principal id
  E24->>E21: client_registration approved
  C->>E03: POST /oauth/device_authorization
  E03-->>C: device code, user code, verification URI
  C->>C: print the URL and code on standard error
  P->>E03: open /oauth/device, enter the code, sign in as a Session Approver
  P->>E03: Approve
  E03->>E21: device_authorization approved
  C->>E03: poll /oauth/token with the device code
  E03->>E03: template must be listed in remote.templates
  E03->>E21: session created (DEVICE_CODE) with the remote origin
  E03-->>C: access and refresh tokens, stored in the CP-43 credential file
  C->>R: MCP over HTTPS with the bearer token, relayed from local stdio
```

## 3. Disable (steps 29–32)

```mermaid
sequenceDiagram
  autonumber 29
  participant O as Operator (Gateway host)
  participant CTL as smcpctl remote
  participant E24 as E-24 Control API
  participant E21 as E-21 Journal
  participant TS as Tunnel CLI (tailscale or cloudflared)

  O->>CTL: remote disable
  CTL->>E24: POST /api/v1/remote/disable
  E24->>E21: remote_access_disabled, remote sessions ended
  CTL->>TS: tailscale funnel off
```

## Implementation

`internal/remote` (listener, OAuth, registrations, `/api/v1/remote*`, `/api/v1/clients*`), `internal/tunnel` (Tailscale Funnel and Cloudflare quick tunnel drivers), `cmd/smcpctl/remote.go` and `internal/adapter/connect.go`. The console view G-11 (Remote access) offers the same enable, disable, approve, deny and revoke actions. Differences from the specification:

- With Cloudflare the tunnel is started before the enable request, because the public URL is only known once `cloudflared` reports it; with Tailscale the Gateway side is enabled first and disabled again if Funnel fails.
- In the Enforced profile `remote enable` installs the nftables table `inet smcp_remote` (SR-4.14-1) before the remote listener exists and `remote disable` removes it; on macOS the pf anchor in `docs/remote-access.md` is loaded by hand. The listeners are loopback-only regardless (SR-2.9-3).
- A remote session's template must be marked `remote_allowed` in the Framework Profile and listed in `remote.templates` (FR-16.12).
- The caller address is what the tunnel connector reports; a connector that reports none makes the per-address limits global.
- Dated runs with the cloud agents themselves (FR-15.9) are not recorded.
