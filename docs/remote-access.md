# Remote Access Profile

The Remote Access Profile lets an agent that runs on a vendor's computer (Grok Bot, ChatGPT agent "dots", Meta Muse, or a cloud coding agent running `smcp-connect`) reach a Gateway that stays on your computer (SRS FR-16). The Gateway opens a second TLS listener on a loopback address; a tunnel connector on your computer forwards one public HTTPS name to it. No inbound port is opened.

Read `docs/security-limitations.md` first. In particular: the tunnel provider terminates the public TLS connection and can read the traffic, and the agent's own browser, terminal and connectors do not pass through the Gateway.

The profile is off by default. A configuration written by `smcpctl bootstrap` has no `[remote]` table and no enabled state.

## What the remote listener serves

| Path | Purpose |
|---|---|
| `/mcp` (CP-01) | MCP endpoint; requires an access token issued to an approved client through this listener |
| `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/mcp` | Protected-resource metadata (RFC 9728) naming the public URL |
| `/.well-known/oauth-authorization-server` | Authorization-server metadata (RFC 8414); issuer is the public URL |
| `/oauth/register` | Dynamic Client Registration (RFC 7591); registrations wait for operator approval |
| `/oauth/authorize` | Authorization-code grant with PKCE `S256`; a Session Approver signs in |
| `/oauth/token` | Token endpoint: `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code` |
| `/oauth/device_authorization` | Device authorization request (RFC 8628), used by `smcp-connect` |
| `/oauth/device` | Device verification page; a Session Approver enters the code and signs in |

Every other path answers 404, including the session API (`/smcp/v1/sessions`), `/healthz`, metrics and the console (FR-16.4). A request whose `Host` is not the public name answers 421 (FR-16.3). A request with an `Origin` header other than the public URL (or a `listener.allowed_origins` entry) answers 403.

Sessions created through the remote listener are bound to it: their tokens are refused on the local harness listener, and local tokens are refused on the remote listener (FR-16.1). Every evidence event written for a remote request carries `channel = "remote"`, `client_id`, `client_address` (the address the tunnel reported) and `client_address_source = "server-asserted"` (FR-16.8).

## Configuration

Add a `[remote]` table to the configuration. It only says how the profile behaves when enabled; enabling is a separate Administrator action.

```toml
[remote]
# address = "127.0.0.1:8445"        # CP-48 loopback listener the tunnel forwards to (default: 8444, or 8445 when the admin listener uses 8444)
default_principal = "cloud-agents"  # principal for approved dynamic registrations
templates = ["remote-readonly"]     # templates remote sessions may use (FR-16.12)
clients = ["grok-preregistered"]    # [[client]] IDs allowed to sign in remotely without registration
# public_url = "https://gw.example.ts.net"   # default public URL for enable requests
# client_address_header = "X-Forwarded-For"  # header carrying the caller address
# max_pending_registrations = 32
# max_pending_per_source = 4         # pending registrations per caller address (IPv6: per /64)
# pending_registration_lifetime = "24h"

[remote.limits]                     # CP-49 defaults shown
calls_per_minute = 30               # tools/call per client ID
calls_burst = 5
oauth_per_second = 10               # OAuth requests per caller address
oauth_burst = 20
lockout_failures = 5                # consecutive failed sign-ins or token requests
lockout = "15m"
body_bytes = 262144
header_bytes = 8192
concurrency_per_client = 4
concurrency_total = 16
session_max_lifetime = "2h"
session_idle_timeout = "15m"
```

| Key | Default | Meaning |
|---|---|---|
| `address` | `127.0.0.1:8444`, or `127.0.0.1:8445` when the admin listener uses 8444 | Must be loopback and differ from the harness and admin listeners. Changing it needs a restart. |
| `public_url` | none | `https://<name>[:port]`, no path. Used when an enable request names none. |
| `clients` | `[]` | Pre-registered `[[client]]` entries allowed on the remote listener. Their `redirect_uris` apply. |
| `default_principal` | none | Principal an approved dynamic registration is bound to when the approval names none. |
| `templates` | `[]` | Templates a remote session may use. The resolved template (requested, or the profile default) must be listed here and marked `remote_allowed` in the principal's Framework Profile; an empty list refuses every remote session. |
| `client_address_header` | `X-Forwarded-For` | For `X-Forwarded-For` the rightmost entry is used (the one the tunnel connector appended). Cloudflare also sets `Cf-Connecting-Ip`. |
| `max_pending_registrations` | 32 | Further registrations are refused with 429 until some are approved, denied or expire. |
| `max_pending_per_source` | 4 | Pending registrations one caller address may hold (an IPv6 address counts as its /64). Further registrations from that address get 429 until some are decided or expire, so one caller cannot take the whole queue. With a tunnel that does not report the caller address every caller shares one quota. |
| `pending_registration_lifetime` | `24h` | A pending registration not approved or denied within this time is dropped (1m to 168h). |
| `limits.*` | CP-49 | As above. A zero or absent key takes the default. |

A remote session's template must also be marked `remote_allowed` in the principal's Framework Profile in the active policy (FR-16.12, `docs/policy-reference.md`), for example `"dev": {"templates": ["read-only"], "default_template": "read-only", "remote_allowed": ["read-only"]}`. The policy decides which templates a cloud agent may ever use; `remote.templates` can only narrow that. A policy from release 1.0.0 marks no template, so after upgrading, remote sign-ins are refused (`invalid_scope`, event `REMOTE_TEMPLATE_REFUSED`) until a revision with the mark is published.

## Enabling

```
smcpctl remote enable --provider tailscale            # Tailscale Funnel on port 443
smcpctl remote enable --provider tailscale --port 8443
smcpctl remote enable --provider cloudflare           # Cloudflare quick tunnel (fallback)
smcpctl remote enable --provider manual --public-url https://mcp.example.com
smcpctl remote check
smcpctl remote status
smcpctl remote disable
```

`smcpctl remote enable` must run as the Gateway's user (it uses the operator token, an Administrator credential). It:

1. Asks the Gateway for its profile (`GET /admin/v1/health`) and, in the Enforced profile, installs the host rules (below) before anything else. If nft refuses them, nothing is enabled.
2. For Tailscale, reads this node's MagicDNS name from `tailscale status --json` and uses `https://<name>` (or `:8443`, `:10000`). Funnel accepts only public ports 443, 8443 and 10000.
3. Calls `POST /api/v1/remote/enable`, which records a `remote_access_enabled` event and opens the remote listener (FR-16.11). The enabled state is kept in `<state>/remote/state.json` and survives restarts (a `remote_access_resumed` event is recorded at start).
4. Starts the tunnel: `tailscale funnel --bg --https=<port> https+insecure://<remote address>`, or `cloudflared tunnel --no-autoupdate --url https://<remote address> --no-tls-verify` in the background (log in `<state>/remote/cloudflared.log`). `https+insecure` and `--no-tls-verify` apply only between the connector and the loopback listener, whose certificate comes from the Gateway's own CA; the public side uses the provider's certificate.
5. Records what it started in `<state>/remote/tunnel.json` so that `disable` can stop it.

The tunnel must preserve the public `Host` header; if it rewrites `Host` to the loopback address the Gateway answers 421 and `smcpctl remote check` says so.

`smcpctl remote check [--public-url URL] [--ca FILE]` fetches the protected-resource metadata through the public name and reports the provider, the public URL, whether it was reachable and which listener answered. It fails when the name is unreachable, when the Gateway refuses the host, or when the tunnel reaches the local harness listener instead of the remote one (FR-16.2).

`smcpctl remote disable` calls `POST /api/v1/remote/disable` (the listener closes and every remote session ends, recorded as `remote_access_disabled`), then runs `tailscale funnel --https=<port> off` or stops cloudflared, and removes the host rules it installed.

The CLIs are found on the `PATH`; `SMCP_TAILSCALE`, `SMCP_CLOUDFLARED` and `SMCP_NFT` override the paths. On this project's Mac the tailnet name is `ethans-macbook-air.tail0ffbd0.ts.net`, so the remote MCP URL would be `https://ethans-macbook-air.tail0ffbd0.ts.net/mcp`.

### Host rules

Remote access adds no inbound firewall exception: the tunnel connector runs on the host and reaches the remote listener over loopback. In the Enforced profile `smcpctl remote enable` also installs this nftables table (SR-4.14-1), with the ports taken from the configured CP-02 harness, CP-03 control API, CP-48 remote and CP-51 metrics addresses:

```
table inet smcp_remote {
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname "lo" accept
		tcp dport { 8443, 8444, 8445, 9464 } counter drop comment "SR-4.14-1: Gateway listeners are reached only through loopback"
	}
}
```

Every TCP connection to those ports that does not arrive on loopback is dropped, so a listener bound to another address by mistake is still unreachable from the network. The table is separate from the base table `inet smcp` that `smcp-nftables.service` loads, so reloading either keeps the other. `--host-rules` chooses: `auto` (default) installs the table in the Enforced profile only; `nftables` installs it on any Linux host; `off` skips it and is refused in the Enforced profile. Loading nftables rules needs root, so in the Enforced profile run `sudo smcpctl remote enable --config /etc/smcp/smcp.toml` (root can read the operator token) and disable it the same way. `smcpctl remote status` shows `host_rules` in the tunnel state. The test `TestHostRulesInNamespace` (CI job linux-integration) checks the table in a network namespace: connections from another host to each port time out and a loopback client still connects.

macOS runs the Standalone profile and has no nftables, and smcpctl does not change pf. The listeners bind loopback only either way (SR-2.9-3). To add the same rule with pf, put this in `/etc/pf.anchors/smcp-remote` (use the ports of your configuration):

```
block drop in quick on ! lo0 proto tcp from any to any port { 8443 8444 8445 9464 }
```

then add `anchor "smcp-remote"` and `load anchor "smcp-remote" from "/etc/pf.anchors/smcp-remote"` to `/etc/pf.conf` and run `sudo pfctl -f /etc/pf.conf -e`.

## Registering and approving clients

A cloud agent that supports Dynamic Client Registration registers itself at `/oauth/register`. The registration is stored as `pending` and recorded (`client_registration`, outcome `pending`). Until it is approved:

- `/oauth/authorize` redirects back with `error=unauthorized_client` and `error_description` "client registration is pending operator approval; ask the Gateway operator to run: smcpctl clients approve <client_id>".
- `/oauth/token` and `/oauth/device_authorization` answer 401 `invalid_client` with the same description.

Approve or deny on the Gateway host:

```
smcpctl clients list --status pending
smcpctl clients show <client-id>
smcpctl clients approve <client-id> [--principal <id>] [--comment TEXT]
smcpctl clients deny <client-id> [--comment TEXT]
smcpctl clients revoke <client-id>          # ends the client's remote sessions
```

Approval binds the client to exactly one principal (`--principal`, or `remote.default_principal`). The client name and software ID in a registration are self-declared by the agent; check the source address and time against what you just did before approving. Registrations accept `redirect_uris` that are `https` or `http` on a loopback address, `grant_types` from `authorization_code`, `refresh_token` and the device-code grant, and `token_endpoint_auth_method` `none`, `client_secret_basic` or `client_secret_post` (a secret is then returned once).

Pre-registered clients listed in `remote.clients` need no approval.

## Signing in

- Browser-based agents use the authorization-code flow. The sign-in page warns that the request came through the tunnel and shows the client, principal, requested scope and the caller address the tunnel reported. A Session Approver (`[[approver]]`) signs in.
- `smcp-connect` uses the device flow: it prints a URL and a code on standard error; open `https://<public name>/oauth/device`, enter the code, sign in as a Session Approver and choose Approve or Deny.

### Device codes and phishing

Anyone who knows the client ID of an approved client can start a device authorization on the public name and send the resulting code to a Session Approver, asking them to "confirm" it. If the approver enters that code and approves, the session belongs to whoever started the request. This is device-code phishing (RFC 8628 section 5.4); the Gateway cannot tell an approver's own request from one an attacker started for the same client.

Rules for Session Approvers:

- Approve only a code that you started yourself, a moment ago, by running `smcp-connect` or the cloud agent's own sign-in. A code that arrives by chat, e-mail, ticket or phone is not yours: choose Deny.
- Before approving, compare the page with what you did: the client and its name (self-declared by the agent, so not proof on its own), the caller address the tunnel reported, and the time. A caller address you do not recognize, or a client you did not just start, means Deny.
- The code is valid for 10 minutes (CP-41). If it has expired, start a new one rather than asking someone else for theirs.
- If you approved a code you did not start, end the session at once: console Sessions view or `POST /api/v1/sessions/{id}/terminate`, then revoke the client (`smcpctl clients revoke <client_id>`) if it is a dynamic registration, and look for the `DEVICE_APPROVED` event and the session's calls in the journal.

Operators reduce the exposure by approving dynamic registrations only for agents they run, revoking registrations that are no longer used, and keeping `remote.templates` to the narrowest templates the agents need, since a phished session gets that template's tools.

Remote sessions last at most `remote.limits.session_max_lifetime` (2 h) and expire after `session_idle_timeout` (15 min) without use; the access token's `expires_in` is the idle timeout. Refresh tokens rotate as on the local listener.

## Limits and lockout

| Situation | Answer |
|---|---|
| More than `concurrency_total` requests in progress on the listener | 503 with `Retry-After: 1`, before the request is read |
| Request head larger than `header_bytes` | 431 |
| Body larger than `body_bytes` (declared or while reading) | 413 |
| `Host` is not the public name | 421 |
| OAuth endpoint requests above `oauth_per_second` from one caller address | 429 `temporarily_unavailable` with `Retry-After` |
| More than `concurrency_per_client` requests of one client | HTTP 429, JSON-RPC `-31005`, `reasonCode` `REMOTE_CONCURRENCY` |
| `tools/call` above `calls_per_minute` for one client | HTTP 429, JSON-RPC `-31005`, `reasonCode` `REMOTE_RATE_LIMITED`, `data.callsPerMinute`, `Retry-After` |
| `lockout_failures` consecutive failed sign-ins, client authentications or invalid grants for a client ID or from a caller address | Both are locked for `lockout`: the sign-in page answers 429 and the token endpoint 429 `temporarily_unavailable`; a `REMOTE_LOCKOUT` event is recorded |
| Twice `lockout_failures` failed sign-ins for one Session Approver username, counted over every client and caller address | The username is locked for `lockout` on the remote sign-in pages (429); a `REMOTE_APPROVER_LOCKOUT` event is recorded with a digest of the username. Local sign-in is not affected |
| A registration while `max_pending_registrations` are pending, or while the caller address holds `max_pending_per_source` | 429 `temporarily_unavailable`, before a client secret is hashed or an event written |
| A second redemption of an authorization code | 400 `invalid_grant`; the session the first redemption created is ended and an `AUTH_CODE_REUSE` event is recorded |

The caller address is whatever the tunnel connector reports. Tailscale Funnel and cloudflared set it; a tunnel that does not makes every caller share one address, so the per-address limits become global limits. An IPv6 caller address counts as its /64 for limits and lockout. When 10,000 caller addresses are tracked at once, further new addresses share one limit until older entries expire.

## Evidence events

| Class | Outcome | Reason code | When |
|---|---|---|---|
| `remote_access` | `remote_access_enabled` | `REMOTE_ACCESS_ENABLED` | Enable request (detail: actor, public URL, provider, listener) |
| `remote_access` | `remote_access_disabled` | `REMOTE_ACCESS_DISABLED` | Disable request (detail: sessions ended) |
| `remote_access` | `remote_access_resumed` | `REMOTE_ACCESS_RESUMED` | Gateway start with the profile enabled |
| `client_registration` | `pending` | `DCR_PENDING` | Registration stored |
| `client_registration` | `approved`, `denied`, `revoked` | `DCR_APPROVED`, `DCR_DENIED`, `DCR_REVOKED` | Operator decision (detail: actor, principal, comment) |
| `auth_failure` | `deny` | `DCR_PENDING` | A pending client tried to authorize or get a token |
| `auth_failure` | `deny` | `CLIENT_AUTH_FAILED`, `CLIENT_NOT_APPROVED`, `APPROVER_SIGNIN_FAILED`, `INVALID_GRANT`, `DEVICE_CODE_UNKNOWN` | Counted failures |
| `auth_failure` | `locked` | `REMOTE_LOCKOUT` | A client ID or caller address reached the failure limit |
| `auth_failure` | `locked` | `REMOTE_APPROVER_LOCKOUT` | A Session Approver username reached twice the failure limit |
| `auth_failure` | `deny` | `AUTH_CODE_REUSE` | An authorization code was redeemed a second time (detail: whether its session was ended) |
| `device_authorization` | `approved`, `denied` | `DEVICE_APPROVED`, `DEVICE_DENIED` | A Session Approver decided a device code |
| `session` | `created` | `OAUTH_CODE`, `DEVICE_CODE` | Remote session created |
| `session` | `deny` | `REMOTE_TEMPLATE_REFUSED` | Requested template not in `remote.templates` |
| `session` | `refreshed` | `REFRESH` | Token refresh |

Call events (`requested`, `authorized`, `dispatched`, `delivered`, denials) of remote calls carry the same remote fields, and so do the Approval Service's events for held remote calls.

## Control API

See `docs/api/remote.md`.
