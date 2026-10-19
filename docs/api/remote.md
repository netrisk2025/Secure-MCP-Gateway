# Control API: remote access and remote clients

Routes of the Remote Access Profile (`internal/remote`) on the control API (admin listener, CP-03). The listener's rules apply: loopback TLS, `Host` must name the admin listener, a foreign `Origin` or cross-site `Sec-Fetch-Site` is refused with 403 `origin_refused`, POST bodies must be `application/json` (up to 64 KiB), responses carry `Cache-Control: no-store`.

Enabling and disabling the profile and revoking a registration need the Administrator. Session Approvers (`[[approver]]`, signed in with `POST /api/v1/console/login` and `"role": "session_approver"`) may list, approve and deny client registrations and read the profile state, which Operators may read too (Appendix C; [console.md](console.md#roles)). A missing or unknown token gets 401 `unauthenticated`; a token of a role the route does not admit (for example an Approver token) gets 403 `role_refused`. Errors have the form `{"error": {"code": "<code>", "message": "<text>"}}`.

## GET /api/v1/remote

Profile state.

```json
{
  "enabled": true,
  "public_url": "https://gw.example.ts.net",
  "provider": "tailscale",
  "changed_by": "operator-token",
  "changed_at": "2026-10-17T14:02:11Z",
  "listener": "127.0.0.1:8444",
  "listening": true,
  "resource_uri": "https://gw.example.ts.net/mcp",
  "pending_registrations": 1,
  "remote_sessions": 2
}
```

`resource_uri` is present only while enabled.

## POST /api/v1/remote/enable

Enables the profile (FR-16.11): opens the remote listener, records `remote_access_enabled`, saves the state. Calling it again while enabled updates the public URL and provider (another event is recorded).

Request:

```json
{ "public_url": "https://gw.example.ts.net", "provider": "tailscale" }
```

| Field | Required | Meaning |
|---|---|---|
| `public_url` | no | `https://<name>[:port]` with no path; default `remote.public_url` |
| `provider` | no | `tailscale`, `cloudflare`, `vendor` or `manual` (default) |

Response 200: the `GET /api/v1/remote` body. Errors: 400 `bad_request` (invalid URL or provider), 503 `audit_unavailable` (the event could not be written; the profile stays off), 500 `remote_listener` (the listener could not be opened, for example the address is in use).

## POST /api/v1/remote/disable

Disables the profile: closes the listener, ends every remote session, saves the state and records `remote_access_disabled`. Body: `{}`.

Response 200: the `GET /api/v1/remote` body. 503 `audit_unavailable` means the profile is disabled but the event could not be written.

## GET /api/v1/clients

Clients that may use the remote listener: dynamic registrations (all states) and the pre-registered clients of `remote.clients`. Query `status=pending|approved|denied|revoked` filters.

```json
{
  "clients": [
    {
      "client_id": "smcp-dcr-01929f7a-...",
      "client_name": "ChatGPT",
      "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none",
      "status": "pending",
      "principal": "",
      "registered_at": "2026-10-17T14:05:00Z",
      "source_address": "203.0.113.7",
      "source_address_source": "server-asserted",
      "registration": "dynamic",
      "software_id": "",
      "software_version": "",
      "decided_by": ""
    },
    {
      "client_id": "grok-preregistered",
      "status": "approved",
      "principal": "cloud-agents",
      "redirect_uris": ["https://grok.example/callback"],
      "registration": "pre-registered",
      "token_endpoint_auth_method": "client_secret_basic"
    }
  ]
}
```

`client_name`, `software_id` and `software_version` are declared by the registrant and not verified. Decided registrations also have `decided_at`.

## GET /api/v1/clients/{id}

One client in the form above. 404 `not_found` when unknown.

## POST /api/v1/clients/{id}/approve

Approves a pending dynamic registration and binds it to one principal (FR-16.5, FR-2.18).

```json
{ "principal": "cloud-agents", "comment": "registered from my ChatGPT workspace at 14:05" }
```

`principal` defaults to `remote.default_principal`. Response 200: the client record with `status` `approved`. Errors: 400 `principal_required`, 400 `unknown_principal` (unknown or disabled), 404 `not_found`, 409 `wrong_status` (not pending), 503 `audit_unavailable`.

## POST /api/v1/clients/{id}/deny

Denies a pending registration. Body `{"comment": "..."}` (optional). Errors as for approve (409 when not pending).

## POST /api/v1/clients/{id}/revoke

Revokes an approved registration and ends its remote sessions. Body `{"comment": "..."}` (optional). 409 when the registration is not approved. Pre-registered clients are removed from `remote.clients` in the configuration instead.

Every decision is recorded as `client_registration` with outcome `approved`, `denied` or `revoked` before the state changes.
