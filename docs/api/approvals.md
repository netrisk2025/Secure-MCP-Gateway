# Control API: approvals

Routes of the Approval Service (E-07) on the control API (admin listener, CP-03). The listener's rules apply to every route: loopback TLS, `Host` must name the admin listener, a foreign `Origin` or a cross-site `Sec-Fetch-Site` is refused with 403 `origin_refused`, and every POST must have `Content-Type: application/json` (bodies up to 64 KiB). Responses carry `Cache-Control: no-store`.

Authentication is a bearer token in the `Authorization` header:

| Token | Role | Obtained from |
|---|---|---|
| Operator token | Administrator | `<state>/keys/admin.token` |
| Administrator session token | Administrator | `POST /admin/v1/login` |
| Approver token | Approver | `POST /api/v1/approvals/login` |

Every route below except `login` accepts the Administrator and Approver roles. A missing or unknown token gets 401 `unauthenticated`; an Approver token on any other control API route gets 403 `role_refused`.

Errors have the form `{"error": {"code": "<code>", "message": "<text>"}}`.

Records use these fields:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Approval ID (UUIDv7) |
| `state` | string | `pending`, `approved`, `denied`, `expired` or `consumed` |
| `session_id`, `principal_id` | string | Session and principal that made the call |
| `server`, `tool`, `public_name` | string | Server alias, backend tool name, public tool name |
| `server_revision`, `tool_revision`, `policy_revision` | string | Revisions the approval is bound to |
| `arguments_digest` | string | `sha256:<hex>` of the canonical arguments |
| `created_at`, `expires_at` | RFC 3339 | Request time and CP-17 expiry |
| `approval_url` | string | Console deep link |
| `template`, `manifest_source`, `correlation_id`, `decision_id` | string | Context of the requesting call |
| `decisive_rules` | array of string | Policy rules that decided the permit |
| `arguments` | object | Canonical arguments (record detail only) |
| `anomaly` | object | When an anomaly band required the approval (FR-3.18): `band`, `contributing_feature`, `z_score`, `snapshot_id`, `context` (record detail only) |
| `decided_by`, `decided_at`, `comment` | string | Decision (FR-3.17) |
| `consumed_at`, `consumed_correlation_id` | string | Consumption |

A summary (list, watch) has `id`, `state`, `public_name`, `server`, `server_revision`, `session_id`, `principal_id`, `created_at`, `expires_at`, `approval_url`, `decided_by` and `decided_at`.

## POST /api/v1/approvals/login

Signs in an Approver account (`[[approvals.account]]`). No bearer token. Sign-in is rate limited per source and locked out per account after repeated failures, like the administrator sign-in.

Request:

```json
{"username": "alice", "password": "alice password 12"}
```

Response 200:

```json
{"token": "<bearer token>", "expires_in": 1800, "role": "approver"}
```

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Body is not `{username, password}` |
| 401 | `signin_failed` | Unknown account or wrong password (Session Approver and administrator credentials are unknown here) |
| 429 | `rate_limited` | Too many attempts; `Retry-After` is set |
| 503 | `busy` | Password verification capacity exhausted |
| 503 | `audit_unavailable` | The sign-in could not be recorded |

## POST /api/v1/approvals/logout

Ends the Approver token used. Body `{}`. Response 204.

## GET /api/v1/approvals

Lists approvals, newest first. Query `state` = `pending` (default), `approved`, `denied`, `expired`, `consumed` or `all`.

Response 200:

```json
{"approvals": [
  {"id": "01a14720-4e59-7d32-a06f-d96c1f6c0312", "state": "pending", "public_name": "fs_write_file", "server": "fs",
   "server_revision": "sha256:...", "session_id": "...", "principal_id": "cc",
   "created_at": "2026-10-16T23:46:04Z", "expires_at": "2026-10-16T23:51:04Z",
   "approval_url": "https://127.0.0.1:8444/approvals/01a14720-4e59-7d32-a06f-d96c1f6c0312"}
]}
```

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Unknown `state` |

## GET /api/v1/approvals/{id}

Returns the full record, including `arguments` (FR-3.18 evidence).

Response 200:

```json
{"id": "01a14720-...", "state": "pending",
 "session_id": "...", "principal_id": "cc", "server": "fs", "tool": "write_file", "public_name": "fs_write_file",
 "server_revision": "sha256:...", "tool_revision": "sha256:...", "policy_revision": "r1",
 "arguments_digest": "sha256:9f2c...",
 "created_at": "2026-10-16T23:46:04Z", "expires_at": "2026-10-16T23:51:04Z",
 "approval_url": "https://127.0.0.1:8444/approvals/01a14720-...",
 "template": "ap", "manifest_source": "live", "correlation_id": "...", "decision_id": "...",
 "decisive_rules": ["ap-write"], "arguments": {"path": "/tmp/x", "data": "..."}}
```

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | No such approval |

## POST /api/v1/approvals/{id}/approve

## POST /api/v1/approvals/{id}/deny

Records the decision (FR-3.17). The journal event is committed before the decision takes effect. A held call continues (approve) or ends with `-31001` (deny) at once.

Request (body may be `{}`; `comment` up to 1000 characters):

```json
{"comment": "checked the path"}
```

Response 200: the updated record, with `state` `approved` or `denied`, `decided_by` (`operator-token`, `admin:<user>` or `approver:<user>`), `decided_at` and `comment`.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Unknown body field or comment too long |
| 404 | `not_found` | No such approval |
| 409 | `not_pending` | The approval was already decided, expired or consumed; the body also has `"state": "<current state>"` |
| 503 | `audit_unavailable` | The decision could not be recorded; nothing changed |

## GET /api/v1/approvals/watch

A `text/event-stream` of approval events (FR-3.23). The stream starts with one `snapshot` event holding the pending approvals, then sends one `approval` event per state change, and an SSE comment `: keep-alive` every 15 seconds. It stays open until the client disconnects.

```
event: snapshot
data: {"approvals":[ ...summaries... ]}

event: approval
data: {"type":"requested","approval":{ ...summary... }}
```

`type` is `requested`, `approved`, `denied`, `expired` or `consumed`. A watcher that does not read its stream may miss events (each watcher buffers 64).

## Older routes

`GET /admin/v1/approvals` (Administrator only) returns `{"service": "running", "approvals": [ ...pending summaries... ]}` and `POST /admin/v1/approvals/{id}` with `{"decision": "approve"|"deny", "reason": "..."}` decides; they remain for compatibility with the first slice.

## Harness listener: GET /smcp/v1/approvals/{id}

Not a control API route: it is on the harness listener and takes the harness session's bearer token (FR-3.16). It reports the approval only to the session that created it.

Response 200:

```json
{"approvalId": "01a14720-...", "state": "approved", "expiresAt": "2026-10-16T23:51:04Z", "approvalUrl": "https://127.0.0.1:8444/approvals/01a14720-..."}
```

| Status | When |
|---|---|
| 401 | Missing or invalid session token (JSON-RPC error `-31006`, `WWW-Authenticate` with the resource metadata URL) |
| 404 | No such approval, or the approval belongs to another session |
