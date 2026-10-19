# Control API: console routes

Routes of the Management Console & Control API (E-24) that the console owns: sessions, servers, the tool catalog and the evidence journal. They are registered by `internal/consoleapi` on the admin listener (CP-03). The operator guide for the console itself is [../console.md](../console.md).

The listener's rules apply to every route: loopback TLS, `Host` must name the admin listener, a foreign `Origin` or a cross-site `Sec-Fetch-Site` is refused with 403 `origin_refused`, and every POST must have `Content-Type: application/json` (bodies up to 64 KiB). Responses carry `Cache-Control: no-store`.

Authentication is a bearer token in the `Authorization` header (smcpctl and scripts) or a browser session cookie (the console; see [Browser sessions](#browser-sessions)). Bearer tokens are the operator token (`<state>/keys/admin.token`) or a sign-in token from `POST /admin/v1/login`; the tokens of the other Appendix C roles come from `POST /api/v1/console/login` and `POST /api/v1/approvals/login` (below). A request with an `Authorization` header is authenticated by it alone. Which role may use which route is the role matrix under [Roles](#roles). A missing or unknown token or session gets 401 `unauthenticated` (recorded as `ADMIN_AUTH_FAILED`); a token of a role the route does not admit gets 403 `role_refused` (recorded as `ADMIN_ROLE_REFUSED`).

Every control API response carries an `ETag` naming the control-state sequence at the time of the answer. The sequence advances with every state-changing request (POST, PUT, PATCH, DELETE) that passes authentication and the role check, from any client, and each object records the sequence of its last change: that is the object's revision. The object of a route is the path below `/api/v1/` or `/admin/v1/` up to its last path parameter (other than `{action}`), so `POST /api/v1/principals/{id}/suspend` for principal `p` changes `principals/{p}`; a route without a parameter is its own object, except `stop` and `resume` (one object, `gateway`), `policy/reload`, `policy/revisions` and `policy/rollback` (`policy`) and `remote/enable` and `remote/disable` (`remote`). The answer of a state-changing request names its object in `X-SMCP-Object`.

## Browser sessions

The console signs in with the same login routes (`POST /admin/v1/login`, `/api/v1/console/login`, `/api/v1/approvals/login`) and the header `X-SMCP-Session: cookie` (SR-2.6-1, CP-29):

- The sign-in token the route issues is revoked at once and not returned. The answer carries `session: "cookie"`, `actor`, `role`, `csrf_token`, `idle_timeout` (900), `expires_in` (28800) and `expires_at`, and sets the cookie `__Host-smcp-session` (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, no `Max-Age`). The session ID is 256 random bits, held by the server as its SHA-256 digest. Evidence: `admin`/`session_started`/`BROWSER_SESSION_STARTED` after the route's own sign-in event.
- Every sign-in issues a new session ID. A session cookie sent to a login route is destroyed before the sign-in, so an ID set before sign-in never becomes a signed-in session. A session's role is fixed; using another role takes a new sign-in and so a new ID.
- The session ends 15 minutes after the last user request and 8 hours after sign-in. Requests with `X-SMCP-Background: 1` (refreshes the console makes on its own, such as live updates) do not count as user activity. Ending a session cancels its requests in flight, including open event streams.
- `POST /admin/v1/session/logout` (with the CSRF token) ends the session at once and clears the cookie; response 204. A browser session that calls any `/logout` route is ended the same way.
- `GET /api/v1/console/session` returns `session`, `csrf_token`, `idle_timeout` and `expires_at` for a browser session, so a reloaded page continues it.

Every state-changing request of a browser session must carry (SR-8.9-1):

| Header | Missing or wrong | Response |
|---|---|---|
| `X-CSRF-Token: <csrf_token>` | missing or wrong | 403 `csrf_invalid` (recorded as `auth_failure`/`CSRF_TOKEN_INVALID`) |
| `If-Match: <ETag>` | missing | 428 `precondition_required` |
| | names a tag older than the last change of the request's object, a tag of another `smcpd` start, or `*` | 412 `revision_stale`, with the current `ETag` |

A change to another object does not make a tag stale. Check and change are atomic, so of two concurrent requests for one object with the same tag only one passes. The console keeps the last `ETag` it received for each resource collection (the first path segment below the version, such as `principals`) and sends the one of the collection it changes; after a 412 it shows that the object changed and the next attempt carries the new tag. Sign-out routes need the CSRF token but not `If-Match`. Bearer-token requests need neither, since a browser cannot attach a bearer token to a cross-site request.

Errors have the form `{"error": {"code": "<code>", "message": "<text>"}}`.

Times are RFC 3339 in UTC. IDs are UUIDv7 strings.

## Sessions

### GET /api/v1/sessions

Active harness sessions, newest first.

Response 200:

```json
{"sessions": [
  {"id": "01a14737-...", "state": "active", "principal_id": "claude-code-local", "framework": "claude-code", "profile": "dev",
   "client_id": "https://claude.ai/api/mcp/oauth/client-metadata", "template": "read-only", "policy_revision": "r1",
   "purpose": "", "approved_by": "approver", "harness_version": "", "listener": "tls",
   "created_at": "2026-10-17T00:20:01Z", "idle_deadline": "2026-10-17T00:50:01Z", "max_deadline": "2026-10-17T08:20:01Z"}
]}
```

Fields with no value are omitted. `approved_by` is the Session Approver who signed the harness in (FR-2.19); it is absent for sessions created through the session API. `state` is `active`, `suspended`, `terminated` or `expired`; `end_reason` (`IDLE_TIMEOUT`, `MAX_LIFETIME`, `TERMINATED` or `REFRESH_TOKEN_REUSE`) and `ended_at` are set once a session has ended.

### GET /api/v1/sessions/{id}

One session in the same form. Ended sessions stay readable for 10 minutes after they end.

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | No such session, or it ended longer ago than the retention time |

### POST /api/v1/sessions/{id}/terminate

Ends an active or suspended session (FR-8.19): its calls in flight are cancelled, its access and refresh tokens stop working and its MCP sessions are closed (FR-2.11). The action is committed to the journal (`class` `admin`, `outcome` `terminate_requested`, `reason_code` `SESSION_TERMINATED_BY_OPERATOR`, `detail.actor`, `detail.reason`) before the session ends; the session end is recorded by E-04 as a `session` event with `reason_code` `TERMINATED`.

Request (`reason` optional, up to 1000 characters):

```json
{"reason": "harness misbehaving"}
```

Response 200: the session, with `state` `terminated`.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Unknown body field or reason too long |
| 404 | `not_found` | No such session |
| 409 | `not_active` | The session has already ended; the body also has `"state": "<current state>"` |
| 503 | `audit_unavailable` | The action could not be recorded; the session was not ended |

### POST /api/v1/sessions/{id}/suspend and /resume

Suspends an active session or resumes a suspended one (FR-2.8, FR-8.19; suspend: Administrator and Operator; resume: Administrator, Appendix C). A suspended session's access and refresh tokens are refused (the harness gets 401 `SESSION_INVALID`) and its calls in flight are refused at the edge's next session check. It keeps its idle and maximum deadlines and its place in the principal's session count, expires as usual, and can be terminated. Resuming lets the harness continue with its current tokens unless the session expired meanwhile. `GET /api/v1/sessions` lists active and suspended sessions with their `state`.

Request: `{"reason": "..."}` (optional, up to 1000 characters). Response 200: the session. Evidence before the change: `admin`/`suspend_requested`/`SESSION_SUSPENDED_BY_OPERATOR` or `admin`/`resume_requested`/`SESSION_RESUMED_BY_OPERATOR` with `detail.actor` and `detail.reason`. Errors: 400 `bad_request`, 404 `not_found`, 409 `wrong_state` (with `state`), 503 `audit_unavailable` (nothing changed).

## Principals and credentials

Principals and OAuth client credentials can be created from the control API in addition to `[[principal]]` and `[[client]]` in `smcp.toml` (`internal/principals`). They are kept in `<state>/principals.json` (mode 0600) and take effect at once: the OAuth authorization server, the session API and the remote profile find them like the file's principals and clients. File principals can be suspended here; their definitions are edited in `smcp.toml`. Every change is committed to the journal before it takes effect and refused with 503 `audit_unavailable` when it cannot be. Reads: Administrator, Operator, Auditor. Changes: Administrator.

### GET /api/v1/principals

```json
{"principals": [{"id": "claude-code-local", "framework": "claude-code", "display_name": "Claude Code on this machine", "profile": "dev",
                 "source": "file", "enabled": true, "active_sessions": 1, "suspended_sessions": 0,
                 "credentials": [{"client_id": "https://claude.ai/api/mcp/oauth/client-metadata", "source": "file", "confidential": false, "redirect_uris": ["http://127.0.0.1:*/callback"]}]},
                {"id": "lab-agent", "framework": "other", "profile": "dev", "source": "console", "enabled": false,
                 "suspension": {"by": "admin:admin", "at": "2026-10-17T03:00:00Z", "reason": "investigating"}, "created_by": "admin:admin", "created_at": "2026-10-17T02:00:00Z",
                 "active_sessions": 0, "suspended_sessions": 1,
                 "credentials": [{"client_id": "smcp-client-1f2e3d4c5b6a7980", "source": "console", "confidential": true, "redirect_uris": ["https://lab.example/cb"],
                                  "created_by": "admin:admin", "created_at": "2026-10-17T02:01:00Z"}]}],
 "frameworks": ["claude-code", "codex", "..."], "profiles": ["dev"]}
```

`profiles` are the framework profiles of the active policy. Secret hashes are never returned.

### POST /api/v1/principals

Request: `{"id": "lab-agent", "framework": "other", "display_name": "Lab agent", "profile": "dev"}`. `id` matches `^[a-z0-9][a-z0-9._-]{0,63}$` and is not used by the file or the directory; `framework` is one of the configuration's framework types; `profile` is a framework profile of the active policy. Response 201: the principal. Evidence: `PRINCIPAL_CREATED`. Errors: 400 `invalid`, 409 `exists`.

### POST /api/v1/principals/{id}/suspend and /enable

Suspend refuses new sessions of the principal (`config.FindPrincipal` reports it disabled) and suspends its active sessions; the response lists them in `suspended_sessions`. Enable lets it sign in again; its suspended sessions stay suspended until resumed one by one. Request: `{"reason": "..."}`. Evidence: `PRINCIPAL_SUSPENDED`, `PRINCIPAL_ENABLED`. Errors: 404 `not_found`.

### POST /api/v1/principals/{id}/credentials

Issues an OAuth client bound to the principal (FR-2.18). Request: `{"redirect_uris": ["http://127.0.0.1:51234/callback"], "confidential": false}`: 1 to 10 absolute URLs without a fragment, `https` or loopback `http`. Response 201: `{"client_id": "smcp-client-…", "principal": "…", "redirect_uris": […], "confidential": true, "client_secret": "…"}`; `client_secret` (256 bits) is returned only here and stored as an Argon2id hash. Public clients use PKCE. Evidence: `CREDENTIAL_ISSUED`.

### POST /api/v1/credentials/{client_id}/revoke

Revokes an issued credential: the client can no longer authorize or refresh, and every session it opened is terminated (listed in `terminated_sessions`). Clients of `[[client]]` answer 409 `defined_in_file`. Request: `{"reason": "..."}`. Evidence: `CREDENTIAL_REVOKED`.

### Session Approver accounts (FR-2.23)

Session Approvers sign in harnesses at the OAuth authorization endpoint (FR-2.19) and use nothing else of the control API beyond their Appendix C rows. These routes are the Administrator's; the accounts are kept in the principal directory (`<state>/principals.json`) next to the `[[approver]]` entries of `smcp.toml`, and every sign-in path (local and remote authorization endpoints, console sign-in) reads both.

- `GET /api/v1/approvers`: `{"approvers": [{"username", "source": "file" | "console", "created_by", "created_at"}]}`. Password hashes are never returned.
- `POST /api/v1/approvers`: `{"username": "desk", "password": "..."}`. `username` matches `^[a-z0-9][a-z0-9._-]{0,63}$` and is not the Administrator's, another Session Approver's, a console account's or an Approver's; the password has 12 to 1024 characters and is refused with 400 `invalid` when it is the Administrator's password. The password is stored as an Argon2id hash and is never recorded in evidence. Response 201: the account. Evidence: `SESSION_APPROVER_CREATED`. Errors: 400 `invalid`, 409 `exists`.
- `POST /api/v1/approvers/{username}/remove`: `{"reason": "..."}`. Deletes an account of the directory, refuses its console tokens and ends its console sessions (`ended_console_sessions`); harness sessions it approved earlier are not affected. Accounts of `[[approver]]` answer 409 `defined_in_file`. Evidence: `SESSION_APPROVER_REMOVED`.

`smcpctl approvers list|add|rm` calls these routes.

### GET /api/v1/sessions/principals

The framework principals, OAuth clients and Session Approver accounts of the configuration. Password and client-secret hashes are never returned.

Response 200:

```json
{"principals": [{"id": "claude-code-local", "framework": "claude-code", "display_name": "Claude Code on this machine", "profile": "dev", "enabled": true, "active_sessions": 1}],
 "clients": [{"client_id": "https://claude.ai/api/mcp/oauth/client-metadata", "principal": "claude-code-local", "confidential": false,
              "redirect_uris": ["http://localhost:*/callback", "http://127.0.0.1:*/callback"]}],
 "session_approvers": [{"username": "approver"}]}
```

## Servers and catalog

### GET /api/v1/servers

Every `[[server]]` of the configuration with its state.

Response 200:

```json
{"servers": [
  {"alias": "ref", "state": "running", "revision": "live-9ecfde7b49bac9b2", "era": "2026-07-28", "verified": false, "manifest_source": "live",
   "tool_count": 4, "command": "/usr/local/bin/smcp-refserver", "args": ["--root", "/home/me/smcp/sandbox"],
   "env_keys": [], "secret_slots": [], "risk_classes": [], "launcher": "subprocess", "confined": false, "oversized_frames": 0,
   "suspended_tools": []}
]}
```

| Field | Meaning |
|---|---|
| `state` | `running` when the registry launched the server, `not_running` otherwise |
| `revision` | Recorded server revision (`live-<hash>` until signed packages exist) |
| `era` | MCP protocol version negotiated with the server |
| `verified`, `manifest_source` | Whether tool definitions come from a verified manifest; `live` means read from the running server |
| `env_keys`, `secret_slots` | Names of the `env` and `secret_env` entries; values are never returned |
| `launcher`, `confined` | Launcher name and whether it confines the instance |
| `oversized_frames` | Messages from the server dropped for exceeding the result bound |
| `suspended_tools` | Tools of the revision that the Local Server Registry holds as suspended because the import-time metadata scan blocked them (SR-5.9-2): `name`, `reason_code` (`METADATA_BLOCKED`), `stage` (`import`) and the blocking `findings` (rule set, rule, rule-set version, location). They are never presented or callable. `smcpctl servers suspended-tools` lists them for every server. |

### GET /api/v1/servers/{alias}

```json
{"server": { ...as above... },
 "tools": [{"name": "read_file", "public_name": "ref_read_file", "description": "Read a UTF-8 text file ...", "revision": "live-9ecfde7b49bac9b2/read_file",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}, "annotations": {"readOnlyHint": true}}]}
```

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | No server with this alias is configured |

### GET /api/v1/catalog

The public tools a session is offered, per Session Allow template of the active policy. Query `template=<name>` returns one template.

Response 200:

```json
{"policy_revision": "r1",
 "templates": [
   {"name": "approval-demo", "profiles": ["dev"], "default_for": [],
    "tools": [{"public_name": "ref_read_file", "server": "ref", "tool": "read_file", "rule_id": "demo-approve", "approval": true, "filters": [], "available": true}]}
 ],
 "tools": [ ...every tool of every running server, in the ToolView form above... ]}
```

`available` is false when the policy names a tool that no running server provides; such a grant appears in no session's catalog. `filters` lists the optional filters the rule adds to the mandatory ones.

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | `template` names no template of the active policy |

## Evidence journal

### GET /api/v1/audit/events

Journal events, newest first, one page at a time. Events are read from the journal files, so the result includes events of the open segment.

| Query | Meaning |
|---|---|
| `class`, `phase`, `origin`, `outcome`, `reason_code`, `session_id`, `correlation_id`, `principal_id`, `decision_id`, `policy_revision` | Exact match |
| `server` | Server revision ID, or the server alias the requested event records |
| `tool` | Tool revision ID, the tool name the requested event records, or the tool name at the end of the tool revision |
| `rule` | A decisive rule of the decision record, by rule-revision ID (`r2/dev/fs-read`) or rule ID (`fs-read`) |
| `q` | Case-insensitive substring of the event's JSON |
| `since`, `until` | RFC 3339 times; `since` inclusive, `until` exclusive |
| `limit` | Page size, 1 to 500, default 100 (FR-7.3) |
| `before` | `event_id` of the last event of the previous page (`next_before` of that response) |

Response 200:

```json
{"events": [{"event_id": "01a14737-...", "time": "2026-10-17T00:17:01.381Z", "class": "admin", "origin": "E-24", "outcome": "signed_in",
             "reason_code": "ADMIN_SIGNIN", "policy_status": "not_evaluated", "detail": {"actor": "admin:admin"}}],
 "next_before": "", "journal_events": 2}
```

`next_before` is empty on the last page. `journal_events` is the number of events in the journal.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Bad `limit`, `since` or `until`, or `before` names no event |
| 503 | `journal_unreadable` | The journal files could not be read |

### GET /api/v1/audit/events/{id}

One event, its 1-based position in the journal, and every event with the same `correlation_id` in journal order (the phases of the call; empty for events without one).

```json
{"event": { ... }, "position": 42, "related": [ { ...requested... }, { ...authorized... }, { ...delivered... } ]}
```

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | No event with this ID |
| 503 | `journal_unreadable` | The journal files could not be read |

### GET /api/v1/audit/export

The matching events, oldest first, as a download (`Content-Disposition: attachment`). Takes the filters of `GET /api/v1/audit/events` (not `limit` or `before`) and `format` = `csv` (default) or `jsonl`.

CSV columns: `event_id`, `time`, `class`, `phase`, `origin`, `correlation_id`, `session_id`, `principal_id`, `decision_id`, `policy_revision`, `server_revision`, `tool_revision`, `outcome`, `reason_code`, `policy_status`, `detail` (JSON). A cell that begins with `=`, `+`, `-` or `@` is prefixed with `'` so that spreadsheets do not evaluate it (SR-6.17-1). JSON Lines has one event object per line.

The export is committed to the journal before any data is sent (`outcome` `exported`, `reason_code` `AUDIT_EXPORTED`, `detail.format`, `detail.events`, `detail.query`).

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Unknown `format` or a bad filter |
| 413 | `export_too_large` | More than 100,000 events match |
| 503 | `audit_unavailable` | The export could not be recorded |
| 503 | `journal_unreadable` | The journal files could not be read |

### POST /api/v1/audit/verify

Runs the journal verifier (FR-7.5: segment body hashes and signatures, the hash chain, the open segment and the anchor) and records the result (`outcome` `verified` or `failed`, `reason_code` `JOURNAL_VERIFIED` or `JOURNAL_VERIFY_FAILED`). One verification runs at a time. Body `{}`.

Response 200 (also when verification fails):

```json
{"status": "verified", "segments": 3, "events": 2140, "open_segment": "segment-000003.jsonl", "truncated_tail": false,
 "recovered": [], "anchor_segment": 2, "findings": [], "checked_at": "2026-10-17T00:30:00Z", "duration_ms": 41, "checked_by": "admin:admin"}
```

On failure `status` is `failed` and `error` names the first failure, for example `segment-000001.jsonl: body hash mismatch`.

| Status | Code | When |
|---|---|---|
| 503 | `journal_unreadable` | No journal or evidence public key is configured |

### GET /api/v1/audit/verify

The result of the last `POST /api/v1/audit/verify` since `smcpd` started, or `{"status": "not_run", ...}`.

### GET /api/v1/audit/stream

A `text/event-stream` with one `audit` event per evidence event the journal accepts, starting with the comment `: stream open` and sending `: keep-alive` every 15 seconds (FR-8.23). The console uses it as a change signal to refresh the open view. A reader that falls 64 events behind loses events; the journal remains the record.

```
event: audit
data: {"event_id":"01a1...","time":"2026-10-17T00:31:12.004Z","class":"admin","origin":"E-12","outcome":"stopped","reason_code":"EMERGENCY_STOP"}
```

Fields: `event_id`, `time`, `class`, `phase`, `origin`, `outcome`, `reason_code`, `session_id`, `correlation_id`; empty fields are omitted. Event details are not streamed.

## Console page and unknown routes

`GET /` and every other path that is not under `/api/` or `/admin/` returns the console page (no authentication; the page signs in through the API). Files under `/assets/` are content-hashed and cached as immutable. The page and its assets carry:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY
```

A method other than GET or HEAD on a page path gets 405 `method_not_allowed`. A request to an `/api/` or `/admin/` path that no element registered gets 404 `route_not_found` with the message `this Gateway build does not serve <METHOD> <path>`; the console shows such a route as "Not available in this build".

## Roles

The control API implements the seven application roles of SRS Appendix C (FR-8.2). The Administrator (operator token or `POST /admin/v1/login`) may use every route. The other roles sign in as follows and reach only the routes the matrix admits; any other route answers 403 `role_refused`.

| Role | Accounts | Sign-in |
|---|---|---|
| Operator | `[[console.account]]` with `role = "operator"` | `POST /api/v1/console/login` |
| Policy Author | `[[console.account]]` with `role = "policy_author"` | `POST /api/v1/console/login` |
| Auditor | `[[console.account]]` with `role = "auditor"` | `POST /api/v1/console/login` |
| Researcher | `[[console.account]]` with `role = "researcher"` | `POST /api/v1/console/login` |
| Session Approver | `[[approver]]` | `POST /api/v1/console/login` with `"role": "session_approver"`; harness sign-ins stay on the OAuth page |
| Approver | `[[approvals.account]]` | `POST /api/v1/approvals/login` ([approvals.md](approvals.md)) |

```toml
[[console.account]]
username = "olga"
password_hash = "$argon2id$..."   # smcpctl hash-password
role = "operator"
```

A person who holds several roles has one account per role. The rules for routes the matrix does not name are in the note under SRS Appendix C; `internal/acceptance.TestRoleMatrixEveryOperation` performs every operation as every role against a running `smcpd` (FR-8.2). The matrix, by Appendix C row (the exact roles per route are `x-smcp-roles` in `GET /api/v1/openapi.json`, and the table is `internal/adminapi/rolematrix.go`):

| Appendix C row | Routes | Roles besides the Administrator |
|---|---|---|
| Emergency stop / resume | `POST /admin/v1/stop`; `POST /admin/v1/resume` | Operator may stop; resume is Administrator-only |
| View health and status | `GET /admin/v1/health`, `GET /api/v1/health/status`, `GET /api/v1/console/session`, `GET /api/v1/openapi.json` | every role |
| Edit, simulate, publish, roll back policy | `POST /api/v1/policy/*`, `POST /admin/v1/policy/reload`, `POST /api/v1/filters/scan` | Policy Author; policy reads also Operator and Auditor |
| Approve research campaign | `POST /api/v1/research/campaigns/{id}/{action}` | Policy Author; a Researcher may `submit` and `stop` only |
| Decide tool-call approvals | `/api/v1/approvals*` | Approver |
| Approve dynamic client registrations | `GET /api/v1/clients*`, `POST /api/v1/clients/{id}/approve`, `deny` | Session Approver; revoke is Administrator-only |
| Enable / suspend / retire servers | `POST /api/v1/packages/{id}/{rev}/enable`, `disable`, `retire`; `POST /api/v1/runtime/instances/{id}/kill`; `POST /api/v1/packages/scan` | Operator may suspend (`disable`), kill an instance and scan |
| Enroll trust anchors | `POST /api/v1/packages/trust`, `DELETE /api/v1/packages/trust/{name}` | none |
| Enable or disable the Remote Access Profile | `POST /api/v1/remote/enable`, `disable` | none |
| Principals, credentials, sessions | `POST /api/v1/sessions/{id}/terminate`, `suspend`; `resume`; principal and credential routes | Operator may terminate and suspend sessions; resume and principal and credential management are Administrator-only; session reads also Auditor |
| Secret create / rotate / revoke | `POST /api/v1/secrets*`, `DELETE /api/v1/secrets/{name}` | none; metadata reads Operator and Auditor |
| Audit query and redacted export | `GET /api/v1/audit/*`, `POST /api/v1/audit/verify`, graph reads, server and catalog reads | Operator, Policy Author, Auditor |
| Observation analytics (S0/S1) | `GET /api/v1/observations/status`, `parameters`, `aggregate`, `metrics`, `cost`, `GET /api/v1/baselines*`, `GET /api/v1/anomalies` | Operator, Policy Author, Auditor, Researcher |
| Observation S2 fields | `GET /api/v1/observations` (raw records) | Operator, Policy Author, Auditor (not the Researcher, whose S2 view would need pseudonymization) |
| Baseline promotion / rollback | `POST /api/v1/baselines/snapshots`, `/{id}/promote`, `/flags` | Policy Author |
| Memory budgets, backups, key rotation | `GET`/`POST /api/v1/backup`, `GET /api/v1/keys`, `POST /api/v1/keys/rotate`, `POST /api/v1/observations/memory-budget`, `POST /api/v1/graph/rebuild` | Operator |
| Dataset export | `POST /api/v1/research/exports`, export reads and downloads | Researcher, for a request naming `campaign_id` (the export route refuses a campaign that is not active, completed or exported) |
| Egress and runtime reads | `GET /api/v1/egress*`, `GET /api/v1/runtime*` | Operator, Auditor |
| Purge, configuration reload, Session Approver accounts, integrity acknowledgment | `POST /api/v1/observations/purge`, `POST /api/v1/config/reload`, `/api/v1/approvers*`, `POST /api/v1/health/ack` | none |

### POST /api/v1/console/login

Signs in an account of `[[console.account]]` or, with `"role": "session_approver"`, a Session Approver of `[[approver]]`. Rate limits, lockout and the bounded Argon2id verification are as for the administrator sign-in.

Request: `{"username": "olga", "password": "...", "role": "operator"}`; `role` is optional for console accounts (it must match when given) and required for Session Approvers.

Response 200: `{"token": "...", "expires_in": 1800, "role": "operator", "actor": "operator:olga"}`. Errors: 400 `bad_request`, 401 `signin_failed`, 429 `rate_limited`, 503 `busy` or `audit_unavailable`. Evidence: `admin`/`signed_in`/`CONSOLE_SIGNIN` with the actor and role, or `auth_failure`/`CONSOLE_SIGNIN_FAILED`.

### POST /api/v1/console/logout

Ends the caller's console token, or the caller's browser session. Response 204.

### GET /api/v1/console/session

The caller's actor and role and every registered route with the roles that may use it; the console builds its navigation and actions from it.

```json
{"actor": "operator:olga", "role": "operator", "roles": ["administrator", "operator", "policy_author", "approver", "session_approver", "auditor", "researcher"],
 "routes": [{"pattern": "POST /admin/v1/stop", "method": "POST", "path": "/admin/v1/stop", "roles": ["administrator", "operator"]},
            {"pattern": "POST /admin/v1/login", "method": "POST", "path": "/admin/v1/login", "public": true}]}
```

`refined` is true on a route where a listed role may use only part of it (campaign actions, dataset export).

## OpenAPI document

`GET /api/v1/openapi.json` (every role) is the OpenAPI 3.1 description of the control API (FR-8.1): one operation per registered route with its path and query parameters, a summary, the reference page under `docs/api/`, `x-smcp-roles` (or `x-smcp-public`) taken from the running Gateway's route table, and the common error schema. The operations are maintained in `internal/openapi/routes.go`; a test fails when a registered route, a route of the role matrix or a control API path used by the console is not described.
