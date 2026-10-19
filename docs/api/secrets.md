# Control API: secrets

Routes of the Secret Vault (E-19) and Secret Broker (E-20) on the admin listener. They use the control API's authentication (operator token or administrator session token as a bearer token), its host, origin and cross-site checks, and its rule that POST bodies are `application/json` of at most 64 KiB. Every change is recorded in the evidence journal with the authenticated actor.

Read operations return metadata only. No response ever contains a secret value or its ciphertext (FR-6.2). Values are accepted on create and rotate only.

Errors have the control API's shape:

```json
{"error": {"code": "secret_not_found", "message": "secret not found"}}
```

| HTTP | `code` | When |
|---|---|---|
| 400 | `bad_request` | Body is not the documented shape, or `expires` is not RFC 3339. |
| 400 | `invalid_secret` | Name, type, value length (8 to 32768 bytes) or overlap (0s to 24h) is invalid. |
| 401 | `unauthenticated` | No valid bearer token. |
| 404 | `secret_not_found` | No secret of that name. |
| 409 | `secret_exists` | Create with a name in use. |
| 422 | `use_policy_invalid` | Reload found an invalid Secret Use Policy; the active policy is unchanged. |
| 503 | `audit_unavailable` | The evidence journal did not accept the event. |
| 503 | `vault_error` | The store could not be written. |

## Metadata object

```json
{
  "ref": "sec_019a0c1e-7b7e-7c4f-9a51-2f0d6b1c9e11",
  "name": "github-pat",
  "type": "token",
  "owner": "admin:alice",
  "description": "CI token",
  "created": "2026-10-16T17:00:00Z",
  "rotated": "2026-10-16T18:00:00Z",
  "expires": "2027-01-01T00:00:00Z",
  "current_version": 2,
  "versions": [
    {"version": 1, "created": "2026-10-16T17:00:00Z", "state": "overlap", "deliverable_until": "2026-10-17T18:00:00Z"},
    {"version": 2, "created": "2026-10-16T18:00:00Z", "state": "current"}
  ]
}
```

`state` is `current`, `overlap` (deliverable until `deliverable_until`) or `retired` (with `retired_at`; the ciphertext is deleted). `rotated` and `expires` are omitted when unset.

## GET /api/v1/secrets

Vault status, the active Secret Use Policy and every secret's metadata.

```json
{
  "vault": {
    "vault_id": "019a0c1d-...",
    "key_source": "keychain",
    "runtime_dir": "/dev/shm/smcp-secrets-1000",
    "runtime_tmpfs": true,
    "rotation_overlap": "24h0m0s",
    "fingerprints": 1240,
    "suspended": {"sec_019a...": "leak detected in a result of gh_get_issue"}
  },
  "use_policy": {
    "revision": "2026-10-16a",
    "digest": "<sha-256 of the file>",
    "slots": [{"server": "db", "name": "password", "modes": ["S3"], "file_env": "PGPASSFILE"}],
    "bindings": [{"id": "db-password", "secret": "db-password", "server": "db", "slot": "password", "mode": "S3",
                  "tools": ["*"], "purpose": "database session", "slot_modes": ["S3"]}]
  },
  "secrets": [ <metadata object>, ... ]
}
```

## POST /api/v1/secrets

Create a secret as version 1.

Request:

```json
{"name": "github-pat", "type": "token", "owner": "", "description": "CI token", "expires": "2027-01-01T00:00:00Z", "value": "<value>"}
```

`name` and `value` are required; `type` defaults to `generic`, `owner` to the authenticated actor. Response `201` with the metadata object.

## GET /api/v1/secrets/{name}

```json
{"secret": <metadata object>, "suspended": false, "suspended_reason": ""}
```

## DELETE /api/v1/secrets/{name}

Retire every version and delete the record. Response `200`:

```json
{"removed": "github-pat"}
```

## POST /api/v1/secrets/{name}/rotate

Request:

```json
{"value": "<new value>", "overlap": "1h"}
```

`overlap` is optional (default `[secrets] rotation_overlap`); `"0s"` retires the previous version at once. Response `200` with the metadata object. If the new version was stored but the journal refused the event, the response is `503 audit_unavailable`.

## GET /api/v1/secrets/{name}/impact

Every Secret Use Policy, server revision and slot that references the secret (FR-6.12).

```json
{
  "secret": "signing-key",
  "ref": "sec_019a...",
  "references": [
    {"use_policy": "sign-key", "server": "sign", "server_revision": "live-3f2a9c0b1d4e5f60", "slot": "key", "mode": "S2",
     "tools": ["sign_release"], "source": "use_policy", "active": true},
    {"server": "old", "server_revision": "live-...", "slot": "SIGNING_KEY", "source": "secret_env", "active": false}
  ]
}
```

`source` is `use_policy` or `secret_env` (a `secret_env` entry with no policy). `active` is true when the secret is delivered to, or prepared for, a running instance.

## POST /api/v1/secrets/{name}/resume

Lift the suspension a detected leak placed on S2 delivery of the secret. Request `{}`. Response:

```json
{"secret": "signing-key", "resumed": true}
```

`resumed` is false when the secret was not suspended.

## POST /api/v1/secrets/reload

Validate and activate the Secret Use Policy file. Request `{}`. Response:

```json
{"revision": "2026-10-16b", "digest": "<sha-256>", "bindings": 3}
```

## Secret Use Policy authoring (G-02)

The Policy Studio's Secret Use Policy editor (FR-8.4) uses four routes, all Administrator-only (secret operations, Appendix C). A published document is validated like a reloaded file, recorded in the journal before it takes effect (`admin`/`activated`/`SECRET_USE_POLICY_ACTIVATED` with `detail.action` `published` or `rolled_back`, the actor, digest and reason), written atomically (mode 0600) to the configured `use_policy_file` so that it survives a restart, archived as `<state>/secrets/use-policy/<revision>.json` and activated.

| Route | Request | Response |
|---|---|---|
| `GET /api/v1/secret-use-policy` | | `{"file", "active": {"revision", "digest", "bindings"}, "document": {...}, "revisions": [{"revision", "digest", "published_at"}]}`; `document` is the file's content when it exists |
| `POST /api/v1/secret-use-policy/validate` | `{"document": {...}}` | 200 `{"revision", "digest", "bindings"}`; 422 `use_policy_invalid` |
| `POST /api/v1/secret-use-policy` | `{"document": {...}, "reason": "..."}` | 200 `{"revision", "digest", "bindings", "action": "published"}`; 422 `use_policy_invalid`; 409 `revision_exists` (the active revision ID, or an archived one with other content), `use_policy_file_unset`; 503 `audit_unavailable` |
| `POST /api/v1/secret-use-policy/rollback` | `{"revision": "...", "reason": "..."}` | as publish, with `"action": "rolled_back"`; 404 `revision_not_found` |
