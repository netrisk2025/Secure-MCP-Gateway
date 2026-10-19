# Control API: packages

Routes of the Library Trust Verifier (E-13) and Local Server Registry (E-14) on the control API (admin listener, CP-03). They are registered by `internal/library` through `adminapi.Server.Handle`, so the control API's rules apply: a bearer token (the operator token in `<state>/keys/admin.token` or an administrator session token from `POST /admin/v1/login`); reads are also open to Operators and Auditors and suspension (`disable`) and scans to Operators ([console.md](console.md#roles)), no foreign `Origin` or cross-site `Sec-Fetch-Site`, and `Content-Type: application/json` on every POST (an empty object `{}` when there is no body). A request without a valid token gets `401` and an `auth_failure` evidence event. A successful authentication is the Administrator action that enabling requires (SR-3.9-1).

Errors have the control API's form: `{"error": {"code": "<reason code>", "message": "<text>"}}`. Refusals are `409` with a reason code from the [packaging guide](../packaging-guide.md#reason-codes); an unknown revision is `404` `PACKAGE_UNKNOWN`; a malformed body is `400` `bad_request`.

State changes are recorded as evidence events of class `package` (origin `E-14`, or `E-13` for imports and revocations) with the actor in `detail.actor` and the revision in `server_revision`.

## GET /api/v1/packages

Lists imported revisions, the packaged `[[server]]` entries of this Gateway, and the trust anchors.

```json
{
  "library": "/srv/smcp/state/library",
  "revisions": [
    {
      "server_id": "mcp-filesystem",
      "revision": "2026.8.31",
      "state": "enabled",
      "state_reason": "enabled",
      "state_changed_at": "2026-10-17T00:16:29Z",
      "state_actor": "admin:alice",
      "alias": "fs",
      "risk_class": "moderate",
      "artifact_type": "npm",
      "index_sha256": "…",
      "manifest_sha256": "…",
      "artifact_sha256": "a8d56c56811437ba3fac961b8083387eec0d843c6f6d7f8ca3121b0a04983fca",
      "tree_sha256": "…",
      "tools_sha256": "…",
      "enablement_sha256": "…",
      "signer_key_id": "7B3357B76507695D",
      "anchor": "operator",
      "imported_at": "2026-10-17T00:16:20Z",
      "tools": ["create_directory", "directory_tree", "…"]
    }
  ],
  "servers": [
    {"alias": "fs", "package": "mcp-filesystem", "revision": "2026.8.31", "status": "running"},
    {"alias": "old", "package": "mcp-old", "status": "not_started", "reason_code": "PACKAGE_NOT_ENABLED", "reason": "…"}
  ],
  "trust_anchors": [
    {"name": "operator", "key_id": "7B3357B76507695D", "classes": ["low", "moderate"], "expires": "2027-10-17T00:00:00Z"}
  ]
}
```

`servers[].status` is `starting`, `running`, `suspended` or `not_started`. `expires`, `recuration_due` and `state_actor` appear when set.

## GET /api/v1/packages/{id}/{revision}

One revision with its signed manifest and provenance statement as stored at import.

```json
{
  "revision": { "server_id": "mcp-filesystem", "revision": "2026.8.31", "state": "enabled", "…": "…" },
  "manifest": { "manifest_version": 1, "server": { "id": "mcp-filesystem", "…": "…" }, "tools": [ … ] },
  "provenance": { "provenance_version": 1, "source": { "kind": "registry-tarball", "uri": "…", "sha256": "…" }, "…": "…" }
}
```

The manifest and provenance are untrusted content supplied by the package publisher; a client must render them as escaped text.

## POST /api/v1/packages/{id}/{revision}/enable

Request: `{}` or `{"alias": "fs2"}` (1 to 16 characters of `a-z 0-9`; default the revision's alias).

Response `200`:

```json
{"revision": {"server_id": "mcp-filesystem", "revision": "2026.8.31", "state": "enabled", "alias": "fs2", "enablement_sha256": "…", "…": "…"}, "restart_required": true}
```

`restart_required` is true unless that revision is already running: servers are launched at Gateway start. Refusals: `STATE_TRANSITION_REFUSED` (revoked or retired), `PROFILE_UNCONFINED`, `ALIAS_CONFLICT`, `STATEFUL_UNCONTRACTED`, `MANIFEST_EXPIRED`, `PUBLIC_NAME_COLLISION`.

## POST /api/v1/packages/{id}/{revision}/disable

Request: `{}` or `{"reason": "maintenance"}`. Changes the revision to `verified-disabled`. A running instance of it is torn down at once and its tools leave the catalog.

Response `200`: `{"revision": { … "state": "verified-disabled" … }}`.

## POST /api/v1/packages/{id}/{revision}/classification

Operator. Tightens one tool's classification (SR-3.11-1). Request: `{"tool": "write_file", "side_effect": "execute", "source_trust": "untrusted", "risk_class": "high"}`; every field but `tool` is optional. Each given value must be at least as restrictive as the signed manifest's (side effect read < write < external < execute; trusted < untrusted; risk low < moderate < high), otherwise the request is refused with 409 `CLASSIFICATION_LOOSENING_REFUSED` and an evidence event. The signed manifest is never changed; the override is stored with the revision, recorded as `CLASSIFICATION_OVERRIDDEN`, and applies the next time the revision's instance starts.

Response `200`: `{"tool", "override", "overridden_tools", "restart_required": true}`.

## POST /api/v1/packages/{id}/{revision}/retire

Request: `{}` or `{"reason": "replaced by 2026.9.1"}`. Changes the revision to `retired` (final), tears down a running instance, and deletes the cached artifact when no non-retired revision references it (FR-5.39).

Response `200`: `{"revision": { … "state": "retired" … }}`.

## POST /api/v1/packages/scan

Request: `{}`. Scans the library now (FR-5.3): imports new packages, applies revocation entries and suspends expired revisions; running instances of revisions that left the enabled state are torn down.

```json
{"imported": ["mcp-memory@2026.8.31"], "rejected": ["/srv/smcp/state/library/x: SIGNER_UNKNOWN: …"], "revoked": [], "suspended": [], "errors": []}
```

A package directory whose index was rejected is not retried until its index changes or the Gateway restarts.

## GET /api/v1/packages/receipts

The 100 most recent import receipts (FR-5.4), newest first.

```json
{
  "receipts": [
    {
      "receipt_version": 1,
      "time": "2026-10-17T00:16:20.123Z",
      "actor": "smcpctl",
      "package_dir": "/srv/smcp/state/library/mcp-filesystem/2026.8.31",
      "server_id": "mcp-filesystem",
      "revision": "2026.8.31",
      "index_sha256": "…",
      "artifact_sha256": "…",
      "manifest_sha256": "…",
      "signer_key_id": "7B3357B76507695D",
      "anchor": "operator",
      "result": "accepted",
      "checks": ["components", "signature", "anchor_expiry", "digests", "manifest_schema", "provenance_binding", "anchor_scope", "revocation", "rollback", "artifact_stored"]
    }
  ]
}
```

`result` is `accepted`, `rejected` (with `reason_code` and `error`) or `unchanged`.

## POST /api/v1/packages/trust

Enrolls a trust anchor (FR-14.8), the control API form of `smcpctl trust add`. Administrator-only. The anchors file is read at every import, so the anchor admits packages from the next library scan.

Request:

```json
{"name": "team", "public_key": "untrusted comment: minisign public key …\nRWQ…", "classes": ["low", "moderate"], "expires": "2027-10-16"}
```

`public_key` is the content of the minisign `.pub` file (`smcpctl package keygen`). `classes` defaults to `low` and `moderate`; `expires` is a date or an RFC 3339 time, default one year.

Enrollment takes two requests (FR-7.10). The first carries `"preview": true` and changes nothing: response `200` `{"key_id": "7B3357B76507695D", "sha256": "<64 hex digits of the SHA-256 of the key line>", "name", "classes", "expires"}`. The administrator compares the key ID with the one the publisher gave out of band; the second request repeats the body with `"confirm_key_id": "7B3357B76507695D"` instead of `preview`. A request without `confirm_key_id` answers 400 `confirmation_required`, one with another key ID 400 `fingerprint_mismatch`; neither enrolls anything. G-10 shows the fingerprint between the two requests and enrolls only after the confirmation box is checked.

Response `201`: `{"name": "team", "key_id": "7B3357B76507695D", "classes": ["low", "moderate"], "expires": "2027-10-17T00:00:00Z"}`. Errors: 400 `bad_request` (body or expiry), 400 `invalid_anchor` (key, name, class, expiry in the past, key or name already enrolled), 400 `confirmation_required`, 400 `fingerprint_mismatch`, 503 `audit_unavailable` (nothing was enrolled). Evidence: class `package`, origin `E-13`, outcome `anchor_enrolled`, reason `TRUST_ANCHOR_ENROLLED`, with the actor, anchor name, key ID, SHA-256 fingerprint, `fingerprint_confirmed`, classes and expiry.

## DELETE /api/v1/packages/trust/{name}

Removes a trust anchor by name or key ID (`smcpctl trust remove`). Administrator-only. Revisions already imported stay in the library. Response `200`: `{"removed": "team"}`. Errors: 404 `not_found`, 503 `audit_unavailable`. Evidence: outcome `anchor_removed`, reason `TRUST_ANCHOR_REMOVED`.
