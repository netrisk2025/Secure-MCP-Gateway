# Control API: operations routes

Routes registered by `internal/ops` on the admin listener (CP-03). They use the control API's authentication (operator token or administrator session token as `Authorization: Bearer`), its host, origin and `Sec-Fetch-Site` checks, and its rule that every POST body is `application/json` of at most 64 KiB. Errors have the control API's shape:

```json
{ "error": { "code": "BACKUP_UNENCRYPTED_REFUSED", "message": "..." } }
```

Every state-changing route records an evidence event with the authenticated actor.

The metrics endpoint `/metrics` is not on the admin listener; it is a separate plain-HTTP loopback listener (`[metrics] address`, default `127.0.0.1:9464`) without authentication. See [../operations/logging-metrics-reload.md](../operations/logging-metrics-reload.md).

## GET /api/v1/health/status

Health monitor report (FR-7.12) combined with the enforcement edge's report.

```json
{
  "state": "degraded",
  "causes": [
    { "name": "unconfined", "critical": false, "detail": "standalone profile: server instances run unconfined", "active": true },
    { "name": "audit_capacity", "critical": true, "detail": "100 MiB free, reserve is 256 MiB", "active": false,
      "since": "2026-10-16T22:01:02Z", "cleared_at": "2026-10-16T22:01:09Z" }
  ],
  "checked_at": "2026-10-16T22:01:10Z",
  "info": { "profile": "standalone", "release_label": "not enforced", "version": "0.0.0-dev",
            "policy_revision": "r1", "emergency_stop": false, "sessions": 1,
            "elements": [
              { "id": "E-07", "name": "Approval Service", "state": "active", "detail": "0 pending approvals; notify off" },
              { "id": "E-18", "name": "Egress Broker", "state": "disabled", "detail": "set [egress] enabled = true" },
              { "id": "E-25/E-26/E-28", "name": "Graph mirror", "state": "degraded", "detail": "unavailable dial tcp 127.0.0.1:7687: connect: connection refused" }
            ] },
  "gateway": { "state": "degraded", "causes": ["unconfined", "unverified_manifests"], "profile": "standalone", "...": "..." }
}
```

`state` is the worse of the monitor's state and `gateway.state` (an emergency stop is only in `gateway`). Latched causes carry `since`, `cleared_at` (when clear), `ack_required` and `acked_by`.

`info.elements` lists every architecture element `smcpd` wires, in element order, with `state` `active` (running), `disabled` (configured off; `detail` says how to enable it) or `degraded` (configured but not working; enforcement continues). The graph mirror and the Observation Store also report the non-critical causes `graph_mirror_unavailable` and `observation_store_unavailable`, which make the Gateway `degraded`, never fail-closed.

## POST /api/v1/health/ack

Acknowledge a latched integrity cause (FR-7.13). Administrator only.

Request: `{ "cause": "evidence_unavailable" }`

Response 200: the status document above. Errors: 400 `bad_request` (no cause), 409 `not_latched` (not latched or not an integrity cause), 503 `audit_unavailable`. Records `admin`/`acknowledged`/`HEALTH_ACK`.

## GET /api/v1/keys

Key inventory; same document as `smcpctl keys status`:

```json
{
  "server_ca": { "subject": "SERIALNUMBER=20261016T220000Z,CN=Secure MCP Gateway server CA", "serial": "5f1c...", "not_before": "...", "not_after": "...", "sha256": "..." },
  "trust_bundle": [ { "...": "..." } ],
  "listener_certificate": { "subject": "...", "issuer": "...", "dns_names": ["localhost"], "ip_addresses": ["127.0.0.1", "::1"], "...": "..." },
  "ca_rotation": { "stage": "overlap", "started_at": "...", "switch_at": "...", "next_ca": { "...": "..." } },
  "ca_due": false,
  "listener_due": false,
  "evidence_public_key": "260686a1...",
  "evidence_trust_root": "c0be5129...",
  "evidence_rotation_pending": false,
  "installation_id": "01a1472b-57cb-74ab-abb5-356b8090a5ed",
  "purposes": { "server_ca": "tls/ca.key", "server_tls": "tls/server.key", "evidence_signing": "keys/evidence.key", "operator_token": "keys/admin.token" }
}
```

`ca_rotation` is omitted when no rotation is in progress.

## POST /api/v1/keys/rotate

Request:

```json
{ "kind": "tls" }
{ "kind": "ca", "overlap": "168h" }
{ "kind": "ca", "finish": true }
{ "kind": "evidence" }
```

`overlap` is a Go duration (default `168h`; `0s` switches at once).

Responses 200:

```json
{ "kind": "tls", "listener_not_after": "2027-01-14T22:00:00Z", "uncovered_names": null }
{ "kind": "ca", "stage": "overlap", "switch_at": "...", "next_ca": { "...": "..." }, "listener_not_after": "...", "trust_bundle": "/.../state/tls/ca.crt" }
{ "kind": "ca", "stage": "finished", "ca_not_after": "...", "listener_not_after": "..." }
{ "kind": "evidence", "public_key": "<hex Ed25519 public key>" }
```

Errors: 400 `bad_request` (unknown kind or bad overlap), 409 `rotation_in_progress`, 500 `rotation_failed`. Records `admin`/`key_rotated` with reason `LISTENER_CERT_ROTATED`, `SERVER_CA_ROTATION_STARTED`, `SERVER_CA_ACTIVATED` or `EVIDENCE_KEY_ROTATED`; the evidence rotation also writes the journal's own `journal`/`key_rotated` event in the transition segment.

## GET /api/v1/backup

```json
{ "dir": "/.../backups",
  "backups": [ { "path": "/.../backups/smcp-backup-20261016T220000.000Z.age", "sha256": "...", "size": 48213,
                 "created_at": "...", "components": ["configuration", "evidence_journal", "key_material", "policy_store", "trust_anchors"], "result": "ok" } ],
  "scheduled": false, "configured": true }
```

`scheduled` is true when `[backup] interval` is set; `configured` is true when a schedule is set or a backup has been taken (the G-01 first-run checklist item "Backup configured", FR-8.31).

## POST /api/v1/backup

Take an online backup (FR-17.6, SR-7.7-1).

Request (exactly one of `passphrase` and `recipients`):

```json
{ "passphrase": "...", "optional": { "observations": "/path/to/copy" } }
{ "recipients": ["age1..."] }
```

Response 200:

```json
{ "path": "/.../backups/smcp-backup-20261016T220000.000Z.age", "sha256": "...", "size": 48213,
  "manifest": { "format": "smcp-backup-v1", "created_at": "...", "installation_id": "...", "version": "...",
                "components": ["..."], "files": [ { "path": "state/journal/segment-000001.jsonl", "size": 1234, "sha256": "...", "mode": 384 } ] } }
```

Errors: 400 `BACKUP_UNENCRYPTED_REFUSED`, 400 `bad_request`, 503 `BACKUP_DRAIN_TIMEOUT`, 500 `BACKUP_FAILED`. Records, in order, the emergency stop (`EMERGENCY_STOP`, reason `backup`), `BACKUP_WRITTEN` (or `BACKUP_FAILED`, `BACKUP_DRAIN_TIMEOUT`), and the resume (`EMERGENCY_RESUME`) unless the Gateway was already stopped. A refused request records `BACKUP_UNENCRYPTED_REFUSED`.

The passphrase travels over the loopback TLS connection and is not stored or logged.

## POST /api/v1/config/reload

Reload the configuration file (FR-17.9). Request body: `{}`.

Response 200:

```json
{ "changed": ["limits.principal_calls_per_minute", "listener.address"],
  "applied": ["limits.principal_calls_per_minute"],
  "restart_required": ["listener.address"],
  "not_applied_until_restart": [] }
```

Errors: 422 `CONFIG_INVALID` (the running configuration is kept). Records `admin`/`reloaded`/`CONFIG_RELOADED` or `admin`/`rejected`/`CONFIG_INVALID`.
