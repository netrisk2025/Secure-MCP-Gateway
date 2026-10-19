# Control API: policy routes

The Policy Administration Service (E-05) serves these routes on the control API (admin listener, CP-03). They use the control API's authentication (the local operator token or an administrator session token as `Authorization: Bearer`), its Host, Origin and `Sec-Fetch-Site` checks, and its rule that every POST body is `application/json` of at most 64 KiB. A request without valid authentication gets HTTP 401 and is recorded as an `auth_failure` event. Harness session tokens are not accepted.

The policy document format is described in [policy-reference.md](../policy-reference.md). Implementation: `internal/policyadmin`.

## Errors

Every error is `{"error": {"code": "<code>", "message": "<text>"}}`.

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `bad_request` | The body is not the documented shape (unknown fields are refused) |
| 401 | `unauthenticated` | No valid control API token |
| 404 | `not_found` | No published revision has this ID |
| 404 | `no_template` | The revision has no such template (permissions route) |
| 409 | `revision_exists` | The revision ID is already published with different content; published revisions cannot be changed |
| 409 | `revision_published` | The revision ID is already published and is not active; give the document a new ID, or roll back to it |
| 409 | `parent_mismatch` | `parent` was given and is not the active revision |
| 422 | `policy_invalid` | The document fails the schema or a publication check; the message names the failure |
| 422 | `policy_signature` | A stored revision does not verify |
| 422 | `no_fixtures` | A simulation had nothing to replay |
| 503 | `audit_unavailable` | The evidence journal did not accept the event; nothing was activated |
| 503 | `activation_failed` | The Gateway refused the activation; the previous active revision stays in force |

## Record

Published revisions are described by a revision record (FR-3.4):

```json
{
  "revision": "r2",
  "sequence": 2,
  "parent": "r1",
  "digest": "9f2c...e1",
  "schema_version": "1",
  "evaluator_version": "2",
  "actor": "operator-token",
  "published_at": "2026-10-16T21:04:05.123456Z",
  "simulation_ref": "019a...",
  "key_id": "3be0c1d2a4f59e10",
  "origin": "publish",
  "rollback_of": ""
}
```

`digest` is the SHA-256 of the canonical document. `key_id` names the policy-signing key. `origin` is `import` (the policy file at first start), `reload` (the policy file through `POST /admin/v1/policy/reload`), `publish` or `rollback`. `parent`, `simulation_ref` and `rollback_of` are omitted when empty.

## GET /api/v1/policy

Store status.

```json
{
  "active": { "revision": "r2", "sequence": 2, "...": "record fields" },
  "loaded_revision": "r2",
  "fault": "",
  "key_id": "3be0c1d2a4f59e10",
  "revisions": 2,
  "schema_version": "1",
  "evaluator_version": "2"
}
```

`fault` is `policy_signature` when the active revision did not verify at start; `active` is then replaced by `active_error`. `damaged` lists revision files that failed verification when the store was opened.

## GET /api/v1/policy/revisions

All published revisions, newest first.

```json
{ "active": "r2", "revisions": [ { "revision": "r2", "...": "record fields" }, { "revision": "r1", "...": "record fields" } ] }
```

## GET /api/v1/policy/revisions/{id}

One revision with its canonical document (export, FR-3.8). `{id}` may be `active`.

```json
{ "record": { "revision": "r1", "...": "record fields" }, "active": false, "document": { "revision": "r1", "framework_profiles": {}, "templates": {} } }
```

## GET /api/v1/policy/revisions/{id}/permissions?template=T&principal=P

Effective permission report (FR-3.6): every tool the template permits after deny rules, with its obligations. `principal` is echoed back and not otherwise used. When `[secrets]` is configured, `secret_bindings` lists the Secret Use Policy bindings of the servers the template grants (FR-6.5): slot, secret, mode, tools, destination, purpose, rate, time window and approval.

```json
{
  "revision": "r2", "template": "ro", "principal": "",
  "permissions": [
    { "server": "fs", "tool": "read_file", "rule": "ro-fs", "approval": false, "side_effect": "read", "filters": ["path-canonicalize"] }
  ],
  "secret_bindings": [
    { "id": "fs-token", "secret": "fs-token", "server": "fs", "slot": "token", "mode": "S2", "tools": ["read_file"], "purpose": "read the share", "slot_modes": ["S2"] }
  ]
}
```

## POST /api/v1/policy/validate

Request: `{"document": { ...policy document... }}`

Response 200:

```json
{ "valid": true, "summary": { "revision": "r2", "digest": "9f2c...e1", "framework_profiles": 1, "templates": 2, "rules": 5, "grants": 7 } }
```

An invalid document is HTTP 422 `policy_invalid`. Validation stores nothing and writes no evidence.

## POST /api/v1/policy/diff

Request, one of:

- `{"document": {...}, "from": "r1"}` compares a document with revision `from` (default the active revision);
- `{"to": "r2", "from": "r1"}` compares two published revisions (`from` defaults to the active revision).

Response 200:

```json
{
  "from": "r1", "to": "r2", "same": false, "widening": true,
  "changes": [
    { "kind": "grant_added", "template": "ro", "server": "fs", "tool": "write_file", "rule": "rw", "after": "rule=rw approval" },
    { "kind": "grant_changed", "template": "ro", "server": "fs", "tool": "read_file", "rule": "ro-fs", "before": "rule=ro-fs approval", "after": "rule=ro-fs" }
  ]
}
```

`kind` is one of `profile_added`, `profile_removed`, `profile_changed`, `template_added`, `template_removed`, `template_changed`, `grant_added`, `grant_removed`, `grant_changed`, `deny_added`, `deny_removed`. `widening` is true when any change adds authority: a new grant or profile template, a removed deny rule, a removed approval obligation, a raised or removed rate or quota bound, a removed filter, a less restrictive side-effect or source-trust class, or `taint_action` relaxed from `deny`.

## POST /api/v1/policy/simulate

Request:

```json
{ "document": { "...": "candidate" }, "fixtures": [ { "template": "ro", "server": "fs", "tool": "write_file" } ], "limit": 1000, "all": false }
```

Without `fixtures` the most recent `limit` tool calls of the evidence journal are replayed (default 1000, at most 10000). `all` includes fixtures whose decision did not change. A fixture has the fields of a scenario line (see [policy-reference.md](../policy-reference.md#simulation)).

Response 200:

```json
{
  "simulation_id": "019a...",
  "source": "journal",
  "active_revision": "r1",
  "candidate_revision": "r2",
  "fixtures": 3,
  "changed": 1,
  "counts": { "unchanged": 2, "permit_to_deny": 1 },
  "results": [
    {
      "index": 1,
      "fixture": { "time": "2026-10-16T20:00:01Z", "principal": "cc", "session": "019a...", "template": "ro", "server": "fs", "tool": "list" },
      "active": { "outcome": "permit", "reason_code": "PERMIT", "decisive_rules": ["ro-fs"], "calls_per_minute": 60 },
      "candidate": { "outcome": "deny", "reason_code": "NO_PERMIT" },
      "change": "permit_to_deny"
    }
  ]
}
```

`change` is `unchanged`, `permit_to_deny`, `deny_to_permit`, `reason_changed` (both deny, different reason) or `obligations_changed` (both permit, different approval, approval reason, rate bound or filters). Each simulation is recorded as an `admin` event with reason `POLICY_SIMULATED`; pass `simulation_id` as `simulation_ref` when publishing.

## POST /api/v1/policy/revisions

Publish and activate a document.

Request: `{"document": {...}, "parent": "r1", "simulation_ref": "019a..."}`; `parent` and `simulation_ref` are optional.

Response 201 (published) or 200 (the identical document is already the active revision, nothing changed):

```json
{ "record": { "revision": "r2", "...": "record fields" }, "created": true, "changed": true }
```

Order of effects: validation; the signed revision file is written; the `POLICY_PUBLISHED` event is committed to the journal; the signed control record is replaced atomically; the decision snapshot is swapped under the Enforcement Coordinator's barrier and the Gateway records `POLICY_ACTIVATED`; open `subscriptions/listen` streams of sessions whose catalog is cached receive `notifications/tools/list_changed`. If the swap fails, the previous control record is restored. Every refusal is recorded as an `admin` event with outcome `rejected` (`POLICY_INVALID`, `POLICY_CONFLICT` or `POLICY_ACTIVATION_FAILED`).

## POST /api/v1/policy/rollback

Publish the content of an earlier revision as a new revision (FR-3.9).

Request: `{"to": "r1", "revision": "r1-restore"}`; `revision` defaults to `<to>-rb<n>` with the smallest unused `n`.

Response 201: as for publish, with `record.origin` `rollback` and `record.rollback_of` set. The evidence event reason is `POLICY_ROLLED_BACK`.

## POST /admin/v1/policy/reload (existing route)

Reads the configured `[policy] file` and publishes it through the store as above (origin `reload`). It answers `{"revision", "digest", "changed"}`; it answers 409 `revision_reused` when the file's revision ID is already published with other content, or is published and not active.

## GET /api/v1/decisions/{id}/explanation

Explains one decision (SR-1.19-1) from the decision record the Enforcement Coordinator commits with the `decision` event: the permit (`authorized`, at launch authorization) or the deny (`denied`). Roles: Operator, Policy Author, Auditor.

```json
{
  "decision_id": "019a...", "correlation_id": "019a...", "policy_revision": "r2", "phase": "authorized", "outcome": "permit",
  "reason_code": "PERMIT", "template": "dev", "route": "fs",
  "considered_rules": ["r2/dev/read-fs", "r2/dev/no-shell"],
  "applicable_rules": ["r2/dev/read-fs"],
  "decisive_rules": ["r2/dev/read-fs"],
  "obligations": {"approval": true, "approval_reason": "", "calls_per_minute": 60, "burst": 0, "calls_per_session": 0, "filters": ["path-canonicalize"]},
  "side_effect": "write", "source_trust": "trusted", "tainted": false,
  "anomaly": []
}
```

Rule-revision IDs are `<policy revision>/<template>/<rule id>`: rules are versioned with the revision that contains them. `baseline_snapshot_id` names the baseline snapshot in force for the decision (the one the decision point recorded, else the one behind an anomaly obligation); it is absent when no snapshot was in force. The console shows the explanation at `/audit/decisions/<id>` (G-14, FR-8.22). `anomaly` lists the anomaly events recorded for the same call. When a request filter transformed the arguments, the call was decided again (SR-5.12-1): the second decision carries `superseded_decision_id` and `redecision_reason: "arguments_transformed"`, and asking for the first decision's ID returns `{"decision_id", "superseded_by"}`. 404 `not_found` when the journal has no decision with the ID; 503 `journal_unreadable` when the journal cannot be read.
