# Control API: observation, baselines, anomalies, research

Routes of SS-10 Observation & Analytics and the Observation Store (E-27, E-29 to E-32) on the control API (admin listener, CP-03). Feature description: [../observation.md](../observation.md).

The listener's rules apply to every route: loopback TLS, `Host` must name the admin listener, a foreign `Origin` or a cross-site `Sec-Fetch-Site` is refused with 403 `origin_refused`, and every POST must have `Content-Type: application/json` (bodies up to 64 KiB). Responses carry `Cache-Control: no-store`. The roles that may use each route are those of the role matrix in [console.md](console.md#roles) (Appendix C), also listed per operation as `x-smcp-roles` in `GET /api/v1/openapi.json`. In short: analytics reads are open to the Operator, Policy Author, Auditor and Researcher (raw records, which carry S2 fields, not to the Researcher); baseline builds, promotion and flags to the Policy Author; campaigns to the Policy Author and Researcher, where a Researcher may only submit and stop and approval is the Policy Author's; dataset exports to the Researcher, for a campaign only. A missing or unknown token gets 401 `unauthenticated` (recorded as an `auth_failure` event); a token of a role the route does not admit gets 403 `role_refused`.

Errors have the form `{"error": {"code": "<code>", "message": "<text>"}}`; the codes are listed in [../observation.md#errors](../observation.md#errors). When observation is disabled every route except `status` and `parameters` answers 503 `observation_disabled`; store-backed routes answer 503 `store_unavailable` when the store could not be opened.

Times in query parameters are RFC 3339 or a Go duration meaning that long before now (`from=24h`). Row values follow the store types: strings, numbers, RFC 3339 timestamps; object and array parameters are JSON text.

## Observations

### GET /api/v1/observations/status

Response 200:

```json
{
  "enabled": true,
  "policy_id": "default",
  "catalog_version": "1.0.0",
  "scoring": "async",
  "require_approval_band": "off",
  "withhold_band": "off",
  "sampling_rate": 0.1,
  "parameters": ["argument_count", "baseline_snapshot_id", "..."],
  "escalation_parameters": [],
  "retention": "2160h0m0s",
  "collector": {"assembled": 1200, "captured": 131, "pending": 0, "queue_depth": 0, "queue_capacity": 4096, "sessions": 3, "drops": {"sampled_down": 1069}},
  "drops": {"sampled_down": 1069},
  "baseline": {"contexts": 4, "characterized": 3, "learned": 1180, "excluded": {"denied": 20}, "flagged_sessions": 0,
               "promoted": "0199f3c2-...", "snapshots": 2, "records_since_build": 180},
  "loaded_snapshot": "0199f3c2-...",
  "thresholds": {"elevated": 2, "abnormal": 3, "critical": 4},
  "contexts": ["principal", "tool"],
  "duckdb_available": true,
  "store": {"backend": "duckdb", "dir": "/.../observation/store", "bytes": 81234, "files": 40,
            "days": {"records": ["2026-10-16"], "metrics": ["2026-10-16"], "spans": ["2026-10-16"], "scores": ["2026-10-16"]},
            "rows_written": {"records": 131, "metrics": 30, "spans": 393, "scores": 140}}
}
```

When the store is unavailable `store` is replaced by `"store_error": "<cause>"`. When observation is disabled the response is `{"enabled": false}`.

### GET /api/v1/observations/parameters

The Parameter Catalog with the current selection.

```json
{"catalog_version": "1.0.0", "parameters": [
  {"id": "P-024", "name": "request_bytes", "description": "...", "unit": "bytes", "data_type": "integer", "sensitivity": "S0",
   "capture_point": "request-received", "baselinable": true, "selected": true, "escalation": false,
   "cost_class": "C0", "derivation": "...", "source_element": "E-01"}
]}
```

### GET /api/v1/observations

Stored observation records, oldest first. Query: `from`, `to`, `principal`, `server` (alias), `tool`, `session` (each repeatable), `limit` (1 to 1000, default 100).

Fields are returned according to the caller's role and each parameter's catalog sensitivity (SR-6-3, Appendix C): S0 and S1 fields to every role of the route, S2 fields only to the Administrator, Policy Author and Auditor (the Operator's rows omit them), and S3 fields to nobody, because payload access needs a separate grant that release 1.0 does not issue. The same applies to `GET /api/v1/observations/metrics` and `GET /api/v1/anomalies`.

```json
{"count": 1, "rows": [
  {"ts": "2026-10-16T12:00:00.123456Z", "correlation_id": "0199...", "server_id": "fs", "capture": "sampled",
   "principal_id": "cc", "session_id": "0199...", "tool_name": "read_file", "decision_outcome": "permit",
   "request_bytes": 31, "argument_entropy": 3.9, "end_to_end_latency": 14.2, "gateway_overhead": 3.1,
   "approval_state": "{\"required\":false}", "release_outcome": "released", "policy_revision": "r1"}
]}
```

### GET /api/v1/observations/aggregate

Aggregate over one numeric column. Query:

| Parameter | Meaning |
|---|---|
| `feature` | Numeric column (required) |
| `table` | `records` (default), `spans`, `metrics` or `scores` |
| `group_by` | Comma-separated columns; `context` expands to the baseline dimensions that are columns |
| `bucket` | Time bucket, a duration of at least `1s` |
| `quantiles` | Comma-separated probabilities, linear interpolation |
| `histogram` | Comma-separated ascending upper bounds b0..bn; counts are returned for (−∞,b0], (b0,b1], ..., (bn,+∞) |
| `from`, `to`, `principal`, `server`, `tool`, `session` | Filters |

```json
{"feature": "request_bytes", "group_by": ["principal_id", "tool_name"], "bucket": "1h", "rows": [
  {"group": {"principal_id": "cc", "tool_name": "read_file"}, "bucket": "2026-10-16T12:00:00Z",
   "count": 120, "mean": 30.5, "variance": 4.2, "min": 20, "max": 41, "quantiles": [30], "histogram": [10, 100, 10]}
]}
```

`variance` is the sample variance (0 for one value).

A `feature` or `group_by` column the role may not see is refused with 403 `sensitivity_refused` (SR-6-3): S2 columns for the Operator and the Researcher, S3 columns for every role.

### GET /api/v1/observations/metrics

System meta-metrics rows (P-240 to P-250). Query: `from`, `to`, `limit` (1 to 10000, default 360).

```json
{"count": 1, "rows": [{"ts": "...", "interval_seconds": 10, "throughput": 2.4, "concurrent_calls": 1,
  "queue_depths": "{\"collector\":0,...}", "capture_drops": "{\"sampled_down\":21}", "observation_ingest_rate": 3.1,
  "baseline_cache_size": 20480, "cpu_per_element": "{\"smcpd\":1.2}", "rss_per_element": "{...}", "store_sizes": "{...}"}]}
```

### GET /api/v1/observations/cost

Time per stage, policy revision and Observation Policy, ranked by total time (FR-10.11). Query: `from`, `to`, `principal`, `tool`.

`rows` aggregates the stored spans in the time range. `policy_objects` is the collector's aggregation of the call-path spans (FR-10.2) since start, by stage, policy revision, decisive rule revision, filter and Observation Policy, most expensive first, with span count, total, mean and maximum time and CPU time in milliseconds; `filters` is the same for filter spans only, so the most expensive filter comes first.

```json
{"rows": [{"group": {"stage": "dispatch", "policy_revision": "r1", "observation_policy": "default"},
           "count": 120, "mean": 10.1, "variance": 2.0, "min": 7, "max": 30, "quantiles": [9.8, 15, 28], "total_ms": 1212}],
 "policy_objects": [{"stage": "filter", "policy_revision": "r1", "rule_id": "r1/ro/ro-t", "filter_id": "secret-fingerprint",
                     "observation_policy": "default", "spans": 120, "total_ms": 30.2, "cpu_ms": 28.9, "mean_ms": 0.25, "max_ms": 1.1}],
 "filters": [{"stage": "filter", "policy_revision": "r1", "rule_id": "r1/ro/ro-t", "filter_id": "secret-fingerprint",
              "observation_policy": "default", "spans": 120, "total_ms": 30.2, "cpu_ms": 28.9, "mean_ms": 0.25, "max_ms": 1.1}]}
```

### POST /api/v1/observations/purge

Administrator only. Deletes the observation data (records, spans, metrics and scores, including captured payloads) of every UTC day before `before` (SR-6.15-1).

Request: `{"before": "2026-10-03", "reason": "data subject request"}`; both are required, and `before` may not be after today.

The deletion receipt is committed to the Evidence Journal before anything is deleted: an `observation` event with outcome `purged`, reason `DATA_PURGED` and detail `receipt_id`, `actor`, `reason`, `before`, `partitions` (each `<table>/day=<date>`), `partition_count` and `issued_at`. If it cannot be recorded, nothing is deleted (503 `audit_unavailable`). Response 200: the receipt with `removed`, the partitions deleted.

## Observation objects

The Audit Profile (G-03), the Observation Policy (G-04), the Anomaly Response Policy (G-06) and the Observation Store memory budget (G-08) are published as numbered, immutable revisions with a SHA-256 digest, actor, time and reason (`internal/obspolicy`, `<state>/observation-objects.json`, mode 0600). The last revision of each kind is active. A revision is validated by resolving the complete observation settings it would produce, exactly as the analytics service does at start, so an invalid combination (an unknown or periodic parameter, approval without synchronous scoring, unordered bands) is refused with 422 `invalid`.

At start smcpd overlays the active revisions onto the `[observation]` table it gives to the analytics service. A revision published while smcpd runs is applied to the running analytics service at once: the Observation Policy ID, parameter selection, sampling rate, band thresholds, escalation parameters, retention, scoring mode and the approval and withhold bands. Two settings are fixed when the observation components start and apply at the next start: `baseline.contexts` (the baseline engine is keyed by them) and `memory_limit_bytes`. A revision that changes either is reported as `pending` with the setting in `restart_required`; its other settings are in force. The mandatory audit floor is not part of any object.

| Kind | Route | Body | Sets in `[observation]` | Who publishes |
|---|---|---|---|---|
| `audit_profile` | `POST /api/v1/observations/audit-profile` | `{"retention": "720h", "escalation_parameters": ["request_bytes"]}` | `retention` (at least 24h), `escalation_parameters` | Policy Author |
| `observation_policy` | `POST /api/v1/observations/observation-policy` | `{"policy_id": "lab", "parameters": [...], "sampling_rate": 0.25, "contexts": ["principal", "tool"], "bands": [2, 3, 5], "escalation": {"abnormal": ["argument_entropy"]}, "features": [{"parameter": "request_bytes", "transform": "log1p", "robust": true, "sigma_floor": 0.5}], "scope": {"principals": ["cc"], "tools": ["ref/echo"]}}`; `escalation`, `features` and `scope` are optional | `policy_id`, `parameters`, `sampling_rate`, `escalation_bands`, `scope`, `baseline.contexts`, `baseline.bands`, `baseline.feature` | Policy Author |
| `anomaly_response` | `POST /api/v1/observations/anomaly-response` | `{"scoring": "sync", "escalate_capture_band": "abnormal", "uncharacterized": "escalate", "require_approval_band": "abnormal", "withhold_band": "critical"}`; the first two are optional | `scoring`, `escalate_capture_band`, `uncharacterized_action`, `require_approval_band`, `withhold_band` | Policy Author |
| `memory_budget` | `POST /api/v1/observations/memory-budget` | `{"observation_memory_limit_bytes": 402653184}` (64 MiB to 64 GiB) | `memory_limit_bytes` | Operator |

Request: `{"body": {...}, "reason": "..."}`. Response 201: `{"revision": {"kind", "number", "digest", "body", "published_by", "published_at", "reason"}, "applies": "at once, except the settings an object lists in restart_required, which apply at the next start of smcpd"}`, plus `apply_error` when the running service refused the settings (the revision is stored and stays `pending`). The publication is committed to the journal first (`admin`/`publish_requested`/`OBSERVATION_OBJECT_PUBLISHED` with `detail.kind`); 503 `audit_unavailable` when it cannot be, and nothing is stored.

### GET /api/v1/observations/objects

```json
{"objects": [{"kind": "audit_profile", "active": {"kind": "audit_profile", "number": 2, "digest": "sha256:…", "body": {"retention": "720h", "escalation_parameters": []},
              "published_by": "policy_author:pat", "published_at": "2026-10-17T03:00:00Z", "reason": "shorter retention"}, "in_force": 1, "pending": true, "revisions": 2}, …],
 "applies": "at once, except the settings an object lists in restart_required, which apply at the next start of smcpd",
 "effective": {"policy_id": "lab", "parameters": [...], "escalation_parameters": [], "sampling_rate": 0.25, "retention": "720h0m0s", "scoring": "sync",
               "require_approval_band": "abnormal", "withhold_band": "critical", "memory_limit_bytes": 402653184, "contexts": ["principal", "tool"], "bands": [2, 3, 5]}}
```

`in_force` is the revision in force (0: the `smcp.toml` settings). `restart_required` lists the active revision's settings that wait for the next start. `effective` is the `[observation]` table the active revisions produce. Readable by the roles of the observation analytics routes.

### GET /api/v1/observations/objects/{kind}

The revisions of one kind, newest first: `{"kind": "audit_profile", "revisions": [...]}`. 404 `unknown_kind`.

## Baselines

### GET /api/v1/baselines

```json
{
  "status": {"contexts": 4, "characterized": 3, "learned": 1180, "excluded": {}, "flagged_sessions": 0, "promoted": "0199...", "snapshots": 2, "records_since_build": 0},
  "snapshots": [{"id": "0199...", "digest": "sha256:...", "created_at": "...", "trigger": "operator",
                 "window": {"from": "...", "to": "..."}, "records": 1180, "contexts": 4, "characterized": 3, "promoted": true}],
  "history": [{"id": "0199...", "at": "...", "by": "operator-token", "mode": "operator"}],
  "flagged_sessions": [],
  "last_drift": null
}
```

A snapshot that fails verification is listed with only `id` and `error`.

### POST /api/v1/baselines/snapshots

Builds a snapshot now. Body `{}`. Response 200:

```json
{"snapshot": {"id": "0199...", "digest": "sha256:...", "trigger": "operator", "records": 1180, "contexts": 4, "characterized": 3, "promoted": false},
 "drift": {"candidate": "0199...", "promoted": "0199...", "contexts": [{"context": "principal=cc|tool=read_file",
           "features": [{"feature": "request_bytes", "mean_shift_sigma": 0.12, "sigma_ratio": 1.05}]}],
           "new_contexts": ["principal=cc|tool=write_file"], "max_abs_mean_shift_sigma": 0.12, "max_sigma_factor": 1.05},
 "promoted": false}
```

`promoted` is true when the automatic-promotion limits allowed it.

### GET /api/v1/baselines/{id}

The full snapshot: `id`, `digest`, `created_at`, `trigger`, `window`, `config` (dimensions, features, n_min, half_life, learning_window), `records`, `contexts` (per context: `dims`, `count`, `features` with `n`, `weight`, `mean`, `variance`, `std`, `median`, `mad`, `robust`, `transform`; `categories`; `first`, `last`) and `transitions` (sequence context → previous tool → next tool → count). 404 `not_found`; 409 `snapshot_integrity` when the stored digest does not match.

### GET /api/v1/baselines/{id}/drift

The drift report of the snapshot against the promoted one (same shape as `drift` above).

### POST /api/v1/baselines/{id}/promote

Promotes the snapshot; an older snapshot than the promoted one is a rollback. Body `{"comment": "optional"}`.

```json
{"promotion": {"id": "0199...", "at": "...", "by": "operator-token", "mode": "operator"}, "loaded_snapshot": "0199..."}
```

`mode` is `operator`, `rollback` or (for builds) `automatic`. 409 `already_promoted`, 409 `snapshot_integrity`, 404 `not_found`.

### POST /api/v1/baselines/flags

Excludes a session from learning, or includes it again. Recorded as a `baseline` event before it takes effect.

```json
{"session_id": "0199...", "flagged": true, "reason": "runtime monitor finding"}
```

Response 200: `{"session_id": "0199...", "flagged": true}`. `flagged` defaults to true.

## Anomalies

### GET /api/v1/anomalies

Scoring records of band `elevated` or worse, oldest first. Query: `from`, `to`, `band` (repeatable), `principal`, `tool`, `session`, `limit` (1 to 1000, default 100).

```json
{"count": 1, "rows": [
  {"ts": "...", "correlation_id": "0199...", "snapshot_id": "0199...", "context": "principal=cc|tool=read_file",
   "combined": 6.2, "contributing_feature": "request_bytes", "band": "critical",
   "features": "[{\"feature\":\"request_bytes\",\"value\":20012,\"transformed\":9.9,\"z\":6.2}]",
   "actions": "[\"alert\",\"capture_escalation\"]", "mode": "async", "principal_id": "cc", "session_id": "0199...", "tool_name": "read_file"}
]}
```

## Research

### GET /api/v1/research/campaigns

`{"campaigns": [<campaign>, ...]}`, newest first.

### POST /api/v1/research/campaigns

Creates a campaign in `draft`. Body: the specification of [../observation.md#research-campaigns-and-exports](../observation.md#research-campaigns-and-exports). Response 201 with the campaign:

```json
{"id": "0199...", "name": "latency study", "purpose": "", "state": "draft",
 "scope": {"principals": ["cc"], "tools": ["read_file"]}, "parameters": ["request_bytes", "end_to_end_latency"],
 "sampling": 1, "start": "...", "end": "...", "quota_bytes": 50000000, "used_bytes": 0, "records": 0,
 "raw_export_grant": false, "created_by": "operator-token", "created_at": "...",
 "history": [{"from": "", "to": "draft", "at": "...", "by": "operator-token"}]}
```

400 `invalid_campaign` for a missing name, unknown or S3 parameter without the grant, end not after start, non-positive quota or sampling outside (0, 1].

### GET /api/v1/research/campaigns/{id}

The campaign. 404 `not_found`.

### POST /api/v1/research/campaigns/{id}/{action}

`action` is `submit`, `approve`, `reject`, `stop` or `expire`. Body `{"reason": "optional"}`. The action is recorded as a `research` event before it is applied. Response 200 with the campaign; 409 `invalid_transition` when the state does not allow it.

### POST /api/v1/research/exports

```json
{"format": "csv", "campaign_id": "0199...", "parameters": ["request_bytes"]}
{"format": "jsonl", "from": "2026-10-16T00:00:00Z", "to": "2026-10-17T00:00:00Z",
 "scope": {"principals": ["cc"], "servers": ["fs"], "tools": []}, "parameters": ["P-024", "P-162"]}
{"format": "graphml", "snapshot_id": "0199..."}
{"format": "graphml", "subgraph": "audit", "from": "2026-10-16T00:00:00Z"}
```

`format` is `parquet`, `csv`, `jsonl` or `graphml`. For `graphml`, `subgraph` is `behavior-model` (default: the baseline snapshot) or `audit` (the calls in scope with their sessions, principals, tools and policy revisions; one `Call` node per record, so its count equals the rows of a tabular export of the same scope). With `campaign_id` the campaign's scope, window and (by default) parameters are used, and the campaign must be `active`, `completed` or `exported`; a `completed` campaign becomes `exported`. Without parameters the default selection is used. Response 200, the manifest:

```json
{"dataset_id": "0199...", "created_at": "...", "created_by": "operator-token", "format": "csv", "campaign": null,
 "filters": {"scope": {}, "parameters": ["request_bytes"]}, "catalog_version": "1.0.0",
 "policy_revisions": ["r1"], "baseline_snapshots": ["0199..."], "time_range": {"first": "...", "last": "..."},
 "rows": 131, "columns": ["ts", "correlation_id", "principal_id", "..."],
 "pseudonymization": {"function": "HMAC-SHA-256", "key": "per dataset, keys/research/<dataset_id>.key"},
 "files": [{"name": "dataset.csv", "bytes": 10240, "sha256": "..."}, {"name": "dictionary.json", "bytes": 2048, "sha256": "..."}],
 "store_backend": "duckdb"}
```

The export is recorded as a `research` event with outcome `exported`. Errors: 400 `bad_export`, 403 `raw_export_not_granted`, 404 `not_found` (campaign), 409 `parquet_unavailable`.

### GET /api/v1/research/exports

`{"exports": [<manifest>, ...]}`, newest first.

### GET /api/v1/research/exports/{id}

One manifest. 404 `not_found`.

### GET /api/v1/research/exports/{id}/files/{name}

Downloads one file of the export (`dataset.*`, `behavior-model.graphml`, `dictionary.json`, `manifest.json`, `SHA256SUMS`) as an attachment. Names are restricted to `[A-Za-z0-9._-]`. The download is recorded as a `research` event with outcome `downloaded`. 404 `not_found`.
