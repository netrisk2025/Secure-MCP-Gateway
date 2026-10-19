# Observation and analytics

The Gateway records an observation record for every tool call, learns statistical baselines of normal behavior, scores calls by their distance from the baseline in standard deviations, and exports research datasets. These functions are SS-10 Observation & Analytics (E-29 Observation Collector, E-30 Behavior Baseline Engine, E-31 Anomaly Scorer, E-32 Research Dataset Service) and the E-27 Observation Store, specified in SRS FR-10, FR-9.7 to FR-9.9 and ArchitectureV2 §9 and §10.

Observation never decides a call by itself. It cannot block, slow or fail a call: evidence events reach it through the evidence fan-out after the journal has accepted them, and the inspection probes hand their data to a bounded queue without waiting. When a queue is full the item is dropped and counted (parameter P-246). The collector takes its queued inputs every 10 ms (sooner when the queue is half full) and the store writer every `flush_interval`, so an offer from the call path does not wake either of them; the evidence fan-out calls the collector's non-blocking offer directly instead of through a queue and goroutine of its own. The observe-response probe reads a result's text parts (for `response_bytes`, `response_entropy`, `response_token_estimate` and `embedded_url_count`) on the collector's goroutine rather than on the call's, except with synchronous scoring, whose score needs them before release. On Linux baseline snapshot builds and DuckDB's query threads run at nice 10, and the store writer runs in the `SCHED_IDLE` scheduling policy (nice 10 where the kernel refuses it), which a call's thread always preempts; the writer's batches are copied to Parquet by a single-threaded DuckDB instance of their own, so that each batch runs entirely on the writer's thread. These keep observation's work from delaying calls on a busy host (FR-11.4). If the store cannot be opened the Gateway runs without storage and `smcpctl observe status` shows the cause. The only effects on calls are the optional synchronous obligations described under [Synchronous scoring](#synchronous-scoring), which are off by default and can only add restrictions.

Commands: `smcpctl observe` ([reference](#smcpctl-observe)). Control API: [api/observation.md](api/observation.md).

## What is recorded

Each call yields one record, assembled from the evidence events that share its correlation ID (requested, decision, approval, dispatched, completed, and the terminal event) and from two probes in the inspection pipelines:

- `observe-request` is a mandatory request filter at order 1000 (after every other request filter). It computes the argument features.
- `observe-response` is a mandatory response filter at order 1000. It computes the result features.

Both appear in the provenance `filters` list of a released result. A record is assembled when the call reaches its terminal event (delivered, denied, filtered, withheld, failed or indeterminate). A call with no terminal event within 10 minutes is dropped and counted as `unterminated`.

The columns are the parameters of the Parameter Catalog, `docs/parameters.json` (catalog version 1.1.0). The store has one column per per-call parameter. This release computes the parameters below. The other catalog parameters stay null until the element that produces them exists (for example runtime parameters P-102 to P-107 need the Runtime Monitor).

| Group | Computed parameters |
|---|---|
| Identity and session | P-001 `principal_id`, P-003 `harness_adapter_version` (the request's `io.modelcontextprotocol/clientInfo` as `name/version`, self-asserted, FR-1.45), P-004 `session_id`, P-005 `session_template`, P-007 `calls_in_session`, P-008 `end_user_claim` (S2), P-009 `trace_parent` (a valid W3C `traceparent` from the request `_meta`, FR-1.44) |
| Request shape | P-020 `mcp_method` (always `tools/call`), P-022 `server_revision`, P-023 `tool_name`, P-024 `request_bytes`, P-025 `argument_count`, P-026 `argument_max_depth`, P-027 `argument_string_lengths`, P-028 `argument_entropy`, P-029 `path_argument_count`, P-030 `url_argument_count` |
| Request content | P-040 `argument_value_hashes` (S2), P-043 `injection_detect_score`, P-044 `unicode_control_count` |
| Filters | P-140 `filter_hits`, P-141 `redaction_count`, P-142 `secret_fingerprint_matches`, P-143 `injection_marker_score`, P-144 `pii_hits`, P-205 `t_request_filters`, P-209 `t_response_filters` |
| Sequence and rate | P-060 `previous_tool`, P-061 `transition_surprise`, P-062 `inter_call_interval`, P-063 `calls_per_minute_session`, P-064 `calls_per_minute_principal`, P-065 `distinct_tools_in_session`, P-066 `repeated_identical_calls` |
| Decision | P-080 `decision_outcome`, P-081 `decisive_rule_ids`, P-083 `obligations_applied`, P-084 `approval_state`, P-085 `anomaly_band`, P-086 `max_abs_z`, P-087 `baseline_snapshot_id` |
| Runtime | P-101 `server_execution_time` |
| Response shape | P-120 `response_bytes`, P-121 `content_parts_by_type`, P-122 `output_schema_conformance`, P-123 `response_entropy`, P-124 `response_token_estimate`, P-125 `is_error`, P-126 `structured_field_count`, P-127 `embedded_url_count` |
| Release | P-160 `release_outcome`, P-161 `delivery_confirmation`, P-162 `end_to_end_latency` |
| Meta-metrics per call | P-206 `t_approval_wait`, P-210 `t_scoring`, P-211 `t_capture`, P-213 `gateway_overhead` |

Records also carry `ts` (time of the requested event, UTC), `correlation_id`, `server_id` (server alias), `policy_revision`, `reason_code` (of the terminal event), `capture`, `campaign_id`, `observation_policy` and `catalog_version`.

Derivation notes, where this release differs from the catalog text:

- P-024 is the length of the arguments JSON as the Gateway received it inside the request, not the whole HTTP body.
- P-029 and P-030 count string leaves that look like a filesystem path (`/`, `~/`, `./`, `../` or a drive letter) or an absolute URL with a host; they do not yet use schema formats or canonicalization filters.
- P-027 lists string-leaf lengths in a walk with object keys sorted.
- P-080 is `permit`, `deny` (refused by the decision) or `not_evaluated` (refused before the decision, for example a session that ended).
- P-160 is `released`, `withheld`, `blocked` (request filter), `refused`, `failed` or `indeterminate`.
- P-101, P-162 and P-213 are computed from the evidence-event timestamps (wall clock, microsecond resolution), not from a monotonic clock. P-213 = P-162 − P-101 − P-206.
- P-043, P-044 and P-140 to P-144 are the values of the `filter` evidence event of each inspection stage (FR-4.7). P-043 and P-143 are the highest score of the injection rule-set findings, P-140 the count of findings per filter ID. P-205 and P-209 hold each filter's time by filter ID and the stage `total`, in milliseconds.
- P-206 runs from the Approval Service's `requested` event to the call's approval decision event; it is 0 when the call needed no approval.
- P-061 is −ln p(tool | previous tool) from the Baseline Engine's current transition counts in the call's sequence context, with add-one smoothing (see [Baselines](#baselines)).
- P-066 is the run length of consecutive calls in the session with the same tool and the same canonical argument digest, 1 for a call that does not repeat the previous one.

Raw payloads (S3: P-045, P-145) are not captured in this release; selecting them is a configuration error. Secret-fingerprint scrubbing (SR-6.7-1) is not needed while no payloads or argument values are stored; it is required before S3 capture can be added.

### System meta-metrics

Every `metrics_interval` (default 10 s) a row is written to the `metrics` table with P-240 `throughput` (records assembled per second), P-241 `concurrent_calls` (calls in progress), P-242 `queue_depths` (collector and store writer), P-243 `rss_per_element` (Go runtime memory of `smcpd`), P-245 `observation_ingest_rate` (rows written per second), P-246 `capture_drops`, P-248 `baseline_cache_size` (bytes of the loaded snapshot), P-249 `cpu_per_element` (percent CPU of `smcpd`), P-250 `store_sizes`, P-244 `graph_memory` (the graph engine's heap use and budget, when the mirror is enabled) and P-247 `journal_signing_lag` (unsigned journal events and the age of the oldest).

P-246 counts drops by reason:

| Reason | Meaning |
|---|---|
| `queue_full` | The collector's input queue was full |
| `observer_queue_full` | The evidence fan-out dropped an event for the observation observer (not used since the fan-out calls the collector directly; its drops are `queue_full`) |
| `sampled_down` | The record was not selected by sampling and no campaign captured it |
| `unterminated` | The call had no terminal event within 10 minutes |
| `orphan_probe` | A probe whose call never appeared |
| `store_queue_full` | The store writer's queue was full |
| `store_error` | The store refused a batch, or no store is open |

### Timing spans

The `spans` table holds, for every stored record, the stages that the collector can derive from the evidence: `pre_dispatch` (requested to dispatched), `dispatch` (dispatched to the backend's response, `responded_at` of the completed event), `release` (the backend's response to delivered, which includes response inspection) and `approval_wait`. Each span has the policy revision and the Observation Policy ID, so `GET /api/v1/observations/cost` ranks the time spent per stage and revision. In addition, the edge emits for every call a span per pipeline stage and per filter run (FR-10.2) with monotonic times, thread CPU time and the decision's policy revision and decisive rule revision. The collector aggregates every call's spans by stage, policy revision, rule, filter and Observation Policy (FR-10.11, `policy_objects` and `filters` of the cost route), and stores the spans of the calls whose record is stored (sampled, escalated or for a campaign) with `monotonic = 1`, `cpu_ms`, `rule_id` and `filter_id`. Until 2026-10-17 the spans of every call were stored, about 20 rows per call, which was most of the store's cost per call.

## Sampling and capture

Every assembled record is offered to the baseline and, when scoring is on, scored. Which records are stored:

1. A record whose band is `elevated` or worse is stored (`capture = "escalated"`) with the selected parameters, the escalation parameters, `anomaly_band` and `max_abs_z`.
2. Otherwise the record is stored (`capture = "sampled"`) when the SHA-256 of its correlation ID, read as a number in [0, 1), is below `sampling_rate`. The same call set always gives the same selection.
3. Each active research campaign whose scope matches stores the record with the campaign's parameters, at the campaign's sampling rate (hashed with the campaign ID), and records `campaign_id`.

Stored records contain only the selected parameters plus the identifiers P-001, P-004, P-022, P-023, P-080 and P-087.

## Baselines

The Behavior Baseline Engine groups records by a baseline context, the values of the configured dimensions. Available dimensions: `principal`, `framework_type`, `session_template`, `end_user`, `server` (alias), `server_revision`, `tool`, `hour` (UTC hour, `00` to `23`) and `weekday` (`Mon` to `Sun`). The default context is (`principal`, `tool`). The context key is written `principal=agent-a|tool=read`.

For each context and numeric feature it keeps the count, mean and M2 with Welford's algorithm. With `half_life`, earlier observations lose half their weight per half-life; the variance is then M2/(W−1) over the effective weight W. Features can be transformed before learning and scoring with `log1p` or `box-cox(λ)` (values outside the transform's domain, such as 0 for Box-Cox, are skipped for that feature). A feature marked `robust` also keeps a t-digest (compression 200) from which the median and the median absolute deviation (MAD) are derived; MAD is found by solving CDF(m+d) − CDF(m−d) = 1/2 on the digest.

Categorical features (`kind = "categorical"`, for example `decision_outcome`) keep value counts per context and baseline the surprise −ln p of each observed value, with p = (c + 1)/(N + K + 1) for a value seen c times among N observations of K distinct values. Tool transitions are counted per sequence context (the context dimensions without `tool`, `server` and `server_revision`); P-061 uses the same smoothing.

Records are not learned when the call was not permitted or not released, when its band is `abnormal` or `critical`, when its session is flagged (`smcpctl observe baseline flag`), or when it is older than `learning_window`.

### Snapshots, promotion and rollback

A snapshot is an immutable copy of the statistics with an ID (UUIDv7), a SHA-256 digest over its canonical JSON, the contexts, per-feature statistics, sample counts, the learning window and the configuration. Snapshots are built every `snapshot_interval` when records were learned, after `snapshot_records` learned records, and on `smcpctl observe baseline build`. They are stored read-only (mode 0400) in `<observation dir>/baselines/` and never replaced.

Each build reports drift against the promoted snapshot: per context and feature the mean shift in units of the promoted σ, the σ ratio, and the contexts newly characterized. The first snapshot is always promoted by an operator (`smcpctl observe baseline promote <id>`). Later snapshots are promoted automatically only when `auto_promote_max_shift` and `auto_promote_max_sigma_factor` are set and every drift value is within them (a σ ratio r counts as max(r, 1/r)). Promoting an older snapshot is a rollback. Every build and promotion is an evidence event (`class = "baseline"`, origin E-30).

The Anomaly Scorer verifies the digest of a snapshot before it loads it, and replaces the loaded snapshot atomically. A snapshot whose digest does not match is refused, the previous one stays loaded, and an `integrity` event with reason `BASELINE_DIGEST_MISMATCH` is recorded. The same check runs at start for the promoted snapshot.

The candidate statistics are saved to `baselines/candidate-state.json` hourly and at shutdown, so learning continues after a restart. A state file written with other dimensions or features is ignored.

## Scoring

Each baselined feature is scored as z = (x − μ)/max(σ, σ_floor), or with `robust`, z = 0.6745 (x − median)/max(MAD, σ_floor), using the transform of learning. The call's score is the feature with the largest |z| (recorded as the contributing feature). Bands, with the CP-30 defaults:

| Band | Default |
|---|---|
| `normal` | \|z\| < 2 |
| `elevated` | 2 ≤ \|z\| < 3 |
| `abnormal` | 3 ≤ \|z\| < 4 |
| `critical` | \|z\| ≥ 4 |
| `uncharacterized` | no promoted snapshot, or the context has fewer than `n_min` (default 30) samples in it |

The default σ floor is 0.5 for an untransformed integer parameter and 0.01 otherwise (in transformed units); set `sigma_floor` per feature.

Default baselined features: `request_bytes` (log1p), `argument_count`, `argument_entropy`, `response_bytes` (log1p), `response_entropy`, `server_execution_time` (log1p), `inter_call_interval` (log1p), `transition_surprise`, `calls_per_minute_session`.

A scoring record (snapshot ID, context key, each feature's value, transformed value and z, combined score, band, actions, mode) is written to the `scores` table for every score of `elevated` or worse and for every stored normal record. A score of `elevated` or worse is also an evidence event: `class = "anomaly"`, origin E-31, `outcome` the band, reason `ANOMALY_ELEVATED`, `ANOMALY_ABNORMAL` or `ANOMALY_CRITICAL`, with the scoring record in `detail`. Abnormal and critical calls are also logged as warnings in the diagnostic log.

### Asynchronous scoring

`scoring = "async"` (the default) scores the assembled record after the result was released. Its actions are `alert` (the evidence event) and `capture_escalation`; it never changes a call.

The Anomaly Response Policy (G-06) maps each band and the uncharacterized state to restrict-only actions (FR-8.14):

- Every band from `elevated` on alerts. `escalate_capture_band` (default `"elevated"`) is the lowest band that also escalates capture; bands below it alert only, and `"off"` makes every band alert only.
- `uncharacterized_action` applies to calls whose context has no baseline yet: `"record"` (default, no action), `"escalate"` (capture escalation) or `"approve"` (escalation and, with `scoring = "sync"`, an approval obligation with reason "anomaly context uncharacterized").
- An escalated call records the policy's parameters, `escalation_parameters`, and the `escalation_bands` parameters of its band and every lower band (FR-8.10).

### Synchronous scoring

`scoring = "sync"` scores in the probes: request features before launch authorization, response features before release authorization. Records refused before the request probe are scored asynchronously. Two optional obligations, both off by default:

- `require_approval_band`: a call whose request band is at least this band needs approval (E-07) although the policy did not ask for it. The probe sets `RequireApproval` on the call (`pipeline.Call`, a restrict-only seam honored by the edge). Without an approval service the call is refused with `-31002` reason `APPROVAL_REQUIRED`.
- `withhold_band`: a result whose response band is at least this band is withheld with `-31003` reason `ANOMALY_WITHHELD`.

Both can only add restrictions: a call denied by policy stays denied whatever its band (SR-1.12-2).

## Research campaigns and exports

A research campaign is a time-boxed, approved capture with its own parameter set. States: `draft`, `submitted`, `approved`, `active`, `completed`, `exported`, `expired`.

| Action | From | To |
|---|---|---|
| `submit` | draft | submitted |
| `approve` | submitted | approved |
| `reject` | submitted | draft |
| (start time) | approved | active |
| (end time or storage quota reached) | active | completed |
| `stop` | active | completed |
| (export) | completed | exported |
| `expire` | approved, completed, exported | expired |
| (end passed before activation) | approved | expired |

A campaign specification (`smcpctl observe campaign create --file spec.json`):

```json
{
  "name": "latency study",
  "purpose": "compare read latency across servers",
  "scope": {"principals": ["cc"], "servers": ["fs"], "tools": ["read_file"]},
  "parameters": ["P-024", "end_to_end_latency", "server_execution_time"],
  "sampling": 1.0,
  "start": "2026-10-17T00:00:00Z",
  "end": "2026-10-18T00:00:00Z",
  "quota_bytes": 50000000,
  "raw_export_grant": false
}
```

The quota counts the JSON size of each record the campaign stores. S3 parameters in a campaign need `raw_export_grant`; raw capture itself is not available in this release.

An export (`smcpctl observe export`) extracts the stored records within a campaign's scope and time window, or within the given time range and scope, and writes a directory `<export dir>/<dataset id>/` (default export directory `<state>/exports`, mode 0700, files 0600) with:

| File | Content |
|---|---|
| `dataset.parquet`, `dataset.csv` or `dataset.jsonl` | The records. Parquet needs the DuckDB store backend. |
| `behavior-model.graphml` | With `--format graphml`: the promoted (or given) snapshot as a graph of `BaselineContext` and `Tool` nodes, `COVERS` edges and `NEXT_TOOL` edges with transition counts |
| `audit.graphml` | With `--format graphml --subgraph audit`: the records in scope as `Call` nodes (pseudonymized correlation ID, time, decision outcome) with pseudonymized `Session` and `Principal` nodes, `Tool` and `PolicyRevision` nodes, and `OPENED`, `MADE`, `INVOKED` and `DECIDED_UNDER` edges |
| `dictionary.json` | One entry per column from the Parameter Catalog (ID, description, unit, data type, derivation, sensitivity, source element, whether pseudonymized) |
| `manifest.json` | Dataset ID, time, actor, format, campaign, filters, catalog version, policy revisions and baseline snapshots seen in the rows, time range, row count, columns, pseudonymization, file checksums |
| `SHA256SUMS` | SHA-256 of the data file, the dictionary and the manifest (`sha256sum -c` format) |

Pseudonymization: `principal_id`, `session_id`, `end_user_claim`, `correlation_id` and every S2 parameter are replaced by `ps_` and the first 32 hex digits of HMAC-SHA-256 under a new random 256-bit key per dataset (CP-40), inside JSON values as well (object keys included). The key is kept in `<state>/keys/research/<dataset id>.key` (mode 0600) and is not part of the export; pseudonyms are consistent within a dataset and differ across datasets. In CSV, a string cell that starts with `=`, `+`, `-`, `@`, tab or carriage return is prefixed with an apostrophe. Every export and download is an evidence event (`class = "research"`).

## Store

`store = "auto"` uses DuckDB (official Go driver, linked with cgo) when the binary has it, and JSON Lines otherwise. Release archives are built with `CGO_ENABLED=0` and use JSON Lines; build from source with cgo for DuckDB and Parquet export. Both backends use the same layout and give the same query results:

```
<observation dir>/store/<table>/day=YYYY-MM-DD/part-<time>-<seq>.parquet   (duckdb)
<observation dir>/store/<table>/day=YYYY-MM-DD/part-<time>-<seq>.jsonl     (jsonl)
```

Tables: `records`, `spans`, `metrics`, `scores`, partitioned by UTC day. Each flushed batch (at most `flush_records` rows or `flush_interval`) is one new file; files are never rewritten. A newer catalog version that adds a parameter adds a column to new files only; queries read older files with the column as null. Directories are 0700 and files 0600. DuckDB runs in memory with `memory_limit_bytes` (CP-33: 512 MiB) in two instances: one with two threads answers queries and research exports, and one with a single thread and 64 MiB of the limit (a quarter of it when the limit is under 256 MiB) writes the batches. Neither installs or loads extensions from the network. Day partitions older than `retention` (CP-25: 90 days) are deleted at start and hourly. Aggregate queries (count, mean, sample variance, minimum, maximum, quantiles by linear interpolation, histograms over given bounds) can be grouped by any columns, by `context` (the baseline dimensions) and by a time bucket.

## Degradation

The Observation Collector sheds load in stages instead of slowing the Gateway (FR-9.12). The path is overloaded while the store writer's queue is at 80% or more of its capacity (the backpressure signal, FR-9.6), while the process heap is above 90% of the observation memory budget (`memory_limit_bytes`, CP-33), or, on Linux, while less than 10% of host memory is available. Every half second the stage moves one step: up while overloaded, down once not. The Health & Safety Monitor reports a stage above `normal` as the non-critical cause `observation_degraded`.

| Stage | Name | Effect |
|---|---|---|
| 0 | `normal` | None |
| 1 | `reduced_sampling` | Normal-band sampling at a tenth of `sampling_rate`; the calls sampled out are counted as drop reason `degraded`. Escalated captures are kept |
| 2 | `s3_capture_suspended` | S3 parameters (`raw_arguments`, `raw_response`) are not captured |
| 3 | `campaigns_paused` | Research campaigns capture nothing |
| 4 | `caches_shrunk` | The per-session cache keeps a quarter of its sessions |

`GET /api/v1/observations/status` reports `degradation` (`stage`, `name`, `reason`, `backpressure`), and health reports the non-critical cause `observation_degraded` while the stage is above 0. Enforcement never degrades. The writer appends to the store in batches of at most `flush_records` (1,000) rows or `flush_interval` (200 ms), whichever comes first (FR-9.5).

## Configuration

Every key of the `[observation]` table is optional.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Observation on or off |
| `store` | `"auto"` | `auto`, `duckdb` or `jsonl` |
| `dir` | `<state>/observation` | Store, baselines and campaigns |
| `export_dir` | `<state>/exports` | Research exports |
| `policy_id` | `"default"` | Observation Policy ID in records and spans |
| `parameters` | every computed S0 and S1 parameter | Captured parameters (IDs or names) |
| `escalation_parameters` | none | Added for escalated calls |
| `escalation_bands` | none | Table `elevated`, `abnormal`, `critical` of parameter lists added for escalated calls of that band and higher (FR-8.10) |
| `escalate_capture_band` | `"elevated"` | Lowest band that escalates capture; lower bands alert only; `"off"` for none (FR-8.14) |
| `uncharacterized_action` | `"record"` | `record`, `escalate` or `approve` (`approve` needs `sync`) for calls without a baseline (FR-8.14) |
| `sampling_rate` | `0.1` | Normal-band capture rate (CP-31) |
| `retention` | `"2160h"` | Partition retention (CP-25) |
| `queue` | `4096` | Collector and writer queue bound |
| `flush_records` | `1000` | Maximum rows per store batch |
| `flush_interval` | `"200ms"` | Maximum batch age |
| `metrics_interval` | `"10s"` | Meta-metrics interval |
| `memory_limit_bytes` | `536870912` | DuckDB memory limit and the observation memory budget the degradation stages use |
| `storage_quota_bytes` | `10737418240` | Storage quota of the observation directory; health warns at 80% (FR-9.15) |
| `scoring` | `"async"` | `off`, `async` or `sync` |
| `require_approval_band` | `"off"` | `sync` only: band that adds the approval obligation |
| `withhold_band` | `"off"` | `sync` only: band that withholds the result |

`[observation.scope]` (FR-8.9) limits the calls the Observation Policy samples and escalates; research campaigns keep their own scope. A call is in scope when it matches every non-empty list. Out-of-scope calls are counted as the drop reason `out_of_scope`. `framework_type` is filled from the principal's framework (file or G-11 directory).

| Key | Matches |
|---|---|
| `principals` | Principal ID |
| `frameworks` | Framework type of the principal |
| `templates` | Session Allow template |
| `servers` | Server alias |
| `tools` | `"<server alias>/<backend tool name>"` |

`[observation.baseline]`:

| Key | Default | Meaning |
|---|---|---|
| `contexts` | `["principal", "tool"]` | Context dimensions |
| `n_min` | `30` | Samples before a context is characterized (CP-30) |
| `half_life` | none | Exponential decay half-life |
| `learning_window` | `"720h"` | Older records are not learned |
| `snapshot_interval` | `"1h"` | Build interval |
| `snapshot_records` | `10000` | Build after this many learned records (0: off) |
| `auto_promote_max_shift` | `0` (off) | Automatic promotion: maximum \|mean shift\| in promoted σ |
| `auto_promote_max_sigma_factor` | `0` (off) | Automatic promotion: maximum σ factor |
| `bands` | `[2, 3, 4]` | \|z\| bounds of elevated, abnormal, critical |

`[[observation.baseline.feature]]` (replaces the default feature list):

| Key | Default | Meaning |
|---|---|---|
| `parameter` | required | Parameter ID or name |
| `kind` | `"numeric"` | `numeric` or `categorical` |
| `transform` | `"none"` | `none`, `log1p` or `box-cox(λ)` with λ in [−5, 5] |
| `robust` | `false` | Median and MAD scoring |
| `sigma_floor` | see [Scoring](#scoring) | σ floor in transformed units |

Example:

```toml
[observation]
sampling_rate = 0.2
scoring = "sync"
require_approval_band = "critical"

[observation.baseline]
contexts = ["principal", "server", "tool"]
auto_promote_max_shift = 0.5
auto_promote_max_sigma_factor = 1.5

[[observation.baseline.feature]]
parameter = "request_bytes"
transform = "log1p"

[[observation.baseline.feature]]
parameter = "argument_entropy"
robust = true
sigma_floor = 0.05
```

Configuration errors stop `smcpd` at start: an unknown parameter, an S3 or periodic parameter in `parameters`, a non-numeric parameter as a numeric feature, unordered bands, or an obligation band without `scoring = "sync"`.

## smcpctl observe

All subcommands use the operator token and take `--config <file>`.

| Command | Effect |
|---|---|
| `smcpctl observe status [--json]` | Collector counters, store, baseline and drop counts |
| `smcpctl observe anomalies [--since 24h] [--band b] [--limit n] [--json]` | Recent scores of `elevated` or worse |
| `smcpctl observe baseline [list] [--json]` | Snapshots, promotion history, flagged sessions |
| `smcpctl observe baseline build` | Build a snapshot now; prints the drift report |
| `smcpctl observe baseline show <id>` | The full snapshot |
| `smcpctl observe baseline drift <id>` | Drift of a snapshot against the promoted one |
| `smcpctl observe baseline promote <id>` | Promote (an older snapshot: roll back) |
| `smcpctl observe baseline rollback <id>` | Same as promote, for an earlier snapshot |
| `smcpctl observe baseline flag <session> [--reason text]` | Exclude a session from learning |
| `smcpctl observe baseline unflag <session>` | Include it again |
| `smcpctl observe campaign list [--json]` | Campaigns |
| `smcpctl observe campaign create --file spec.json` | Create a campaign (draft) |
| `smcpctl observe campaign show <id>` | One campaign with its history |
| `smcpctl observe campaign submit\|approve\|reject\|stop\|expire <id> [--reason text]` | Campaign actions |
| `smcpctl observe export --format f [--campaign id] [--from t] [--to t] [--principal p] [--server s] [--tool t] [--parameters a,b] [--snapshot id] [--download dir]` | Export a dataset; with `--download`, save the files under `dir/<dataset id>/` |
| `smcpctl observe exports [--json]` | Manifests of the exports |

## Errors

Control API error codes of these routes (`{"error": {"code", "message"}}`):

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Malformed body or query parameter |
| 400 | `bad_query` | Aggregate over an unknown or non-numeric column |
| 400 | `invalid_campaign` | Campaign specification invalid |
| 400 | `bad_export` | Unknown format or parameter, campaign not completed, no snapshot for GraphML |
| 403 | `raw_export_not_granted` | S3 parameter without a campaign raw-export grant |
| 404 | `not_found` | Unknown snapshot, campaign, export or file |
| 409 | `already_promoted` | The snapshot is already promoted |
| 409 | `snapshot_integrity` | The snapshot digest does not match (also recorded as an integrity event) |
| 409 | `invalid_transition` | Campaign action not allowed in its state |
| 409 | `parquet_unavailable` | Parquet export with the JSON Lines store |
| 503 | `observation_disabled` | `[observation] enabled = false` |
| 503 | `store_unavailable` | The store could not be opened |
| 503 | `audit_unavailable` | The action could not be recorded |
| 500 | `store_error`, `snapshot_failed`, `snapshot_error`, `campaign_error`, `export_error` | Internal failure |

Tool-call reason codes added: `APPROVAL_REQUIRED` (existing code, now also from `require_approval_band`) and `ANOMALY_WITHHELD`.

## Limits of this release

- Every tool call emits a span per pipeline stage and per filter run with monotonic time and thread CPU time (FR-10.2, `spans` table; [acceptance.md](acceptance.md)). Instrumented elements other than the edge's evidence events, the spans and the two probes do not emit observables (FR-10.1 is partly verified).
- Observation Policies, Audit Profiles, Anomaly Response Policies and the memory budget are published as numbered revisions (`internal/obspolicy`, console G-03, G-04, G-06, G-08) and apply to the running analytics service when published; baseline contexts and the memory budget, which the running components were built with, apply at the next start of smcpd. They are not part of the signed policy document of E-05. Per-band escalation parameters are part of the Observation Policy; first-N-per-session capture and the overhead budget are not implemented.
- The scorer uses one snapshot for all scopes; the Anomaly Response Policy maps the uncharacterized state to record, escalate or approve (`uncharacterized_action`).
- The Researcher reads aggregates, not raw records: pseudonymized S2 fields in record listings are not implemented, so the raw record route is closed to that role.
- Storage quotas (FR-9.15, health warning at 80%) and the degradation stages under memory or queue pressure (FR-9.12) are implemented; storage tiering (FR-9.13) is deferred from release 1.0 (SRS Appendix N).
- The per-dataset key is kept by E-32 in the key directory, not issued by a separate key manager service.
