# Policy reference

This document describes the policy document, how the Gateway evaluates it, the signed Policy Store that holds published revisions, and the commands that manage them. It is the policy reference of SRS FR-18.5. The control API routes are in [api/policy.md](api/policy.md). The schema is `internal/policy/policy.schema.json` (schema version 1).

Release 1.0 has seven policy object types (FR-3.1). Each is kept by the element that evaluates it:

| Object type | Element | Where it is kept | Fields |
|---|---|---|---|
| Framework Profile | E-05 | Signed policy document (`framework_profiles`) | [Framework Profile](#framework-profile) |
| Session Allow Policy Template | E-05 | Signed policy document (`templates`) | [Template](#template), [Rule](#rule), [Predicates](#predicates) |
| Secret Use Policy | E-20 | `[secrets] use_policy_file`, schema `internal/secrets/usepolicy.schema.json` | [secrets.md, Secret Use Policy](secrets.md#secret-use-policy) |
| Audit Profile | E-24 | Published observation object `audit_profile` | [Audit Profile](#audit-profile) |
| Observation Policy | E-24 | Published observation object `observation_policy` | [Observation Policy](#observation-policy) |
| Anomaly Response Policy | E-24 | Published observation object `anomaly_response` | [Anomaly Response Policy](#anomaly-response-policy) |
| Research Campaign | E-32 | Research Dataset Service campaign file | [Research Campaign](#research-campaign) |

Response Policy and Runtime Profile objects are deferred (FR-3.26). The obligations a decision carries are listed under [Obligations](#obligations).

## Document

```json
{
  "revision": "r2",
  "framework_profiles": {
    "dev": { "templates": ["ro"], "default_template": "ro", "calls_per_minute": 30, "servers": ["fs", "fetch"] }
  },
  "templates": {
    "ro": {
      "description": "Read files and the web",
      "calls_per_minute": 20,
      "calls_per_session": 500,
      "taint_action": "approve",
      "rules": [
        { "id": "fs-read", "server": "fs", "tools": ["read_file", "list_directory"], "side_effect": "read", "source_trust": "trusted",
          "filters": ["path-canonicalize"], "when": [{ "arg": "path", "op": "path_within", "value": ["/home/me/projects"] }] },
        { "id": "web", "server": "fetch", "tools": ["fetch"], "side_effect": "read", "source_trust": "untrusted" },
        { "id": "fs-write", "server": "fs", "tools": ["write_file"], "side_effect": "write", "approval": true, "calls_per_session": 20 },
        { "id": "no-delete", "effect": "deny", "server": "fs", "tools": ["delete_file"] }
      ]
    }
  }
}
```

### Top level

| Key | Required | Meaning |
|---|---|---|
| `revision` | yes | Revision ID, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. Every published document needs a new ID; a published ID can never carry other content. |
| `framework_profiles` | yes, at least one | Map of profile name to Framework Profile. A principal's `profile` in the configuration names one. |
| `templates` | yes, at least one | Map of template name to Session Allow Policy Template. |

### Framework Profile

| Key | Required | Meaning |
|---|---|---|
| `templates` | yes | Templates sessions of this profile may use. Each must exist. |
| `default_template` | yes | Template used when the harness asks for none. Must be in `templates`. |
| `calls_per_minute` | no | Rate bound for calls under this profile (at least 1). |
| `servers` | no | Authority ceiling: the server aliases sessions of this profile may reach through any of its templates. Absent means unrestricted. |
| `high_risk` | no | High-risk tool classes (`general-sql`, `code-execution`, `cad-scripting`, `browser-automation`) the profile's sessions may be granted; see High-risk classes. |
| `remote_allowed` | no | Templates of this profile that sessions created through the Remote Access listener may use (FR-16.12). Each must be in `templates`; a remote sign-in for any other template, including the default, is refused with `invalid_scope` and a `REMOTE_TEMPLATE_REFUSED` event. The configuration's `remote.templates` narrows further: a remote session needs both. Absent or empty: no remote session for this profile. |

A session whose template is no longer listed by its principal's profile in the active revision is denied with `NO_TEMPLATE`, and a session whose profile sets `servers` is denied (`NO_PERMIT`) every server outside it even when its template names one (each layer can only remove authority, SR-1-2).

### Template

| Key | Required | Meaning |
|---|---|---|
| `rules` | yes | Permit and deny rules; may be empty (permits nothing). |
| `description` | no | Free text. |
| `calls_per_minute` | no | Rate bound for calls under this template. |
| `calls_per_session` | no | Quota: permitted calls of one session under this template over its lifetime. |
| `taint_action` | no | `approve` (default) or `deny`: what a tainted session gets for tools whose side-effect class is not `read` (see Session taint). |
| `high_risk` | no | High-risk tool classes this template may grant; see High-risk classes. |

### Rule

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Unique within the template; reported as considered, applicable and decisive rule ID. |
| `server` | yes | Server alias (`^[a-z0-9]{1,16}$`), as in `[[server]] alias`. |
| `tools` | yes | Backend tool names. A deny rule may use `"*"` for every tool of the server; a permit rule may not. |
| `effect` | no | `permit` (default) or `deny`. A deny rule wins over every permit for the same tool (SR-1.4-1) and carries no other keys than `id`, `server`, `tools` and `effect`. |
| `approval` | no | `true` adds an approval obligation (`-31002 APPROVAL_REQUIRED` until approved). Presented tools get the `anthropic/requiresUserInteraction` and `local.smcpgw/approvalRequired` metadata. |
| `calls_per_minute` | no | Rate bound for calls permitted by this rule. |
| `calls_per_session` | no | Quota: calls one session may make through this rule. |
| `side_effect` | no | `read`, `write`, `external` or `execute` (CP-44). Combined with the verified manifest's class; the more restrictive one applies. |
| `source_trust` | no | `trusted` or `untrusted` (CP-44). Combined with the manifest's value; `untrusted` wins. |
| `filters` | no | Optional request and response filter IDs that must run on calls this rule permits. Mandatory filters always run. |
| `egress_limits` | no | Bounds on each outbound operation a server instance makes through the Egress Broker while serving a call this rule permits (FR-5.38): `request_bytes`, `response_bytes` and `timeout_ms` (at least one; each at least 1, `timeout_ms` at most 3,600,000). The broker applies the smallest of these, the limits the server's manifest declares for the destination and the `[egress]` limits and grant. The obligation reaches the broker with the call's one-use egress capabilities; with `[egress] require_capability = false` the tightest obligation of the calls the instance is serving applies (`docs/egress.md`). |
| `when` | no | Argument predicates of a permit rule (at most 32): the rule applies only when every one holds; see Predicates. A deny rule takes none. |

### Predicates

Each `when` entry has an `op` and, for operators on an argument, an `arg`: a top-level argument name, or names separated by `.` for nested objects. The operator set is fixed (SR-1.7-1); a document with another `op` is refused at validation.

| `op` | Other keys | Holds when |
|---|---|---|
| `eq` | `arg`, `value` (string, number or boolean) | The argument equals `value` |
| `in` | `arg`, `value` (list) | The argument equals a member of `value` |
| `range` | `arg`, `min` and/or `max` (numbers) | The argument is a number with `min` ≤ argument ≤ `max` |
| `path_within` | `arg`, `value` (list of absolute paths) | The argument is an absolute path whose canonical form (`.` and `..` resolved) is one of the roots or below one |
| `url_in` | `arg`, `value` (list of `scheme://host[:port]`) | The argument is a URL whose scheme, host and port (the scheme's default when absent) match an entry |
| `data_class_in` | `arg`, `value` (list) | The argument, a data-class label, is in `value` |
| `expiry` | `not_before` and/or `not_after` (RFC 3339) | The decision time is in [`not_before`, `not_after`) |
| `approval` | `value`: `"required"` | Always; the permit carries the approval obligation (the approval state the call needs) |

A predicate whose argument is missing, of the wrong type or malformed does not hold, so the rule does not permit the call: the decision is `NO_PERMIT` with the failed predicate in its record (SR-1.7-2). Because overlapping permits are refused, a call has one candidate permit rule per tool. Predicates are evaluated on the arguments as received and again on the arguments a request filter transformed (re-decision). Policy simulation replays recorded calls without their arguments, so a rule with argument predicates does not permit replayed calls. The effective permission report (`GET /api/v1/policy/revisions/{id}/permissions`) lists each grant's predicates as its argument constraints (FR-3.6).

### High-risk classes

A server declares its tool classes in `[[server]] risk_classes`. Granting a server whose classes include `general-sql`, `code-execution`, `cad-scripting` or `browser-automation` needs that class in `high_risk` on the template and on every framework profile that uses the template: publication refuses the revision otherwise, and a call under a template or profile without the flag is denied with `HIGH_RISK_UNFLAGGED` (SR-3.13-1).

### Publication checks

A document is refused (`policy_invalid`) when it does not match the schema, has unknown keys, names an unknown template in a profile, has a `default_template` outside the profile's `templates`, repeats a rule ID in a template, has two permit rules of one template naming the same server and tool (SR-1.9-1; the error names both rules), puts obligations or classes on a deny rule, uses `"*"` in a permit rule, or has a template granting a server that no framework profile using the template permits through `servers` (SR-1-3; the error names the rule, the server and the profiles).

The capability ceiling check of SR-1-1 is deferred: release 1.0 grants name a server alias and tools only. The objects outside the document are validated by their own elements (below).

## Objects outside the policy document

### Audit Profile

Published with `POST /api/v1/observations/audit-profile` (Policy Author); the latest revision is active ([api/observation.md](api/observation.md#observation-objects)). It sets capture and retention above the mandatory audit floor, which no object changes.

```json
{"retention": "720h", "escalation_parameters": ["request_bytes"]}
```

| Key | Required | Meaning |
|---|---|---|
| `retention` | yes | Observation retention, a Go duration of at least `24h`. |
| `escalation_parameters` | no | Parameter Catalog IDs or names captured in addition for escalated calls. |

### Observation Policy

Published with `POST /api/v1/observations/observation-policy` (Policy Author).

```json
{"policy_id": "lab", "parameters": ["request_bytes", "end_to_end_latency"], "sampling_rate": 0.25,
 "contexts": ["principal", "tool"], "bands": [2, 3, 5], "escalation": {"abnormal": ["argument_entropy"]},
 "features": [{"parameter": "request_bytes", "kind": "numeric", "transform": "log1p", "robust": true, "sigma_floor": 0.5}],
 "scope": {"principals": ["cc"], "frameworks": ["claude-code"], "templates": ["ro"], "servers": ["fs"], "tools": ["fs/read_file"]}}
```

| Key | Required | Meaning |
|---|---|---|
| `policy_id` | yes | Observation Policy ID (1 to 64 characters), recorded with every observation and in the `ObservationPolicy` obligation. |
| `parameters` | yes | Parameter Catalog parameters the collector records (at least one; not periodic parameters). |
| `sampling_rate` | yes | Fraction of calls recorded, above 0 and at most 1. |
| `contexts` | yes | Baseline context keys (for example `principal`, `tool`); applies at the next start. |
| `bands` | no | The three absolute z-score bounds of the `elevated`, `abnormal` and `critical` bands, ascending; empty keeps the configured bands. |
| `escalation` | no | Map of band name to parameters captured in addition for calls in that band and every higher band. |
| `features` | no | Baselined features, replacing the configured ones. Each has `parameter`, `kind` (`numeric` or `categorical`), `transform` (`none`, `log1p`, `box-cox(λ)`), `robust` (median and MAD statistics) and `sigma_floor` (smallest σ used for z). |
| `scope` | no | Calls the policy observes: lists of `principals`, `frameworks` (framework types), `templates`, `servers` and `tools`; an empty list matches all. |

### Anomaly Response Policy

Published with `POST /api/v1/observations/anomaly-response` (Policy Author). Its actions are restrict-only: every band from `elevated` raises an alert.

```json
{"scoring": "sync", "escalate_capture_band": "abnormal", "uncharacterized": "escalate", "require_approval_band": "abnormal", "withhold_band": "critical"}
```

| Key | Required | Meaning |
|---|---|---|
| `scoring` | yes | `async`, `sync` or `off`. Approval and withholding need `sync`. |
| `escalate_capture_band` | no | Lowest band whose calls get escalated capture (`off`, `elevated`, `abnormal`, `critical`; default `elevated`). |
| `uncharacterized` | no | Action for a call whose context has no baseline: `record` (default), `escalate` or `approve`. |
| `require_approval_band` | yes | Lowest band whose calls need approval, or `off`. |
| `withhold_band` | yes | Lowest band whose results are withheld, or `off`. |

The Observation Store memory budget (`memory_budget`, field `observation_memory_limit_bytes`) is published the same way by an Operator; it is a resource setting, not a policy object.

### Research Campaign

Created with `smcpctl observe campaign create --file spec.json` or `POST /api/v1/research/campaigns`, then submitted and approved before it captures anything ([observation.md](observation.md#research-campaigns-and-exports)).

```json
{"name": "latency study", "purpose": "compare read latency across servers",
 "scope": {"principals": ["cc"], "servers": ["fs"], "tools": ["read_file"]},
 "parameters": ["request_bytes", "end_to_end_latency"], "sampling": 1,
 "start": "2026-11-01T00:00:00Z", "end": "2026-11-08T00:00:00Z", "quota_bytes": 50000000, "raw_export_grant": false}
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Campaign name (at most 128 characters). |
| `purpose` | no | Declared research purpose, shown to the approver. |
| `scope` | no | Calls captured: lists of `principals`, `servers` (aliases) and `tools`; an empty list matches all. |
| `parameters` | yes | Parameter Catalog parameters captured. An S3 raw-payload parameter needs `raw_export_grant`. |
| `sampling` | no | Fraction of in-scope calls captured, in (0, 1]; default 1. |
| `start`, `end` | yes | RFC 3339 capture window; `end` after `start`. |
| `quota_bytes` | yes | Storage quota; the campaign completes when it is reached. |
| `raw_export_grant` | no | Grant for S3 raw-payload parameters. |

## Evaluation

The Policy Decision Service evaluates every `tools/call` against the in-memory snapshot of the active revision, in this order. The first failing step decides.

| Step | Outcome | Reason code | Harness error |
|---|---|---|---|
| No verified revision is loaded | deny | `NO_SNAPSHOT` | `-31004` |
| The session's template is not in the revision, or the principal's profile does not list it | deny | `NO_TEMPLATE` | `-31001` |
| The principal's profile sets `servers` and the server is not in it | deny | `NO_PERMIT` | `-31001` |
| More than CP-12 (256) rules of the template name the server | deny | `EVAL_BOUND` | `-31001` |
| The principal is disabled, the credential revoked or expired, the session not active, or the server revision not enabled (SR-1.5-1) | deny | `PRINCIPAL_DISABLED`, `CREDENTIAL_INVALID`, `SESSION_STATE`, `REVISION_NOT_ENABLED` | `-31001`, `-31006` for `SESSION_STATE` |
| No route, or more than one, is eligible for the server and tool revision (SR-1.11-1) | deny | `NO_ROUTE`, `AMBIGUOUS_ROUTE` | `-31001` |
| A deny rule covers the tool | deny | `DENY_RULE` | `-31001` |
| No permit rule names the tool, or a predicate of the permit rule does not hold | deny | `NO_PERMIT` | `-31001` |
| The server has a high-risk class the template or profile does not flag | deny | `HIGH_RISK_UNFLAGGED` | `-31001` |
| Session tainted, tool not `read`, `taint_action` `deny` | deny | `TAINT_DENIED` | `-31001` |
| Evaluation took longer than CP-12 (500 ms) | deny | `EVAL_BOUND` | `-31001` |
| A `calls_per_session` quota of the template or rule is used up | deny | `QUOTA_EXHAUSTED` | `-31005`, `data.callsPerSession` |
| A rate or burst window is full | deny | `RATE_LIMITED` | `-31005`, `data.callsPerMinute`, `data.burst` |
| Otherwise | permit | `PERMIT` | — |

A permit carries the obligations (FR-3.12): approval (from the rule, an `approval` predicate, the approval floor, or session taint with reason `TAINT_APPROVAL`), the rate bound, the burst and the session quota that applied, the rule's request and response filters, and, from the objects outside the document, the effective Audit Profile revision, the Observation Policy, the Anomaly Response Policy revision, the size limit (`result_bytes`, CP-08), the timeout (`upstream_timeout`, CP-13), the server's egress grants and secret grants, and its runtime profile. A refusal consumes no rate window and no quota.

### Obligations

The decision record lists the obligations under `obligations` with these fields (FR-3.12). Several layers can set the same obligation; they combine restrict-only (SR-1.10-1): the union of filters, the smallest rate, burst, quota, size and time bounds, and approval when any layer requires it.

| Obligation type | Field | Source |
|---|---|---|
| Request filters, response filters | `Filters` | The rule's `filters`; mandatory filters run in every case |
| Approval | `Approval`, `ApprovalReason` | The rule's `approval`, an `approval` predicate, the approval floor, session taint (`TAINT_APPROVAL`) or an Anomaly Response Policy band |
| Rate limit | `CallsPerMinute`, `Burst` | Smallest of rule, template, profile and CP-11 |
| Session quota | `CallsPerSession` | Smallest `calls_per_session` of template and rule |
| Audit profile | `AuditProfile` | Active Audit Profile revision |
| Observation policy | `ObservationPolicy` | Active Observation Policy ID |
| Anomaly response | `AnomalyResponse` | Active Anomaly Response Policy revision |
| Size limit | `SizeLimit` | `[limits] result_bytes` (CP-08) |
| Timeout | `Timeout` | `[limits] upstream_timeout` (CP-13) |
| Egress grants | `EgressGrants`, `EgressLimits` | The server's `[[egress.grant]]` destinations; the rule's `egress_limits` (`request_bytes`, `response_bytes`, `timeout_ms`), which the Egress Broker combines with the manifest's and the configuration's limits, the smallest applying (FR-5.38) |
| Secret grants | `SecretGrants` | The Secret Use Policy slots bound for the server |
| Runtime profile | `RuntimeProfile` | The launcher and sandbox profile of the server's instance |

### Approval floor

A tool whose verified manifest declares the side-effect class `write`, `external` or `execute` always carries the approval obligation, whatever the rule says (SR-1.18-1): these classes cover the approval triggers of the security SRS (file and repository mutation, external transmission, code execution). A policy can add approvals with `approval: true` but cannot remove the floor. Tools of an unverified live tool list have no manifest class, so the floor does not apply to them; a rule's own `side_effect` affects taint, not the floor.

### Re-decision after a transforming filter

When a request filter transforms the arguments, the call is decided again before approval and launch (SR-5.12-1). The second decision does not count against rate windows or quotas. It governs the approval, which is therefore requested for the transformed arguments (SR-1.18-3), and the launch capability; its decision record carries `superseded_decision_id` and `redecision_reason: "arguments_transformed"`.

### Decision records

Every `decision` event (the deny, or the permit committed at launch authorization) and every approval refusal carries the decision record in its `detail`: outcome, reason code, template, route, the considered, applicable and decisive rule-revision IDs (`<policy revision>/<template>/<rule id>`), the effective obligations, the side-effect class and source trust, and, for an approval added by the Anomaly Scorer, `anomaly_obligation` with the baseline snapshot ID (SR-1.12-3). `GET /api/v1/decisions/{id}/explanation` returns it with the anomaly events of the call (SR-1.19-1, `docs/api/policy.md`).

### Rates, bursts and quotas

The rate bound of a call is the smallest of the rule's, the template's and the profile's `calls_per_minute` and the configuration's `[limits] principal_calls_per_minute` (CP-11, default 60). It is applied as a one-minute sliding window to three counters at once: the principal, the session, and the session's calls of that tool (FR-3.13).

The burst (`[limits] principal_call_burst`, CP-11, default 10; 0 disables it) limits each of the same counters to at most `burst` calls in any window of `burst / bound` minutes; with the defaults, 10 calls in any 10 seconds. The burst is never larger than the bound.

Quotas count permitted calls per session: `calls_per_session` on a template counts every call of the session under that template, on a rule the calls through that rule. Quota state ends with the session. Quotas are counted when the decision permits, so a call later refused by approval, a filter or the backend still counts.

### Session taint

Taint is restrict-only (SR-5.13-2, ARCH §7.1 layer 5). When the result of a call whose effective `source_trust` is `untrusted` is released to a session, the session is tainted until it ends. In a tainted session, every call of a tool whose effective side-effect class is not `read` gets an approval obligation with reason `TAINT_APPROVAL`, or is denied with `TAINT_DENIED` when the template's `taint_action` is `deny`. Taint never removes an obligation and never turns a deny into a permit.

The effective classes combine the rule's `side_effect` and `source_trust` with the classes of a verified manifest (the `local.smcpgw/sideEffect` and `local.smcpgw/sourceTrust` tool metadata set by a verified ManifestSource): the more restrictive side-effect class (`read` < `write` < `external` < `execute`) and `untrusted` over `trusted`. A live, unverified tool list is not trusted to classify itself. A tool with no class is treated as not `read` (gated), and only an explicit `untrusted` taints a session.

`execute` tools are gated as well as `write` and `external`.

## Policy Store

Published revisions are kept in the state directory (D-01):

| Path | Contents |
|---|---|
| `keys/policy.key` | Ed25519 policy-signing key, hex seed, mode 0600. Created on first start. |
| `keys/policy.pub` | Its public key. The key ID is the first 16 hex digits of its SHA-256. |
| `policy/revisions/<digest>.json` | One revision: the record, the canonical document and the signature. `<digest>` is the SHA-256 of the canonical document. Mode 0400; created exclusively and never rewritten. |
| `policy/active.json` | Signed policy-control record naming the active revision, its digest, a sequence number, the actor and the time. |

The canonical document is the JSON with object keys sorted, numbers as written and no insignificant whitespace; two documents with the same content have the same digest.

At start the Gateway verifies the control record and the active revision: both signatures, the file name against the digest, and the document against the schema. If the store is empty, the configured `[policy] file` is validated, stored as the first revision (origin `import`) and activated; after that the file is only read by `smcpctl policy reload`. If verification fails, the Gateway starts fail-closed: health is `fail-closed` with cause `policy_signature` (a signature does not verify, a file is missing or altered) or `policy_invalid` (the signed document fails the schema, field, enumeration or cross-reference checks, for example after an upgrade that tightened them), every call is refused with `-31004 NO_SNAPSHOT`, and the event `POLICY_SIGNATURE` is recorded. Restore the file from a backup and restart, or publish a valid revision.

Activation writes the new control record to a temporary file, flushes it, renames it over `active.json` and flushes the directory before the decision snapshot is swapped (SR-1.15-1). The swap happens under the Enforcement Coordinator's barrier, so every launch authorization sees one revision. After the swap each cached session catalog is updated in place, and sessions with an open `subscriptions/listen` stream that asked for `toolsListChanged` receive `notifications/tools/list_changed`. Other clients see the new catalog when their cached `tools/list` expires (`catalog_ttl_ms`). A session may hold `[limits] listen_streams_per_session` listen streams at once (CP-20, default 2; FR-1.38), and the Gateway at most 256; a further `subscriptions/listen` gets HTTP 429 with `-31005` and reason code `LISTEN_LIMIT`. A stream whose reader does not take an event within 10 seconds is ended.

## Commands

All commands take `--config <file>` (default `smcp.toml`). `validate` runs offline; the others call the running Gateway's control API with the operator token from the state directory.

| Command | Effect |
|---|---|
| `smcpctl policy validate <file>` | Validate a document; print its revision, digest and counts. |
| `smcpctl policy diff <file> [--from <rev>] [--json]` | Compare a document with the active revision (or `--from`). |
| `smcpctl policy diff --to <rev> [--from <rev>] [--json]` | Compare two published revisions. |
| `smcpctl policy simulate <file> [--scenario <file.jsonl>] [--limit N] [--all] [--json]` | Replay recent journal calls (default 1000) or a scenario file against the active revision and the document; print the decisions that change and a simulation ID. |
| `smcpctl policy publish <file> [--parent <rev>] [--simulation <id>]` | Sign, store and activate the document. `--parent` refuses unless that revision is active. |
| `smcpctl policy rollback <rev> [--as <new-rev>]` | Publish the content of `<rev>` as a new revision (default ID `<rev>-rb<n>`). |
| `smcpctl policy history [--json]` | List revisions, newest first; `*` marks the active one. |
| `smcpctl policy show [rev] [--document]` | Show a revision record and document (default the active revision); `--document` prints only the canonical document (export). |
| `smcpctl policy reload` | Publish the configured `[policy] file`. |

### Simulation

A simulation replays fixtures in time order against two fresh deciders, one with the active revision and one with the candidate. Rate windows run on the fixtures' recorded times, and a permitted call of an untrusted-source tool taints its session on that side, so later fixtures see the taint obligation as they would live. The live 500 ms deadline is not applied during replay.

Journal fixtures are taken from the `requested` events of tool calls, which record the server, tool, template, profile and the manifest's classes. Calls recorded before this version have no such detail and are skipped.

A scenario file has one JSON object per line; blank lines and lines starting with `#` are skipped; unknown keys are an error.

```json
{"time": "2026-10-16T20:00:00Z", "principal": "cc", "session": "s1", "profile": "dev", "template": "ro", "server": "fs", "tool": "write_file", "side_effect": "write", "source_trust": "trusted"}
```

`template`, `server` and `tool` are required; `principal` and `session` default to `simulated`; `time` defaults to the epoch (all fixtures without a time share one rate window).

## Configuration keys

| Key | Default | Meaning |
|---|---|---|
| `[policy] file` | `policy.json` | Document imported at first start and published by `smcpctl policy reload`. |
| `[limits] principal_calls_per_minute` | 60 | CP-11 default rate bound. |
| `[limits] principal_call_burst` | 10 | CP-11 burst; 0 disables the burst window. |

## Evidence

| Reason code | Outcome | When |
|---|---|---|
| `POLICY_IMPORTED` | `imported` | The policy file became the first revision |
| `POLICY_PUBLISHED` | `published` | A revision was stored (before activation) |
| `POLICY_ROLLED_BACK` | `published` | A rollback revision was stored |
| `POLICY_ACTIVATED` | `activated` | The decision snapshot was swapped (Enforcement Coordinator) |
| `POLICY_INVALID` | `rejected` | A document failed validation at publication |
| `POLICY_CONFLICT` | `rejected` | Revision ID conflict or stale parent |
| `POLICY_ACTIVATION_FAILED` | `rejected` | The swap failed; the previous control record was restored |
| `POLICY_SIMULATED` | `simulated` | A simulation ran; detail has its ID and counts |
| `POLICY_SIGNATURE` | `refused` | The active revision did not verify at start |

All are `admin` events with origin `E-05`, except `POLICY_ACTIVATED`, which also has origin `E-05` and is written by the Gateway under its barrier.

## Not implemented

Draft workspaces (FR-3.3), Response Policy and Runtime Profile objects (FR-3.26), routes other than the server alias (SR-1.11-1) and manifest ceiling checks at publication (SR-1-1) are deferred from release 1.0 (SRS Appendix N).
