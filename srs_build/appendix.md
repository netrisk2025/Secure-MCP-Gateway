## Appendix A — Controlled parameters (CP)

Values marked **SEC** are inherited from `MCP_Gateway_Security_SRS.md` Appendix A. Values marked **ARCH** come from `ArchitectureV2.md`. Changing a value requires a controlled revision of this SRS.

| ID | Parameter | Value | Origin |
|---|---|---|---|
| CP-01 | Northbound MCP endpoint path | `/mcp` | New |
| CP-02 | Harness listeners | TLS: `127.0.0.1:8443`; UDS (profile): `/run/smcp/harness.sock` | New |
| CP-03 | Admin listener | `127.0.0.1:9443` (TLS) | New |
| CP-04 | Northbound supported protocol versions | `["2026-07-28", "2025-11-25"]`, both served in the baseline | SEC 5.1 |
| CP-05 | Southbound protocol eras | Modern `2026-07-28`; legacy `2025-11-25` | SEC 5.1 |
| CP-06 | Header limit / header deadline | 16 KiB / 5 s | SEC |
| CP-07 | Request body limit / body deadline | 1 MiB / 15 s | SEC |
| CP-08 | Expanded result size / JSON depth | 8 MiB / 32 | SEC |
| CP-09 | Connections / unauthenticated work / per-source rate | 128 / 32 concurrent / 10 req/s, burst 20 | SEC |
| CP-10 | Tool concurrency / queue | 4 per principal, 16 total / 32 | SEC |
| CP-11 | Default principal tool rate | 60 calls/min, burst 10 | SEC |
| CP-12 | Decision deadline / candidate rules | 500 ms / 256 | SEC |
| CP-13 | Upstream execution / client deadline | 45 s / 60 s | SEC |
| CP-14 | Required filter deadline | 2 s per profile | SEC |
| CP-15 | Credential lifetime / rotation overlap | 30 days / ≤ 24 h | SEC |
| CP-16 | Revocation propagation | ≤ 2 s | SEC |
| CP-17 | Approval lifetime | ≤ 5 min, one use | SEC |
| CP-18 | Session max lifetime / idle timeout / concurrent sessions per principal | 8 h / 30 min / 8 | New |
| CP-19 | Catalog `ttlMs` / page size | 60,000 ms / 100 tools | New |
| CP-20 | Listen keep-alive / listen streams per session | 15 s / 2 | New |
| CP-21 | Progress relay rate | ≤ 10 notifications/s per request | New |
| CP-22 | Gateway error codes | Appendix B | New |
| CP-23 | Gateway metadata names | `_meta` prefix `local.smcpgw/`; session token in `Authorization: Bearer` (RFC 6750 header only) on the TLS listener and `_meta["local.smcpgw/session"]` on the UDS listener; egress header `Smcp-Egress-Auth` | New |
| CP-24 | Default instance budget | 512 MiB RAM, 1 CPU, 128 PIDs | SEC |
| CP-25 | Retention defaults | Metadata 90 d; payload 7 d; temporary full capture ≤ 24 h | SEC |
| CP-26 | Audit/evidence quota | 10 GiB; warn at 80% | SEC |
| CP-27 | Journal export lag | Target 5 s; stop at > 60 s or > 1,000 events | SEC |
| CP-28 | Argon2id | 64 MiB, t = 3, p = 1, salt ≥ 16 B | SEC |
| CP-29 | Admin session | 15 min idle, 8 h absolute | SEC |
| CP-30 | Anomaly defaults | Bands: normal \|z\| < 2, elevated < 3, abnormal < 4, critical ≥ 4; n_min = 30; σ_floor from catalog | ARCH §9.2 |
| CP-31 | Sampling defaults | Normal band 10%; elevated and above 100% | ARCH §9.5 |
| CP-32 | Performance targets | Decision p95 ≤ 10 ms (ceiling 100 ms); scoring p95 ≤ 2 ms; capture ≤ 1 ms; overhead p95 ≤ 50 ms (ceiling 250 ms); ingest ≥ 2,000 rec/s; snapshot ≤ 60 s / 10k contexts; GUI query p95 ≤ 2 s; idle RSS ≤ 4 GiB | ARCH §14; SEC |
| CP-33 | Default memory budget | Graph heap 1 GiB; graph page cache 1 GiB; DuckDB 512 MiB; baseline cache 128 MiB; capture queues 64 MiB; Gateway core 512 MiB | New |
| CP-34 | Revocation feed maximum staleness | 24 h | New |
| CP-35 | Artifact re-verification | At every instance launch | ARCH §4 E-13 |
| CP-36 | Schema validation bounds | Depth 32; 1,000 subschemas; 50 ms | New |
| CP-37 | stderr capture | 64 KiB per call; 1 MiB ring per instance | New |
| CP-38 | Instance idle teardown | 10 min | New |
| CP-39 | MRTR `requestState` lifetime | 5 min | New |
| CP-40 | Research pseudonym function | HMAC-SHA-256, per-dataset key | ARCH §4 E-32 |
| CP-41 | OAuth parameters | Authorization-code grant; PKCE `S256` only; resource URI `https://127.0.0.1:8443/mcp`; scope prefix `smcp:` with `template`, `purpose`, `project`, `user`; access-token lifetime = CP-18 idle timeout; refresh-token lifetime = CP-18 maximum lifetime; client-secret lifetime = CP-15; `iss` in authorization responses | New |
| CP-42 | Public tool names | `<alias>_<tool>`; alias `[a-z0-9]{1,16}`; tool part `[A-Za-z0-9_]`; whole name ≤ 64 characters | New |
| CP-43 | Adapter credential file | `$XDG_CONFIG_HOME/smcp/credentials.toml` (default `~/.config/smcp/`), mode 0600; refresh at 50% of access-token lifetime | New |

## Appendix B — Gateway error codes

Gateway-specific codes lie outside the JSON-RPC reserved range (`-32768` to `-32000`), as the MCP specification recommends. Every error carries `data.reasonCode` and `data.correlationId`, plus `data.decisionId` when a decision exists (FR-1.20).

| Code | Name | HTTP status (Streamable HTTP) | Meaning |
|---|---|---|---|
| `-31001` | PolicyDenied | 200 | The policy decision denied the request |
| `-31002` | ApprovalRequired | 200 | A human approval is pending; retry after approval (`data.approvalId`, `data.expiresAt`) |
| `-31003` | ResponseWithheld | 200 | The response was withheld by response inspection, scoring or release checks |
| `-31004` | GatewayFailClosed | 503 | Enforcement dependencies are unavailable or the Gateway is stopped |
| `-31005` | RateLimited | 429 | A rate, concurrency, queue or stream limit was reached |
| `-31006` | SessionInvalid | 401 | Missing, invalid, expired, suspended or misbound session |
| `-31007` | BackendError | 200 | The backend failed or returned a protocol error (`data.backendCode`) |
| `-31008` | Timeout | 200 | The client deadline expired |
| `-31009` | IndeterminateOutcome | 200 | A possibly executed mutation lost its outcome; it is not retried |
| `-31010` | InputRequiredUnsupported | 200 | The backend requested client input and the MRTR Relay Profile is disabled |

Standard codes used: `-32700`, `-32600`, `-32601`, `-32602`, `-32603`, `-32020` (HeaderMismatch), `-32022` (UnsupportedProtocolVersion).

## Appendix C — Application role matrix

| Operation | Administrator | Operator | Policy Author | Approver | Auditor | Researcher |
|---|---|---|---|---|---|---|
| Emergency stop / resume | Stop + resume | Stop | — | — | — | — |
| View health and status | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Edit, simulate policy drafts | ✓ | — | ✓ | — | — | Observation drafts and campaigns only |
| Publish / roll back policy | ✓ | — | ✓ | — | — | — |
| Approve research campaign | ✓ | — | ✓ | — | — | — |
| Decide tool-call approvals | ✓ | — | — | ✓ | — | — |
| Enable / suspend / retire servers; aliases | ✓ | Suspend only | — | — | — | — |
| Enroll trust anchors | ✓ | — | — | — | — | — |
| Principals, credentials, sessions | ✓ | Suspend/terminate sessions | — | — | — | — |
| Secret create / rotate / revoke | ✓ | — | — | — | — | — |
| Audit query and redacted export | ✓ | ✓ | ✓ | — | ✓ | — |
| Observation analytics (S0/S1) | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| Observation S2 fields | ✓ | — | ✓ | — | ✓ | Pseudonymized |
| Payload (S3) access | Separate grant | — | — | — | Separate grant | Campaign grant only |
| Baseline promotion / rollback | ✓ | — | ✓ | — | — | — |
| Memory budgets, backups | ✓ | ✓ | — | — | — | — |
| Dataset export | ✓ | — | — | — | — | ✓ (approved campaigns) |
| Purge | ✓ | — | — | — | — | — |

Harness principals have no control-plane role (SR-2.5-1).

## Appendix D — Graph data model

Every label has a uniqueness constraint on `id` (FR-9.1). Required-property and cardinality checks are enforced by the Data Access Service (SR-7.3-1), because Community Edition lacks Enterprise existence constraints.

| Node label | Key properties | Owner |
|---|---|---|
| `Principal`, `CredentialRef` | id, frameworkType, enabled, profileId, certThumbprint, expiry, revocationEpoch | E-03, E-22 |
| `Session` | id, principalId, templateId, revisionId, observationPolicyId, contextKey, state, created, expires | E-04 |
| `Server`, `ServerRevision`, `ToolRevision` | id, alias, version, artifactDigest, manifestDigest, state, riskClass, sideEffectClass, era | E-14 |
| `ImportReceipt`, `TrustAnchor` | id, signer, results / fingerprint, scope, expiry | E-13, E-22 |
| `PolicyControl` | activeRevisionId, revocationEpoch, stopEpoch | E-12 |
| `PolicyRevision`, `PolicyObject`, `RuleRevision`, `RouteRevision` | id, parentId, digest, schemaVersion, type, effect, predicates | E-05 |
| `Approval` | id, sessionId, argsDigest, state, expiresAt, approver | E-07 |
| `Decision`, `Invocation` | id, outcome, reasonCode, revisionId, snapshotId, correlationId | E-06, E-12 |
| `AuditEvent`, `PayloadRef`, `OutboxRecord`, `Checkpoint` | id, class, phase, origin, policyStatus / digest, keyRef | E-21 |
| `SecretRef`, `SecretUse` | id, slot, mode, version (no value) | E-19, E-20 |
| `BaselineContext`, `FeatureStat`, `BaselineSnapshot`, `AbnormalEvent` | id, dims / feature, n, mean, m2 / digest, promoted | E-30, E-31 |
| `Parameter`, `CatalogVersion` | id, name, unit, sensitivity, cost | E-05 |
| `Campaign`, `Dataset` | id, state, scope, quota / checksum | E-32 |

| Relationship | From → To |
|---|---|
| `CONTAINS` | PolicyRevision → PolicyObject, RuleRevision, RouteRevision |
| `APPLIES_TO` | RuleRevision → ToolRevision |
| `BELONGS_TO` | ToolRevision → ServerRevision; ServerRevision → Server |
| `SELECTS_ROUTE` | RuleRevision → RouteRevision |
| `REQUIRES_AUDIT`, `REQUIRES_OBSERVATION` | RuleRevision → PolicyObject |
| `EVALUATED_UNDER`, `DECIDED_BY`, `CONSIDERED_RULE`, `APPLICABLE_RULE` | Decision → PolicyRevision / RuleRevision |
| `TARGETED`, `SELECTED_ROUTE` | Decision → ServerRevision / RouteRevision |
| `SCORED_AGAINST` | Decision → BaselineSnapshot |
| `AUTHORIZED_BY` | Invocation → Decision |
| `FOR_DECISION`, `FOR_INVOCATION`, `OBSERVED_FROM`, `RECORDED_UNDER`, `HAS_EXPORT` | AuditEvent → Decision / Invocation / ServerRevision / PolicyObject / OutboxRecord |
| `IN_SESSION`, `OF_PRINCIPAL` | Decision, Session → Session, Principal |
| `HAS_CONTEXT`, `HAS_STAT`, `INCLUDES`, `IN_CONTEXT`, `NEXT_TOOL` | Principal/ToolRevision → BaselineContext → FeatureStat; BaselineSnapshot → FeatureStat; AbnormalEvent → BaselineContext; ToolRevision → ToolRevision |
| `USES_SECRET` | SecretUse → SecretRef, Decision |
| `VERIFIED_BY`, `SIGNED_BY` | ServerRevision → ImportReceipt → TrustAnchor |
