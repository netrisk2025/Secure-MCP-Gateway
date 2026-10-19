# Graph mirror (Neo4j)

The graph mirror holds a copy of the evidence journal as a graph of sessions, principals, calls, decisions, approvals and policy, server and tool revisions, for the console graph views (G-05, G-14) and investigation queries. It implements the graph side of the Data Server: E-25 Graph Database Engine (Neo4j Community Edition), E-26 Data Access Service and the graph part of E-28 Data Lifecycle & Memory Manager.

The graph is a mirror, not an authority (ARCH A-9). The signed evidence journal stays the record that `smcpctl journal verify` checks. When the database is stopped, unreachable or slow, tool calls are served exactly as before; the mirror reports `unavailable` and catches up from the journal when the database returns.

## Engine version

Neo4j Community Edition **2026.05.0** (GPLv3). No Enterprise, Aura or plugin features are used (FR-12.11).

- macOS: `brew install neo4j` (Homebrew ships 2026.05.0 at the time of writing; check with `brew list --versions neo4j`), then `brew services start neo4j`.
- Linux or CI: the container image `neo4j:2026.05.0-community`.

## Setting up the database

1. Apply the hardening and memory settings. `smcpctl graph config` prints the `neo4j.conf` lines for the configured budget:

   ```
   $ smcpctl graph config --config smcp.toml
   # Secure MCP Gateway graph engine settings (SR-4.2-1, SR-7.4-1, FR-9.10).
   server.default_listen_address=127.0.0.1
   server.bolt.enabled=true
   server.bolt.listen_address=127.0.0.1:7687
   server.http.enabled=false
   server.https.enabled=false
   dbms.usage_report.enabled=false
   dbms.security.allow_csv_import_from_file_urls=false
   dbms.security.procedures.unrestricted=
   server.memory.heap.initial_size=1g
   server.memory.heap.max_size=1g
   server.memory.pagecache.size=1g
   ```

   Append them to `neo4j.conf` (Homebrew: `$(brew --prefix)/Cellar/neo4j/<version>/libexec/conf/neo4j.conf`) and restart the engine. With the HTTP connector disabled, use `cypher-shell` for administration.

2. Create a dedicated database user for the Gateway, so that the Gateway never holds the `neo4j` administrator password:

   ```
   cypher-shell -a bolt://127.0.0.1:7687 -u neo4j -d system \
     "CREATE USER smcp_graph SET PASSWORD 'choose-a-long-password' CHANGE NOT REQUIRED"
   ```

   Community Edition has no role-based access control: every user can read and write every database. The separation therefore rests on the listener being loopback-only and on the Gateway's Data Access Service being the only holder of this password. Fine-grained database privileges need Enterprise Edition and are not used.

3. Write the password to the password file, readable only by the Gateway's user:

   ```
   umask 077
   printf '%s\n' 'choose-a-long-password' > <state>/graph/password
   chmod 600 <state>/graph/password
   ```

   The Gateway refuses a password file that is readable by group or others.

4. Enable the mirror in `smcp.toml` and restart `smcpd`:

   ```toml
   [graph]
   enabled = true
   ```

## Configuration: `[graph]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Run the mirror. When false, events are ignored and the `/api/v1/graph*` routes answer `graph_disabled`. |
| `uri` | `bolt://127.0.0.1:7687` | Bolt URI. Only loopback hosts (`127.0.0.1`, `localhost`, `[::1]`) are accepted (SR-4.2-1). Schemes `bolt`, `neo4j`, with optional `+s` or `+ssc`. |
| `username` | `smcp_graph` | Database user. |
| `password_file` | `graph/password` | Password file; relative paths are under the state directory. Mode must deny group and others. |
| `database` | `neo4j` | Database name (Community Edition has one user database). |
| `retention` | `720h` (30 days) | Mirrored events older than this are deleted, and are not re-created by a catch-up or rebuild. At least `1h`. |
| `retention_interval` | `24h` | How often retention runs. At most `24h`. Retention also runs once after each successful connect. |
| `catchup_interval` | `60s` | How often the mirror re-reads the journal from its checkpoint, to recover events dropped from its queue. |
| `memory_interval` | `5s` | How often the engine heap is sampled (FR-9.11). |
| `batch_size` | `500` | Events per write transaction (1 to 5000). Live events wait at most 200 ms for their batch. |
| `queue` | `4096` | Events buffered between the journal and the mirror (16 to 1048576). A full queue drops the event from the live path only; the next catch-up applies it from the journal. |
| `heap_bytes` | `1073741824` (1 GiB, CP-33) | Heap budget of the engine. Checked against `server.memory.heap.max_size`; heap use above 90% of it sets `memory.pressure`. |
| `page_cache_bytes` | `1073741824` (1 GiB, CP-33) | Page cache budget, checked against `server.memory.pagecache.size`. |
| `require_hardening` | `false` | When true, any finding of the engine configuration check refuses the mirror (state `refused`). When false, findings are logged and shown in `smcpctl graph status`. |

## How the mirror works

- **Feed.** The mirror is an evidence observer: after the journal accepts an event, the mirror queues it without blocking. A worker writes batches through the Data Access Service in one managed transaction each.
- **Idempotence.** Every node is written with `MERGE` on an ID taken from the event (event ID, session ID, correlation ID, decision ID, revision IDs). Applying an event twice changes nothing; a uniqueness constraint on `id` exists for every Appendix D label.
- **Catch-up.** On connect, every `catchup_interval`, and after any write failure, the mirror reads the journal from its checkpoint (the first segment not yet fully applied). Sealed segments advance the checkpoint; the open segment (at most 1,000 events) is re-applied, which is harmless. The checkpoint is a `Checkpoint` node with ID `journal-mirror`.
- **Outage.** While the database is down the mirror retries with backoff from 1 s to 60 s, discards live events (the journal has them) and reports `unavailable`. No call waits on it.
- **Schema.** Ordered migrations run at connect: `0001_constraints` (uniqueness on `id` for all 30 Appendix D labels) and `0002_indexes` (decision timestamp, event timestamp, event correlation ID, event session ID, event server revision, and the `lastSeen` indexes used by retention). The applied version is the `Checkpoint` node with ID `schema`. A database whose version is newer than the release supports is refused (state `refused`, until restart).
- **Templates.** Every statement comes from `internal/graph/templates/templates.cypher`, verified at startup against `MANIFEST.sha256`. Callers name an operation and pass parameters; parameters are validated against the operation's declaration and bound as values. There is no way to send query text, labels or procedure names.
- **Retention.** In bounded batches of 1,000 per transaction: audit events older than `retention`, then decisions, approvals, calls and sessions older than `retention` that no remaining event references. Principals and policy, server and tool revisions are kept.
- **Rebuild.** `smcpctl graph rebuild` deletes the mirrored labels and the checkpoint and replays the whole journal (honouring `retention`). Use it after restoring a backup or when the graph was changed by hand. Behavior-model labels owned by other elements are not touched.

## Graph model

Mirrored labels and their properties:

| Label | ID | Properties |
|---|---|---|
| `AuditEvent` | event ID | `ts` (Unix ns), `time`, `class`, `phase`, `origin`, `outcome`, `reasonCode`, `policyStatus`, `correlationId`, `sessionId`, `principalId`, `decisionId`, `serverRevision`, `toolRevision`, `policyRevision` |
| `Session` | session ID | `principalId`, `state`, `endReason`, `revisionId`, `observationPolicyId` and `contextKey` (from the creation event, FR-2.13) |
| `Principal` | principal ID | — |
| `Invocation` | correlation ID | `sessionId`, `principalId`, `serverRevision`, `toolRevision`, `phase`, `outcome`, `reasonCode` (latest event) |
| `Decision` | decision ID | `ts`, `outcome` (`permit` or `deny`), `reasonCode`, `revisionId`, `correlationId`, `sessionId` |
| `PolicyRevision` | revision | `activatedAt` |
| `PolicyControl` | `control` | `activeRevisionId` |
| `ServerRevision`, `ToolRevision` | revision | `name` (tool) |
| `Approval` | approval ID | `sessionId`, `state`, `argsDigest`, `expiresAt`, `approver`, `publicName`, `correlationId` |
| `RuleRevision` | `<policy revision>/<template>/<rule>` | `parentId` (the policy revision) |
| `PolicyObject` | observation object revision, for example `audit_profile@3` | `type` (`audit_profile`) |

Every mirrored node also has `firstSeen` and `lastSeen` (Unix ns of the events that touched it). Properties are applied only from an event at least as new as `lastSeen`, so replaying older events never regresses a state. Relationships: `IN_SESSION`, `OF_PRINCIPAL`, `FOR_INVOCATION`, `FOR_DECISION`, `OBSERVED_FROM`, `RECORDED_UNDER`, `INVOKED`, `AUTHORIZED_BY`, `EVALUATED_UNDER`, `TARGETED`, `BELONGS_TO`, `CONTAINS` (policy revision to rule revision), `CONSIDERED_RULE`, `APPLICABLE_RULE` and `DECIDED_BY` (decision to rule revision), and `RECORDED_UNDER` from a decision event to the effective Audit Profile revision (SRS Appendix D). The event path query (`GET /api/v1/graph/events/{id}/path`) returns, with the decision, the decision's decisive rule revisions (`decisiveRules`) and Audit Profile revision (`auditProfile`), so every evaluated-request event reaches its decision, policy revision, decisive rules, server and tool revisions and audit profile (SR-6.4-1). No tool arguments or results are mirrored.

## Commands

All commands take `--config <file>` (default `smcp.toml`). Every command except `config` talks to the running Gateway with the operator token.

| Command | Does |
|---|---|
| `smcpctl graph status [--json]` | State, last error, schema version, template set version and digest, journal checkpoint, live applied and dropped counts, retention and rebuild results, memory, node counts, engine configuration findings. |
| `smcpctl graph rebuild [--yes]` | Queues a rebuild after confirmation; the request is recorded in the journal (`class admin`, `reason_code GRAPH_REBUILD`, origin E-26). Follow progress with `status`. |
| `smcpctl graph query` | Lists the canned queries. |
| `smcpctl graph query <name> [--param name=value] [--limit n] [--json]` | Runs a read-only canned query; `--limit` 1 to 500, default 50. |
| `smcpctl graph neighborhood <label> <id> [--limit n] [--json]` | One-hop neighborhood of a node. Labels: `AuditEvent`, `Session`, `Principal`, `Invocation`, `Decision`, `PolicyRevision`, `ServerRevision`, `ToolRevision`, `Approval`. |
| `smcpctl graph config` | Prints the `neo4j.conf` hardening and memory lines (offline). |

Canned queries:

| Name | Parameters | Rows |
|---|---|---|
| `recent_sessions` | — | `session`, `principal`, `state`, `firstSeen`, `lastSeen`, `calls` |
| `recent_denials` | — | `decision`, `ts`, `reasonCode`, `session`, `correlationId`, `policyRevision` |
| `tool_usage` | — | `toolRevision`, `calls`, `lastSeen` |
| `call_timeline` | `correlationId` | `event`, `ts`, `class`, `phase`, `origin`, `outcome`, `reasonCode` |
| `principal_activity` | — | `principal`, `sessions`, `calls`, `lastSeen` |
| `policy_revisions` | — | `policyRevision`, `activatedAt`, `decisions`, `lastSeen` |
| `approvals` | — | `approval`, `state`, `tool`, `session`, `lastSeen` |

Parameter values may contain letters, digits and `._:@/+-`, up to 256 characters.

## States and findings

| State | Meaning |
|---|---|
| `disabled` | `[graph] enabled = false`. |
| `connecting` | Connecting, reading engine settings or migrating. |
| `ready` | Mirroring. |
| `unavailable` | The database cannot be reached or a write failed; retried with backoff. `error` says why (for example a missing password file). |
| `refused` | The database schema is newer than this release, or `require_hardening` is set and the configuration check found problems. Fix the cause and restart `smcpd`. |

Configuration findings name the setting, its value, the wanted value and the requirement: HTTP and HTTPS connectors disabled, usage reporting disabled, file-URL CSV import disabled, no unrestricted procedures (SR-7.4-1), loopback listen addresses (SR-4.2-1), heap and page cache within the budget (FR-9.10). A setting absent from the engine's effective configuration is reported as `(unset)`. Inside a container the listen address is `0.0.0.0` by necessity; publish the port on `127.0.0.1` only.

## Control API

See [api/graph.md](api/graph.md).

## Not covered yet

- nftables rules that admit only the Data Server identity to the engine port, and outbound network denial for the engine (SR-4.2-1, SR-7.4-1, Linux Enforced profile).
- Unix-socket peer-credential authentication of calling elements and a per-element operation allowlist (SR-4.3-1); the Data Access Service runs inside `smcpd`.
- Write priority classes (FR-9.4) are deferred from release 1.0 (SRS Appendix N); observation batching and backpressure (FR-9.5, FR-9.6) are in the Observation Store and Collector ([observation.md](observation.md)).
- Page cache use is not measured (Community Edition exposes no page-cache JMX bean); only the configured size is reported. Memory budgets of the other components and the degradation order (FR-9.12) are applied by the observation stack ([observation.md](observation.md)).
- The mirror registers a health check that reports `degraded`, never `fail-closed`, when the engine is unavailable; `smcpctl graph status` shows the detail.
- Backups do not include a graph dump, and restore does not rebuild the mirror (FR-9.16 and SR-7.8-1 are partly verified); run `smcpctl graph rebuild` after a restore, which replays the journal.
- Mirroring the Policy Store and Server Registry contents (rule, route and package revisions) beyond the revision IDs carried by events.
