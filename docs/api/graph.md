# Control API: graph

Routes of the graph mirror (E-25, E-26, E-28) on the control API (admin listener, CP-03). The listener's rules apply: loopback TLS, `Host` must name the admin listener, a foreign `Origin` or cross-site `Sec-Fetch-Site` is refused with 403 `origin_refused`, POST bodies must be `application/json`. The roles that may use each route are those of the role matrix in [console.md](console.md#roles) (Appendix C), also listed per operation as `x-smcp-roles` in `GET /api/v1/openapi.json`; reads are open to the Operator, Policy Author and Auditor, a rebuild to the Operator. A missing token gets 401 `unauthenticated`, a token of a role the route does not admit 403 `role_refused`.

Errors have the form `{"error": {"code": "<code>", "message": "<text>"}}`:

| Status | Code | When |
|---|---|---|
| 400 | `invalid_parameter` | A parameter is missing, malformed, out of range (`limit` 1 to 500) or not declared by the query |
| 400 | `invalid_label` | `label` is not a neighborhood label |
| 404 | `not_found` | No node with that label and ID |
| 404 | `unknown_query` | No canned query with that name |
| 409 | `rebuild_queued` | A rebuild is already queued |
| 502 | `graph_error` | The database rejected the statement |
| 503 | `graph_disabled` | `[graph] enabled = false` |
| 503 | `graph_unavailable` | The database is unavailable; enforcement is not affected |
| 503 | `audit_unavailable` | The rebuild request could not be recorded in the journal |

## GET /api/v1/graph/status

Query: `detail=0` omits `counts` and `schema` (default includes them when the mirror is ready).

Response 200:

```json
{
  "enabled": true,
  "state": "ready",
  "uri": "bolt://127.0.0.1:7687",
  "database": "neo4j",
  "schema_version": 2,
  "supported_schema_version": 2,
  "template_set_version": "2026-10-16.1",
  "template_digest": "1c51f4e5...",
  "checkpoint": {"segment": 12, "events": 11843, "updated": 0},
  "live_applied": 5120,
  "live_dropped": 0,
  "catch_ups": 31,
  "last_catch_up": "2026-10-16T22:10:00Z",
  "last_retention": "2026-10-16T21:40:00Z",
  "retention_deleted": {"AuditEvent": 0, "Decision": 0, "Approval": 0, "Invocation": 0, "Session": 0},
  "hardening": [
    {"setting": "server.default_listen_address", "value": "0.0.0.0", "want": "127.0.0.1", "reason": "SR-4.2-1: listen on loopback only"}
  ],
  "memory": {"budget": {"heap_bytes": 1073741824, "page_cache_bytes": 1073741824}, "heap_used": 90177536,
             "heap_max": 536870912, "page_cache_configured": 134217728, "pressure": false, "sampled_at": "2026-10-16T22:10:05Z"},
  "counts": {"auditEvents": 11843, "sessions": 12, "principals": 2, "invocations": 2301, "decisions": 2290,
             "policyRevisions": 2, "serverRevisions": 3, "toolRevisions": 9, "approvals": 4},
  "schema": [{"kind": "constraint", "name": "smcp_audit_event_id", "state": "ONLINE"}]
}
```

`error`, `last_rebuild` and `rebuild_error` appear when set. `state` is one of `disabled`, `connecting`, `ready`, `unavailable`, `refused` (see [graph.md](../graph.md)).

## POST /api/v1/graph/rebuild

Body `{}`. Records an evidence event (`class admin`, `origin E-26`, `outcome requested`, `reason_code GRAPH_REBUILD`, `detail.actor`), then queues a rebuild: delete the mirrored labels and the checkpoint, replay the journal.

Response 202:

```json
{"status": "queued"}
```

Errors: `graph_disabled`, `graph_unavailable`, `rebuild_queued`, `audit_unavailable`.

## GET /api/v1/graph/neighborhood

Query: `label` (one of `AuditEvent`, `Session`, `Principal`, `Invocation`, `Decision`, `PolicyRevision`, `ServerRevision`, `ToolRevision`, `Approval`), `id`, optional `limit` (default 50, at most 500). Returns the node and up to `limit` relationships to neighbors, most recently seen neighbors first.

Response 200:

```json
{
  "node": {"id": "s1", "labels": ["Session"], "properties": {"principalId": "cc", "state": "active", "firstSeen": 1792188000000000000, "lastSeen": 1792188600000000000}},
  "neighbors": [{"id": "cc", "labels": ["Principal"], "properties": {"firstSeen": 1792188000000000000, "lastSeen": 1792188600000000000}}],
  "edges": [{"type": "OF_PRINCIPAL", "from": "s1", "to": "cc"}],
  "degree": 41,
  "truncated": true
}
```

`degree` is the node's total relationship count; `truncated` is true when `edges` holds fewer than `degree`.

## GET /api/v1/graph/events/{id}/path

The investigation path of one audit event (G-14). Query: optional `limit` for `phases` (default 50, at most 500).

Response 200:

```json
{
  "event": {"id": "0192...", "class": "call", "phase": "delivered", "correlationId": "c1", "ts": 1792188600000000000},
  "decision": {"id": "d1", "outcome": "permit", "revisionId": "r1"},
  "invocation": {"id": "c1", "phase": "delivered", "outcome": "ok"},
  "session": {"id": "s1", "state": "active"},
  "principal": {"id": "cc"},
  "serverRevision": {"id": "live-abc"},
  "toolRevision": {"id": "live-abc/echo", "name": "echo"},
  "policyRevision": {"id": "r1"},
  "phases": [{"id": "0191...", "phase": "requested"}, {"id": "0192...", "phase": "delivered"}]
}
```

Members without a related node are `null`. `phases` lists the events of the same correlation ID by time.

## GET /api/v1/graph/queries

Response 200:

```json
{"queries": [{"name": "call_timeline", "description": "every evidence event of one call, in order", "params": ["correlationId", "limit"]}]}
```

## GET /api/v1/graph/queries/{name}

Runs a read-only canned query. Query parameters: the query's declared parameters (each once; values match `^[A-Za-z0-9._:@/+-]{1,256}$`) and optional `limit`.

```
GET /api/v1/graph/queries/call_timeline?correlationId=c1&limit=10
```

Response 200:

```json
{"query": "call_timeline", "limit": 10, "rows": [
  {"event": "0191...", "ts": 1792188600000000000, "class": "call", "phase": "requested", "origin": "E-02", "outcome": null, "reasonCode": null}
]}
```

The queries and their row fields are listed in [graph.md](../graph.md#commands).
