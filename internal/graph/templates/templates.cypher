// Query template set of the Data Access Service (E-26), FR-9.3 and
// SR-1.13-1. Each "op:" block is one typed operation with exactly one fixed
// parameterized template. Labels, relationship types and procedure names
// are written here and never supplied by a caller. The digest of this file
// is recorded in MANIFEST.sha256 and checked at startup (SR-1.13-2).
//
// Header lines: "op: <id>", "mode: read|write", "params: <name>:<type> ...".
// Types: rows (list of row maps built by the mirror projection), string,
// int, strings (list of strings fixed by the service).

// op: ping
// mode: read
// params:
RETURN 1 AS ok

// op: upsert.AuditEvent
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:AuditEvent {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.Session
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:Session {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.Principal
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:Principal {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.Invocation
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:Invocation {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.Decision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:Decision {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.PolicyRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:PolicyRevision {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.PolicyControl
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:PolicyControl {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.ServerRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:ServerRevision {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.ToolRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:ToolRevision {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.Approval
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:Approval {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.RuleRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:RuleRevision {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: upsert.PolicyObject
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (n:PolicyObject {id: row.id})
SET n.firstSeen = CASE WHEN n.firstSeen IS NULL OR row.ts < n.firstSeen THEN row.ts ELSE n.firstSeen END
WITH n, row
WHERE coalesce(n.lastSeen, -1) <= row.ts
SET n += row.props, n.lastSeen = row.ts

// op: link.AuditEvent.IN_SESSION.Session
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:AuditEvent {id: row.from})
MERGE (b:Session {id: row.to})
MERGE (a)-[:IN_SESSION]->(b)

// op: link.AuditEvent.FOR_INVOCATION.Invocation
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:AuditEvent {id: row.from})
MERGE (b:Invocation {id: row.to})
MERGE (a)-[:FOR_INVOCATION]->(b)

// op: link.AuditEvent.FOR_DECISION.Decision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:AuditEvent {id: row.from})
MERGE (b:Decision {id: row.to})
MERGE (a)-[:FOR_DECISION]->(b)

// op: link.AuditEvent.OBSERVED_FROM.ServerRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:AuditEvent {id: row.from})
MERGE (b:ServerRevision {id: row.to})
MERGE (a)-[:OBSERVED_FROM]->(b)

// op: link.AuditEvent.RECORDED_UNDER.PolicyRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:AuditEvent {id: row.from})
MERGE (b:PolicyRevision {id: row.to})
MERGE (a)-[:RECORDED_UNDER]->(b)

// op: link.Session.OF_PRINCIPAL.Principal
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Session {id: row.from})
MERGE (b:Principal {id: row.to})
MERGE (a)-[:OF_PRINCIPAL]->(b)

// op: link.Invocation.IN_SESSION.Session
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Invocation {id: row.from})
MERGE (b:Session {id: row.to})
MERGE (a)-[:IN_SESSION]->(b)

// op: link.Invocation.INVOKED.ToolRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Invocation {id: row.from})
MERGE (b:ToolRevision {id: row.to})
MERGE (a)-[:INVOKED]->(b)

// op: link.Invocation.AUTHORIZED_BY.Decision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Invocation {id: row.from})
MERGE (b:Decision {id: row.to})
MERGE (a)-[:AUTHORIZED_BY]->(b)

// op: link.Decision.IN_SESSION.Session
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Decision {id: row.from})
MERGE (b:Session {id: row.to})
MERGE (a)-[:IN_SESSION]->(b)

// op: link.Decision.EVALUATED_UNDER.PolicyRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Decision {id: row.from})
MERGE (b:PolicyRevision {id: row.to})
MERGE (a)-[:EVALUATED_UNDER]->(b)

// op: link.Decision.TARGETED.ServerRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Decision {id: row.from})
MERGE (b:ServerRevision {id: row.to})
MERGE (a)-[:TARGETED]->(b)

// op: link.ToolRevision.BELONGS_TO.ServerRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:ToolRevision {id: row.from})
MERGE (b:ServerRevision {id: row.to})
MERGE (a)-[:BELONGS_TO]->(b)

// op: link.AuditEvent.RECORDED_UNDER.PolicyObject
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:AuditEvent {id: row.from})
MERGE (b:PolicyObject {id: row.to})
MERGE (a)-[:RECORDED_UNDER]->(b)

// op: link.PolicyRevision.CONTAINS.RuleRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:PolicyRevision {id: row.from})
MERGE (b:RuleRevision {id: row.to})
MERGE (a)-[:CONTAINS]->(b)

// op: link.Decision.CONSIDERED_RULE.RuleRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Decision {id: row.from})
MERGE (b:RuleRevision {id: row.to})
MERGE (a)-[:CONSIDERED_RULE]->(b)

// op: link.Decision.APPLICABLE_RULE.RuleRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Decision {id: row.from})
MERGE (b:RuleRevision {id: row.to})
MERGE (a)-[:APPLICABLE_RULE]->(b)

// op: link.Decision.DECIDED_BY.RuleRevision
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Decision {id: row.from})
MERGE (b:RuleRevision {id: row.to})
MERGE (a)-[:DECIDED_BY]->(b)

// op: link.Approval.FOR_INVOCATION.Invocation
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Approval {id: row.from})
MERGE (b:Invocation {id: row.to})
MERGE (a)-[:FOR_INVOCATION]->(b)

// op: link.Approval.IN_SESSION.Session
// mode: write
// params: rows:rows
UNWIND $rows AS row
MERGE (a:Approval {id: row.from})
MERGE (b:Session {id: row.to})
MERGE (a)-[:IN_SESSION]->(b)

// op: checkpoint.get
// mode: read
// params: id:string
MATCH (c:Checkpoint {id: $id})
RETURN c.segment AS segment, c.events AS events, c.updated AS updated

// op: checkpoint.set
// mode: write
// params: id:string segment:int events:int updated:int
MERGE (c:Checkpoint {id: $id})
SET c.segment = $segment, c.events = $events, c.updated = $updated

// op: checkpoint.delete
// mode: write
// params: id:string
MATCH (c:Checkpoint {id: $id})
DETACH DELETE c

// op: schema.get
// mode: read
// params:
MATCH (c:Checkpoint {id: 'schema'})
RETURN c.version AS version

// op: schema.set
// mode: write
// params: version:int updated:int
MERGE (c:Checkpoint {id: 'schema'})
SET c.version = $version, c.updated = $updated

// op: status.counts
// mode: read
// params:
RETURN COUNT { (:AuditEvent) } AS auditEvents, COUNT { (:Session) } AS sessions, COUNT { (:Principal) } AS principals,
       COUNT { (:Invocation) } AS invocations, COUNT { (:Decision) } AS decisions, COUNT { (:PolicyRevision) } AS policyRevisions,
       COUNT { (:ServerRevision) } AS serverRevisions, COUNT { (:ToolRevision) } AS toolRevisions, COUNT { (:Approval) } AS approvals

// op: status.settings
// mode: read
// params: names:strings
SHOW SETTINGS YIELD name, value
WHERE name IN $names
RETURN name, value

// op: status.heap
// mode: read
// params:
CALL dbms.queryJmx('java.lang:type=Memory') YIELD attributes
RETURN attributes.HeapMemoryUsage.value.properties.used AS used,
       attributes.HeapMemoryUsage.value.properties.committed AS committed,
       attributes.HeapMemoryUsage.value.properties.max AS max

// op: status.schema
// mode: read
// params:
SHOW CONSTRAINTS YIELD name, type, labelsOrTypes, properties
RETURN 'constraint' AS kind, name, type, labelsOrTypes, properties, 'ONLINE' AS state
UNION ALL
SHOW INDEXES YIELD name, type, labelsOrTypes, properties, state, owningConstraint
WHERE owningConstraint IS NULL AND type = 'RANGE'
RETURN 'index' AS kind, name, type, labelsOrTypes, properties, state

// op: neighborhood.AuditEvent
// mode: read
// params: id:string limit:int
MATCH (n:AuditEvent {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.Session
// mode: read
// params: id:string limit:int
MATCH (n:Session {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.Principal
// mode: read
// params: id:string limit:int
MATCH (n:Principal {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.Invocation
// mode: read
// params: id:string limit:int
MATCH (n:Invocation {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.Decision
// mode: read
// params: id:string limit:int
MATCH (n:Decision {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.PolicyRevision
// mode: read
// params: id:string limit:int
MATCH (n:PolicyRevision {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.ServerRevision
// mode: read
// params: id:string limit:int
MATCH (n:ServerRevision {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.ToolRevision
// mode: read
// params: id:string limit:int
MATCH (n:ToolRevision {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: neighborhood.Approval
// mode: read
// params: id:string limit:int
MATCH (n:Approval {id: $id})
CALL (n) {
  OPTIONAL MATCH (n)-[r]-(m)
  WITH r, m ORDER BY coalesce(m.lastSeen, 0) DESC, m.id LIMIT $limit
  RETURN collect(CASE WHEN r IS NULL THEN null ELSE {type: type(r), from: startNode(r).id, to: endNode(r).id, node: m {.*, labels: labels(m)}} END) AS links
}
RETURN n {.*, labels: labels(n)} AS node, links, COUNT { (n)--() } AS degree

// op: event.path
// mode: read
// params: id:string limit:int
MATCH (e:AuditEvent {id: $id})
OPTIONAL MATCH (e)-[:FOR_DECISION]->(d:Decision)
OPTIONAL MATCH (e)-[:FOR_INVOCATION]->(i:Invocation)
OPTIONAL MATCH (e)-[:IN_SESSION]->(s:Session)
OPTIONAL MATCH (s)-[:OF_PRINCIPAL]->(p:Principal)
OPTIONAL MATCH (e)-[:OBSERVED_FROM]->(sr:ServerRevision)
OPTIONAL MATCH (i)-[:INVOKED]->(t:ToolRevision)
OPTIONAL MATCH (e)-[:RECORDED_UNDER]->(pr:PolicyRevision)
CALL (d) {
  OPTIONAL MATCH (d)-[:DECIDED_BY]->(r:RuleRevision)
  WITH r ORDER BY r.id LIMIT 256
  RETURN collect(r {.*}) AS decisiveRules
}
CALL (d) {
  OPTIONAL MATCH (d)<-[:FOR_DECISION]-(:AuditEvent)-[:RECORDED_UNDER]->(ap:PolicyObject)
  WITH ap ORDER BY ap.id LIMIT 1
  RETURN collect(ap {.*}) AS auditProfiles
}
CALL (e) {
  OPTIONAL MATCH (o:AuditEvent {correlationId: e.correlationId})
  WITH o ORDER BY o.ts, o.id LIMIT $limit
  RETURN collect(o {.*}) AS phases
}
RETURN e {.*} AS event, d {.*} AS decision, i {.*} AS invocation, s {.*} AS session, p {.*} AS principal,
       sr {.*} AS serverRevision, t {.*} AS toolRevision, pr {.*} AS policyRevision, decisiveRules,
       CASE WHEN size(auditProfiles) > 0 THEN auditProfiles[0] END AS auditProfile, phases

// op: query.recent_sessions
// mode: read
// params: limit:int
MATCH (s:Session)
OPTIONAL MATCH (s)-[:OF_PRINCIPAL]->(p:Principal)
RETURN s.id AS session, p.id AS principal, s.state AS state, s.firstSeen AS firstSeen, s.lastSeen AS lastSeen,
       COUNT { (:Invocation)-[:IN_SESSION]->(s) } AS calls
ORDER BY s.lastSeen DESC, s.id LIMIT $limit

// op: query.recent_denials
// mode: read
// params: limit:int
MATCH (d:Decision {outcome: 'deny'})
RETURN d.id AS decision, d.ts AS ts, d.reasonCode AS reasonCode, d.sessionId AS session, d.correlationId AS correlationId,
       d.revisionId AS policyRevision
ORDER BY d.ts DESC, d.id LIMIT $limit

// op: query.tool_usage
// mode: read
// params: limit:int
MATCH (t:ToolRevision)
WITH t, COUNT { (:Invocation)-[:INVOKED]->(t) } AS calls
RETURN t.id AS toolRevision, calls, t.lastSeen AS lastSeen
ORDER BY calls DESC, toolRevision LIMIT $limit

// op: query.call_timeline
// mode: read
// params: correlationId:string limit:int
MATCH (e:AuditEvent {correlationId: $correlationId})
RETURN e.id AS event, e.ts AS ts, e.class AS class, e.phase AS phase, e.origin AS origin, e.outcome AS outcome,
       e.reasonCode AS reasonCode
ORDER BY e.ts, e.id LIMIT $limit

// op: query.principal_activity
// mode: read
// params: limit:int
MATCH (p:Principal)
RETURN p.id AS principal, COUNT { (:Session)-[:OF_PRINCIPAL]->(p) } AS sessions,
       COUNT { (:Invocation)-[:IN_SESSION]->(:Session)-[:OF_PRINCIPAL]->(p) } AS calls, p.lastSeen AS lastSeen
ORDER BY p.lastSeen DESC, p.id LIMIT $limit

// op: query.policy_revisions
// mode: read
// params: limit:int
MATCH (r:PolicyRevision)
RETURN r.id AS policyRevision, r.activatedAt AS activatedAt, COUNT { (:Decision)-[:EVALUATED_UNDER]->(r) } AS decisions,
       r.lastSeen AS lastSeen
ORDER BY r.lastSeen DESC, r.id LIMIT $limit

// op: query.approvals
// mode: read
// params: limit:int
MATCH (a:Approval)
RETURN a.id AS approval, a.state AS state, a.publicName AS tool, a.sessionId AS session, a.lastSeen AS lastSeen
ORDER BY a.lastSeen DESC, a.id LIMIT $limit

// op: retention.AuditEvent
// mode: write
// params: cutoff:int limit:int
MATCH (n:AuditEvent) WHERE n.ts < $cutoff
WITH n LIMIT $limit
DETACH DELETE n
RETURN count(*) AS deleted

// op: retention.Decision
// mode: write
// params: cutoff:int limit:int
MATCH (n:Decision) WHERE n.lastSeen < $cutoff AND NOT EXISTS { (:AuditEvent)-[:FOR_DECISION]->(n) }
WITH n LIMIT $limit
DETACH DELETE n
RETURN count(*) AS deleted

// op: retention.Approval
// mode: write
// params: cutoff:int limit:int
MATCH (n:Approval) WHERE n.lastSeen < $cutoff
WITH n LIMIT $limit
DETACH DELETE n
RETURN count(*) AS deleted

// op: retention.Invocation
// mode: write
// params: cutoff:int limit:int
MATCH (n:Invocation) WHERE n.lastSeen < $cutoff AND NOT EXISTS { (:AuditEvent)-[:FOR_INVOCATION]->(n) }
  AND NOT EXISTS { (:Approval)-[:FOR_INVOCATION]->(n) }
WITH n LIMIT $limit
DETACH DELETE n
RETURN count(*) AS deleted

// op: retention.Session
// mode: write
// params: cutoff:int limit:int
MATCH (n:Session) WHERE n.lastSeen < $cutoff AND NOT EXISTS { ()-[:IN_SESSION]->(n) }
WITH n LIMIT $limit
DETACH DELETE n
RETURN count(*) AS deleted

// op: wipe.mirror
// mode: write
// params: limit:int
MATCH (n)
WHERE n:AuditEvent OR n:Session OR n:Principal OR n:Invocation OR n:Decision OR n:PolicyRevision OR n:PolicyControl
   OR n:ServerRevision OR n:ToolRevision OR n:Approval OR n:RuleRevision OR n:PolicyObject
WITH n LIMIT $limit
DETACH DELETE n
RETURN count(*) AS deleted
