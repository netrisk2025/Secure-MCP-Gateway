// Package graph is the graph side of the Data Server (SS-9): the
// integration with the Graph Database Engine (E-25, Neo4j Community
// Edition), the Data Access Service (E-26) and the graph part of the Data
// Lifecycle & Memory Manager (E-28).
//
// The graph is a mirror (A-9). Mirror implements audit.Observer: it queues
// each event the journal accepted and projects batches of events into the
// Appendix D labels (AuditEvent, Session, Principal, Invocation, Decision,
// PolicyRevision, PolicyControl, ServerRevision, ToolRevision, Approval)
// with MERGE on the event-derived IDs, so applying an event twice changes
// nothing. After any gap (database down, queue full, restart) it catches up
// by reading the journal segments from its checkpoint. Its unavailability
// never blocks or fails a call: Observe only enqueues, and the Fanout runs
// it on its own goroutine.
//
// Every database statement comes from the embedded, digest-verified
// template set (templates/templates.cypher, MANIFEST.sha256). Callers
// select an operation by ID and pass parameters, which are validated
// against the operation's declaration and bound as Bolt parameters; labels,
// relationship types and procedure names are fixed in the templates.
//
// Lifecycle (E-28, graph part): ordered schema migrations with refusal of a
// newer schema, retention of mirrored records in bounded batches at least
// once per day, an engine configuration check (hardening and CP-33 memory
// budget) at connect time, and a heap sample every 5 seconds.
package graph
