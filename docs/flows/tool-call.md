# Tool call

The path of one `tools/call` from a harness to a backend server and back, as specified in SRS V1.2 (FR-4.3 stage order) and ARCH §18.3. Element IDs are those of `ArchitectureV2.md`.

The path is drawn in three parts. Step numbers run on from one part to the next.

## 1. Authentication and decision (steps 1–12)

```mermaid
sequenceDiagram
  autonumber
  participant H as Harness
  participant E01 as E-01 Endpoint
  participant E03 as E-03/E-04 Identity and Session
  participant E02 as E-02 Protocol Mediator
  participant E08 as E-08 Access EP
  participant E06 as E-06 Decision
  participant E21 as E-21 Journal

  H->>E01: POST /mcp tools/call, Authorization Bearer
  E01->>E01: Host and Origin checks, header and body bounds before parsing
  E01->>E03: verify access token
  E03-->>E01: session (principal, template, pinned revision, taint flag)
  E01->>E02: framed request
  E02->>E02: parse, protocol era, method allowlist, header and body agreement
  E02->>E08: canonical request
  E08->>E08: public tool name in the session catalog
  E08->>E06: evaluate against the in-memory snapshot
  E06-->>E08: permit or deny, obligations, route
  alt deny or rate limit
    E08->>E21: decision event (denied)
    E02-->>H: -31001 or -31005 with reasonCode, correlationId, decisionId, message
  else permit
    Note over E08,E06: continues in part 2
  end
```

## 2. Request inspection, approval and launch authorization (steps 13–22, on permit)

```mermaid
sequenceDiagram
  autonumber 13
  participant E08 as E-08 Access EP
  participant E09 as E-09 Request filters
  participant E07 as E-07 Approval
  participant E12 as E-12 Coordinator
  participant E21 as E-21 Journal
  participant E10 as E-10 Dispatcher

  E08->>E09: request filters named by the obligations
  E09->>E09: schema-validate, path and URL canonicalization, secret fingerprint, injection tags
  opt approval obligation (policy, anomaly or session taint)
    E09->>E07: create pending approval and hold the call (see approval-hold.md)
    E07-->>E09: approved
  end
  E09->>E12: request launch
  E12->>E12: recheck stop epoch, policy revision, session state
  E12->>E21: append decision and intent record
  E21->>E21: flush to stable storage
  E21-->>E12: flushed
  E12-->>E10: one-use launch capability
```

## 3. Dispatch, response inspection and release (steps 23–31)

```mermaid
sequenceDiagram
  autonumber 23
  participant H as Harness
  participant E02 as E-02 Protocol Mediator
  participant E10 as E-10 Dispatcher
  participant B as Backend in E-15/E-16
  participant E11 as E-11 Response filters
  participant E12 as E-12 Coordinator
  participant E21 as E-21 Journal

  E10->>B: acquire instance, tools/call with backend credential
  B-->>E10: result, buffered and size-bounded
  E10->>E11: envelope, correlation and output-schema checks
  E11->>E11: response filters, provenance labels, taint update
  E11->>E12: request release
  E12->>E12: recheck stop epoch, policy revision, session state
  E12->>E21: append outcome and release disposition, flush
  E12-->>E02: release authorization
  E02-->>H: result with _meta local.smcpgw/provenance (untrusted)
  Note over E21: E-21 feeds the graph mirror from the journal asynchronously. No step waits on the graph (A-9).
```

Every stage, from E-01 to E-11, emits timing spans and observables to E-29 asynchronously.

## Requirements on this path

| Step | Requirements |
|---|---|
| 2 | SR-2.9-1, SR-2.9-2, SR-7.11-1 |
| 3–4 | FR-2.5, SR-2.1-3, SR-2.11-1 |
| 6 | FR-1.10, FR-1.11, SR-5.2-1 |
| 8–10 | FR-1.30, SR-5.5-1, SR-1.3-1, FR-3.10 |
| 11–12 | FR-1.20, FR-1.51, SR-6.1-1 |
| 13–14 | FR-4.5, FR-4.16, FR-4.17, SR-1.8-1 |
| 15–16 | FR-3.14, FR-3.19, SR-5.13-2 |
| 17–22 | SR-1.17-1, SR-6.2-1, FR-4.13 |
| 23–24 | FR-4.8, FR-4.9, FR-4.10 |
| 25–26 | SR-5.20-1, SR-5.9-1, SR-5.13-1, SR-5.13-2 |
| 27–30 | SR-1.17-2, SR-6.3-1 |
| 31 | FR-4.12 |

## Implementation

`internal/edge/pipeline.go` follows the same order (authenticate, session check, fail-closed check, decision, request inspection, approval, launch authorization, dispatch, response inspection, provenance, release authorization). Differences:

- Request and response scoring (E-31) run as the last filters of the request and response chains; scoring is asynchronous by default, with optional synchronous approval and withhold obligations ([../observation.md](../observation.md)).
- A request filter that transforms the arguments causes a second decision before launch, and the launch is bound to it (SR-5.12-1).
- Progress notifications from backends are relayed with the northbound token after the response filters, at most 10 per second per request (CP-21), never after the response; the backend gets a Gateway-issued token.
- Backend instances are shared across sessions (no per-session or per-call scope).
- The graph mirror is fed asynchronously from the journal and is never consulted on the call path.
