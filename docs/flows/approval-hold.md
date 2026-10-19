# Approval in hold mode

What happens when a call carries an approval obligation from policy, from an anomaly band or from session taint (FR-3.14 to FR-3.25, FR-1.51, SR-1.18-2, SR-5.13-2). CP-45 sets the hold bound (default 120 s) and keep-alive interval (default 10 s).

```mermaid
sequenceDiagram
  autonumber
  participant H as Harness
  participant E02 as E-02 Protocol Mediator
  participant E07 as E-07 Approval Service
  participant N as OS notification
  participant P as Approver (G-13 or smcpctl approvals)
  participant E12 as E-12 Coordinator
  participant E21 as E-21 Journal

  E07->>E07: create pending approval bound to session, principal, tool revision, argument digest, policy revision
  E07->>E21: approval_requested event
  par notify within 2 s
    E07->>N: tool, server alias, approval ID, console link (no arguments)
    E07->>P: entry in G-13 and in smcpctl approvals watch
  end
  loop every keep-alive interval until decision or hold bound
    E02-->>H: notifications/progress (with progress token) or SSE comment
  end
  alt approved before the bound
    P->>E07: approve (Approver role)
    E07->>E21: approval decision event
    E07->>E07: consume approval
    E07->>E12: continue to launch authorization in the same call
    Note over H,E12: The harness receives the tool result as the response to its original request
  else denied
    P->>E07: deny
    E07->>E21: approval decision event
    E02-->>H: -31001 APPROVAL_DENIED with message
  else hold bound reached
    E02-->>H: -31002 with approvalId, expiresAt, message and approvalUrl
    Note over E07: The approval stays pending until its CP-17 expiry
    P->>E07: approve later
    H->>E02: same request again
    E07->>E07: digest matches, consume approval
    E07->>E12: continue to launch authorization
  end
```

The `-31002` message tells the person in plain words to open the approval URL, approve, and run the same request again (Appendix B, Table B.2).

## Implementation

Implemented by `internal/approval` (E-07) with the edge changes in `internal/edge/stream.go`; see [../approvals.md](../approvals.md) and [../api/approvals.md](../api/approvals.md). Differences from the diagram:

- The console's Approvals view (G-13) belongs to E-24; it reads `/api/v1/approvals` and the watch stream this service provides.
- The keep-alive is sent once when the call is held and then every interval. A `tools/call` is answered as an event stream only once it is held; other calls stay JSON.
- Anomaly-band obligations (off by default, `require_approval_band`) and session-taint obligations (`TAINT_APPROVAL`) reach the service like policy-rule approvals, and an anomaly-band approval carries the band, the contributing feature, its z-score, the baseline snapshot and the context, which G-13 shows (FR-3.18).
- The real-harness run of FR-3.25 is recorded in [../verification/FR-3.25.md](../verification/FR-3.25.md).
