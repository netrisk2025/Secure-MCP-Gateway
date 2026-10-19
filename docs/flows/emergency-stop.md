# Emergency stop

How an operator stops all tool execution (FR-4.14, SR-7.6-1, SR-7.6-2, SR-1.16-1; ARCH §18.7). Stop is serialized through the coordinator's gate, so every launch and release is ordered entirely before or after it.

The flow is drawn in two parts. Step numbers run on from one part to the next.

## 1. Stop (steps 1–9)

```mermaid
sequenceDiagram
  autonumber
  participant O as Operator
  participant E24 as E-24 Control API (G-01 or smcpctl stop)
  participant E12 as E-12 Coordinator gate
  participant E21 as E-21 Journal
  participant E10 as E-10 Dispatcher
  participant E15 as E-15 Runtime
  participant E20 as E-20 Secret Broker
  participant E04 as E-04 Sessions

  O->>E24: stop (Operator or Administrator)
  E24->>E12: stop request
  E12->>E12: take the gate, advance stop epoch
  E12->>E21: emergency_stop event, flushed
  par fan-out over I-20
    E12->>E10: cancel in-flight calls (cancellation is not proof of rollback)
    E12->>E15: tear down instances
    E12->>E20: withdraw secret grants
    E12->>E04: end affected sessions
  end
  E12-->>E24: stopped
```

## 2. While stopped, and resume (steps 10–14)

```mermaid
sequenceDiagram
  autonumber 10
  participant H as Harness
  participant E12 as E-12 Coordinator gate
  participant E21 as E-21 Journal
  participant E24 as E-24 Control API (G-01 or smcpctl stop)
  participant O as Operator

  H->>E12: new launch or pending release
  E12-->>H: -31004 EMERGENCY_STOP
  O->>E24: resume (Administrator only)
  E24->>E12: resume, new epoch
  E12->>E21: resume event
```

The CP-16 propagation bound and FR-11.10 stop latency apply.

## Implementation

`smcpctl stop --reason <text>`, the console's Stop button and `POST /admin/v1/stop` call `Gateway.Stop` in `internal/edge`, which sets the stop state under the coordinator's gate and commits an `admin` event with outcome `stopped`, the actor and the reason. While stopped, every MCP request (including `initialize`) and every launch and release authorization is refused with `-31004` `EMERGENCY_STOP`, and health is `fail-closed`. The Secret Broker (`internal/secrets`) observes the stop event and withdraws S1 grants and S2 files. `smcpctl resume` (Administrator) commits `resumed` and clears the state. Differences from the diagram:

- Calls in flight are cancelled (the dispatcher sends `notifications/cancelled` southbound) and their results are withheld; the `stopped` event counts them in `calls_cancelled` (SR-7.6-2). The drain stop that an online backup uses instead lets calls in flight finish and release their results (SR-7.7-1).
- Server instances are not torn down; use `smcpctl runtime kill` or disable the package (see the [runbook](../runbooks/emergency-stop.md)).
- Sessions are not ended.
- Operator accounts (`[[console.account]]` with `role = "operator"`) and the Administrator can stop; only the Administrator can resume.
