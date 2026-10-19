# Runbook: emergency stop

Use when tool execution must end now: a server behaves unexpectedly, a policy is wrong and simulation is not an option, or a compromise is suspected. Reference: [../flows/emergency-stop.md](../flows/emergency-stop.md), [../operator-guide.md](../operator-guide.md#emergency-stop). Execution records go in `docs/verification/runbooks/` (FR-18.8); the latest is [runbook-emergency-stop-2026-10-18.md](../verification/runbooks/runbook-emergency-stop-2026-10-18.md).

## Stop

1. `smcpctl stop --reason "<what happened>" --config smcp.toml` — expect `"state": "stopped"`. In the console, use **Stop** in the status bar.
2. `smcpctl health --config smcp.toml` — expect `health: fail-closed` with `emergency_stop` among the gateway causes.
3. Every MCP request from a harness, including `initialize` and requests without a token, now answers HTTP 503 with the JSON-RPC error `-31004`, reason `EMERGENCY_STOP` and the message "The Gateway operator has stopped all tool calls." A client that signs in first sees the 503 instead of the usual 401 challenge. The journal holds an `admin` event with outcome `stopped`, the actor and the reason.
4. S1 egress grants and S2 per-call secret files are withdrawn (when the vault is enabled).

What stop does not do in this build: it does not cancel calls already dispatched to a backend, it does not tear down running server instances, and it does not end sessions. A call already past release authorization completes. To end a misbehaving instance as well:

5. Enforced profile: `smcpctl runtime instances --config smcp.toml`, then `smcpctl runtime kill <id> --reason "<text>" --config smcp.toml`.
6. To take a server out of use until reviewed: `smcpctl package disable <id>@<rev> --config smcp.toml` (tears its instance down), or revoke it ([revocation.md](revocation.md)).
7. To end sessions: console Sessions view, **Terminate session**.

If the control API does not answer, stop the `smcpd` process (`launchctl bootout gui/$(id -u)/com.smcp.gateway`, `sudo systemctl stop smcpd`, or `kill <pid>`). Stopping the process ends every instance it launched. On the next start the Gateway is not in emergency stop, so start it only after the cause is handled.

## Investigate

1. `smcpctl journal verify --config smcp.toml` — expect `journal OK`.
2. Console Audit view (`/audit`), filtered by session, server or tool, or `GET /api/v1/audit/events`, to find the calls that led to the stop.
3. `smcpctl approvals list --state all --config smcp.toml` for approvals granted shortly before.

## Resume

1. Fix the cause (policy rollback, package disabled or revoked, key rotated).
2. `smcpctl resume --config smcp.toml` — expect `"state": "running"`. Only the Administrator can resume.
3. `smcpctl health --config smcp.toml` — `emergency_stop` is gone.
4. Make one known-good call from a harness and confirm it succeeds.
