# Runbook execution: emergency stop

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/emergency-stop.md` |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

## Setup

`smcpd`, `smcpctl`, `smcp-refserver` and `scripts/itest-client` built with `go build -trimpath` from the commit above (main on 2026-10-18). A fresh instance was bootstrapped with `smcpctl bootstrap --dir inst --port 28843 --admin-port 28844 --notify off --admin-password-file admin.pw --approver-password-file approver.pw` (metrics on 28845), a file `sandbox/hello.txt` was written, and the Gateway was started with `smcpd --config smcp.toml`. The harness was `itest-client`, which signs in through the OAuth form as the Session Approver and calls `ref_read_file` on `hello.txt` in the sandbox, each time in a new session. Every command ran from the instance directory. Started 20:37:38Z, finished 20:37:49Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| Before | `itest-client ... -call ref_read_file` | `PASS` (4 tools listed) |
| Stop 1 | `smcpctl stop --reason "runbook execution: emergency stop" --config smcp.toml` | `{"state": "stopped"}` |
| Stop 2 | `smcpctl health --config smcp.toml` | `health: fail-closed; causes: unconfined`; `gateway.causes` = `["unconfined", "emergency_stop"]`, `info.emergency_stop` = true |
| Stop 3 | `itest-client ... -call ref_read_file` | `FAIL: unauthenticated POST: status 503, want 401` |
| Stop 3 | `curl -X POST https://127.0.0.1:28843/mcp` with an `initialize` request, no token | HTTP 503, body `{"error":{"code":-31004,"message":"gateway fail-closed","data":{"correlationId":"01a150bb-...","message":"The Gateway operator has stopped all tool calls.","reasonCode":"EMERGENCY_STOP"}},"id":1,"jsonrpc":"2.0"}` |
| Stop 3 | journal | `admin` event, outcome `stopped`, reason `EMERGENCY_STOP`, detail `actor: operator-token`, `reason: runbook execution: emergency stop`, `calls_cancelled: 0` |
| Stop 5 | `smcpctl runtime instances --config smcp.toml` | `{"instances": []}` (Standalone profile: the instance table is empty; the step applies to the Enforced profile) |
| Stop 6 | `smcpctl package list --config smcp.toml` | the example package `smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e` enabled as `ref`; disabling it was not needed for this run (the revocation record takes a package out of use) |
| Investigate 1 | `smcpctl journal verify --config smcp.toml` | `journal OK: 1 segments, 31 events (segment-000001.jsonl is still open; its 31 events are not signed yet)` |
| Investigate 2 | `GET /api/v1/audit/events?limit=3` with the operator token | the `stopped` event first, then the `release` and `ok` call events of the call before the stop |
| Investigate 3 | `smcpctl approvals list --state all --config smcp.toml` | `no approvals` |
| Resume 2 | `smcpctl resume --config smcp.toml` | `{"state": "running"}` |
| Resume 3 | `smcpctl health --config smcp.toml` | `health: degraded; causes: unconfined`; `emergency_stop` gone, `info.emergency_stop` = false |
| Resume 4 | `itest-client ... -call ref_read_file` | `PASS` |

## Not executed

- Stop 4 (S1 egress grants and S2 secret files withdrawn): the bootstrap configuration has no vault and no egress grants.
- Stop 7 (terminate sessions in the console): covered by the console's Playwright tests, not by this run.
- Stopping the process with launchd or systemd: the Gateway was not installed as a service; stopping the process with `kill` is exercised by the other runbook records.

## Deviations and corrections

None. The runbook as corrected by the 2026-10-17 execution (HTTP 503 instead of the 401 challenge) matched every observation.
