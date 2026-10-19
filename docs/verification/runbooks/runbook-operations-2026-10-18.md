# Procedure execution: health report, metrics and configuration reload

| Field | Content |
|---|---|
| Runbook | `docs/operations/health.md`, `docs/operations/logging-metrics-reload.md` |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

The operations pages are reference pages rather than step lists; this record runs the procedures they describe. The backup, key and upgrade pages are exercised by the runbook records next to this one. Instance `inst2` of the key-compromise record of the same date (ports 28853 to 28855). Since the previous record every critical health check runs on each evaluation (once per second) and a `policy_currency` check raises `decision_snapshot_stale`; the last rows exercise it. Started 20:43:39Z, finished 20:44:07Z.

## Observations

| Procedure | Command | Observed |
|---|---|---|
| Reading the report | `smcpctl health --require-not-fail-closed` | `health: degraded; causes: unconfined`, exit 0 |
| `/healthz` | `curl https://127.0.0.1:28853/healthz` | HTTP 200, `{"causes":["unconfined"],"profile":"standalone","release_label":"not enforced","state":"degraded","version":"0.0.0-dev"}` |
| `/healthz` while stopped | `smcpctl stop`, then the same request | HTTP 503, `"causes":["unconfined","emergency_stop"]`, `"state":"fail-closed"` |
| `--require-not-fail-closed` while stopped | `smcpctl health --require-not-fail-closed` | `smcpctl: gateway is fail-closed`, exit 1 |
| `health ack` of a cause that is not latched | `smcpctl health ack trust_anchor_invalid` (after `smcpctl resume`) | `no latched integrity cause by that name (not_latched)`, exit 1 |
| Metrics | a call, then `curl http://127.0.0.1:28855/metrics` | `smcp_calls_total{server_alias="ref",tool="ref_read_file",outcome="delivered",reason_code=""} 1`, `smcp_health_state 1`, `smcp_active_sessions 1`, `smcp_pending_approvals 0` |
| Reload, applied key | add `[log] level = "debug"`; `smcpctl reload` | `"applied": ["log.level"]`, `"changed": ["log.level"]`; journal `CONFIG_RELOADED` with `applied: ["log.level"]`, actor `operator-token` |
| Reload, restart-required key | change `[listener] address`; `smcpctl reload` | `"applied": []`, `"restart_required": ["listener.address"]`; journal `CONFIG_RELOADED` with `restart_required: ["listener.address"]` |
| Reload, invalid file with `smcpctl` | `[log] level = "loud"`; `smcpctl reload` | refused by `smcpctl` itself: `configuration does not match schema ... at '/log/level': value must be one of 'debug', 'info', 'warn', 'error'`, exit 1; no journal event |
| Reload, invalid file through the Gateway | the same file; `kill -HUP <smcpd>` | journal `admin` event, outcome `rejected`, reason `CONFIG_INVALID`, actor `signal:SIGHUP` |
| Reload through the API without a body | `POST /api/v1/config/reload` with no body | HTTP 415, `json_required: POST bodies must be application/json` |
| Reload, invalid file through the API | the same file; `POST /api/v1/config/reload` with body `{}` (20:43:41Z) | HTTP 422, `CONFIG_INVALID: new configuration is invalid; the running configuration is kept: ...`; journal `CONFIG_INVALID`, actor `operator-token` |
| Diagnostic log | `ls -l state/log` | `smcpd.log`, mode 0600, JSON Lines with `configuration reloaded` entries |
| `decision_snapshot_stale`, detection | change the revision ID inside the active Policy Store revision file (`r1` to `r1x`) while the Gateway runs; poll `smcpctl health` | reported in the first poll, within the same second (20:43:53Z): `health: fail-closed; causes: decision_snapshot_stale, unconfined`, cause `critical: true`, `integrity: true`, `ack_required: true`, detail `policy store integrity check failed: 766f5315....json signature does not verify under key 5bb4cffa4491da26`; journal `health` event `HEALTH_FAIL_CLOSED` with the cause |
| `decision_snapshot_stale`, latch | put the original file back (same content and modification time); wait 12 s; `smcpctl health` | still `fail-closed`; the cause `active: false`, `cleared_at` 20:43:54Z, not acknowledged |
| `decision_snapshot_stale`, acknowledgment | `smcpctl health ack decision_snapshot_stale` | the cause with `acked_by: operator-token`; journal `admin` event `HEALTH_ACK`; 1 s later `health: degraded; causes: unconfined` and a `HEALTH_DEGRADED` event with `previous: fail-closed` |

`smcpd` was stopped afterwards; `smcpctl journal verify` gave `journal OK: 7 segments, 74 events, anchored at segment 7, 1 evidence-key transitions (segments [4])`.

## Deviations and corrections

- None in the pages. The `decision_snapshot_stale` rows match the cause table and the Recovery section of `docs/operations/health.md` (an integrity cause when a store file no longer verifies; released only after 10 s clear and an acknowledgment).
- No `DEBUG` entry was checked for in the diagnostic log after setting `log.level` to `debug`; the run does not show debug output (FR-17.1 is verified by `internal/diag` and `internal/acceptance` tests).
