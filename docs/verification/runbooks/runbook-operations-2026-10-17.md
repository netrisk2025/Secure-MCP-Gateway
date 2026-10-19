# Procedure execution: health report, metrics and configuration reload

| Field | Content |
|---|---|
| Runbook | `docs/operations/health.md`, `docs/operations/logging-metrics-reload.md` |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Result | pass |

The operations pages are reference pages rather than step lists; this record runs the procedures they describe. The backup, key and upgrade pages are exercised by the runbook records next to this one. Instance `inst2` of the key-compromise record (ports 28653 to 28655). Started 19:13:07Z, finished 19:16:38Z.

## Observations

| Procedure | Command | Observed |
|---|---|---|
| Reading the report | `smcpctl health --require-not-fail-closed` | `health: degraded; causes: unconfined`, exit 0 |
| `/healthz` | `curl https://127.0.0.1:28653/healthz` | HTTP 200, `{"causes":["unconfined"],"profile":"standalone","release_label":"not enforced","state":"degraded","version":"0.0.0-dev"}` |
| `/healthz` while stopped | `smcpctl stop`, then the same request | HTTP 503, `"causes":["unconfined","emergency_stop"]`, `"state":"fail-closed"` |
| `--require-not-fail-closed` while stopped | `smcpctl health --require-not-fail-closed` | `smcpctl: gateway is fail-closed`, exit 1 |
| `health ack` of a cause that is not latched | `smcpctl health ack trust_anchor_invalid` | `no latched integrity cause by that name (not_latched)`, exit 1 |
| Metrics | a call, then `curl http://127.0.0.1:28655/metrics` | `smcp_calls_total{server_alias="ref",tool="ref_read_file",outcome="delivered",reason_code=""} 1`, `smcp_health_state 1`, `smcp_active_sessions 1`, `smcp_pending_approvals 0` |
| Reload, applied key | add `[log] level = "debug"`; `smcpctl reload` | `"applied": ["log.level"]`, `"changed": ["log.level"]`; journal `CONFIG_RELOADED` with `applied: ["log.level"]` |
| Reload, restart-required key | change `[listener] address`; `smcpctl reload` | `"applied": []`, `"restart_required": ["listener.address"]`; journal `CONFIG_RELOADED` |
| Reload, invalid file with `smcpctl` | `[log] level = "loud"`; `smcpctl reload` | refused by `smcpctl` itself: `configuration does not match schema ... at '/log/level': value must be one of 'debug', 'info', 'warn', 'error'`; no journal event |
| Reload, invalid file through the Gateway | the same file; `kill -HUP <smcpd>` | journal `admin` event, outcome `rejected`, reason `CONFIG_INVALID`, actor `signal:SIGHUP` |
| Reload through the API without a body | `POST /api/v1/config/reload` with no body | HTTP 415, `json_required: POST bodies must be application/json` |
| Reload, invalid file through the API | the same file; `POST /api/v1/config/reload` with body `{}` (19:16:38Z) | HTTP 422, `CONFIG_INVALID: new configuration is invalid; the running configuration is kept: ...`; journal `CONFIG_INVALID`, actor `operator-token` |
| Diagnostic log | `ls -l state/log` | `smcpd.log`, mode 0600, JSON Lines with `configuration reloaded` entries |

## Deviations and corrections

- `docs/operations/logging-metrics-reload.md` said an invalid file makes the reload report `CONFIG_INVALID` and record it in the journal. That holds for `SIGHUP` and the API; `smcpctl reload` validates the file first and refuses it without contacting the Gateway, so nothing is recorded. The page now says so, and that the API needs a JSON body.
- No `DEBUG` entry was written in the second between setting `log.level` to `debug` and the next reload; the run does not show debug output (FR-17.1 is verified by `internal/diag` and `internal/acceptance` tests).
