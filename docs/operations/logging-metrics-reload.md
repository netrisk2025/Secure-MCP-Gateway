# Diagnostic log, metrics and configuration reload

## Diagnostic log (FR-17.1 to FR-17.3)

`smcpd` writes its diagnostic log (D-14) to two places:

- the file `[log] file` (default `<state.dir>/log/smcpd.log`), always as JSON Lines, mode 0600 in a 0700 directory;
- standard error, in `[log] format` (`text`, the default, or `json`).

Levels are `error`, `warn`, `info` (default) and `debug`, set by `[log] level` or the `--log-level` flag of `smcpd`, and changed at run time by a reload. The file is rotated when a write would take it past `[log] max_bytes` (default 10 MiB); rotated files are `smcpd.log.1` (newest) to `smcpd.log.<max_files>` and older ones are deleted (CP-50: 5 kept).

The diagnostic log is not evidence: security events go only to the evidence journal, whatever the log level. The log never contains secret values, tokens, passwords, tool arguments or tool results; in addition to the code rule, every attribute whose name is or ends in `password`, `passphrase`, `token`, `secret`, `authorization`, `cookie`, `arguments`, `args`, `result`, `content`, `seed` or `private_key` is written as `[REDACTED]`.

The backup archive does not include `log/`.

## Metrics endpoint (FR-17.4, FR-17.5)

With `[metrics] enabled = true`, `smcpd` serves the Prometheus text format at `http://127.0.0.1:9464/metrics` (`[metrics] address`). The address must be loopback; any other address is refused at configuration load and again when the listener binds, and the daemon does not start. The endpoint is plain HTTP without authentication, so any local user can read the counts; it exposes no tool arguments, results, principals or sessions.

A configuration written by `smcpctl bootstrap` enables the endpoint on the admin port plus one (8445 with the default ports); `--metrics-port N` picks another port and `--metrics-port 0` writes `enabled = false`.

| Metric | Type | Labels |
|---|---|---|
| `smcp_calls_total` | counter | `server_alias`, `tool` (public tool name), `outcome` (`delivered`, `denied`, `failed`, `indeterminate`, `withheld`, `blocked`), `reason_code` |
| `smcp_decision_latency_seconds` | histogram | none; time from the call's `requested` event to its decision event, for calls not held for approval |
| `smcp_journal_flush_seconds` | histogram | none; duration of each journal fsync |
| `smcp_health_state` | gauge | none; 0 healthy, 1 degraded, 2 fail-closed |
| `smcp_active_sessions` | gauge | none |
| `smcp_pending_approvals` | gauge | none; 0 until the Approval Service (E-07) supplies its queue length |
| `smcp_backend_instances_running` | gauge | `server_alias` |

Call counts are taken from the evidence events the journal accepted, so they match the journal. Example scrape configuration:

```yaml
scrape_configs:
  - job_name: smcp
    static_configs: [{ targets: ["127.0.0.1:9464"] }]
```

## Configuration reload (FR-17.9)

`smcpctl reload`, `POST /api/v1/config/reload` and `SIGHUP` to `smcpd` all do the same:

1. Read and validate the configuration file. If it is invalid, nothing changes; the API reports `CONFIG_INVALID` (HTTP 422) and the journal records `CONFIG_INVALID`. `smcpctl reload` validates the file itself first and refuses an invalid file with the schema error without contacting the Gateway, so no event is recorded; `SIGHUP` and `POST /api/v1/config/reload` (with a JSON body such as `{}`) reach the Gateway and record it.
2. Compare it with the configuration in force and apply the changed keys that can change without ending sessions.
3. Report every changed key in one of three lists and record a `CONFIG_RELOADED` event.

```
$ smcpctl reload
{ "changed": ["limits.principal_calls_per_minute", "listener.address"],
  "applied": ["limits.principal_calls_per_minute"],
  "restart_required": ["listener.address"],
  "not_applied_until_restart": [] }
```

| List | Keys |
|---|---|
| `applied` | the CP-50 reloadable keys: `log.level`, `limits.principal_calls_per_minute`, `limits.principal_call_burst` |
| `not_applied_until_restart` | always empty in this release (kept for compatibility) |
| `restart_required` | every other key, including listener addresses, `state.dir`, `profile` and the other `limits.*`. Servers are enabled and disabled at run time from the console (G-10) and clients managed in G-11, not by a reload. |

A key reported in `restart_required` or `not_applied_until_restart` stays reported on later reloads until the Gateway restarts.

## Configuration `schema_version` (FR-13.13)

The configuration file carries a top-level integer `schema_version`. This release reads version 1; a file without the key is read as version 1.

| File | Result |
|---|---|
| `schema_version` greater than the release supports | Refused at start and by every `smcpctl` command: `configuration schema_version is newer than this release supports: the file has schema_version 2 and this release supports up to 1` |
| `schema_version` older than the release reads | Refused with `... run smcpctl config migrate to rewrite it` |
| Current | Accepted |

`smcpctl config migrate` rewrites an older file step by step to the current version, keeps the original as `<file>.v<old>.bak`, and validates the result before replacing the file; a failed migration leaves the file unchanged. `smcpctl upgrade` runs the new release's `config migrate` before starting it.
