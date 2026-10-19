# Operations

Day-to-day operation of the Gateway: health, logs, metrics, keys, backups, configuration reload, upgrade and removal. These documents cover SRS FR-7.11 to FR-7.14, FR-13.7 to FR-13.13 and FR-17, and the operations part of the operator guide (FR-18.4).

| Topic | Document |
|---|---|
| Health monitor, causes, acknowledgment | [health.md](health.md) |
| Diagnostic log, metrics endpoint, configuration reload, `schema_version` | [logging-metrics-reload.md](logging-metrics-reload.md) |
| Certificates and keys: lifetimes, status, rotation | [keys.md](keys.md) |
| Encrypted backup and restore, evidence export | [backup.md](backup.md) |
| Upgrade with rollback, uninstall and purge | [upgrade-uninstall.md](upgrade-uninstall.md) |
| Control API routes of these functions | [../api/ops.md](../api/ops.md) |
| Runbooks | [../runbooks/](../runbooks/) |

## Commands

| Command | Needs a running Gateway | Purpose |
|---|---|---|
| `smcpctl health [--require-not-fail-closed]` | yes | Health report with state, causes and release label |
| `smcpctl health ack <cause>` | yes | Acknowledge a latched integrity cause |
| `smcpctl reload` | yes | Reload the configuration file (same as `kill -HUP <smcpd pid>`) |
| `smcpctl keys status` | no | Key and certificate inventory (from the Gateway when it runs, else from the state directory) |
| `smcpctl keys rotate tls\|ca\|evidence` | yes, except `tls` and `ca` with `--offline` | Rotate the listener certificate, the server CA or the evidence-signing key |
| `smcpctl backup [--passphrase-file F \| --recipient age1...] [--optional name=path] [--list]` | no | Encrypted backup; online through the Gateway when it runs |
| `smcpctl restore --archive A [--passphrase-file F \| --identity-file F] [--verify-only]` | must be stopped (except `--verify-only`) | Verify and restore a backup |
| `smcpctl journal export [--to DIR]` | no | Copy closed journal segments and the anchor to an export directory |
| `smcpctl journal verify [--dir D --key K] [--strict]` | no | Verify the journal, following evidence-key transitions |
| `smcpctl config migrate` | no | Rewrite the configuration to this release's `schema_version` |
| `smcpctl version [--short]` | no | Version; with a running Gateway also its profile and release label |
| `smcpctl upgrade --release DIR ...` | yes | Upgrade with pre-upgrade backup, health wait and automatic rollback |
| `smcpctl uninstall [--purge]` | stops it | Remove services and binaries; `--purge` also removes state |

Every command takes `--config <file>` (default `smcp.toml`).

## Configuration keys added for operations

| Key | Default | Meaning |
|---|---|---|
| `schema_version` | `1` when absent | Configuration format version (FR-13.13) |
| `[log] file` | `<state.dir>/log/smcpd.log` | Diagnostic log file, JSON Lines (D-14) |
| `[log] max_bytes` | `10485760` (10 MiB) | Rotation size (CP-50); at least 65536 |
| `[log] max_files` | `5` | Rotated files kept (CP-50); 1 to 100 |
| `[metrics] enabled` | `false` | Serve `/metrics` (CP-51) |
| `[metrics] address` | `127.0.0.1:9464` | Metrics listener; must be loopback and differ from the other listeners |
| `[evidence] export_dir` | none (export off) | Directory that receives closed journal segments and the anchor (FR-7.14) |
| `[evidence] export_interval` | `10s` | How often the export runs; 1 s to 50 s so a closed segment is copied within 60 s |
| `[evidence] quota_bytes` | `10737418240` | Journal storage quota (CP-26); health warns with `storage_quota_journal` at 80% (FR-9.15) |
| `[backup] dir` | `backups` next to the configuration file | Where backup archives and `index.json` are written |
| `[backup] interval` | off | Scheduled backups (FR-9.16); needs `recipients` or `passphrase_file` |
| `[backup] recipients`, `passphrase_file` | none | Encryption of scheduled backups |

Relative paths are resolved against the directory of the configuration file.
