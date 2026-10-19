# Runbook execution: upgrade and rollback

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/upgrade-rollback.md` |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record of the same date, after the backup and restore record (policy revision `r3`). `smcpd` and `smcpctl` of the commit above were copied into a directory `installed/`, and the Gateway was started from there. It was not run by launchd or systemd, so every upgrade passed these commands:

- `--start-cmd 'nohup installed/smcpd --config "$SMCP_CONFIG" >>smcpd.log 2>&1 & echo $! > smcpd.pid'`
- `--stop-cmd 'p=$(cat smcpd.pid); [ -n "$p" ] && kill "$p"; while [ -n "$p" ] && kill -0 "$p"; do sleep 0.1; done; true'`

(absolute paths in the run). Started 20:40:11Z, finished 20:41:12Z.

## Upgrade, with the published v1.0.0 release

| Step | Command | Observed |
|---|---|---|
| Before | `installed/smcpctl version --config smcp.toml` | `smcpctl 0.0.0-dev`, `smcpd 0.0.0-dev (standalone profile, not enforced)` |
| 1 | `gh release download v1.0.0 -R ethan03805/Secure-MCP-Gateway -D rel-100 -p 'smcp_1.0.0_checksums.txt*' -p 'smcp_1.0.0_darwin_arm64.tar.gz'` | the checksum file, its `.minisig` and `.sigstore.json`, and the darwin/arm64 archive |
| 2 | `installed/smcpctl upgrade --config smcp.toml --release rel-100 --bin-dir installed --passphrase-file backup.pass --start-cmd ... --stop-cmd ...` (default `--pubkey`, the release key in `SECURITY.md`) | `release verified: signature of smcp_1.0.0_checksums.txt and checksum of smcp_1.0.0_darwin_arm64.tar.gz`; `upgrading from 0.0.0-dev to 1.0.0`; `backup written: .../smcp-backup-20261018T204017.227Z.age`; `dispatch stopped`; `installed smcpd, smcpctl, smcp-refserver, smcp-connect, smcp-stdio, smcp-session`; `configuration is at schema_version 1; nothing to migrate`; `Gateway answers: state degraded, version 1.0.0`; `upgrade complete; the previous binaries are kept as <name>.prev in .../installed` |
| 3 | `installed/smcpctl version` | `smcpctl 1.0.0`, `smcpd 1.0.0 (standalone profile, not enforced)`; `smcpctl health` degraded (`unconfined`), policy revision `r3`; `itest-client ... -call ref_read_file` `PASS` |
| 4 | `ls installed` | `smcpd.prev` and `smcpctl.prev` next to the new binaries |

## When the upgrade rolls back

A release that fails on purpose was made in the way of `scripts/ci-integration.sh`: an archive `smcp_9.9.10_darwin_arm64.tar.gz` whose `smcpd` is `#!/bin/sh` + `exit 1` and whose `smcpctl` is the commit's, with a checksum file signed by a throwaway minisign key passed with `--pubkey`. The rollback ran twice: first with v1.0.0 installed (from the upgrade above), then with the binaries of the commit above installed again, so that the rollback code under test (`backup.Restore` with `GraphBestEffort`, changed since the previous record) is this commit's.

| Step | Command | Observed (second run, this commit's `smcpctl`) |
|---|---|---|
| 1 | `installed/smcpctl upgrade --config smcp.toml --release rel-bad --pubkey <test key> --bin-dir installed --passphrase-file backup.pass --start-cmd ... --stop-cmd ... --health-timeout 10s` | exit 1; `release verified: ... smcp_9.9.10_checksums.txt ...`; `backup written: .../smcp-backup-20261018T204054.633Z.age`; `installed smcpd, smcpctl`; `rolling back: the Gateway did not leave fail-closed within 10s (no answer)`; `pre-upgrade backup restored; the state of the failed attempt is kept at .../inst/state.pre-restore-20261018T204105Z`; `Gateway answers: state degraded, version 0.0.0-dev`; last line `smcpctl: upgrade rolled back: the Gateway did not leave fail-closed within 10s (no answer); the previous version is running` |
| 2 | `smcpctl health`; `installed/smcpctl version` | degraded (`unconfined`), version `0.0.0-dev`; `itest-client ... -call ref_read_file` `PASS` |
| 3 | journal | `admin` event, outcome `upgrade_rolled_back`, reason `UPGRADE_ROLLED_BACK`, actor `smcpctl upgrade`, `from_version` `0.0.0-dev`, the backup and the reason |
| 4 | `ls -d state.pre-restore-*` | `state.pre-restore-20261018T204105Z` present |
| after | stop `smcpd`; `smcpctl journal verify --config smcp.toml --strict` | `journal OK: 11 segments, 165 events, anchored at segment 11, 1 evidence-key transitions (segments [2])` |

The first run (v1.0.0's `smcpctl`, 20:40:33Z) gave the same messages, printed `upgrading from 1.0.0 to 0.0.0-dev`, kept `state.pre-restore-20261018T204045Z`, answered `Gateway answers: state degraded, version 1.0.0` and left v1.0.0 running (`itest-client` `PASS`); its `upgrade_rolled_back` event has `from_version` `1.0.0`.

Step 5 (`the rollback had errors`) did not occur. The restored configuration has no `[graph]` table, so the rollback reported no graph mirror outcome.

## Deviations and corrections

- The upgrade went from a development build of the commit (`0.0.0-dev`) to v1.0.0, the newest published release; no release newer than the commit under test exists yet.
- The failing release's archive carried the commit's `smcpctl`, so the command printed `upgrading from ... to 0.0.0-dev` (the version of that `smcpctl`) rather than 9.9.10. The runbook does not depend on the printed target version.
- None in the runbook.
