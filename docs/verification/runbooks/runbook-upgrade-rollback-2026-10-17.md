# Runbook execution: upgrade and rollback

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/upgrade-rollback.md` |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record. `smcpd` and `smcpctl` of the commit above were copied into a directory `installed/`, and the Gateway was started from there. It was not run by launchd or systemd, so every upgrade passed these commands:

- `--start-cmd 'nohup installed/smcpd --config "$SMCP_CONFIG" >>smcpd.log 2>&1 & echo $! > smcpd.pid'`
- `--stop-cmd 'p=$(cat smcpd.pid); kill $p; while kill -0 $p; do sleep 0.1; done'`

(absolute paths in the run). Started 19:10:23Z, finished 19:11:09Z.

## Upgrade, with the published v1.0.0-rc.2 release

| Step | Command | Observed |
|---|---|---|
| Before | `installed/smcpctl version --config smcp.toml` | `smcpctl 0.0.0-dev`, `smcpd 0.0.0-dev (standalone profile, not enforced)` |
| 1 | `gh release download v1.0.0-rc.2 -R ethan03805/Secure-MCP-Gateway -D rel-rc2 -p 'smcp_1.0.0-rc.2_checksums.txt*' -p 'smcp_1.0.0-rc.2_darwin_arm64.tar.gz'` | the checksum file, its `.minisig` and `.sigstore.json`, and the darwin/arm64 archive |
| 2 | `installed/smcpctl upgrade --config smcp.toml --release rel-rc2 --bin-dir installed --passphrase-file backup.pass --start-cmd ... --stop-cmd ...` (default `--pubkey`, the release key in `SECURITY.md`) | `release verified: signature of smcp_1.0.0-rc.2_checksums.txt and checksum of smcp_1.0.0-rc.2_darwin_arm64.tar.gz`; `upgrading from 0.0.0-dev to 1.0.0-rc.2`; backup written; `installed smcpd, smcpctl, smcp-refserver, smcp-connect, smcp-stdio, smcp-session`; `configuration is at schema_version 1; nothing to migrate`; `Gateway answers: state degraded, version 1.0.0-rc.2`; `upgrade complete` |
| 3 | `installed/smcpctl version` | `smcpctl 1.0.0-rc.2`, `smcpd 1.0.0-rc.2`; `smcpctl health` degraded (`unconfined`), policy revision `r4`; `itest-client ... -call ref_read_file` `PASS` |
| 4 | `ls installed` | `smcpd.prev` and `smcpctl.prev` next to the new binaries |

## When the upgrade rolls back

A release that fails on purpose was made in the way of `scripts/ci-integration.sh`: an archive `smcp_9.9.10_darwin_arm64.tar.gz` whose `smcpd` is `#!/bin/sh` + `exit 1`, with a checksum file signed by a throwaway minisign key passed with `--pubkey`. The rollback ran twice: first with v1.0.0-rc.2 installed (from the upgrade above), then with the binaries of the commit above installed again, so that the rollback code under test is this commit's.

| Step | Command | Observed (second run, this commit's `smcpctl`) |
|---|---|---|
| 1 | `installed/smcpctl upgrade --config smcp.toml --release rel-bad --pubkey <test key> --bin-dir installed --passphrase-file backup.pass --start-cmd ... --stop-cmd ... --health-timeout 10s` | exit 1; `rolling back: the Gateway did not leave fail-closed within 10s (no answer)`; `pre-upgrade backup restored; the state of the failed attempt is kept at .../inst/state.pre-restore-20261017T191107Z`; `Gateway answers: state degraded, version 0.0.0-dev`; last line `smcpctl: upgrade rolled back: the Gateway did not leave fail-closed within 10s (no answer); the previous version is running` |
| 2 | `smcpctl health`; `installed/smcpctl version` | degraded (`unconfined`), version `0.0.0-dev`; `itest-client ... -call ref_read_file` `PASS` |
| 3 | journal | `admin` event, outcome `upgrade_rolled_back`, reason `UPGRADE_ROLLED_BACK`, actor `smcpctl upgrade` |
| 4 | `ls -d state.pre-restore-*` | `state.pre-restore-20261017T191107Z` present |
| after | stop `smcpd`; `smcpctl journal verify --config smcp.toml --strict` | `journal OK: 10 segments, 169 events, anchored at segment 10, 1 evidence-key transitions (segments [1])` |

The first run (v1.0.0-rc.2's `smcpctl`) gave the same messages and kept `state.pre-restore-20261017T191039Z`.

Step 5 (`the rollback had errors`) did not occur.

## Deviations and corrections

- The upgrade went from a development build (`0.0.0-dev`) to v1.0.0-rc.2, the newest published release; no release newer than the commit under test exists yet.
- The failing release's archive carried the installed `smcpctl`, so the command printed `upgrading from 0.0.0-dev to 1.0.0-rc.2` (the version of that `smcpctl`) rather than 9.9.10. The runbook does not depend on the printed target version.
