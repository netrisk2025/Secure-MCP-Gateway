# Runbook execution: backup and restore

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/backup-restore.md`; `docs/runbooks/policy-rollback.md`, section "When the Gateway starts fail-closed with `policy_signature`" |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record, running, active policy revision `r4`. The backup passphrase was a random 24-byte value in a 0600 file. After the backup, the state was damaged on purpose so that the restore had something to repair: with the Gateway stopped, the revision ID inside the active signed policy revision record (`state/policy/revisions/0c16bee0....json`) was changed from `r4` to `r4x`. Started 19:09:41Z, finished 19:09:44Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| Back up 1 | `smcpctl health --config smcp.toml` | `health: degraded; causes: unconfined` |
| Back up 2 | `smcpctl backup --config smcp.toml --passphrase-file backup.pass` | `backup written: .../backups/smcp-backup-20261017T190941.447Z.age`, `sha256: 21430f94e56528be4ddf3617c5c34a0be8c761c85e36d797a4127547345a3ede`, components `configuration, evidence_journal, key_material, policy_store, trust_anchors` |
| Back up 3 | `cat <archive>.sha256` | the same digest |
| Back up 4 | `smcpctl backup --list --config smcp.toml` | newest entry `"result": "ok"`, the same path and digest |
| Back up 5 | copied the archive and its `.sha256` to a separate directory; `shasum -a 256` there | the same digest |
| After the backup | `itest-client ... -call ref_list_files` | `PASS` (work recorded in the journal after the backup) |
| Damage | stop `smcpd`; change `"r4"` to `"r4x"` in the active revision record; start `smcpd` | `smcpctl health`: `health: fail-closed; causes: no_decision_snapshot, policy_signature, unconfined`; a harness request answers HTTP 503 |
| Restore 1 | stop `smcpd` | exited |
| Restore 2 | `smcpctl restore --config smcp.toml --archive <copy> --passphrase-file backup.pass --verify-only` | `checksum_verified: true`, the archive manifest listed, last line `archive verified; nothing was changed` |
| Restore 3 | the same without `--verify-only` | `restored; the previous state is kept at .../inst/state.pre-restore-20261017T190943Z` (`previous_state` in the JSON); `smcp.toml` and `policy.json` were kept as `*.pre-restore-20261017T190943Z` too |
| Restore 4 | `smcpctl journal verify --config smcp.toml` | `journal OK: 3 segments, 109 events, anchored at segment 3, 1 evidence-key transitions (segments [1])` |
| Restore 5 | start `smcpd`; `smcpctl health` | `health: degraded; causes: unconfined`, policy revision `r4`; `itest-client ... -call ref_read_file` `PASS` |
| Restore 6 | `ls -d state.pre-restore-*` | `state.pre-restore-20261017T190943Z` present |

The `policy_signature` section: step 1 matched (`smcpctl health` named `policy_signature`); step 2 (restore from the last good backup) is the restore above. Step 3 (publish a valid revision instead) was not executed.

## Deviations and corrections

None in the runbook. The Gateway ran as a plain process, so "Stop the Gateway" and "Start the Gateway" were `kill <pid>` and `smcpd --config smcp.toml`.
