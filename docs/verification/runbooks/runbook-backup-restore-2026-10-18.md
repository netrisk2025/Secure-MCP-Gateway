# Runbook execution: backup and restore

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/backup-restore.md`; `docs/runbooks/policy-rollback.md`, section "When the Gateway starts fail-closed with `policy_signature`" |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record of the same date, running, active policy revision `r3` (from the policy-rollback record). The backup passphrase was a random 24-byte value in a 0600 file. After the backup, the state was damaged on purpose so that the restore had something to repair: the revision ID inside the active signed policy revision record (`state/policy/revisions/e984c015....json`) was changed from `r3` to `r3x`. Unlike the 2026-10-17 run, the damage was made while the Gateway was running, to exercise the Policy Store currency check added since (`policy_currency`), and the Gateway was then restarted. Started 20:39:13Z, finished 20:39:59Z. The restore's re-application of a package revocation recorded after the backup was executed with the revocation record of the same date.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| Back up 1 | `smcpctl health --config smcp.toml` | `health: degraded; causes: unconfined` |
| Back up 2 | `smcpctl backup --config smcp.toml --passphrase-file backup.pass` | `backup written: .../backups/smcp-backup-20261018T203914.011Z.age`, `sha256: 9a02cfbc494d3cdb26ca62571baff1108bea62b9f909fd700e0b660b9190ca09`, components `configuration, evidence_journal, key_material, policy_store, server_registry, trust_anchors` (`server_registry` is new: the Local Server Registry `state/packages/registry.json` is now named) |
| Back up 3 | `cat <archive>.sha256` | the same digest |
| Back up 4 | `smcpctl backup --list --config smcp.toml` | newest entry `"result": "ok"`, the same path, digest and components |
| Back up 5 | copied the archive and its `.sha256` to a separate directory `offsite/`; `shasum -a 256` there | the same digest |
| After the backup | `itest-client ... -call ref_list_files -args '{"path":"."}'` | `PASS` (work recorded in the journal after the backup) |
| Damage, running | change `"r3"` to `"r3x"` in the active revision record; `smcpctl health` 2 s later | `health: fail-closed; causes: decision_snapshot_stale, unconfined`, detail `policy store integrity check failed: e984c015....json signature does not verify under key 37f593a5b76747d6`; a harness request answers HTTP 503 |
| Damage, restart | stop and start `smcpd`; `smcpctl health` | `health: fail-closed; causes: no_decision_snapshot, policy_signature, unconfined` |
| Restore 1 | stop `smcpd` | exited |
| Restore 2 | `smcpctl restore --config smcp.toml --archive offsite/<archive> --passphrase-file backup.pass --verify-only` | `checksum_verified: true`, the archive manifest listed, `policy_store_revision` `r3`, `policy_revisions_verified` 4, `package_revocations` 0, `graph_mirror` `not configured; nothing to rebuild`; last line `archive verified; nothing was changed` |
| Restore 3 | the same without `--verify-only` | `restored; the previous state is kept at .../inst/state.pre-restore-20261018T203958Z` (`previous_state` in the JSON, `applied: true`); `smcp.toml` and `policy.json` were kept as `*.pre-restore-20261018T203958Z` too |
| Restore 4 | `smcpctl journal verify --config smcp.toml` | `journal OK: 4 segments, 96 events, anchored at segment 4, 1 evidence-key transitions (segments [2])` |
| Restore 5 | start `smcpd`; `smcpctl health` | `health: degraded; causes: unconfined`, policy revision `r3`; `itest-client ... -call ref_read_file` `PASS` |
| Restore 6 | `ls -d state.pre-restore-*` | `state.pre-restore-20261018T203958Z` present |

The `policy_signature` section: step 1 matched after the restart (`smcpctl health` named `policy_signature`); while the Gateway was still running the cause was `decision_snapshot_stale` instead. Step 2 (restore from the last good backup) is the restore above. Step 3 (publish a valid revision instead) was not executed.

Restore after a revocation (revocation record, 20:41:53Z): with the Gateway stopped, the same archive (taken before `smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e` was revoked) was restored again. The report listed the revocation from the current journal (`class` `package`, `reason_code` `REVOKED`) and `package_revocations: 1`; the restored `state/packages/registry.json` held the revision as `revoked` with reason `revocation re-applied from the journal at restore` and the revocation in its `revocations` table, although the archive had neither the revocation entry file nor the revoked state. After the start `smcpctl package list` showed the revision `revoked` and the server `ref` `not_started` (`PACKAGE_NOT_ENABLED`), and a new session listed 0 tools.

## Deviations and corrections

- `docs/runbooks/backup-restore.md` did not say what the restore now checks and re-applies. Restore step 3 now says that the restore verifies the archived Policy Store and re-applies the revocations recorded in the restored and the current journal, so a package revoked after the backup stays revoked, and names the report fields.
- `docs/runbooks/policy-rollback.md` said the Gateway starts fail-closed with `policy_signature`; it did not say that a running Gateway reports the damage within seconds as `decision_snapshot_stale`. That section now says so (see the policy-rollback record).
- The Gateway ran as a plain process, so "Stop the Gateway" and "Start the Gateway" were `kill <pid>` and `smcpd --config smcp.toml`.
