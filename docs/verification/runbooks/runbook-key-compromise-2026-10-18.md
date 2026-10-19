# Runbook execution: key or credential compromise

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/key-compromise.md` |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

## Setup

A second fresh instance (`smcpctl bootstrap --dir inst2 --port 28853 --admin-port 28854 --notify off ...`, metrics on 28855), started, with a call through `ref` passing and a backup taken at the start (`smcp-backup-20261018T204210.189Z.age`, the "backup taken before the exposure"). Started 20:42:10Z, finished 20:43:16Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| First 1 | `smcpctl stop --reason "runbook execution: key compromise"` | `{"state": "stopped"}` |
| First 2 | `smcpctl journal verify`; `smcpctl journal export --to export2` | `journal OK: 2 segments, 16 events, anchored at segment 1 (segment-000002.jsonl is still open; its 3 events are not signed yet)`; `exported 1 new segments; anchor at segment 1; verify with: smcpctl journal verify --dir export2/journal --key export2/keys/evidence-genesis.pub`; `export2/` holds `journal/`, `journal.anchor` and `keys/` |
| Operator token | stop `smcpd`; `openssl rand -hex 32 > state/keys/admin.token; chmod 600 state/keys/admin.token`; start `smcpd` | `smcpctl keys status` worked with the new file; `GET /api/v1/keys` answered 401 with the old token and 200 with the new one |
| Session Approver password | `smcpctl hash-password --password-file approver2.pw`; replaced `password_hash` of `[[approver]]` in `smcp.toml`; restarted `smcpd`; `smcpctl resume` | sign-in with the old password: `sign-in POST: status 401`; with the new password: token issued, `PASS` |
| Server CA key | `smcpctl keys rotate ca --overlap 0` | `"stage": "finished"` at once (`switch_at` = the command's time), new CA serial `2000bc79...`; a client with the new `state/tls/ca.crt` started right after the command: `x509: certificate signed by unknown authority`; 1.5 s later, a client with only the old CA file: `tls: failed to verify certificate: x509: certificate signed by unknown authority`; with the new `state/tls/ca.crt`: `PASS` |
| Listener key | `smcpctl keys rotate tls` | `PASS` afterwards |
| Evidence key | `smcpctl keys rotate evidence` | new public key `375ab1ab...` reported |
| Policy-signing key | stop; replace `keys/policy.key` and `keys/policy.pub` with another Ed25519 pair (copies of the evidence key pair); start | `health: fail-closed; causes: no_decision_snapshot, policy_signature, unconfined`, `policy_revision` null |
| Policy-signing key, recovery | stop; `smcpctl restore --archive <backup from the start> --passphrase-file ...`; start | `restored; the previous state is kept at .../inst2/state.pre-restore-20261018T204259Z`; the report: `policy_store_revision` `r1`, `policy_revisions_verified` 1 (the archived Policy Store verified under the archived key); `health: degraded; causes: unconfined`, policy revision `r1` |
| Afterwards 1 | `smcpctl keys status` | listener not_after `2027-01-16T20:42:00Z` and CA not_after `2027-10-18T20:42:00Z` (the bootstrap's), `evidence_public_key` = `evidence_trust_root` = `9df5cd88...`: the restore brought back the key material of the backup |
| Afterwards 2 | `smcpctl health`; `smcpctl resume`; a call | degraded (`unconfined`); the new approver password: `sign-in POST: status 401`; the original approver password (the restored `smcp.toml`): `PASS` |
| Afterwards 3 | `smcpctl backup --passphrase-file ...`; stop; `smcpctl journal verify` | `backup written: ...smcp-backup-20261018T204301.015Z.age`; `journal OK: 3 segments, 31 events, anchored at segment 3` |

### After a restore (20:43:12Z to 20:43:16Z)

The section added by the 2026-10-17 execution was carried out: with the Gateway stopped, a new operator token was written and the approver's `password_hash` replaced again; then `smcpd` was started and `smcpctl keys rotate ca --overlap 0`, `keys rotate tls` and `keys rotate evidence` were run (with a 1.5 s pause after the CA switch).

| Step | Command | Observed |
|---|---|---|
| Rotations repeated | as above | `"stage": "finished"`; `{"kind": "tls"}`; `{"kind": "evidence"}`; `smcpctl` worked with the new token file |
| Check | `smcpctl keys status`; calls | listener not_after `2027-01-16T20:43:14Z`, CA not_after `2027-10-18T20:43:12Z`, `evidence_public_key` `7a9d11bb...` differs from `evidence_trust_root` `9df5cd88...`; the original approver password: `sign-in POST: status 401`; the new one: `PASS` |
| Afterwards 3 | `smcpctl backup`; stop; `smcpctl journal verify` | `backup written: ...smcp-backup-20261018T204316.129Z.age`; `journal OK: 6 segments, 52 events, anchored at segment 6, 1 evidence-key transitions (segments [4])` |

Rows not executed: Administrator password and Approver accounts (`[[approvals.account]]`, none configured), OAuth client secrets and adapter credential files, Remote Access clients (remote access off), package signing keys (see the revocation record), vault master key and secret values (no vault configured).

## Deviations and corrections

- Server CA key: after `--overlap 0` the new bundle is written at once, but the listeners present the old listener certificate for up to one second more (their certificate reloader checks the file at most once per second, `internal/keys/rotate.go`), so the first client with the new bundle failed verification. This is a defect of the rotation, which does not force the listeners to reload; it was not fixed by this task (see the key-rotation record of the same date). The Server CA row of `docs/runbooks/key-compromise.md` now says that the new certificate is served within a second.
- None otherwise. The restore again undid the rotations done before it, as the runbook's "After a restore" section says; repeating them gave the expected state.
