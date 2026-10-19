# Runbook execution: key or credential compromise

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/key-compromise.md` |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Result | pass |

## Setup

A second fresh instance (`smcpctl bootstrap --dir inst2 --port 28653 --admin-port 28654 --notify off ...`, metrics on 28655), started, with a call through `ref` passing and a backup taken at the start (`smcp-backup-20261017T191217.712Z.age`, the "backup taken before the exposure"). Started 19:12:17Z, finished 19:12:45Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| First 1 | `smcpctl stop --reason "runbook execution: key compromise"` | `{"state": "stopped"}` |
| First 2 | `smcpctl journal verify`; `smcpctl journal export --to export2` | `journal OK: 2 segments, 16 events, anchored at segment 1 (segment-000002.jsonl is still open; ...)`; `exported 1 new segments; anchor at segment 1`; `export2/` holds `journal/`, `journal.anchor` and `keys/` |
| Operator token | stop `smcpd`; `openssl rand -hex 32 > state/keys/admin.token; chmod 600 state/keys/admin.token`; start `smcpd` | `smcpctl` worked with the new file; `GET /api/v1/keys` answered 401 with the old token and 200 with the new one |
| Session Approver password | `smcpctl hash-password --password-file approver2.pw`; replaced `password_hash` of `[[approver]]` in `smcp.toml`; restarted `smcpd`; `smcpctl resume` | sign-in with the old password: `sign-in POST: status 401`; with the new password: token issued, `PASS` |
| Server CA key | `smcpctl keys rotate ca --overlap 0` | a client with only the old CA file: `tls: failed to verify certificate: x509: certificate signed by unknown authority`; with the new `state/tls/ca.crt`: `PASS` |
| Listener key | `smcpctl keys rotate tls` | `PASS` afterwards |
| Evidence key | `smcpctl keys rotate evidence` | new public key reported |
| Policy-signing key | stop; replace `keys/policy.key` and `keys/policy.pub` with another Ed25519 pair (copies of the evidence key pair); start | `health: fail-closed; causes: no_decision_snapshot, policy_signature, unconfined`, `policy_revision` null |
| Policy-signing key, recovery | stop; `smcpctl restore --archive <backup from the start> --passphrase-file ...`; start | `restored; the previous state is kept at .../inst2/state.pre-restore-20261017T191223Z`; `health: degraded; causes: unconfined`, policy revision `r1` |
| Afterwards 1 | `smcpctl keys status` | listener not_after `2027-01-15T19:11:54Z` and CA not_after `2027-10-17T19:11:54Z` (the bootstrap's), `evidence_public_key` = `evidence_trust_root`: the restore brought back the key material of the backup |
| Afterwards 2 | `smcpctl health`; `smcpctl resume`; a call | degraded (`unconfined`); `PASS` with the original approver password (the restored `smcp.toml`) |
| Afterwards 3 | `smcpctl backup --passphrase-file ...`; stop; `smcpctl journal verify` | `backup written: ...smcp-backup-20261017T191224.829Z.age`; `journal OK: 3 segments, 29 events, anchored at segment 3` |

The first attempt at the operator-token check used `GET /api/v1/health`, which does not exist and answers 404 for any token; the check was repeated at 19:12:44Z with `GET /api/v1/keys` (after the restore, with the Gateway stopped while the token file was rewritten) and gave 401 for the old token and 200 for the new one.

Rows not executed: Approver accounts (`[[approvals.account]]`, none configured), OAuth client secrets and adapter credential files, Remote Access clients (remote access off), package signing keys (see the revocation record), vault master key and secret values (no vault configured).

## Deviations and corrections

The restore that the policy-signing-key row recommends also restored the operator token, the approver password hash, the CA, the listener certificate and the evidence key from the archive, undoing the rotations done earlier in the run. The runbook did not say so. `docs/runbooks/key-compromise.md` now has a section "After a restore" that says to repeat the rotations once the restored Gateway runs.
