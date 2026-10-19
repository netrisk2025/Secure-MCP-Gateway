# Runbook execution: key and certificate rotation

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/key-rotation.md` |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record of the same date (ports 28843 to 28845), running. A harness call is `itest-client` signing in and calling `ref_read_file`, each time with a new session, trusting `state/tls/ca.crt`. Started 20:37:53Z, finished 20:38:42Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| Before | `smcpctl keys status --config smcp.toml` | listener serial `5852f99f...`, not_after 2027-01-16T20:36:52Z; server CA serial `6bbc8fae...`; one CA in `trust_bundle`; `evidence_public_key` = `evidence_trust_root` = `5e3ca7f8...` |
| Listener 1 | `smcpctl keys rotate tls --config smcp.toml` | `{"kind": "tls", "listener_not_after": "2027-01-16T20:37:58Z", "uncovered_names": null}` |
| Listener 2 | `smcpctl keys status` | new listener serial `22a83a3e...`, not_after 2027-01-16T20:37:58Z (90 days ahead) |
| Listener 3 | `itest-client ... -call ref_read_file` (same CA file) | `PASS` |
| CA 1 | `smcpctl keys rotate ca --overlap 168h --config smcp.toml` | `"stage": "overlap"`, `"switch_at": "2026-10-25T20:37:58.715318Z"`, next CA serial `7203ef26...` |
| CA 2 | `grep -c "BEGIN CERTIFICATE" state/tls/ca.crt` | `2` (both CAs in the bundle) |
| CA 3 | `itest-client` with `state/tls/ca.crt` | `PASS` |
| CA 4 | `smcpctl keys rotate ca --finish --config smcp.toml` | `"stage": "finished"`, `ca_not_after` 2027-10-18T20:37:58Z, `listener_not_after` 2027-01-16T20:37:59Z |
| CA 5 | `smcpctl keys status` | `server_ca` serial `7203ef26...`; `trust_bundle` holds one CA; no `ca_rotation` field; the listener certificate was reissued by the new CA (serial `746da520...`) |
| CA 5 | `itest-client` with `state/tls/ca.crt`, started right after the `--finish` command returned | `FAIL: ... tls: failed to verify certificate: x509: certificate signed by unknown authority` |
| CA 5 | the same, a few seconds later | `PASS`; `openssl s_client` shows the listener certificate issued by the new CA |
| Evidence 1 | `smcpctl keys rotate evidence --config smcp.toml` | `"public_key": "b4648244..."` |
| Evidence 2 | `smcpctl keys status` | `evidence_public_key` = `b4648244...`, `evidence_trust_root` unchanged `5e3ca7f8...` |
| Evidence 3 | stop `smcpd` (`kill`), then `smcpctl journal verify --config smcp.toml` | `journal OK: 3 segments, 74 events, anchored at segment 3, 1 evidence-key transitions (segments [2])` |
| Evidence 4 | `ls -l state/keys/evidence-genesis.pub` | present, 65 bytes, mode 0644 (copying it off the machine was not part of this run) |

`smcpd` was started again afterwards for the next runbook.

## Deviations and corrections

- The CA 5 failure: after `--finish` (and at `switch_at`) `ca.crt` holds only the new CA at once, but the listeners keep presenting the old listener certificate until their certificate reloader next checks the file, which it does at most once per second (`keys.CertReloader`, `internal/keys/rotate.go`); the rotation does not force a reload. A client that already trusts only the new bundle and connects in that second fails verification once. During a normal overlap rotation clients still hold both CAs, so they are not affected; after `--overlap 0` (the key-compromise runbook) they are, for up to a second. This was also reproduced in the key-compromise record of the same date. The code was not changed by this task; step 5 of the Server CA section of `docs/runbooks/key-rotation.md` now says to allow a second before checking a client against the new bundle.
- Executor error: the first `journal verify` of Evidence 3 ran while `smcpd` was still running (the run's start script had saved the PID of a wrapper shell, so `kill` did not stop the Gateway) and reported segment 3 open with 1 unsigned event. The Gateway process was then stopped by its own PID and the verification repeated at 20:38:42Z with the result above. The start script was corrected for the rest of the run.
- Clients were represented by `itest-client` with the instance's CA file; distributing the bundle to real harnesses (step CA 2) was not exercised.
