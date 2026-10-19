# Runbook execution: key and certificate rotation

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/key-rotation.md` |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record (ports 28643 to 28645), running. A harness call is `itest-client` signing in and calling `ref_read_file`, each time with a new session. Started 19:08:51Z, finished 19:08:55Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| Before | `smcpctl keys status --config smcp.toml` | listener serial `3efec61c...`, not_after 2027-01-15T19:07:25Z; server CA serial `6b67d0b9...`; one CA in `trust_bundle`; `evidence_public_key` = `evidence_trust_root` = `ec5d4ae0...` |
| Listener 1 | `smcpctl keys rotate tls --config smcp.toml` | `{"kind": "tls", "listener_not_after": "2027-01-15T19:08:51Z", "uncovered_names": null}` |
| Listener 2 | `smcpctl keys status` | new listener serial `1e120f11...`, not_after 2027-01-15T19:08:51Z (90 days ahead) |
| Listener 3 | `itest-client ... -call ref_read_file` (same CA file) | `PASS` |
| CA 1 | `smcpctl keys rotate ca --overlap 168h --config smcp.toml` | `"stage": "overlap"`, `"switch_at": "2026-10-24T19:08:52.80147Z"`, next CA serial `47f5f605...` |
| CA 2 | `grep -c "BEGIN CERTIFICATE" state/tls/ca.crt` | `2` (both CAs in the bundle) |
| CA 3 | `itest-client` with `state/tls/ca.crt` | `PASS` |
| CA 4 | `smcpctl keys rotate ca --finish --config smcp.toml` | `"stage": "finished"`, CA not_after 2027-10-17T19:08:52Z |
| CA 5 | `smcpctl keys status` | `server_ca` serial `47f5f605...`; `trust_bundle` holds one CA; no `ca_rotation` field; the listener certificate was reissued by the new CA (serial `2d27eea1...`) |
| CA 5 | `itest-client` | `PASS` |
| Evidence 1 | `smcpctl keys rotate evidence --config smcp.toml` | `"public_key": "46c150e4..."` |
| Evidence 2 | `smcpctl keys status` | `evidence_public_key` = `46c150e4...`, `evidence_trust_root` unchanged `ec5d4ae0...` |
| Evidence 3 | stop `smcpd` (`kill`), then `smcpctl journal verify --config smcp.toml` | `journal OK: 2 segments, 74 events, anchored at segment 2, 1 evidence-key transitions (segments [1])` |
| Evidence 4 | `ls -l state/keys/evidence-genesis.pub` | present, 65 bytes, mode 0644 (copying it off the machine was not part of this run) |

`smcpd` was started again afterwards for the next runbook.

## Deviations and corrections

None. Clients were represented by `itest-client` with the instance's CA file; distributing the bundle to real harnesses (step CA 2) was not exercised.
