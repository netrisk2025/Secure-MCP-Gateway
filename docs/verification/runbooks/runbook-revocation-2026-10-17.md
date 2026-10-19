# Runbook execution: withdraw a server package (revocation)

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/revocation.md` |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record, started again after the upgrade record. `smcpctl bootstrap` signs the example package with a one-time key that it does not keep, so a second trust anchor was enrolled to sign the revocation: `smcpctl package keygen --out runbook-anchor --unencrypted` (key `68951BE1CD8EFA9E`), then `smcpctl trust add runbook-anchor.pub --name runbook-anchor --key-id 68951BE1CD8EFA9E --classes low --expires 30d --config smcp.toml` (`enrolled runbook-anchor ... for risk classes low until 2026-11-16T19:11:29Z`). A call through `ref` passed before the revocation. Started 19:11:29Z, finished 19:11:30Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| 1 | `smcpctl package list --config smcp.toml` | `smcp-ref-filesystem@0.0.0-dev+9c2c3169cf1c`, state `enabled`, anchor `bootstrap-C832E6BE696F49E8`, signer `C832E6BE696F49E8` |
| 2 | `smcpctl package revoke smcp-ref-filesystem@0.0.0-dev+9c2c3169cf1c --key runbook-anchor.key --reason "runbook execution: withdraw the example server" --config smcp.toml` | `wrote .../state/library/revocations/smcp-ref-filesystem@0.0.0-dev+9c2c3169cf1c.json`, followed by a scan result with the revision under `"revoked"`; the directory holds the entry and its `.minisig` |
| 3 | `smcpctl package scan --config smcp.toml` | empty result (`revoked: []`): the revoke command had already applied the entry |
| 4 | `smcpctl package list` | state `revoked`, `state_reason` `revocation entry: runbook execution: withdraw the example server`; server `ref` `suspended` (`revision left the enabled state`) |
| 4 | `itest-client ... -call ref_read_file` (new session) | `tools/list returned 0 tools`, `FAIL: empty tool catalog` |
| 4 | `smcpctl package enable smcp-ref-filesystem@0.0.0-dev+9c2c3169cf1c --alias ref` | refused: `STATE_TRANSITION_REFUSED: ... is revoked and cannot be enabled` |
| 5 | journal | `package` event from E-13, `server_revision` `smcp-ref-filesystem@0.0.0-dev+9c2c3169cf1c`, outcome `revoked`, reason `REVOKED`, detail with the reason and signer `68951BE1CD8EFA9E` |
| Signing key 3 | `smcpctl trust remove runbook-anchor --config smcp.toml`; `smcpctl trust list` | `removed runbook-anchor`; only `bootstrap-C832E6BE696F49E8` remains |
| after | `smcpctl health`; stop; `smcpctl journal verify` | degraded (`unconfined`); `journal OK: 11 segments, 185 events, anchored at segment 11, 1 evidence-key transitions (segments [1])` |

Step 6 (install a fixed revision) and signing-key steps 1, 2 and 4 (list, revoke and re-sign the other revisions of a key) were not executed: the instance had one package.

## Deviations and corrections

The runbook said that with `smcpd` running, `smcpctl package scan` applies the entry; in fact `package revoke` applies it at once when the Gateway is running (step 3 found nothing to do). Steps 2 to 4 of `docs/runbooks/revocation.md` now say that the scan is needed only for an entry written offline or copied in, and that the server entry becomes `suspended` and `package enable` is refused.
