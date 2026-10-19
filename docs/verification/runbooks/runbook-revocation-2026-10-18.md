# Runbook execution: withdraw a server package (revocation)

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/revocation.md` |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record of the same date, started again after the upgrade record. `smcpctl bootstrap` signs the example package with a one-time key that it does not keep, so a second trust anchor was enrolled to sign the revocation: `smcpctl package keygen --out runbook-anchor --unencrypted` (key `8193ED0F8D759765`), then `smcpctl trust add runbook-anchor.pub --name runbook-anchor --key-id 8193ED0F8D759765 --classes low --expires 30d --config smcp.toml` (`enrolled runbook-anchor (key 8193ED0F8D759765) for risk classes low until 2026-11-17T20:41:22Z`). A call through `ref` passed before the revocation. Started 20:41:18Z, finished 20:41:53Z.

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| 1 | `smcpctl package list --config smcp.toml` | `smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e`, state `enabled`, anchor `bootstrap-367C76C65C5DD834`, signer `367C76C65C5DD834` |
| 2 | `smcpctl package revoke smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e --key runbook-anchor.key --reason "runbook execution: withdraw the example server" --config smcp.toml` | `wrote .../state/library/revocations/smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e.json`, followed by a scan result with the revision under `"revoked"`; the directory holds the entry and its `.minisig` |
| 3 | `smcpctl package scan --config smcp.toml` | empty result (`revoked: []`): the revoke command had already applied the entry |
| 4 | `smcpctl package list` | state `revoked`, `state_reason` `revocation entry: runbook execution: withdraw the example server`; server `ref` `suspended` (`revision left the enabled state`) |
| 4 | `itest-client ... -call ref_read_file` (new session) | `tools/list returned 0 tools`, `FAIL: empty tool catalog` |
| 4 | `smcpctl package enable smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e --alias ref` | refused: `STATE_TRANSITION_REFUSED: smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e is revoked and cannot be enabled` |
| 5 | journal | `package` event, `server_revision` `smcp-ref-filesystem@0.0.0-dev+e7b20cb38c9e`, outcome `revoked`, reason `REVOKED`, detail with the reason, `revoked_at` and signer `8193ED0F8D759765` |
| Signing key 3 | `smcpctl trust remove runbook-anchor --config smcp.toml`; `smcpctl trust list` | `removed runbook-anchor`; only `bootstrap-367C76C65C5DD834` remains |
| after | `smcpctl health`; stop; `smcpctl journal verify` | degraded (`unconfined`); `journal OK: 12 segments, 181 events, anchored at segment 12, 1 evidence-key transitions (segments [2])` |
| after, restore | stop; `smcpctl restore --archive offsite/smcp-backup-20261018T203914.011Z.age --passphrase-file backup.pass` (the backup of the backup and restore record, taken before the revocation); start | `package_revocations: 1`; `smcpctl package list`: the revision `revoked` (`revocation re-applied from the journal at restore`), server `ref` `not_started`; a new session lists 0 tools (details in the backup and restore record) |

Step 6 (install a fixed revision) and signing-key steps 1, 2 and 4 (list, revoke and re-sign the other revisions of a key) were not executed: the instance had one package.

## Deviations and corrections

None. The runbook as corrected by the 2026-10-17 execution matched every observation. The last row checks the restore behaviour added since the previous record: a restore from a backup older than the revocation keeps the revision revoked.
