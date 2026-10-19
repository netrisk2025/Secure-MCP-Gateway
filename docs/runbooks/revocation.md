# Runbook: withdraw a server package

Use when a packaged server revision must never run again: a malicious or vulnerable release, a compromised upstream, or a key that signed it is no longer trusted. Reference: [../packaging-guide.md](../packaging-guide.md#revoking). Execution records go in `docs/verification/runbooks/` (FR-18.8); the latest is [runbook-revocation-2026-10-18.md](../verification/runbooks/runbook-revocation-2026-10-18.md).

| Need | Command | Reversible |
|---|---|---|
| Stop using a revision for now | `smcpctl package disable <id>@<rev>` | Yes, `package enable` |
| Remove it from use for good | `smcpctl package retire <id>@<rev>` | No |
| Withdraw it with a signed record that also blocks re-import | `smcpctl package revoke <id>@<rev> --key <file>` | No |

## Revoke

1. `smcpctl package list --config smcp.toml` — find the server ID and revision (`<id>@<rev>`) and its state.
2. `smcpctl package revoke <id>@<rev> --key <signing key> --reason "<why>" --config smcp.toml` — any enrolled trust anchor's secret key may sign the entry. It is written to `<library>/revocations/`. With `smcpd` running, the command also asks the Gateway to scan the library: the printed scan result lists the revision under `revoked`, the revision becomes `revoked` and its instance is torn down.
3. If the entry was written with `--offline` or copied into `<library>/revocations/` by hand, `smcpctl package scan --config smcp.toml` applies it now (otherwise the next scan, within `[packages] scan_interval`, default 300 s).
4. `smcpctl package list --config smcp.toml` — state `revoked`, and the server entry using it `suspended`. New sessions no longer list its tools; calls to them are refused; a session catalog built earlier may still list them until the session is renewed. `smcpctl package enable` refuses the revision (`STATE_TRANSITION_REFUSED`).
5. The journal records the revocation as a `package` event.
6. Remove or change the `[[server]]` entry that named the package, or enable a fixed revision (`smcpctl package install <dir> --enable`), and restart `smcpd` so the replacement is launched.

## When the signing key is the problem

1. List what it signed: `smcpctl package list --config smcp.toml` shows `anchor` and `signer_key_id` for each revision.
2. Revoke each of those revisions as above, signing with another anchor's key.
3. `smcpctl trust remove <anchor name> --config smcp.toml` so the key admits nothing new.
4. Re-sign the packages you still trust with a new key (`smcpctl package keygen`, `smcpctl trust add`, `smcpctl package sign`) and install them again.

## Emergency

If the server is causing harm now, run the [emergency stop](emergency-stop.md) first, then revoke.
