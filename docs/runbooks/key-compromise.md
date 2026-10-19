# Runbook: key or credential compromise

Use when a key, token or password of the Gateway may have been read by someone else: a copied state directory, a leaked backup together with its passphrase, a stolen laptop, a credential pasted into a chat or a log. Reference: [../operations/keys.md](../operations/keys.md), [key-rotation.md](key-rotation.md). Execution records go in `docs/verification/runbooks/` (FR-18.8); the latest is [runbook-key-compromise-2026-10-18.md](../verification/runbooks/runbook-key-compromise-2026-10-18.md).

Holding the state directory is equivalent to holding the Gateway. If the whole state directory was exposed, do every section below.

## First

1. [Emergency stop](emergency-stop.md) if the exposed credential lets someone run tools or approve calls.
2. `smcpctl journal verify --config smcp.toml` and copy the journal off the machine (`smcpctl journal export --to <dir>`), so the evidence written so far is preserved.
3. Note the time of exposure; journal events after it are the ones to review.

## By credential

| Exposed | Effect | Action |
|---|---|---|
| Operator token `keys/admin.token` | Full Administrator access to the control API | Stop `smcpd`; write a new token: `openssl rand -hex 32 > <state>/keys/admin.token; chmod 600 <state>/keys/admin.token`; start `smcpd`. `smcpctl` reads the new file. No command replaces it while the Gateway runs. |
| Administrator password | Console and control API sign-in | `smcpctl hash-password`, replace `[admin] password_hash`, restart `smcpd`. |
| Approver password (`[[approvals.account]]`) | Can approve held tool calls | Replace its `password_hash` or remove the account; restart. Review `smcpctl approvals list --state all` for decisions by that account (`approver:<name>`). |
| Session Approver password (`[[approver]]`) | Can approve harness sign-ins | Replace its `password_hash` or remove the account; restart (sessions are in memory and end with the restart). Review `session` events with that approver. |
| OAuth client secret (`client_secret_hash`) or an adapter credential file (`~/.config/smcp/credentials.toml`) | Can open sessions as that principal | Generate a new secret, replace `client_secret_hash`, restart `smcpd`, and rewrite the credential file with `smcpctl clients credentials`. |
| Remote Access client | Can sign in through the tunnel | `smcpctl clients revoke <client-id>` (ends its sessions); `smcpctl remote disable` if the tunnel itself is in doubt. |
| Server CA key `tls/ca.key` | Can issue certificates that clients trusting the Gateway CA accept for loopback names | `smcpctl keys rotate ca --overlap 0` (switches at once; the listeners serve the reissued certificate within a second), then redistribute `<state>/tls/ca.crt` to every client and remove the old CA wherever it was installed (for example the OS trust store after `clients setup --system-trust`). Clients that still trust only the old CA stop connecting until updated. |
| Listener key `tls/server.key` | Can impersonate the listeners to clients | `smcpctl keys rotate tls`. If the CA key was exposed too, rotate the CA first. |
| Evidence key `keys/evidence.key` | Can sign forged journal segments | `smcpctl keys rotate evidence`. Segments signed after the exposure and before the rotation can no longer be trusted on their signature alone; compare them with the off-machine export. Keep `keys/evidence-genesis.pub` off the machine as the trust root. |
| Policy-signing key `keys/policy.key` | Can sign policy revisions (needs write access to the state directory to use them) | No rotation command exists. Replacing the key makes the stored revisions fail verification and the Gateway start fail-closed with `policy_signature`. Treat the host's state directory as compromised: restore from a backup taken before the exposure onto a clean host, or reinstall and publish the policy again. |
| Package signing key (a trust anchor) | Can sign packages the Gateway will admit | Follow [revocation.md](revocation.md#when-the-signing-key-is-the-problem): revoke what it signed, `smcpctl trust remove <name>`, re-sign with a new key. |
| Vault master key or its passphrase, or a backup archive with its passphrase | Decrypts every secret value | Rotate every secret at its issuer first, then `smcpctl secrets rotate <name>` for each. There is no command that re-keys the vault; to change the master key, create a new vault (`smcpctl secrets init` on an empty `vault_dir`) and set each secret again. |
| A secret value | Use of that credential at its issuer | Revoke it at the issuer, then `smcpctl secrets rotate <name>`. `smcpctl secrets impact <name>` lists the servers that receive it. |

## After a restore

A restore brings back the configuration, key material, tokens and trust anchors that the archive holds. Rotations done after that backup are undone, so repeat the rows above that you have already carried out (operator token, passwords, CA, listener and evidence keys) once the restored Gateway is running.

## Afterwards

1. `smcpctl keys status --config smcp.toml` — check the new certificate dates and evidence key.
2. `smcpctl health --config smcp.toml`, then `smcpctl resume` if you stopped.
3. Take a new backup (`smcpctl backup`) and destroy backups whose passphrase was exposed.
4. Review the journal from the exposure time in the console Audit view.
