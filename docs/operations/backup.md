# Backup, restore and evidence export

## Backup (FR-17.6, SR-7.7-1, D-15)

```
smcpctl backup [--passphrase-file FILE | --recipient age1... [--recipient ...]] [--optional name=path ...]
smcpctl backup --list
```

Every archive is encrypted with [age](https://age-encryption.org): to a passphrase (prompted, or read from `--passphrase-file`, mode 0600 or stricter; `-` is standard input) or to one or more age X25519 recipients. There is no unencrypted mode; a backup without either is refused with `BACKUP_UNENCRYPTED_REFUSED`. A passphrase and recipients cannot be combined.

When the Gateway runs, the backup is taken by the Gateway:

1. Dispatch is stopped (an emergency stop with reason `backup`), and in-flight calls are given 30 s to finish and return their results; new calls are refused meanwhile. If they do not finish, the backup is abandoned with `BACKUP_DRAIN_TIMEOUT` and dispatch resumes. An emergency stop made during the backup stays in force after it.
2. The open journal segment is sealed, so every event up to the stop is signed in the archive.
3. The archive is written to `[backup] dir` as `smcp-backup-<UTC time>.age`, its SHA-256 to `<archive>.sha256`, and the result to `<backup dir>/index.json`.
4. A `BACKUP_WRITTEN` event with the path, checksum, size and components is committed, and dispatch resumes. If the Gateway was already in emergency stop before the backup, it stays stopped.

When the Gateway is stopped, `smcpctl backup` writes the archive directly from the state directory.

### Scheduled backups (FR-9.16)

With `[backup] interval` set (at least `1s`; `24h` is typical), the running Gateway takes a backup every interval by the same procedure, with the actor `scheduler` on its events. Scheduled backups are encrypted to `[backup] recipients` (age public keys) or with the passphrase in `[backup] passphrase_file` (mode 0600); the configuration is refused when an interval is set without either. A failed scheduled backup is recorded (`BACKUP_FAILED` or in `index.json`) and the next one runs at the next interval.

```toml
[backup]
interval = "24h"
recipients = ["age1..."]
```

### Contents

| Archive path | Component |
|---|---|
| `state/journal/`, `state/journal.anchor` | Evidence journal and its anchor |
| `state/keys/` | Key material (evidence keys, operator token, installation ID, administrator password hash) |
| `state/tls/` | Trust anchors: CA bundle, CA key, listener certificate |
| `state/policy/` | The signed Policy Store (revisions and the signed control record) |
| `state/packages/`, `state/library/`, `state/vault/`, `state/trust/` and any other state | Included when present (Local Server Registry `state/packages/registry.json` and the package store, vault, curation trust anchors) |
| `config/<name>` | Configuration file |
| `policy/<name>` | Active policy file (the Policy Store of this build) |
| `optional/<name>/` | Each `--optional name=path` (for example an Observation Store copy or a graph dump) |
| `manifest.json` | Format `smcp-backup-v1`, time, installation ID, version, component list, and the SHA-256 and size of every other entry |

`state/log/` and backup directories are never archived. The manifest's `components` lists `configuration`, `policy_store`, `evidence_journal`, `key_material`, `trust_anchors` and, when present, `server_registry`, `vault` and `optional:<name>`.

The archive contains the CA key and the evidence-signing key. Keep the passphrase or the age identity separately from the archives.

Scheduled backups (FR-9.16) belong to the Data Lifecycle & Memory Manager (E-28) and are not implemented; run `smcpctl backup` from cron or a systemd timer meanwhile.

## Restore (SR-7.8-1)

```
smcpctl restore --archive FILE [--passphrase-file FILE | --identity-file FILE] [--verify-only]
```

The Gateway must be stopped (`--verify-only` works while it runs). Restore:

1. Checks the archive against `<archive>.sha256` when that file is present.
2. Decrypts into an isolated directory `.smcp-restore-<time>-*` next to the state directory and checks every entry against the manifest (missing, extra, changed or unsafe entries fail).
3. Verifies the restored journal: hash chain, signatures, key transitions and anchor, from the restored `evidence-genesis.pub`.
4. Validates the restored configuration and policy file, and verifies the restored signed Policy Store: every revision file and the control record `policy/active.json` must verify under the restored policy-signing key.
5. Collects every revocation recorded in the restored journal and in the current journal (events of class `revocation`, outcome `revoked`, or a reason code ending in `_REVOKED`, and principal suspensions), writes them to `state/revocations.json` as a record, and re-applies them to the restored state: principal suspensions and credential revocations to the principal directory (a later `PRINCIPAL_ENABLED` wins), package revocations to the package registry (`revoked`; a revision the restored registry does not hold is recorded so that a later import is refused), and dynamic client registration revocations (`DCR_REVOKED`) to `remote/clients.json`. Sessions are not persisted across restarts, so there is no session to revoke.
6. When the restored configuration has `[graph] enabled = true`, wipes the graph mirror and rebuilds it from the restored journal (waiting up to 5 minutes for the graph database). If the database cannot be reached the restore is refused; start the database, or disable `[graph]`, and restore again. `--verify-only` does not touch the graph. The rollback of a failed upgrade does not depend on the graph: it reports the mirror as not rebuilt instead (rebuild it with `smcpctl graph rebuild --yes`).
7. Only then moves the current state directory to `<state>.pre-restore-<time>`, moves the restored state into place, and writes the restored configuration and policy over the current files (each kept as `<file>.pre-restore-<time>`).

If any step before 7 fails, nothing is changed and the isolated directory is removed. The previous state directory holds the journal written after the backup was taken; keep it, it is evidence. The report printed by restore counts the re-applied revocations (`directory_changes`, `package_revocations`, `client_revocations`), the verified Policy Store revisions (`policy_revisions_verified`, `policy_store_revision`) and the graph mirror outcome (`graph_mirror`).

## Evidence export (FR-7.14, X-09)

With `[evidence] export_dir` set, the Gateway copies each closed journal segment and the anchor (the checkpoint) to the export directory every `export_interval` (default 10 s), so a segment is exported within 60 s of closing. The export has the journal's layout:

```
<export_dir>/journal/segment-NNNNNN.jsonl
<export_dir>/journal.anchor
<export_dir>/keys/evidence.pub
<export_dir>/keys/evidence-genesis.pub
```

Each segment is copied once; a copy already present with the same content is skipped, and a copy that differs is never overwritten (the export fails with `differs from the journal segment` and health reports `evidence_export_failed`). Verify an export with:

```
smcpctl journal verify --dir <export_dir>/journal --key <export_dir>/keys/evidence-genesis.pub
```

`smcpctl journal export --to DIR` runs one export without a running Gateway. Point the export directory at storage the Gateway's other files are not on (a mounted share, a removable disk): replacing the local anchor together with deleting trailing segments is detected only against a copy kept elsewhere.

## Errors

| Code or message | Meaning |
|---|---|
| `BACKUP_UNENCRYPTED_REFUSED` (HTTP 400) | Neither a passphrase nor a recipient was given |
| `BACKUP_DRAIN_TIMEOUT` (HTTP 503) | In-flight calls did not finish within 30 s; no backup was taken |
| `BACKUP_FAILED` (HTTP 500) | Writing the archive failed; recorded in `index.json` with the error |
| `archive checksum mismatch` | The archive does not match its `.sha256` file |
| `decrypt: ...` | Wrong passphrase or identity |
| `restored journal does not verify` | The archived journal is damaged; nothing was changed |
| `the Gateway is running; stop it before restoring` | Stop `smcpd` first |
