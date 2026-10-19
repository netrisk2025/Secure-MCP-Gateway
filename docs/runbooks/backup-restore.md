# Runbook: backup and restore

Reference: [../operations/backup.md](../operations/backup.md). Execution records go in `docs/verification/runbooks/` (FR-18.8); the latest is [runbook-backup-restore-2026-10-18.md](../verification/runbooks/runbook-backup-restore-2026-10-18.md). `scripts/ci-integration.sh` runs steps 1 to 6 on every pull request.

## Back up

1. `smcpctl health --config smcp.toml` — note the state; a backup works in any state.
2. `smcpctl backup --config smcp.toml --passphrase-file /secure/backup.pass` (or `--recipient age1...`).
3. Record the printed path and `sha256`.
4. `smcpctl backup --list --config smcp.toml` — the newest entry has `"result": "ok"`.
5. Copy the `.age` file and its `.sha256` file off the machine.

## Restore

1. Stop the Gateway (`launchctl bootout gui/$(id -u)/com.smcp.gateway`, `sudo systemctl stop smcpd`, or stop the process).
2. `smcpctl restore --config smcp.toml --archive <file> --passphrase-file /secure/backup.pass --verify-only` — expect `archive verified; nothing was changed`.
3. `smcpctl restore --config smcp.toml --archive <file> --passphrase-file /secure/backup.pass` — note `previous_state`. Before changing anything the restore verifies the archived Policy Store (`policy_store_revision`, `policy_revisions_verified`) and re-applies the revocations recorded in the restored and the current journal (`directory_changes`, `package_revocations`, `client_revocations`), so a package revoked after the backup stays revoked.
4. `smcpctl journal verify --config smcp.toml` — expect `journal OK`.
5. Start the Gateway; `smcpctl health` answers with a state other than `fail-closed`.
6. Keep the `previous_state` directory: its journal holds the evidence written after the backup.
