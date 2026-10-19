# Runbook execution records (FR-18.8)

Each file records one execution of a runbook in [docs/runbooks/](../../runbooks/) (or of the procedures in [docs/operations/](../../operations/)) against a real `smcpd`: the commit built, the platform, the date, the commands as run and what they printed, and any correction made to the runbook as a result. File names are `runbook-<name>-<date>.md`; a later execution is a new file.

An execution record starts with a `| Runbook | ... |` row instead of `| Requirement or scenario | ... |`, so `tools/reqreport` does not count it by itself. [FR-18.8.md](FR-18.8.md) is the Inspection record of FR-18.8 that reviews the runbooks against these records; the report counts that one.

| Runbook | Latest record |
|---|---|
| [emergency-stop.md](../../runbooks/emergency-stop.md) | [runbook-emergency-stop-2026-10-18.md](runbook-emergency-stop-2026-10-18.md) |
| [revocation.md](../../runbooks/revocation.md) | [runbook-revocation-2026-10-18.md](runbook-revocation-2026-10-18.md) |
| [backup-restore.md](../../runbooks/backup-restore.md) | [runbook-backup-restore-2026-10-18.md](runbook-backup-restore-2026-10-18.md) |
| [upgrade-rollback.md](../../runbooks/upgrade-rollback.md) | [runbook-upgrade-rollback-2026-10-18.md](runbook-upgrade-rollback-2026-10-18.md) |
| [key-rotation.md](../../runbooks/key-rotation.md) | [runbook-key-rotation-2026-10-18.md](runbook-key-rotation-2026-10-18.md) |
| [key-compromise.md](../../runbooks/key-compromise.md) | [runbook-key-compromise-2026-10-18.md](runbook-key-compromise-2026-10-18.md) |
| [policy-rollback.md](../../runbooks/policy-rollback.md) | [runbook-policy-rollback-2026-10-18.md](runbook-policy-rollback-2026-10-18.md) |
| [operations/health.md](../../operations/health.md), [operations/logging-metrics-reload.md](../../operations/logging-metrics-reload.md) | [runbook-operations-2026-10-18.md](runbook-operations-2026-10-18.md) |
