# Runbook: roll back a policy

Use when a published policy grants too much, refuses legitimate calls, or was published by mistake. Reference: [../policy-reference.md](../policy-reference.md#policy-store). Execution records go in `docs/verification/runbooks/` (FR-18.8); the latest is [runbook-policy-rollback-2026-10-18.md](../verification/runbooks/runbook-policy-rollback-2026-10-18.md).

A rollback never rewrites history: it publishes the content of an earlier revision as a new revision, signed and activated atomically like any other publication.

## Roll back

1. `smcpctl policy history --config smcp.toml` — the active revision is marked `*`. Pick the last good revision.
2. `smcpctl policy diff --from <active> --to <good> --config smcp.toml` — confirm the changes are the ones to undo.
3. If the policy grants too much and calls must stop while you decide, run the [emergency stop](emergency-stop.md) first.
4. `smcpctl policy rollback <good> --config smcp.toml` — expect `published and activated revision <good>-rb<n>`. Use `--as <id>` to choose the new revision ID.
5. `smcpctl policy history --config smcp.toml` — the new revision is active, with origin `rollback of <good>`.
6. Sessions keep running. Their cached catalogs are updated in place, and clients with an open listen stream get `notifications/tools/list_changed`; others see the change when their cached tool list expires (60 s by default).

## Afterwards

1. Update `[policy] file` (`policy.json`) to the rolled-back content with a new `revision` ID, or the next `smcpctl policy reload` publishes the bad document again. `smcpctl policy show --document --config smcp.toml` prints the active canonical document.
2. Before publishing a corrected policy: `smcpctl policy simulate <file> --config smcp.toml`, then `smcpctl policy publish <file> --parent <active> --simulation <id> --config smcp.toml`.

## When the Gateway starts fail-closed with `policy_signature`

The active revision or control record in `<state>/policy/` failed verification (tampering or damage). Every call is refused with `-31004 NO_SNAPSHOT`.

1. `smcpctl health --config smcp.toml` shows the cause `policy_signature`. If the files were changed while the Gateway runs, it reports the damage within seconds as `decision_snapshot_stale` ("policy store integrity check failed") and is fail-closed until the cause clears and an administrator runs `smcpctl health ack decision_snapshot_stale`; `policy_signature` appears at the next start.
2. Restore the state directory from the last good backup ([backup-restore.md](backup-restore.md)), or
3. publish a valid revision: `smcpctl policy publish <file> --config smcp.toml`.
4. Investigate how the state directory was changed; its files are owned by the Gateway's account.
