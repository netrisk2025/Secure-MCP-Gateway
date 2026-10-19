# Runbook execution: roll back a policy

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/policy-rollback.md` |
| Commit | `d55c08f8da49db12fe877a2de57a1bbecec069b8` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.9 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 runbook records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record of the same date, running with the bootstrap policy revision `r1`. A bad revision `r2` was made by removing `read_file` from the `read-only` template in `policy.json` and publishing it with `smcpctl policy reload`; a new session then listed 3 tools (`ref_echo ref_list_files ref_time_now`) and `tools/call ref_read_file` failed with `Unknown tool`. Started 20:38:53Z, finished 20:39:06Z. The section "When the Gateway starts fail-closed with `policy_signature`" was executed with the backup and restore runbook (see that record).

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| 1 | `smcpctl policy history --config smcp.toml` | `*  2  r2  r1  reload  operator-token`, `1  r1  none  import` |
| 2 | `smcpctl policy diff --from r2 --to r1 --config smcp.toml` | `from r2 to r1: 1 changes (widens authority)`, `grant_added  read-only ref/read_file  rule=ro-ref` |
| 4 | `smcpctl policy rollback r1 --config smcp.toml` | `published and activated revision r1-rb1 (sequence 3, parent r2, digest 6efe9b56..., key 37f593a5b76747d6)` |
| 5 | `smcpctl policy history` | `*  3  r1-rb1  r2  rollback of r1  operator-token` |
| 6 | `itest-client ... -call ref_read_file` (new session) | `PASS`; `smcpctl health` reports `policy_revision` `r1-rb1` and only the cause `unconfined` (the `policy_currency` check, new since the previous record, raised no `decision_snapshot_stale` across the rollback) |
| Afterwards 1 | `smcpctl policy show --document --config smcp.toml` | the canonical document with `"revision":"r1-rb1"`; written to `policy.json` with revision `r3` |
| Afterwards 2 | `smcpctl policy simulate policy.json --config smcp.toml` | `simulation 01a150bd-3fe6-7557-ba32-fe6c779f9813: 8 fixtures from journal, active r1-rb1, candidate r3: 0 changed` |
| Afterwards 2 | `smcpctl policy publish policy.json --parent r1-rb1 --simulation 01a150bd-3fe6-7557-ba32-fe6c779f9813 --config smcp.toml` | `published and activated revision r3 (sequence 4, parent r1-rb1, ...)` |
| Afterwards 2, check | the same document as revision `r4`, published with `--parent r1-rb1` | refused: `the active revision is not the stated parent: active "r3", stated parent "r1-rb1" (parent_mismatch)` |

Step 3 (emergency stop first) was not needed; the emergency-stop record covers it.

## Deviations and corrections

None in the steps above. The execution of the `policy_signature` section with the backup and restore record found that a revision file damaged while the Gateway runs is now reported at once as `decision_snapshot_stale` (an integrity cause that needs `smcpctl health ack`), and `policy_signature` only at the next start; that section of `docs/runbooks/policy-rollback.md` now says so.
