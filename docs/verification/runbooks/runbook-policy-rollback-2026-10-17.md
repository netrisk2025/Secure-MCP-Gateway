# Runbook execution: roll back a policy

| Field | Content |
|---|---|
| Runbook | `docs/runbooks/policy-rollback.md` |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Go 1.26.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Result | pass |

## Setup

The instance of the emergency-stop record, running with the bootstrap policy revision `r1`. A bad revision `r2` was made by removing `read_file` from the `read-only` template in `policy.json` and publishing it with `smcpctl policy reload`; a new session then listed 3 tools and `tools/call ref_read_file` failed with `Unknown tool`. Started 19:09:07Z, finished 19:09:19Z. The section "When the Gateway starts fail-closed with `policy_signature`" was executed with the backup and restore runbook (see that record).

## Steps and observations

| Step | Command | Observed |
|---|---|---|
| 1 | `smcpctl policy history --config smcp.toml` | `*  2  r2  r1  reload  operator-token`, `1  r1  none  import` |
| 2 | `smcpctl policy diff --from r2 --to r1 --config smcp.toml` | `from r2 to r1: 1 changes (widens authority)`, `grant_added  read-only ref/read_file  rule=ro-ref` |
| 4 | `smcpctl policy rollback r1 --config smcp.toml` | `published and activated revision r1-rb1 (sequence 3, parent r2, digest 6efe9b56..., key 3bed5452...)` |
| 5 | `smcpctl policy history` | `*  3  r1-rb1  r2  rollback of r1  operator-token` |
| 6 | `itest-client ... -call ref_read_file` (new session) | 4 tools listed, `PASS`; `smcpctl health` reports `policy_revision` `r1-rb1` |
| Afterwards 1 | `smcpctl policy show --document --config smcp.toml` | the canonical document with `"revision":"r1-rb1"`; written to `policy.json` with revision `r3` |
| Afterwards 2 | `smcpctl policy simulate policy.json --config smcp.toml` | `simulation 01a14b44-91f9-...: 8 fixtures from journal, active r1-rb1, candidate r3: 0 changed` |
| Afterwards 2 | `smcpctl policy publish policy.json --parent "" --simulation "" ...` | published `r3`; the run's script failed to extract the IDs and passed empty values, which the command accepts as "not given" |
| Afterwards 2, again | `smcpctl policy simulate` on revision `r4`, then `smcpctl policy publish policy.json --parent r3 --simulation 01a14b44-befc-72c0-a1f8-bc096cb6e428 --config smcp.toml` | `published and activated revision r4 (sequence 5, parent r3, ...)` |
| Afterwards 2, check | the same publish of a revision `r5` with `--parent r3` | refused: `the active revision is not the stated parent: active "r4", stated parent "r3" (parent_mismatch)` |

Step 3 (emergency stop first) was not needed; the emergency-stop record covers it.

## Deviations and corrections

None in the runbook. The script error above is the executor's; the repeated step used the IDs as the runbook states.
