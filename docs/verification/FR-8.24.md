# FR-8.24 G-04 first-time task: scripted, timed run

This is not the Demonstration the SRS asks for (a timed task with three first-time users, at least two of whom finish within 10 minutes). It records the same task performed by a Playwright script that follows the view's help, so that the steps the task needs and the view's behavior are on record. It has no `Requirement or scenario` row: `tools/reqreport` does not count it, and FR-8.24 stays unverified until the Demonstration with people is recorded.

| Field | Content |
|---|---|
| Task | Create and publish a scoped Observation Policy of at least 10 parameters in G-04 (FR-8.24) |
| Commit | `2038ec81f688530c32a5b9ac1be3e7bf345740fb` on branch `docs/verification-records` (squash-merged; not an ancestor of `main`) |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64; Playwright 1.64.1 with Chromium 156.0.8078.4, Firefox 157.0 and WebKit 27.2 at 1280 x 720 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task); the script `console/e2e/firsttime.spec.ts` |
| Method | Scripted run (supporting the Demonstration) |
| Result | completed in every browser |

## The script

`console/e2e/firsttime.spec.ts` signs in, then times from the click on "Observation workbench" in the view list to the "Published Observation Policy revision n" message:

1. Open G-04 from the view list.
2. Open "Help for this view" and confirm it tells the user to start from the selection or a preset, check the cost preview and publish the Observation Policy.
3. For each of `tool_name`, `request_bytes`, `response_bytes`, `argument_count`, `decision_outcome`, `server_execution_time`, `is_error`, `calls_in_session`, `inter_call_interval`, `end_to_end_latency`: type the name into "Search parameters" and tick "Capture <name>" when it is not ticked.
4. Clear the search.
5. Type a policy ID into "Observation Policy ID".
6. Under Scope, tick the tool `ref/read_file`.
7. Press "Publish the Observation Policy".

It then reads the published revision from `GET /api/v1/observations/objects/observation_policy` and checks the policy ID, that all ten parameters are in it, that it has at least 10 parameters and that its scope is `{"tools": ["ref/read_file"]}`.

## Results (console matrix run of 2026-10-17, 19:38Z onward)

| Browser | Time from opening G-04 to the published message | Steps | Parameters in the published policy | Scope |
|---|---|---|---|---|
| Chromium 156 | 0.5 s | 16 | 55 | `tools: ["ref/read_file"]` |
| Firefox 157 | 0.8 s | 16 | 55 | `tools: ["ref/read_file"]` |
| WebKit 27.2 | 1.4 s | 16 | 55 | `tools: ["ref/read_file"]` |

The 16 steps were: open the view, open its help, ten searches, one tick (`end_to_end_latency`; the other nine were already in the selection in force, which the view starts from), clear the search, name the policy, choose the scope, publish. The published policy has 55 parameters: the selection in force, which already held nine of the ten, and the one ticked.

## What this shows and what it does not

- The task can be completed in G-04 with the controls its help names, in 16 actions, in all three engines, and the published Observation Policy has the parameters and the scope that were chosen.
- The times are machine times. They say nothing about how long a first-time person needs to find the controls, read the help and decide on parameters, which is what FR-8.24 measures. The Demonstration with three first-time users remains to be done and recorded as `FR-8.24` with method Demonstration.
