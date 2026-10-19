# Acceptance scenarios, release label and performance

This page describes how the acceptance scenarios AT-01 to AT-21 of SRS Appendix M are run and reported (FR-19.4), how a release gets its "enforced" or "not enforced" label (FR-19.3), and how the FR-11 performance measurements are produced.

## Claiming a scenario

A Go test claims a scenario with `reqtest.Scenario(t, profile, "AT-nn")`, where `profile` is `reqtest.Standalone` or `reqtest.Enforced` and must be the profile the Gateway actually ran in. The test claims the scenario's requirements separately with `reqtest.Verifies` or `reqtest.Partial`. A Playwright test claims one with the annotation `{ type: "scenario", description: "AT-nn profile=standalone" }`. A scenario executed by a person is recorded in `docs/verification/AT-nn.md` in the record format of [verification/README.md](verification/README.md); its "Profile and platform" field starts with `Enforced` or `Standalone`.

`tools/reqreport` computes, for every scenario and profile:

- **fail**: a claiming test in that profile failed or never finished, or the latest counted record says `fail`;
- **pass**: at least one claiming test or counted record passed and nothing failed;
- **not-run**: otherwise. A skipped test is not a result.

A record counts only when it is complete and its commit is the commit of the report. The results are in `build/reqreport.md` ("Acceptance scenarios") and in the `acceptance` member of the status data, which the project site shows on its Status page.

## The release label

The label is "enforced" only when every one of the 21 scenarios passed in the Enforced profile for the release commit, and "not enforced" otherwise (FR-19.3). The release workflow runs

```
go run ./tools/reqreport label -status status.json -commit "$GITHUB_SHA" -out release-label.md
```

on the status data of the tagged commit and adds the result to the release notes: the document the CI status job published to `site-data` when it is for that commit, and otherwise the `status-document` artifact of the CI run started by the tag push, which the release workflow waits for. Status data for any other commit labels the release "not enforced". The Standalone profile can never earn the label.

The CI jobs that produce Enforced results (`acceptance-enforced`, `console-enforced`, `hostile`, `offline`) and `perf` run on pushes to main, on release tags (`v*`) and when CI is dispatched; `acceptance-enforced`, `console-enforced`, `offline` and `perf` are skipped on pull requests. Every non-pull-request run uploads its merged status document (`status-document`, with `release-label.md`) and prints the label in the status job summary; only pushes to main publish to `site-data`. The Enforced runs of the hostile suite and of the console are reported under their own package names (`internal/hostile/enforced`, `console/e2e/chromium/enforced`), as the acceptance runs are (`internal/acceptance/enforced`, `internal/acceptance/offline/enforced`), so a Standalone result of the same test name never replaces an Enforced one. The Go tests that `linux-integration` runs against real Podman and in a network namespace are merged from `build/linux-integration-test.json`.

## Where each scenario runs

| Scenario | Tests | Profile |
|---|---|---|
| AT-01 to AT-06, AT-09, AT-10, AT-13 to AT-16, AT-18 to AT-21 | `internal/acceptance`: the real `smcpd`, `smcpctl` and `smcp-refserver`, bootstrapped in temporary directories and driven through the CLI, the control API and an OAuth-signed MCP client | Standalone in the `go` job; Enforced in the `acceptance-enforced` job (`SMCP_ACCEPTANCE_PROFILE=enforced`, rootless Podman) |
| AT-08 | `internal/hostile`: HF-20 to HF-24 must all pass | Enforced (CI job `hostile`) |
| AT-09 | also `internal/hostile`: HF-04 to HF-09 and HF-16 | Standalone and Enforced (CI job `hostile`) |
| AT-11 | `internal/graph` `TestAT11AuditLinkageSurvivesChanges` (fake graph backend); `internal/acceptance` `TestAT11AuditLinkage`: the real binaries with the Neo4j mirror (`SMCP_NEO4J_URL`); a permitted and a denied call, then the reference server renamed, updated to a new signed package revision and its old revision retired; the first call's mirror links are unchanged and the denied call is never linked as observed from a server | Standalone (unit tests in the `go` job, `TestAT11AuditLinkage` in the `graph` job); Enforced in the `acceptance-enforced` job (Neo4j service container) |
| AT-12 | `internal/edge` (journal flush faults before launch and before release) and `internal/graph` (mirror replay, duplicate event IDs); `internal/acceptance` `TestAT12AuditConsistency`: the real binaries with the Neo4j mirror, smcpd killed in a burst of calls and restarted (the mirror then holds every journal event once), then a real journal write error (the file size limit of the running smcpd lowered with prlimit, Linux only): the call is refused or withheld and the next fails closed, and after a restart the journal verifies | Standalone (unit tests; `TestAT12AuditConsistency` in the `graph` job); Enforced in the `acceptance-enforced` job |
| AT-17 | `internal/acceptance` `TestAT17OfflineEngineeringWorkflow`, in the CI job `offline`: the reference filesystem and git packages are built with network access, then the acceptance suite runs in a network namespace with loopback only; AT-17 then runs there again in the Enforced profile, with the node and python packages on `node:24-bookworm-slim` and `python:3.12-bookworm` images pulled and pinned by digest first (`SMCP_AT17_NODE_IMAGE`, `SMCP_AT17_PYTHON_IMAGE`) | Standalone and Enforced (CI job `offline`) |
| AT-20 | `internal/acceptance` `TestAT20LimitsAndLoad` mounts a 320 MiB file system (disk image on macOS, tmpfs with sudo on Linux) to fill the audit reserve | Standalone |
| AT-07 | `console/e2e/inert.spec.ts` (Playwright): hostile strings in every view are inert text, and G-10 bounds evidence to 256 KiB per page | Standalone (CI job `console`, three browsers); Enforced (CI job `console-enforced`, Chromium, `SMCP_E2E_PROFILE=enforced`: the reference server runs in rootless Podman and the claim names the profile the Gateway reports) |
| AT-10 | `internal/acceptance` `TestAT10WebBroker`: the `EGRESS` probe fixture of `smcp-hostile` behind the Egress Broker with one-use capabilities required, a DNS fixture (`[egress] resolvers`) and a test CA (`ca_file`); grant scope, capabilities, reserved addresses, rebinding, redirect chains and public fetch | Standalone in the `go` job; Enforced in the `acceptance-enforced` job (`network = "egress"`) |

Run the suite locally with `go test ./internal/acceptance/` (about 100 seconds; skipped with `-short`). AT-17 skips unless `SMCP_ACCEPTANCE_OFFLINE=1` and `SMCP_REFPKG_DIR` are set; AT-11 and AT-12 skip unless `SMCP_NEO4J_URL` (and `SMCP_NEO4J_USER`, `SMCP_NEO4J_PASSWORD`) name a Neo4j database, whose contents they wipe, and AT-12 needs Linux.

## Performance measurements (FR-11)

`smcp-workload` (`cmd/smcp-workload`, shipped in the release archives) is the reference workload generator of FR-11.1:

- `smcp-workload generate --out DIR [--state STATE]` writes the reference policy (9,995 rules plus the 5 registry nodes of the reference server, 256 candidate rules for every decision of the decision template) and, with `--state`, a signed 100,000-event Evidence Journal spanning 30 days into a bootstrapped state directory;
- `smcp-workload run --bin DIR --out perf.json --test-json perf-test.json` starts real `smcpd` instances and measures, with eight concurrent callers:

| Requirement | Measurement | Budget (CP-32) |
|---|---|---|
| FR-11.2 | p95 latency of 100,000 decisions against the compiled reference policy, as the caller sees it | 10 ms |
| FR-11.4 | p95 P-213 with observation enabled minus disabled, same workload on sixteen fresh instances (enabled, disabled, disabled, enabled, then the mirror, twice; mean p95 per condition), each load started after `sync(2)`, with the instances' state on a memory file system where the host has one (`/dev/shm` on Linux) | 1 ms |
| FR-11.5 | p95 P-213 for 64 KiB results with synchronous scoring (journal timestamps: the request's receipt, `received_at` of the requested event, to the delivered event, minus server execution from the dispatched event to the backend's response, `responded_at` of the completed event) | 50 ms |
| FR-11.8 | p95 of the console's audit queries over the 30-day, 100,000-event journal, 100 repetitions | 2 s |
| FR-11.9 | resident memory of an idle `smcpd` 10 minutes after start | 4 GiB |

The CI job `perf` runs on pushes to main and on demand; the status job publishes `perf.json` as the `performance` member of the status data and merges `perf-test.json`, where each measurement within its budget is a partial claim of its requirement and each one over budget is a failing test. CI runners are not the recorded reference hardware, so these measurements never fully verify an FR-11 requirement. Until 2026-10-17 the harness took server execution to end at the completed event, which the edge writes after response inspection, so P-213 left response inspection out (about 35 ms of rule scanning for a 64 KiB result before the literal prefilter of `docs/filters.md`); the completed event now carries `responded_at`, and the FR-11.4 and FR-11.5 measurements count request receipt and response inspection. AT-20, which runs in the go job beside every other package's tests, still checks the time before dispatch and after the completed event against the 50 ms budget.

Since 2026-10-18 the FR-11.4 instances keep their state on a memory file system where the host has one, and every load measurement starts after `sync(2)`. P-213 includes the journal flush before launch, which is the disk's latency and the same with observation on or off. On some CI runners a few percent of those flushes stalled for about 190 ms, at the same rate in both conditions (0.56% of 208,000 enabled calls, 0.60% of 208,000 disabled), so each run's p95 landed anywhere from 13 to 130 ms and the difference between the conditions said nothing about observation: the 45.9 ms published for `5d0d1cc`, a commit that changed only documentation after `788c8b4` measured 0.97 ms, was such a run. FR-11.5 still measures P-213 with the state on disk. The CPU time observation takes on a busy host still counts in FR-11.4, whichever thread spends it.

## Stage timing spans (FR-10.2, FR-10.11)

Every tool call emits one span per pipeline stage (authenticate, session check, decision, request inspection, approval, launch authorization, dispatch, response inspection, release authorization) and one per filter run, with monotonic start and end, the thread CPU time of the stage, the correlation ID and the policy revision and decisive rule revision of the call's decision. The Observation Collector stores them in the `spans` table (`monotonic = 1`, `cpu_ms`, `rule_id`, `filter_id`) and aggregates span time by stage, policy revision, rule, filter and Observation Policy; `GET /api/v1/observations/cost` returns the aggregation as `policy_objects` and the filters alone, most expensive first, as `filters`.

The CPU time of a stage is the thread CPU time of the call's goroutine in the stage outside its waits (for the filters, the server, the approver and the journal); the inspection stages add the CPU time of their filters, each measured on its own goroutine outside its waits (`pipeline.WaitUnmeasured`). A goroutine is locked to its OS thread only while it runs: one that blocks while locked can resume only on that thread, and on a busy host that delayed every wait of the call by up to a scheduling quantum. Held for the whole call, the lock was most of the FR-11.4 capture overhead the CI job `perf` measured.
