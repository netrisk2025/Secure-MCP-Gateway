# FR-8.30 Console browser matrix run

Supporting record for a Test-method requirement. The verifying test is the per-view Playwright suite run in each engine (`console/e2e/run-browsers.mjs`, claimed by `console/e2e/browsers.TestConsoleSuiteOnEveryBrowser` in CI); this record is one local run of it, with the browser versions, and does not count as verification by itself.

| Field | Content |
|---|---|
| Requirement or scenario | FR-8.30 |
| Commit | `2038ec81f688530c32a5b9ac1be3e7bf345740fb` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64; Playwright 1.64.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Method | Test |
| Result | pass |

Steps: `cd console && npm run test:e2e` (19:38:28Z to 19:52:44Z). For each engine the runner starts a fresh acceptance Gateway (`console/e2e/global-setup.ts`: `smcpd` built from the commit, a bootstrap instance with an Approver, the four role accounts, the vault and the Egress Broker) and runs every spec file against it at 1280 x 720.

| Engine (Playwright 1.64.1 build) | Corresponding browser | Tests | Passed | Duration |
|---|---|---|---|---|
| Chromium 156.0.8078.4 | Chrome / Edge 156 | 58 | 58 | 3.6 min |
| Firefox 157.0 | Firefox 157 | 58 | 58 | 4.7 min |
| WebKit 27.2 | Safari 27 on macOS | 58 | 58 | 5.9 min |

The 58 tests are those of `a11y.spec.ts`, `console.spec.ts`, `firsttime.spec.ts`, `help.spec.ts`, `inert.spec.ts`, `keyboard.spec.ts`, `session.spec.ts`, `style.spec.ts` and `views.spec.ts`. The runner then wrote `claims: FR-8.30 partial; FR-8.34 verified` (`console/e2e/claims.mjs`).

Deviations from the requirement:

- The requirement names the two most recent major versions of Chromium-based browsers, Firefox and Safari at release time. Playwright 1.64.1 provides one build of each engine; the previous major versions (Chromium 155, Firefox 156, Safari 26) were not run. The CI claim is partial for the same reason.
- WebKit is Playwright's build of the engine, not Safari itself; Safari's own settings (for example "Press Tab to highlight each item") are not exercised. The keyboard tests press Option+Tab in WebKit for that reason.
- The commit is on branch `docs/verification-records` before it was squash-merged, so it is not an ancestor of `main`.
