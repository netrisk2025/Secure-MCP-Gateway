# FR-8.32 Manual accessibility check in WebKit: focus order, target size and contrast

Supporting record for a Test-method requirement, the WebKit counterpart of [FR-8.32.md](FR-8.32.md) (which covered Chromium and Firefox, before the keyboard tests ran in WebKit). The verifying tests are `console/e2e/a11y.spec.ts` and `console/e2e/keyboard.spec.ts`; this record is the manual check the SRS asks to file next to them.

| Field | Content |
|---|---|
| Requirement or scenario | FR-8.32 |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64; Playwright 1.64.1 WebKit 27.2 at 1280 x 720 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Method | Test |
| Result | pass |

## Steps

1. Automated part, in the browser matrix run of 2026-10-17 (`FR-8.30.md`, commit `2038ec8`, whose console sources equal those of the commit above): in WebKit, axe with the WCAG 2.2 A and AA tags found no violation on any of the 24 view paths in either scheme (`console/e2e/a11y.spec.ts:38`); the Tab walk (Option+Tab in WebKit) reached all 1,004 controls in the light scheme and 1,007 in the dark one with a visible focus indicator of at least 3:1 (`console/e2e/a11y.spec.ts:70`); and the keyboard flows of `console/e2e/keyboard.spec.ts` passed axe on 111 intermediate states in WebKit.
2. Manual part (19:39:01Z to 19:39:13Z), against a bootstrap Gateway of the commit above (instance `inst2` of the runbook records): signed in to the console in WebKit, opened G-02 (`/policy`), G-04 (`/observations`) and G-13 (`/approvals`) in the light and the dark scheme, pressed Option+Tab 12 to 24 times on each, wrote down each focus stop with its outline and size, took a screenshot with the focus on a control, and measured every interactive element of the page.

## Observations

- Focus order: after a view loads, focus is on its heading (tabindex -1), so the first Option+Tab stop is the view's help ("Help for this view"), followed by the view's controls in reading order (G-02: Revisions, Draft, Filter workbench, the active revision link, "Start a draft from the active revision", the revisions table and its sort buttons; G-04: the presets, the search and filter fields, the parameter groups, the configuration and campaign buttons, the policy fields; G-13: the state tabs pending to all). After the last control of the page, focus leaves the document and comes back to "Skip to content", the status strip (Emergency stop, Sign out) and the view list. No element has a positive tabindex.
- Focus indicator: every stop had a 2 px solid outline: `#1f4fc4` on the light page and surface backgrounds `#f4f5f0` and `#fbfbf8` (6.4:1 and 6.8:1), `#8fb0ff` on the dark ones `#121614` and `#181d1a` (8.5:1 and 8.0:1) (`console/src/styles.css:26`, `console/src/styles.css:67`), and the strip ink color (`rgb(244, 245, 240)` light, `rgb(228, 232, 226)` dark) on the dark status strip. The screenshots show the outline around the focused revision link in G-02, the focused band field in G-04 and the focused view-list link in G-13; none is clipped or hidden behind another element.
- Target size: the smallest interactive elements were the revision-ID links in table text (15.6 x 18.2 and 15.6 x 16.9 px, G-02), the escalation checkboxes of G-04 (12 x 28 px, in table columns more than 24 px apart), the theme select in the view list (72 x 20 px) and the skip link (88 x 20 px). All other controls measured at least 24 px in both dimensions. The small ones fall under the spacing exception of WCAG 2.5.8 (no other target within the 24 px circle), which is what axe-core's `target-size` rule checks, and axe reported no violation for them in WebKit.
- Text contrast: axe's `color-contrast` rule passed on every view in both schemes in WebKit.

## Deviations

- The check was made by an agent driving WebKit through Playwright and reading the screenshots, not by a person using Safari.
- Only three views were stepped through by hand; the other 21 view paths are covered by the automated Tab walk and axe run only.
