# FR-8.32 Manual accessibility check: focus order, target size and contrast

The SRS verifies FR-8.32 by Test: `axe-core` with the WCAG 2.2 AA rules on every view and state of the Playwright suite, plus this record of a manual check of focus order, target size and contrast. The record supports the automated tests and does not by itself verify the requirement.

| Field | Content |
|---|---|
| Requirement or scenario | FR-8.32 |
| Commit | `fc13edb7ff6c1da95d0f7d808afb2328f61b8361` |
| Profile and platform | Standalone; darwin/arm64, Chromium and Firefox of Playwright 1.64.1 at 1280 x 720 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification task) |
| Method | Test |
| Result | pass |

## Steps

1. Started the console acceptance Gateway (`console/e2e/global-setup.ts`) and ran `npx playwright test --project=chromium e2e/a11y.spec.ts`, then the keyboard tests with `--project=firefox`. The views are the 24 paths of `console/e2e/a11y.spec.ts:10`, which cover G-01 to G-14 and the Egress, Runtime and Remote access views, each in the light and the dark color scheme.
2. Focus order: the keyboard test (`console/e2e/a11y.spec.ts:70`) marks every tabbable control of a view in DOM order, starts before the first one and presses Tab until each has been focused. It fails when a control is never reached (a trap or an unreachable control), when focus lands on an unmarked element, or when any element has a positive `tabindex`.
3. Focus indicator: at each Tab stop the test reads the computed outline (or box shadow) of the focused element and computes the contrast ratio of its color against the first opaque background behind it; it fails below 3:1 (WCAG 1.4.11).
4. Target size: the axe run (`console/e2e/a11y.spec.ts:38`) includes axe-core 4.14.0's `target-size` rule, which is the one rule tagged `wcag22aa` (WCAG 2.5.8, 24 by 24 CSS pixels or the spacing exception). In addition, screenshots of G-02, G-04 and G-13 in both schemes were taken with the focus on a control, and the smallest interactive elements of each were measured.
5. Text contrast: the axe run includes the `color-contrast` rule (WCAG 1.4.3) in both schemes.

## Observations

- First run (commit `d714c6c`): in the light scheme the focus outline of the three status-strip controls (Skip to content, Emergency stop, Sign out) had 2.50:1 contrast, because the page focus color `#1f4fc4` sits on the strip background `#141a17`. The dark scheme passed. Commit `fc13edb` gives controls in the strip the strip ink color as their outline (`console/src/styles.css:326`).
- After the fix, Tab reached every control of every view in both schemes in Chromium (972 controls in the light scheme, 975 in the dark) and in Firefox (966 and 969); no view has a positive `tabindex`; every focus outline is 2 px solid (`console/src/styles.css:156`) with at least 3:1 contrast against its background.
- Focus order follows the DOM: skip link, status strip, navigation, then the view's main content from top to bottom, with each view's controls in reading order. The skip link targets `#main`. No CSS rule uses `order` or reversed flex directions; the only explicit grid placement puts the page-header actions in a right-hand column beside the title and lede (`console/src/styles.css:452`), and they follow the lede in focus order, which matches reading the left column before the right.
- axe found no `target-size` or `color-contrast` violation on any view in either scheme. Buttons and quiet link-buttons have a 24 px minimum height (`console/src/styles.css:240`, `console/src/styles.css:300`); the smallest measured controls were the 16 px checkboxes of G-04, each inside a label that is part of its target, with the centers of neighboring checkboxes at least 24 px apart.

## Deviations

- The commit above is on branch `test/verification-records` before it was rebased and squash-merged (pull request #40), so it is not an ancestor of `main`; the merged tree contains the same code.
- WebKit is not covered by the keyboard test: WebKit's Tab moves only between form controls unless the macOS keyboard setting is changed. The axe run covers WebKit.
- The axe run checks each view as it loads, not every intermediate state of every acceptance test.
