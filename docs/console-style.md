# Console visual rules

Checklist for the management console (E-24). Each view is inspected against it before release (SRS FR-8.35). The rules follow the owner's direction: dense, stark, typographic, tables over cards.

| Rule | Check |
|---|---|
| Lists are tables | Every collection (sessions, servers, approvals, decisions, events, policy revisions) is a `<table>` with a header row and sortable column headers. No card grids. |
| One typeface family | One family for text and one monospaced face for IDs, digests and code, with a fixed type scale of at most five sizes. |
| No decoration | No gradients, drop shadows used for decoration, emoji, illustrations or decorative icon grids. Icons appear only where they carry meaning and have a text label. |
| Color carries state only | Color marks state (fail-closed, degraded, denied, pending) and is never the only cue; each state also has a text label. |
| Density | Table rows at most 32 px high at the default size; no empty hero areas. |
| Text | Plain, specific labels and messages; no marketing language and no exclamation marks. Error states show the control API message and reason code (FR-8.29). |
| Hand-built components | Components are written in the project; no component kit (no Mantine or similar). |
| Accessibility | WCAG 2.2 AA (FR-8.32): contrast at least 4.5:1 for text, visible focus, target size at least 24 by 24 CSS px, every action reachable by keyboard (FR-8.33). |
| Local assets | All scripts, styles and fonts are served by the Gateway (FR-8.26). |

## Implementation

The console (`console/src/styles.css`) applies these rules with:

- Typeface: IBM Plex Sans (400, 600) for text and IBM Plex Mono (400, 500) for IDs, revisions, digests and reason codes, bundled from `@fontsource` (OFL-1.1) and served by `smcpd`.
- Type scale: 12, 13, 14, 16 and 20 px. Tables and monospace text are 13 px; body text 14 px.
- Table rows are 30 px high plus a 1 px rule.
- Palette: the reference site tokens (paper, surface, ink, rule, moss) plus four state colors, each redefined for the dark scheme. State is also carried by a word and a shape: square (good), diamond (degraded or warning), triangle (failure or refusal), ring (pending).
- Components are in `console/src/ui.tsx`; there is no component library.
- Charts (`console/src/charts.tsx`) and graphs (`console/src/graph.tsx`) are hand-built SVG: one y-axis, 2 px lines, bars at most 16 px thick from one baseline with 4 px rounded ends, hairline recessive grid, a legend only for two or more series, three validated categorical series colors (`--series-1` to `--series-3`, separate light and dark steps), status colors only for state with a shape as well (circle elevated, diamond abnormal, triangle critical), a tooltip that answers pointer and keyboard focus, and a table of the same values under every chart.
- Automated checks: `console/e2e/a11y.spec.ts` runs axe-core with the WCAG 2.2 A and AA rule sets on every view in light and dark schemes.
