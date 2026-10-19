# Site

The technical reference for the Secure MCP Gateway: a static Next.js export built from the repository on every push to
main and deployed on Vercel (`vercel.json` at the repository root).

Nothing on the site is typed in by hand. Counts, element pages, requirements, controls and diagrams are parsed from the
documents at build time; implementation, test, coverage and verification figures come from the CI status data.

## Commands

```
npm ci
npm test            # unit tests (test/*.test.ts, node --test with type stripping)
npm run build       # static export to out/
npm run check-out   # after a build: every docs/ file has a page, every internal link and anchor resolves
npm run check-diagrams  # after a build: every diagram and chart fits its box (Chrome, 1280 and 390 px)
npm run typecheck   # tsc --noEmit
npm run dev
```

## Inputs

| Input | Read by | Notes |
|---|---|---|
| `ArchitectureV2.md` | `src/lib/parse-arch.ts` | The build fails with a named section if an expected heading or table is missing. |
| `srs_build/req*.txt` | `src/lib/parse-reqs.ts` | The requirement source records, not the generated SRS. |
| `MCP_Gateway_Security_SRS.md` | `src/lib/parse-sec.ts` | |
| `docs/flows/*.md` | `src/lib/flows.ts` | Every file becomes a page under Flows. An empty or missing directory is allowed. |
| `docs/**/*.md` (except flows) | `src/lib/content.ts` | Every file becomes a page under `/docs/` at its path (`docs/api/policy.md` is `/docs/api/policy/`, a `README.md` is its directory). Order and groups follow the sections of `docs/README.md` that first link each file; subdirectories form their own group. Root documents are listed in `ROOT_DOCS`. Two files mapping to one path fail the build. |
| `status.json`, `history.json` | `src/lib/status.ts` | Published by CI to the `site-data` branch. See below. |
| `data/openapi.json` | `src/lib/openapi.ts` | The control API document, written by `go run ./tools/openapi` (`make openapi`) from the Go sources. A Go test fails when it is stale and the regenerate workflow rewrites it on pull requests. Served as `/openapi.json` and rendered by the Control API page. |
| `docs/clients/matrix.json` | `src/lib/matrix.ts` | The client matrix with per-client notes, joined with the `agents` results of the status data on the Agents page. |
| GitHub releases API | `src/lib/release.ts` | The five latest releases for the Install page, read once per build with a 5 second timeout (`SITE_RELEASES_URL` overrides the URL; `GITHUB_TOKEN` is sent when set). A failed read is shown on the page and never fails the build. |

## Status data

`next.config.ts` calls `prepareStatusSnapshot()` once per build, before any page renders. It fetches:

| Variable | Default |
|---|---|
| `SITE_STATUS_URL` | `https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/site-data/status.json` |
| `SITE_HISTORY_URL` | the status URL with `status.json` replaced by `history.json` |

Each request has a 5 second timeout. `file://` URLs work, for local testing. If the status file cannot be fetched,
is not JSON, or is not schema 1, the build uses `data/status.sample.json` and `data/history.sample.json` instead and
every page that shows status figures says "sample data". The build never fails because status data is missing.

The snapshot is written to `.status/snapshot.json` (ignored by git) so every page in one build shows the same data.

The schema is the shared status contract between the CI job and the site; `Status` and `HistoryPoint` in
`src/lib/status.ts` mirror it field for field.

## Testing other inputs

```
SITE_STATUS_URL=http://10.255.255.1/status.json npm run build   # unreachable: falls back to the sample
SITE_STATUS_URL=file:///path/to/status.json npm run build       # a local status file, read as live data
SITE_FLOWS_DIR=/path/to/flows npm run build                     # flow documents from another directory
```

## Diagrams

Mermaid diagrams are drawn in the browser by `src/components/Mermaid.tsx` with `useMaxWidth`: each SVG is as wide as
its box and never wider than drawn, so a whole diagram is always in view and nothing scrolls sideways. A box is 860 px
on document pages and 1,136 px on flow pages (the flow figure spans the rail column) at 1280 px and wider. When a box
is narrower than the drawing (a phone, a narrow window) the caption offers "View full size", a dialog with the diagram
at 100%.

A diagram stays legible only if its source is laid out for those widths: about six sequence participants on a
document page and eight on a flow page, flowcharts top to bottom when a left-to-right layout has many ranks. Split a
longer sequence into parts and continue the numbers with `autonumber N`; the step tables follow (`src/lib/diagram.ts`,
tested in `test/diagram.test.ts`). Diagrams of one section of `ArchitectureV2.md` share one Flows page.

`npm run check-diagrams` (after a build) loads every page with a diagram or chart in Chrome (`playwright-core`, the
installed `chrome` channel, else Playwright's Chromium, else `CHROME_PATH`) at 1280 x 800 and 390 x 844. It fails
when a diagram is wider than its box, is drawn outside it, is clipped or loses its aspect ratio, when the page scrolls
sideways, or, at 1280 px, when the smallest text is under 11 px (`CHECK_DIAGRAMS_MIN_TEXT_PX`).

## System map

`docs/flows/system-map.md` is one flowchart of the whole product. It does not use the flow page: `/flows/system-map/`
(`src/app/flows/system-map/page.tsx`, `src/lib/system-map.ts`, `src/components/SystemMap.tsx`) draws it across the
full page width with built-in pan and zoom, and lists the stages from the document's "Stages" table; selecting a stage
zooms to its subgraph. The overview is fitted to the page width and is as tall as the chart; zoomed, the box is as tall
as the window. The source is laid out so the overview stays legible at 1280 px: stages run top to bottom, each split
into left-to-right rows of at most four boxes, with lines of about 30 characters. `check-diagrams` measures the
overview like any diagram and also every stage view at 1280 and 390 px (`measureSystemMap`).

`public/system-map.svg` is the static download, written by `npm run render-system-map` (Chrome, light colors, SVG text
labels) with the SHA-256 of the Mermaid source in its first comment; `test/system-map.test.ts` fails when it is older
than the source, when a stage names a missing subgraph, or when an element E-01 to E-33 is not on the chart. After
changing the chart, run `npm run render-system-map` and commit the SVG.

## Charts

Charts are server-rendered SVG in `src/components/charts/`. Each has a title and description for assistive
technology, a legend when it has more than one series, and a data table in a `details` element. The requirement
status colors were checked for adjacent-pair separation under color-vision deficiency in light and dark mode; status
is always also given as a word and a glyph.
