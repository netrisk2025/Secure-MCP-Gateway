# Management console

The management console is the browser interface of the Management Console & Control API (E-24). It is built into `smcpd` and served on the admin listener; there is nothing to install separately and it loads nothing from the Internet (FR-8.26). Everything it does goes through the control API, so every action is authenticated, checked for origin and recorded in the evidence journal exactly as the same action from `smcpctl`. The routes it uses are documented in [api/console.md](api/console.md) and [api/approvals.md](api/approvals.md). Its visual rules are in [console-style.md](console-style.md).

## Opening the console

1. Start `smcpd`. The console is at the admin listener address in `smcp.toml` (`[admin_listener] address`), by default `https://127.0.0.1:8444/`. `smcpd` logs it at startup as `admin=`.
2. Open that exact address. Use the same host form as the configuration (`127.0.0.1`, not `localhost`, for the default): the control API refuses requests whose `Origin` differs from the configured admin URL, so sign-in fails from another host name with `origin_refused`.
3. The listener certificate is issued by the Gateway's local CA (`<state>/tls/ca.crt`). Until you trust that CA the browser shows a certificate warning. To trust it on macOS: `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <state>/tls/ca.crt`. The CA is name-constrained to loopback names, so trusting it does not let it vouch for other sites.

Approval links in harness error messages (`data.approvalUrl`) and in desktop notifications open the console at `/approvals/<id>`. Every view and every session, server, event and approval has its own path, and a path opened before sign-in opens after sign-in (FR-8.28).

## Signing in

| Account | Configured in | What it can open |
|---|---|---|
| Administrator | `[admin]` (`username`, `password_hash`), or the bootstrap token | Every view and action |
| Operator | `[[console.account]]` with `role = "operator"` | Gateway control with emergency stop (not resume or the acknowledgment of an integrity cause), sessions (suspend and terminate, not resume), servers and library (suspend), secrets metadata, egress, runtime (kill), data server, backups and keys, analytics, audit |
| Policy Author | `[[console.account]]` with `role = "policy_author"` | Policy studio with drafts, simulation, publication, rollback and the filter workbench; baseline promotion; campaign approval; analytics and audit |
| Auditor | `[[console.account]]` with `role = "auditor"` | Audit investigation and export; read-only policy, sessions, servers, secrets metadata, egress, runtime, analytics and campaigns |
| Researcher | `[[console.account]]` with `role = "researcher"` | Observation workbench, analytics aggregates, research campaigns (create, submit, stop) and dataset exports of campaigns |
| Approver | `[[approvals.account]]` | Approvals (G-13): list, inspect, approve, deny; Gateway control read-only |
| Session Approver | `[[approver]]` | Remote access: approve or deny client registrations; Gateway control read-only. Harness sign-ins are approved on the Gateway's own OAuth page when a harness connects (FR-2.19) |

The roles and their routes are the matrix of SRS Appendix C, listed in [api/console.md](api/console.md#roles). The console asks the Gateway which routes the signed-in role may use (`GET /api/v1/console/session`), lists only the views that role may open and offers only the actions it may take; the control API enforces the same table.

Choose the account kind on the sign-in page (Administrator; Approver; Session Approver; or Operator, Policy Author, Auditor or Researcher, whose role comes from the account), then enter the username and password. A sign-in ends after 15 minutes without use or 8 hours after sign-in (CP-29); live updates the console makes on its own do not count as use. When it ends the console returns to the sign-in page and keeps the path you were on. Reloading the page keeps the sign-in. **Sign out** ends the session on the Gateway at once.

First installation: when `smcpctl bootstrap` ran without `--admin-password-file`, it printed a one-use bootstrap token valid for 24 hours. On the sign-in page select **set the administrator password with a bootstrap token**, enter the token and a password of at least 12 characters, then sign in.

Failed sign-ins are rate limited per source and locked out per account with backoff, as for the control API; the error shows the reason code (`signin_failed`, `rate_limited` with the wait time, `busy`).

The sign-in is a browser session (SR-2.6-1): an `HttpOnly`, `Secure`, `SameSite=Strict` cookie that page script cannot read, with a new session ID at every sign-in. No bearer token reaches the page. Every action that changes Gateway state sends the session's CSRF token and an `If-Match` header with the tag of the console's last read of that kind of object (SR-8.9-1). Revisions are per object: when another administrator or `smcpctl` changed the same object in between, the action is refused with "The Gateway state changed since this view was last read"; check the view and submit again. Changes to other objects do not refuse it. The page's Content-Security-Policy allows no inline or third-party script. The protocol is in [api/console.md](api/console.md#browser-sessions).

## Layout

- **Status bar** (top of every view): enforcement state (`healthy`, `degraded`, `fail-closed`, or `emergency stop`), profile and release label (`not enforced` in the Standalone profile, FR-13.10), active policy revision, active session count, whether live updates are connected, the **Emergency stop** or **Resume** button for roles that may use it, the signed-in role and account and **Sign out**. In the fail-closed state the bar turns red.
- **Navigation** (left): the views the signed-in role may open, grouped by task, each with its view code. An Approver sees Gateway control and Approvals.
- **Theme**: System, Light or Dark, kept per browser.

Each view has a **Help for this view** section. Lists are tables; select a column header (or focus it and press Enter) to sort by it, again to reverse.

## Views

| Code | View | Path | What it does | Backend |
|---|---|---|---|---|
| G-01 | Gateway control | `/` | Enforcement state and each health cause with its meaning, health monitor causes with **Acknowledge** for latched ones, profile, policy revision, sessions, launcher, servers; **Reload policy**; journal verification; first-run checklist | `/admin/v1/health`, `/api/v1/health/*`, `/admin/v1/policy/reload`, `/api/v1/audit/verify` |
| G-11 | Sessions and principals | `/sessions`, `/sessions/<id>` | Active and suspended sessions; a session's binding; **Suspend session**, **Resume session**, **Terminate session**; principals of `smcp.toml` and the principal directory with **Create principal**, **Suspend** and **Enable**; credentials with **Issue credential** (a confidential client's secret is shown once) and **Revoke**; Session Approver accounts | `/api/v1/sessions*`, `/api/v1/principals*`, `/api/v1/credentials/*` |
| G-11 | Remote access | `/remote`, `/remote/clients/<id>` | Remote Access Profile state, **Enable remote access** (public URL, tunnel provider) and **Disable**; client registrations by state with **Approve** (bound to a principal), **Deny** and **Revoke** | `/api/v1/remote*`, `/api/v1/clients*` |
| G-10 | Servers and library | `/servers`, `/servers/<alias>`, `/library`, `/library/<id>/<revision>`, `/catalog` | Servers with state, revision, manifest source and launcher; package revisions with state, reason (drift, expiry, revocation), alias, risk class, signer and trust anchor, **Enable** (with alias), **Suspend**, **Retire**; packaged servers; trust anchors with **Enroll a trust anchor** and **Remove**; import receipts; **Scan the library now**; a revision's bill of materials (from its signed provenance statement), launcher argument vector, mounts, egress destinations, secret slots and sandbox profile, then its signed manifest and provenance as text; the tool catalog per template | `/api/v1/servers*`, `/api/v1/catalog`, `/api/v1/packages*` |
| G-12 | Secrets | `/secrets`, `/secrets/<name>` | Vault status, secret metadata, Secret Use Policy bindings and **Reload**; **Create a secret** (value write-only), **Rotate**, **Revoke** with the reference impact shown first, **Resume delivery** after a leak suspension | `/api/v1/secrets*` |
| | Egress | `/egress` | Broker limits and attached instances, effective grants, the connection log with server, decision, time and limit filters | `/api/v1/egress*` |
| | Runtime | `/runtime`, `/runtime/instances/<id>` | Launcher and sandbox defaults, enforced-profile prerequisite checks, instances with resource use and deviations; an instance's observations, launch specification, stderr tail and **Kill this instance** | `/api/v1/runtime*` |
| G-02 | Policy studio | `/policy`, `/policy/revisions/<id>`, `/policy/draft`, `/policy/filters`, `/policy/secret-use` | Revisions with **Roll back**; a revision's record, effective permissions per template and canonical document, diff against the active revision; a draft with structured editors for templates, rules and Framework Profiles and the whole document as JSON, **Validate**, **Diff against the active revision**, **Simulate** (journal replay) and **Publish**; the filter workbench (FR-8.27): run selected request or response filters on synthetic text and see each filter's matches, action and timing, the disposition and the transformed output; the Secret Use Policy (Administrator): structured slots and bindings, **Validate**, **Diff against the active document**, **Publish the Secret Use Policy** to `use_policy_file` and **Roll back** to an earlier published revision | `/api/v1/policy*`, `/api/v1/filters*` |
| G-03 | Audit profile tuning | `/audit-profiles` | The mandatory audit floor, read-only; the capture settings in force; an Audit Profile editor (retention, escalation parameters) with **Publish the Audit Profile** and the published and in-force revisions | `/api/v1/observations/status`, `/api/v1/observations/objects`, `/api/v1/observations/audit-profile` |
| G-06 | Anomaly response | `/anomaly-response` | The action per band in force; an editor that maps each band to a restrict-only action, with **Publish the Anomaly Response Policy** | `/api/v1/observations/status`, `/api/v1/observations/objects`, `/api/v1/observations/anomaly-response` |
| G-13 | Approvals | `/approvals`, `/approvals/<id>` | Pending approvals with time left; other states; an approval's bound request and canonical arguments; **Approve this call** and **Deny this call** | `/api/v1/approvals*` |
| G-14 | Audit investigation | `/audit`, `/audit/events/<id>`, `/audit/decisions/<id>`, `/audit/graph` | Journal browser with filters, paging and export; an event with links to its decision, call, session and principal and every phase of the call; a decision with its outcome, considered, applicable and decisive rule revisions (each with the rule as published), policy revision, template, route, server and tool revision, baseline snapshot, obligations, anomaly evidence and the phases of the call; the investigation path drawn as a graph (event, call, decision, policy revision, session, principal, tool and server revision) when the graph mirror is enabled; the neighborhood of any mirrored node, bounded at 25, 50 or 100 neighbors | `/api/v1/audit/*`, `/api/v1/decisions/{id}/explanation`, `/api/v1/graph/*` |
| G-04 | Observation workbench | `/observations` | Collector status; the Parameter Catalog grouped by capture point with search, description, unit, sensitivity and cost class; five presets, saved presets and **Clear the selection**; a cost preview that refreshes with each edit (publishing needs at least one parameter); the Observation Policy draft (policy ID, sampling rate, band bounds, baseline context dimensions) with **Publish the Observation Policy**; up to 20 recent stored records within the draft's scope, with a column per selected parameter, S2 and S3 values masked and parameters the policy in force does not capture marked | `/api/v1/observations/*` |
| G-05 | Behavior analytics | `/analytics`, `/analytics/snapshots/<id>` | z-score timeline and abnormal-event list with drill-down to the call in the journal; feature distribution and per-context statistics; baseline status, snapshots with **Build a snapshot now**, **Promote** and roll back, drift, promotion history; excluding a session from learning | `/api/v1/anomalies`, `/api/v1/observations/aggregate`, `/api/v1/baselines*` |
| G-07 | Performance | `/performance` | Throughput and CPU over time, gateway overhead p50, p95 and p99 per policy revision, time per stage and policy object, time per decisive rule and per filter, filterable by policy revision and time range | `/api/v1/observations/metrics`, `/cost`, `/aggregate` |
| G-08 | Data server and memory | `/data-server` | Graph mirror state, heap and page cache against budget, node counts, hardening findings, **Rebuild from the journal**; Observation Store size, queue and degradation stage; the Observation Store memory budget with **Publish the memory budget**; storage quota levels (percent of quota); backups with **Take a backup now**; key inventory with listener certificate and evidence key rotation | `/api/v1/graph/status`, `/api/v1/observations/status`, `/api/v1/health/status`, `/api/v1/backup`, `/api/v1/keys*` |
| G-09 | Research campaigns | `/research`, `/research/new`, `/research/campaigns/<id>`, `/research/exports/<id>` | Campaigns and exports; a new campaign with its scope chosen from observed principals, servers and tools and its parameters from the catalog; **Submit**, **Approve**, **Reject**, **Stop**, **Expire**; **Export** (CSV, JSON Lines, Parquet, GraphML), file downloads and the data dictionary of each dataset | `/api/v1/research/*` |

When this Gateway build does not serve a view's route, the view says **Not available in this build** and names the route; when the element is present but turned off in the configuration (egress, graph mirror), it says **Not enabled on this Gateway** with the configuration key. Charts are drawn by the console itself, without a chart library; each has a table of the same values under **Show values as a table**, and its marks are reachable by keyboard.

### Emergency stop

**Emergency stop** in the status bar opens a dialog that asks for a reason. **Stop the Gateway** refuses every tool call at once: no call is dispatched, calls in flight are cancelled (the server is sent `notifications/cancelled` and the harness gets `-31003` with `EMERGENCY_STOP`), no result of a call in flight is released (FR-4.14, SR-7.6-2), and the Secret Broker withdraws its grants. The status bar then shows `emergency stop` and the Gateway health is `fail-closed` with cause `emergency_stop`. The stop is recorded with your account and the reason (`reason_code` `EMERGENCY_STOP`). **Resume** asks for confirmation and records `EMERGENCY_RESUME`. If the journal cannot record the stop, the Gateway still stops and the console shows the warning.

### Approving a held call

When a policy rule with `"approval": true` is used, the call is held and appears in Approvals within about a second, without reloading. Open it, check the arguments and the bound revisions, optionally add a comment, then **Approve this call** or **Deny this call**. An approval during the hold lets the held call continue; after the hold the harness has an error telling the person to approve and run the request again, and the approval is used by that retry. See [approvals.md](approvals.md).

### First-run checklist

Gateway control lists the setup steps of FR-8.31 and marks each from Gateway state:

| Item | Done when |
|---|---|
| Administrator created | You are signed in as the administrator |
| Session Approver created | At least one `[[approver]]` account exists |
| First server packaged and enabled | A running server's tools come from a verified package manifest |
| First policy revision published | A policy revision is active |
| First harness connected | A `session` event is in the journal, or a session is active |
| Approval tested | An approval has been approved or denied |
| Backup configured | The backup route reports a configured backup; `unknown` while backups are not available in this build |

### Journal browser and export

Filters match exact values (`class`, `outcome`, `reason_code`, `session_id`, `correlation_id`, `principal_id`, `decision_id`, `origin`), except **Text**, which matches any part of the event, and the time range in RFC 3339 (`2026-10-17T00:00:00Z`). The filter is part of the address, so a filtered list can be bookmarked. The search for a harness error is its `data.correlationId` in **Correlation ID** (see [troubleshooting.md](troubleshooting.md)).

Exports contain the events matching the current filter, oldest first, up to 100,000 events. Each export is recorded in the journal. In CSV a cell that begins with `=`, `+`, `-` or `@` is prefixed with an apostrophe so that spreadsheet programs show it as text. All journal content is shown as text in the console; nothing from an event is interpreted as markup.

**Verify the journal now** checks every closed segment's hash and signature, the chain between segments, the open segment and the anchor, and shows the result and any findings (for example a segment sealed by crash recovery). It is the same check as `smcpctl journal verify`.

## Live updates

While signed in with a role that may read the journal (Administrator, Operator, Policy Author, Auditor), the console keeps an event stream open (`/api/v1/audit/stream`) and refreshes the open view when the journal records something, typically within a second (FR-8.23). Approvers use the approvals watch stream; Researchers and Session Approvers have no live channel and the status bar says `updates on reload`. The status bar shows `live`; if the stream drops it shows `not live: refresh to update` and reconnects with backoff.

## States and errors

Each view shows `Loading` while it reads, an empty state that says what would fill it, and on failure the control API message, HTTP status and reason code with **Retry** (FR-8.29). Common codes:

| Code | Meaning | What to do |
|---|---|---|
| `unauthenticated` | The sign-in ended or the token is unknown | Sign in again |
| `role_refused` | The account's role may not use this route | Sign in with an account whose role may (see Signing in) |
| `origin_refused` | The page was opened from a different address than the configured admin URL | Open the console at the address in `[admin_listener]` |
| `route_not_found` | This build does not serve the route | Shown as "Not available in this build" |
| `audit_unavailable` | The journal could not record the action, so it was not taken | Check disk space and `smcpctl health` |
| `journal_unreadable` | The journal files could not be read | Check the state directory permissions |
| `not_active` | The session ended before it could be terminated | None |
| `not_pending` | The approval was already decided, expired or used | Refresh the list |
| `export_too_large` | More than 100,000 events match | Narrow the filter |

## Keyboard and accessibility

Every action works with the keyboard. **Skip to content** is the first focusable element. Tab moves through the navigation, view controls and table headers; Enter or Space activates; Escape closes a dialog and returns focus. Focus is always visible. Moving to a view moves focus to its heading. State is never shown by color alone: each state has a word and a shape (square for good, diamond for degraded or warning, triangle for failure or refusal, ring for pending). Motion is limited to what the browser does natively and respects reduced-motion settings. The console is checked against WCAG 2.2 AA with axe-core in light and dark schemes in CI; automated checks do not cover every criterion.

Supported browsers (FR-8.30): current Chromium-based browsers, Firefox and Safari on macOS. CI runs the acceptance and accessibility tests on Playwright's Chromium, Firefox and WebKit engines, one fresh Gateway per engine. Playwright ships one version of each engine, and WebKit is not Safari itself, so the requirement's "two most recent major versions" is not tested.

## Building the console

The sources are in `console/` (React, TypeScript, Vite; no component library). The build output in `console/dist` is committed and embedded into `smcpd` by `console/embed.go`, so building `smcpd` needs only Go.

| Command | What it does |
|---|---|
| `make console` | `npm ci` if needed, typecheck, and build `console/dist` |
| `make console-check` | Fails when the committed `console/dist` differs from a fresh build |
| `make console-e2e` | For each of Chromium, Firefox and WebKit (`npm run test:e2e`, `e2e/run-browsers.mjs`): builds `smcpd`, bootstraps a temporary instance in `console/.e2e` (with the Secret Vault, the Egress Broker, an account per role and desktop notifications off), and runs the Playwright acceptance tests (`e2e/views.spec.ts` has one test per view, `e2e/session.spec.ts` covers the browser session, `e2e/inert.spec.ts` renders hostile server strings in every view, `e2e/help.spec.ts` checks inline help) and the accessibility tests against it (`e2e/a11y.spec.ts`; `e2e/keyboard.spec.ts` completes actions with the keyboard alone and runs axe on every intermediate state). `npx playwright test --project=chromium` runs one engine |

Requirement claims: tests claim requirements with annotations (`claims()` in `e2e/helpers.ts`; type `requirement-partial`, or `requirement` for a full claim). The reporter `e2e/reqreport.ts` writes them as `build/console-<engine>-test.json` in the `go test -json` format, and `e2e/claims.mjs` adds `build/console-browsers-test.json` with the cross-engine claims: FR-8.30 (partial) when every test passed on all three engines, FR-8.34 when every view G-01 to G-14 has a passing claim of its FR-8 requirement on each engine. The CI `status` job merges these files into the requirement report.
| `cd console && npm run dev` | Development server on `http://localhost:5173` proxying `/api` and `/admin` to `https://127.0.0.1:8444`; sign-in from the development server is refused by the origin check unless the admin listener is configured for it, so use it for layout work |

After changing anything under `console/src`, run `make console` and commit `console/dist` with the change. The CI job `console` fails when they differ.

## Not built yet

- Server aliases can be set only when a revision is enabled.
- Published Audit Profiles, Observation Policies and Anomaly Response Policies take effect at once. A change of baseline contexts and the memory budget take effect at the next start of smcpd, because the baseline engine and the Observation Store are built with them; the object is shown as pending until then. The graph memory budget is edited in `[graph]`.
- The investigation graph needs the graph mirror (`[graph] enabled`, Neo4j); without it the event view shows the journal's phases only. The z-score timeline needs a promoted baseline with characterized contexts.
- The Researcher's pseudonymized view of S2 fields is not implemented; the raw record route is closed to the Researcher instead. S3 payload grants are not implemented.
- The journal browser reads the journal files on every request; it has no index, so large journals are slow to page (FR-11.8).
- Browser coverage is Playwright's engines (one version each), not the two latest releases of each browser that FR-8.30 names.
- Keyboard-only flows (`e2e/keyboard.spec.ts`) cover the actions of every view, including G-10 server suspend and enable and the G-01 health acknowledgment on a dedicated Gateway, G-08 key rotation and graph rebuild, the Runtime instance kill and journal export downloads. The instance table for the kill is mocked (the acceptance Gateway runs no sandboxed instance) and an accepted graph rebuild is mocked (no graph database in the console job; the refusal is real).
