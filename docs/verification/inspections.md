# Inspection and analysis records

Records for requirements whose SRS verification method is Inspection, Analysis or Demonstration (SRS Section 2.6). Each record follows the field table of [README.md](README.md). `tools/reqreport` counts a record as verification of a requirement when every field is filled in, the method equals the requirement's SRS method, every cited evidence file exists, and the record with the latest date for that requirement has result `pass`.

Line numbers in evidence references are those of the commit named in the record. Requirements that were inspected and found not met are listed in [gap-list.md](gap-list.md) instead of here.

## FR-10.37 Parameter Catalog content

| Field | Content |
|---|---|
| Requirement or scenario | FR-10.37 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Not profile-specific; darwin/arm64 |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: ran `python3 -I srs_build/gen.py . <out>` (the `make srs-check` build that CI runs) and read its parameter-catalog check and the generated catalog row.

Observations:

- `srs_build/gen.py:144` lists the eleven attributes the requirement names (ID, name, description, unit, data type, source element, capture point, derivation, sensitivity class, baselinable flag, cost class) and `srs_build/gen.py:149` fails the build for any entry missing one of them.
- `srs_build/gen.py:159` fails the build for any ARCH §10.3 `P-nnn` ID absent from the catalog; `srs_build/gen.py:157` rejects duplicate IDs.
- The build printed `OK: 558 requirements` with no warnings, and the generated SRS states "92 parameters; all 92 ARCH §10.3 IDs present" (`srs_build/gen.py:351`).
- `docs/parameters.json:1` carries `catalogVersion`, so the catalog is versioned.

Deviation: none.

## FR-12.11 No paid database features

| Field | Content |
|---|---|
| Requirement or scenario | FR-12.11 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Enforced and Standalone; source and CI configuration |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the database components the Data Server uses, the configuration the Gateway applies to them and the database installation used by CI.

Observations:

- Graph engine: Neo4j Community Edition 2026.05.0 (GPL-3.0), documented in `docs/graph.md:9`; the CI graph job runs the `neo4j:2026.05.0-community` image (`.github/workflows/ci.yml:287`).
- The schema migrations use only uniqueness constraints (`internal/graph/templates/0001_constraints.cypher:3`), which Community Edition supports. No property-existence or node-key constraints, roles, privileges, multiple databases, APOC or GDS procedures appear in `internal/graph` (searched for `IS NOT NULL`, `NODE KEY`, `CREATE ROLE`, `GRANT`, `CREATE DATABASE`, `apoc`, `gds.`).
- The Data Access Service connects over Bolt to a self-hosted engine on loopback (`internal/graph/backend.go:29`); there is no Aura or other hosted endpoint.
- Observation Store: DuckDB (MIT), embedded through `github.com/duckdb/duckdb-go/v2` (`go.mod:46`), or JSON Lines files.

Deviation: the Gateway does not query the engine's edition at start; an operator who installs Enterprise Edition would not be warned. No Enterprise feature is used either way.

## FR-18.2 Security Limitations

| Field | Content |
|---|---|
| Requirement or scenario | FR-18.2 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Documentation; not platform-specific |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: read `docs/security-limitations.md` against each limitation the requirement lists.

Observations (each item is stated with its consequence and, where one exists, a mitigation):

| Listed limitation | Where |
|---|---|
| The Standalone profile contains no server | `docs/security-limitations.md:11` (section 1) |
| In the Standalone profile the agent runs as the Gateway's identity | `docs/security-limitations.md:18` (section 2) |
| An agent's non-MCP native tools bypass the Gateway | `docs/security-limitations.md:24` (section 3) |
| Lockdown profiles are only as strong as each client's settings enforcement | `docs/security-limitations.md:30` (section 4) |
| A tunnel provider can read remote traffic | `docs/security-limitations.md:36` (section 5) |
| Running the Gateway inside a vendor's agent machine is not a control | `docs/security-limitations.md:42` (section 6) |
| Detection filters have measured false-positive and false-negative rates | `docs/security-limitations.md:46` (section 7) |
| Injection findings are tags only | `docs/security-limitations.md:50` (section 8) |
| Remote backends, resources and prompts are not supported | `docs/security-limitations.md:62` (section 11) |

Deviation: section 11 also says sampling, elicitation and roots are refused; southbound, the dispatcher currently declares the SDK's default `roots` capability (see SR-5.6-2 in [gap-list.md](gap-list.md)). This does not affect the items FR-18.2 lists.

## FR-19.2 Hostile suite results

| Field | Content |
|---|---|
| Requirement or scenario | FR-19.2 |
| Commit | `9e29ef00dcc41fd9be4a0293e2f0547eda280ab1` |
| Profile and platform | Standalone and Enforced (CI hostile job, ubuntu-latest) |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: fetched the status data published from the main-branch CI run of the commit above (`site-data` branch, `status.json`, generated 2026-10-17T03:02:06Z) and compared its `hostile` array with SRS Appendix L.

Observations:

- The `hostile` array has 27 entries, one for each Appendix L row HF-01 to HF-27 (`srs_build/appendix2.md` lists 27 `HF-` rows); each fixture ID appears exactly once.
- Every entry has non-empty `fixture`, `attack`, `expected`, `observed` and `pass` fields (20 entries pass, 7 do not; FR-19.2 requires publication, not passing).
- The CI hostile job produces `build/hostile.json` (`.github/workflows/ci.yml:324`) and `tools/reqreport` copies it into the status data (`tools/reqreport/main.go:119`).

Deviation: none.

## SR-1.12-1 No semantic authorization

| Field | Content |
|---|---|
| Requirement or scenario | SR-1.12-1 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Not profile-specific; source inspection |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected every input of the permit and route decision.

Observations:

- `policy.Request` (`internal/policy/policy.go:409`) holds only principal, session, framework profile, template, server, tool, and the manifest's side-effect class and source trust. It has no field for text, scores, embeddings or model output.
- `Decider.Decide` (`internal/policy/policy.go:550`) reads only that request, the compiled snapshot, the rate and quota counters and the session taint mark; the route is the request's server (`dec.Route = req.Server`).
- The only production caller builds the request from the authenticated session and the registry's tool reference (`internal/edge/pipeline.go:102`); `policy.Simulate` replays recorded requests of the same type (`internal/policy/simulate.go:200`).
- Filter findings and anomaly scores are produced after the decision by the request filter chain (`internal/analytics/service.go:178` registers the anomaly probe as a request filter) and can only block, add approval or withhold; they never produce a permit or select a route.

Deviation: none.

## SR-2.9-3 Loopback binding

| Field | Content |
|---|---|
| Requirement or scenario | SR-2.9-3 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Enforced and Standalone; default configuration, source inspection |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the default listener addresses and every place the daemon opens a TCP listener (`net.Listen` in `internal` and `cmd`).

Observations:

- Defaults: harness listener `127.0.0.1:8443` (`internal/config/config.go:393`), admin listener `127.0.0.1:8444` (`internal/config/config.go:408`), remote listener `127.0.0.1:8445` when the admin port is taken (`internal/config/remote.go:65`).
- Harness listener: `Gateway.Listen` refuses a non-loopback address before binding (`internal/edge/edge.go:363`, check at `internal/edge/edge.go:314`).
- Management Console and Control API (one admin listener): `adminapi.Server.Listen` applies the same check (`internal/adminapi/adminapi.go:481`).
- Remote Access listener: configuration validation refuses a non-loopback `remote.address` (`internal/config/remote.go:122`, called from `internal/config/config.go:523`), and the listener binds only that address (`internal/remote/remote.go:337`).
- The other TCP listeners are the loopback-checked metrics listener (`internal/metrics/metrics.go:267`) and the Egress Broker's per-instance proxies (`internal/egress/egress.go:280`), which are not harness or console listeners.

Deviation: the check accepts the host name `localhost` without resolving it.

## SR-4.13-1 Exclusive-gateway label

| Field | Content |
|---|---|
| Requirement or scenario | SR-4.13-1 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Documentation and matrix data |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: read `docs/clients/matrix.json` and the latest matrix results recorded in it.

Observations:

- All ten clients in `docs/clients/matrix.json:1` carry `"label": "gateway-available"`; no client is labelled `exclusive-gateway`. With no `exclusive-gateway` label, there is no client whose bypass results need checking, and every other client is marked `gateway-available` as the requirement states.
- `docs/security-limitations.md:34` states the same rule for operators.

Deviation: the result depends on the current data: no client has yet passed the FR-15.1 and SR-4.9-1 bypass tests. A record must be repeated when any client is relabelled.

## SR-5.7-3 No result caching

| Field | Content |
|---|---|
| Requirement or scenario | SR-5.7-3 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Not profile-specific; source inspection |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the dispatch path, the response chain and the release path for any store of `tools/call` results.

Observations:

- `Registry.Call` (`internal/backend/backend.go:416`) spends a one-use launch capability and sends every call to the backend (`internal/backend/backend.go:449`); it returns the result to its caller and keeps no reference to it.
- The edge pipeline holds the result in local variables of one call's handler, runs the response filters on it and releases it after committing the delivered event (`internal/edge/pipeline.go:316`); nothing is stored on the `Gateway` or session structures.
- The only caches in `internal/edge`, `internal/backend` and `internal/pipeline` are the per-session tool catalogs and compiled input schemas (`internal/pipeline/filters.go:357`); neither holds results. The `ttlMs` cache hints apply to `server/discover` and `tools/list` only.
- Optional payload capture by the Observation Collector writes evidence copies for analysis; they are never returned to a request.

Deviation: none.

## SR-7.1-1 No side effects in retryable transactions

| Field | Content |
|---|---|
| Requirement or scenario | SR-7.1-1 |
| Commit | `a84aef79d8670572f206db22563941abb3b0bf47` |
| Profile and platform | Not profile-specific; source inspection |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification task) |
| Method | Inspection |
| Result | pass |

Steps: searched the module for the Neo4j driver and for every way to open a database transaction (`ExecuteWrite`, `ExecuteRead`, `BeginTransaction`, `database/sql` `Begin` and `BeginTx`), then read each transaction function and everything it calls.

Observations:

- Only `internal/graph/backend.go` imports the Neo4j driver. It opens retryable transaction functions in two places: `Neo4j.Write` (`internal/graph/backend.go:88`) and `Neo4j.Read` (`internal/graph/backend.go:109`).
- The write function loops over the prepared statements and calls `runTx`; the read function calls `runTx` once. `runTx` (`internal/graph/backend.go:118`) calls only `tx.Run`, `Result.Collect` and `Record.AsMap`, and `driverParams` (`internal/graph/backend.go:58`) only converts parameter maps and slices. No dispatch, egress, file, export, logging or channel operation occurs inside either function; results are returned to the caller, which acts on them after the transaction ends.
- The Data Access Service reaches the engine only through these two functions: `DAS.write` (`internal/graph/das.go:60`) checks the statement modes and calls `Backend.Write` outside any transaction.
- The Observation Store (DuckDB) uses `database/sql` with single statements (`internal/obsstore/duckdb.go:87`) and opens no transaction; nothing in the module calls `Begin` or `BeginTx`, so no other retryable transaction function exists.
- `TestTransactionFunctionsHoldOnlyDatabaseWork` (`internal/graph/catalog_test.go:159`) parses `backend.go` and fails when a transaction function calls anything outside that set, so a later change to these two functions is caught.

Deviation: none.

## FR-8.35 Console visual rules

| Field | Content |
|---|---|
| Requirement or scenario | FR-8.35 |
| Commit | `1391541c07403092c5818faf132c97bfde4f4577` |
| Profile and platform | Standalone; darwin/arm64, Chromium, Firefox and WebKit of Playwright 1.64.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the 24 view paths of `console/e2e/style.spec.ts:12` (G-01 to G-14 and the Egress, Runtime, Remote access, library, draft, filter workbench, investigation graph and new-campaign pages) against each rule of the checklist in `docs/console-style.md:5`, in the light and the dark color scheme. The measurable rules were checked by `console/e2e/style.spec.ts:40`, which opens every disclosure of each view and reads the rendered page; the other rules were checked by reading the source and the rendered views.

Observations, by checklist rule:

- Lists are tables: every collection is rendered by `DataTable` (`console/src/ui.tsx:205`), a `<table>` with a header row whose sortable columns are buttons with `aria-sort`. The test found the nine G-04 parameter catalog tables without sortable headers; they were changed to `DataTable` before this record. Four tables list a fixed enumeration in a meaningful order rather than a collection of records (the G-01 first-run steps, the two G-06 band tables, the G-03 mandatory audit floor) and have no sort; the test names them as exemptions. No card grid exists.
- One typeface family: text is IBM Plex Sans and IDs, digests and code are IBM Plex Mono (`console/src/styles.css:37`, `console/src/styles.css:38`), bundled from `@fontsource` (`console/package.json:13`). Every visible text node of every view uses one of the two faces at 12, 13, 14, 16 or 20 px.
- No decoration: no element has a gradient background or a drop shadow; the one box shadow is an inset 3 px bar that marks a refused row next to its outcome text (`console/src/styles.css:573`). No emoji appear. The only glyph icons are the sort marks, which are `aria-hidden` next to the column label, and the state marks, which sit next to a text label.
- Color carries state only: state is shown by `StateLabel` (`console/src/ui.tsx:85`), which always renders the state word next to its colored mark.
- Density: every table row whose cells hold one line is at most 32 px high.
- Text: no exclamation mark appears in headings, labels, buttons, table headers or paragraphs. Error states show the control API status, message and reason code (`console/src/ui.tsx:130`).
- Hand-built components: the console's runtime dependencies are React, React DOM and the two font packages (`console/package.json:12`); there is no component kit.
- Accessibility: see `FR-8.32.md` and `console/e2e/a11y.spec.ts:38`.
- Local assets: the console page loads scripts, styles and fonts only from the Gateway under a strict content security policy (`console/e2e/console.spec.ts:150`).

Deviation: the four fixed-enumeration tables are not sortable. Sorting them would remove meaning, because their order is the order of the steps or bands.

## FR-2.1 Principal registry

| Field | Content |
|---|---|
| Requirement or scenario | FR-2.1 |
| Commit | `e8b6606a426d0d209e1fa5a461cbdeb38fa7f85d` |
| Profile and platform | Not profile-specific; darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (gap implementation task) |
| Method | Inspection |
| Result | pass |

Steps: ran `go test ./internal/principals -run TestRoutes -v`, which creates principal `agent` through `POST /api/v1/principals` (the G-11 route), issues it a credential through `POST /api/v1/principals/agent/credentials`, suspends and re-enables it, and lists it through `GET /api/v1/principals`. Then ran the same Directory calls the routes make (`AddPrincipal`, `Issue`, `SetSuspended`) in a scratch test and read the stored file `state/principals.json` and the listed view.

Observations:

- The stored principal record (`internal/principals/principals.go:70`) holds `id`, `framework`, `display_name` and `profile` (the Framework Profile ID), with `created_by` and `created_at`; the route fills them from the request (`internal/principals/http.go:142`).
- Credentials are stored with a reference to their principal (`internal/principals/principals.go:80`, member `principal`), and the principal's view lists its credential references with client ID, redirect URIs and revocation state, never the secret hash (`internal/principals/principals.go:333`, `internal/principals/principals.go:359`).
- The enabled state is the absence of an entry in the suspension map (`internal/principals/principals.go:102`); the view reports `enabled` and the suspension's actor, time and reason. Principals of the configuration file appear in the same view with `source: "file"` and their `enabled` value (`internal/principals/principals.go:386`).
- The scratch run stored `{"id": "agent", "framework": "codex", "display_name": "Agent", "profile": "dev", ...}`, a credential with `"principal": "agent"`, and `"suspended": {"agent": {"by": "admin:admin", ...}}`; the view showed `"enabled": false` with the suspension and the credential.

Deviation: none.


## FR-7.7 Local certificate authorities

| Field | Content |
|---|---|
| Requirement or scenario | FR-7.7 |
| Commit | `5e43a626323809132161cb9fb85bab8c6d71d5a8` |
| Profile and platform | Standalone; darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (console gap task) |
| Method | Inspection |
| Result | pass |

The statement inspected is the release 1.0 form of FR-7.7 (one server CA; the client CA is deferred with the mTLS Harness Profile as FR-7.15).

Steps: bootstrapped an instance with `smcpctl bootstrap` (the Playwright acceptance setup, `console/e2e/gateway.ts`), ran `openssl x509 -noout -text` on `state/tls/ca.crt` and `state/tls/server.crt`, read the key inventory code, and searched the source for every use of the CA key file and every certificate the Gateway signs.

Observations:

- The CA certificate is `CN=Secure MCP Gateway server CA`, `CA:TRUE, pathlen:0`, key usage `Certificate Sign, CRL Sign, Digital Signature`, with critical name constraints permitting only the listener names (`DNS:localhost` here) (`internal/keys/keys.go:169`, `internal/keys/keys.go:183`).
- The issued listener certificate has issuer `Secure MCP Gateway server CA`, key usage `Digital Signature` and extended key usage `TLS Web Server Authentication` only (`internal/keys/keys.go:266`, `internal/keys/keys.go:267`).
- The Gateway signs exactly two kinds of certificate: the self-signed CA (`internal/keys/keys.go:188`) and the listener certificate (`internal/keys/keys.go:271`). The CA key file is loaded only to issue or renew the listener certificate (`internal/keys/keys.go:337`, `internal/keys/rotate.go:151`); no other package opens it (the only other reference is the list of key files that `smcpctl bootstrap` refuses to overwrite, `cmd/smcpctl/bootstrap.go:233`).
- The key inventory names one file per purpose, with `server_ca` mapped to `tls/ca.key` and no other purpose sharing it (`internal/keys/rotate.go:460`).

Deviation: none for the release 1.0 statement. A separate client CA does not exist; it is FR-7.15, deferred.

## FR-7.10 Trust anchor enrollment

| Field | Content |
|---|---|
| Requirement or scenario | FR-7.10 |
| Commit | `76fb76bf8c7012823b008ac84f6c7d5787953133` |
| Profile and platform | Standalone; darwin/arm64 (Chromium 1248, Playwright 1.64.1) |
| Date | 2026-10-17 |
| Executor | Claude Code agent (console gap task) |
| Method | Demonstration |
| Result | pass |

Steps: at the commit above, started the console acceptance Gateway (`console/e2e/global-setup.ts`) and ran `npx playwright test --project=chromium e2e/views.spec.ts -g "G-10"`. The first G-10 test (`console/e2e/views.spec.ts:581`) creates a minisign key with `smcpctl package keygen`, opens G-10 "Library and trust anchors", fills "Enroll a trust anchor" with the name `e2e-rev2`, the public key, risk class `low` only (moderate unchecked) and expiry 2027-10-16, and presses "Show fingerprint".

Observations:

- G-10 showed a "Key fingerprint" panel with the key ID printed by `keygen`, the 64-digit SHA-256 of the key line, the risk class `low` and the expiry, and the "Enroll anchor" button stayed disabled; the trust anchor table did not list `e2e-rev2` at that point (`console/src/views/Library.tsx:302`).
- After the box "The key ID matches the publisher's" was checked, "Enroll anchor" enrolled the key; the trust anchor row showed the same key ID, class `low` (not `moderate`) and an expiry in 2027.
- The control API enforces the step for every client: an enrollment without `confirm_key_id` answers 400 `confirmation_required`, one with another key ID 400 `fingerprint_mismatch` (`internal/library/trust_api.go:60`, `internal/library/trust_api.go:63`); the enrollment event records the key ID, the SHA-256 fingerprint, `fingerprint_confirmed` and the classes and expiry (`internal/library/trust_api.go:92`). `smcpctl trust add` needs `--key-id` or the key ID typed at a prompt.
- The test passed.

Deviation: the Gateway was built from the `main` commit above, not a release commit.

## FR-8.18 G-10 Servers & Library

| Field | Content |
|---|---|
| Requirement or scenario | FR-8.18 |
| Commit | `76fb76bf8c7012823b008ac84f6c7d5787953133` |
| Profile and platform | Standalone; darwin/arm64 (Chromium 1248, Playwright 1.64.1) |
| Date | 2026-10-17 |
| Executor | Claude Code agent (console gap task) |
| Method | Demonstration |
| Result | pass |

Steps: in the same run as the FR-7.10 record, the two G-10 tests of `console/e2e/views.spec.ts` (`:581` and `:653`): a second revision `99.0.0-e2e` of `smcp-ref-filesystem` was built from a recipe, signed with the newly enrolled key and installed with `smcpctl package install` through the running Gateway; it was retired from G-10; then the enabled bootstrap revision was suspended and enabled again from G-10.

Observations:

- The "Package revisions" table listed both revisions with state, "Why" (the state reason, where drift and revocation causes appear), alias, risk class, signing anchor (the attestation) and manifest digest (`console/src/views/Library.tsx:159`, `console/src/views/Library.tsx:162`). The new revision showed `verified-disabled`, signed by `e2e-rev2`.
- Retire: the row action "Retire smcp-ref-filesystem 99.0.0-e2e" (`console/src/views/Library.tsx:180`) opened a dialog stating that retiring is final; after confirmation with a reason the page said "Retired smcp-ref-filesystem 99.0.0-e2e. This cannot be undone.", the row showed `retired` and offered no further action, and the enabled revision was unaffected.
- Suspend: the enabled revision changed to `verified-disabled` with the message that a running instance was stopped. Enable: it changed back to `enabled`; the enable dialog offers the alias (`console/src/views/Library.tsx:112`).
- Trust-anchor actions: enrollment with the fingerprint step (FR-7.10 record) and removal of `e2e-anchor` and `e2e-rev2` from the trust anchor table.
- The package detail page showed the signed manifest and provenance statement as text.
- Both tests passed.

Deviation: the Gateway was built from the `main` commit above, not a release commit.

## FR-8.25 Inline help

| Field | Content |
|---|---|
| Requirement or scenario | FR-8.25 |
| Commit | `76fb76bf8c7012823b008ac84f6c7d5787953133` |
| Profile and platform | Standalone; darwin/arm64 (Chromium 1248, Playwright 1.64.1) |
| Date | 2026-10-17 |
| Executor | Claude Code agent (console gap task) |
| Method | Inspection |
| Result | pass |

Steps: at the commit above, ran `npx playwright test --project=chromium e2e/help.spec.ts` and a scratch Playwright script that read the G-04 parameter tables, then read the help sources.

Observations:

- Views: each of the 19 views of the view list (G-01 to G-14, Egress, Runtime, Remote access, the catalog and the library) has one "Help for this view" section with text (`console/e2e/help.spec.ts:12`).
- Policy fields: the G-02 field reference lists help for all 32 fields of `internal/policy/policy.schema.json`, and every control of the draft editor (document, template, rule and profile fields) is described by its help text through `aria-describedby` (`console/src/policyhelp.ts:7`, `console/e2e/help.spec.ts:54`).
- Catalog parameters: G-04 lists the 92 catalog parameters with their descriptions. A sample of 30 (every third row): P-022, P-061, P-082, P-085, P-203, P-210, P-207, P-240, P-243, P-246, P-249, P-161, P-213, P-027, P-030, P-041, P-044, P-006, P-021, P-063, P-066, P-202, P-122, P-125, P-140, P-143, P-209, P-104, P-107, P-002; each showed a description (for example P-022 "Server ID and revision targeted by the call", P-213 "Gateway-added overhead: end-to-end minus server execution minus approval wait").
- Local loading: view and policy help is part of the embedded console bundle, and parameter descriptions come from the catalog the Gateway serves (`docs/parameters.json` built into the binary); the help test records no request to another origin.

Deviation: none.

## FR-13.1 Release archives

| Field | Content |
|---|---|
| Requirement or scenario | FR-13.1 |
| Commit | `4ba218973fd4279d3e385cd4751285417a68103f` |
| Profile and platform | Not profile-specific; the GitHub Release v1.0.0-rc.2 (pre-release), inspected on darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (release rehearsal task) |
| Method | Inspection |
| Result | pass |

Steps: tagged v1.0.0-rc.2 on main `4ba2189`; the release workflow (run 39032406916) published it. Downloaded every asset with `gh release download v1.0.0-rc.2 -R ethan03805/Secure-MCP-Gateway`, ran `minisign -Vm smcp_1.0.0-rc.2_checksums.txt -P <key from SECURITY.md>`, `shasum -a 256 -c smcp_1.0.0-rc.2_checksums.txt`, `tar -tzf` on each archive, read `sbom.spdx.json` from the linux-amd64 archive, and installed the darwin-arm64 archive with `install.sh --version v1.0.0-rc.2`.

Observations:

- Four archives: `smcp_1.0.0-rc.2_darwin_arm64.tar.gz`, `_darwin_amd64`, `_linux_amd64`, `_linux_arm64` (`.goreleaser.yaml:95`). Each lists `smcpd`, `smcpctl`, `smcp-refserver`, `smcp-session`, `smcp-stdio`, `smcp-connect`, `LICENSE`, `README.md`, `CHANGELOG.md`, `docs/icd/x-01-harness-interface.md`, `docs/icd/x-12-adapter-hooks.md` and `sbom.spdx.json`; the release workflow checked the same list for all four (`.github/workflows/release.yml:88`).
- Console assets: `smcpd` embeds the built console (`console/embed.go:13`, served through `internal/consoleapi/consoleapi.go:130`, attached in `cmd/smcpd/main.go:181`); there is no separate asset directory to ship.
- License notices: `LICENSE` in every archive (`.goreleaser.yaml:102`).
- SBOM: `sbom.spdx.json` in every archive (`.goreleaser.yaml:26`, `.goreleaser.yaml:105`), SPDX-2.3 with 51 packages: the Go modules of `go.mod` (for example `github.com/modelcontextprotocol/go-sdk@v1.8.0`, `aead.dev/minisign@v0.3.0`) and the console's npm packages (`react@19.3.1`, `@fontsource/ibm-plex-sans@5.3.0`).
- One checksum file `smcp_1.0.0-rc.2_checksums.txt` (`.goreleaser.yaml:113`) lists the four archives and their SBOM assets; every line verified.
- Signature: `smcp_1.0.0-rc.2_checksums.txt.minisig` (`.goreleaser.yaml:123`) verified with the key published at `SECURITY.md:33` ("Signature and comment signature verified", trusted comment `smcp 1.0.0-rc.2 file:smcp_1.0.0-rc.2_checksums.txt`). `install.sh` and `smcpctl upgrade` embed the same key (`cmd/smcpctl/release.go:23`).
- Installed binaries report the release version: `smcpd 1.0.0-rc.2`, `smcpctl 1.0.0-rc.2`, `smcp-stdio 1.0.0-rc.2`, `smcp-session 1.0.0-rc.2`, `smcp-connect 1.0.0-rc.2`.

Deviation: the inspected release is a pre-release candidate. v1.0.0 is built by the same workflow and configuration; the release checklist repeats this inspection for it.

## SR-2.13-1 Vault encryption

| Field | Content |
|---|---|
| Requirement or scenario | SR-2.13-1 |
| Commit | `e0a7b06c05ef4cf6d828c5352fdb9c13599d04a0` |
| Profile and platform | Not profile-specific; darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (partials sweep, E-19 to E-22) |
| Method | Inspection |
| Result | pass |

Steps: read the vault's encryption and key-source code; ran `go test ./internal/secrets -run 'TestVaultRecordIsEncryptedWithAge|TestVaultUnlockFailures' -v` (both pass), which creates and rotates a secret in a passphrase vault and reads the store and master-key files back.

Observations:

- The master key is an age X25519 identity generated at vault creation (`internal/secrets/vault.go:194`); only its recipient is written to the store.
- Every secret version is encrypted with `age.Encrypt` to that recipient before it is stored (`internal/secrets/vault.go:367`); the stored record holds only the ciphertext (`internal/secrets/vault.go:106`). The test finds no plaintext and the `age-encryption.org/v1` header on every version (`internal/secrets/vault_test.go:86`).
- Key sources: the passphrase source wraps the identity with an age scrypt recipient (`internal/secrets/keysource.go:161`), and the test finds the master-key file age-encrypted with no `AGE-SECRET-KEY` text; the Keychain source stores it with `security add-generic-password` (`internal/secrets/keysource.go:108`).

Deviation: none against the narrowed statement (the master key is held by the vault's key sources, not by the files of `internal/keys`; SRS rationale).

## SR-2.3-1 Bearer key generation

| Field | Content |
|---|---|
| Requirement or scenario | SR-2.3-1 |
| Commit | `e0a7b06c05ef4cf6d828c5352fdb9c13599d04a0` |
| Profile and platform | Not profile-specific; darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (partials sweep, E-19 to E-22) |
| Method | Inspection |
| Result | pass |

Steps: searched `internal` and `cmd` for every place a token, code, secret or bearer key is generated (`ids.Secret`, `rand.Read`) and stored; ran `go test ./cmd/smcpctl -run TestUDSKey` and `go test ./internal/session -run TestAuthenticateAndLifetimes` (pass).

Observations:

- One generator: `ids.Secret` returns 32 bytes (256 bits) from `crypto/rand` (`internal/ids/ids.go:24`).
- Session, access and refresh tokens: `ids.Secret` (`internal/session/session.go:312`); the table keeps only their SHA-256 hashes (`internal/session/session.go:306`, lookup `internal/session/session.go:371`, rotation `internal/session/session.go:406`).
- Authorization codes: `ids.Secret` (`internal/session/oauth.go:399`), stored under their SHA-256 hash (`internal/session/oauth.go:411`); the remote listener does the same (`internal/remote/oauth.go:590`).
- Client secrets: `ids.Secret` with an Argon2id verifier for credentials issued in G-11 (`internal/principals/principals.go:291`, `internal/principals/principals.go:292`) and for approved registrations (`internal/remote/oauth.go:338`, `internal/remote/oauth.go:342`).
- UDS bearer keys: `smcpctl uds key` generates them with `ids.Secret` and prints only the Argon2id verifier for `key_hash` (`cmd/smcpctl/udskey.go:31`, `cmd/smcpctl/udskey.go:32`); the listener verifies against that hash (`internal/edge/uds.go:275`).

Deviation: none against the narrowed statement (Argon2id rather than SHA-256 for client secrets and UDS keys; SRS rationale).

## FR-7.8 Key purposes

| Field | Content |
|---|---|
| Requirement or scenario | FR-7.8 |
| Commit | `e0a7b06c05ef4cf6d828c5352fdb9c13599d04a0` |
| Profile and platform | Not profile-specific; darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (partials sweep, E-19 to E-22) |
| Method | Inspection |
| Result | pass |

Steps: listed every key the Gateway generates or loads (searched for `GenerateKey`, `GenerateX25519Identity`, `rand.Read` into key buffers, `NewScryptRecipient` and password files) and checked that each is used for one purpose only.

Observations:

- Server CA: a P-256 key of its own (`internal/keys/keys.go:170`). Server TLS: a separate P-256 key signed by the CA (`internal/keys/keys.go:252`).
- Policy signing: an Ed25519 key in `keys/policy.key` (`internal/policystore/store.go:50`, generated at `internal/policystore/store.go:191`).
- Evidence signing: a separate Ed25519 key (`internal/keys/keys.go:405`), replaced at rotation by a new one (`internal/keys/rotate.go:311`).
- Vault master: an age X25519 identity (`internal/secrets/vault.go:194`).
- Backup encryption: the operator's passphrase (scrypt) or age recipients (`internal/backup/backup.go:72`, `internal/backup/backup.go:80`); no Gateway key is used.
- Cursor protection: a random 32-byte key per process (`internal/edge/edge.go:245`).
- Leak-fingerprint keying: random per-process keys in the inspector and the broker (`internal/filters/fingerprints.go:42`, `internal/secrets/fingerprint.go:69`).
- Research pseudonymization: a new key per dataset (`internal/research/export.go:103`).
- Data Server credentials: the graph engine password file (`internal/graph/mirror.go:23`).
- No key appears in more than one of these uses: each is generated in, and read only by, the code listed.

Deviation: none against the narrowed statement (no client CA, MRTR or payload-encryption key in release 1.0; SRS rationale).

## SR-1.1-1 Single policy source

| Field | Content |
|---|---|
| Requirement or scenario | SR-1.1-1 |
| Commit | `39e7e703c7e7251d8453f66a17f0b9536af3b33e` |
| Profile and platform | Not profile-specific; source inspected on darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (partial claims sweep, E-05 to E-18) |
| Method | Inspection |
| Result | pass |

Steps: read every path by which a snapshot reaches the Policy Decision Service and every input of a decision; listed the packages the decision path imports with `go list -deps ./internal/policy ./internal/policystore ./internal/policyadmin ./internal/edge` and searched the policy packages for environment reads.

Observations:

- At start the only snapshot source is `policyadmin.Load` (`internal/app/app.go:179`): it returns the active revision of the signed Policy Store, and reads the policy file only when the store has no active revision, importing it as the first signed revision before use (`internal/policyadmin/service.go:84`). The decider is created from that snapshot (`internal/app/app.go:291`).
- At run time the snapshot changes only through `Gateway.ActivatePolicy` (`internal/edge/edge.go:501`), which ends in `Decider.Replace` (`internal/edge/edge.go:526`, `internal/policy/policy.go:667`). Its callers are the Policy Administration Service after it stored, signed and activated a revision (`internal/policyadmin/service.go:234`) and the `policy/reload` route of the control API (`internal/adminapi/adminapi.go:460`), whose controller is the same service: the reloaded file is published through the store (`internal/policyadmin/service.go:172`). `Decider.Activate` (`internal/policy/policy.go:658`) has no caller outside tests.
- A decision reads the snapshot, the request built by the edge, rate and quota counters and the session's taint mark (`internal/policy/policy.go:742`). The obligation context set at `internal/app/app.go:293` adds the observation objects, size and time bounds, egress and secret grants and runtime profile in force as obligations; it supplies no permit, deny or route rule and no rule filter.
- None of `internal/policy`, `internal/policystore`, `internal/policyadmin` and `internal/edge` imports `internal/graph` (the `go list -deps` output has no graph package), so no edit to the graph mirror can reach a decision. No `os.Getenv` or `os.LookupEnv` call exists in the three policy packages.

Deviation: none. The audit and observation settings and the mandatory filters are kept outside the policy document in release 1.0, as the SR-1.1-1 rationale states.

## FR-5.9 Launch specification

| Field | Content |
|---|---|
| Requirement or scenario | FR-5.9 |
| Commit | `39e7e703c7e7251d8453f66a17f0b9536af3b33e` |
| Profile and platform | Standalone host, darwin/arm64; launch specification generated for the Podman launcher (`[runtime] sandbox = "podman"`) |
| Date | 2026-10-17 |
| Executor | Claude Code agent (partial claims sweep, E-05 to E-18) |
| Method | Inspection |
| Result | pass |

Steps: built `smcpctl` and `smcp-refserver` from the commit, ran `smcpctl bootstrap` (which packages, signs, imports and enables the reference server `smcp-ref-filesystem` with its `root` slot bound to the instance's `sandbox` directory), added `[runtime] sandbox = "podman"` and a `[[runtime.server]]` entry for `ref` granting that directory, ran `smcpctl runtime spec` (`cmd/smcpctl/runtime.go:129`), and compared the printed launch specification with the revision's signed manifest (`state/packages/revisions/smcp-ref-filesystem/<revision>/manifest.json`) and the Runtime Profile defaults.

Observations:

- Artifact digest: `sha256:86eb3e6b…aefd0`, equal to the manifest's `artifact.sha256`; the command is the unpacked artifact under `state/packages/unpacked/<sha256>/` (resolved from the enabled revision, `internal/library/runtime.go:161`), mounted read-only at `/smcp/bin/smcp-refserver` (`internal/sandbox/spec.go:341`).
- Argument vector: `/smcp/bin/smcp-refserver --root <sandbox dir>`, the manifest's `launch.argv` `["smcp-refserver", "--root", "{root}"]` with the `root` slot substituted.
- Environment allowlist: `env_names` empty; the manifest declares no environment variables and no secret slot, and the specification lists names only (`internal/sandbox/spec.go:407`).
- Mounts: the executable (read-only) and the granted `root` directory, read-only, as the manifest's `capabilities.filesystem` slot `root` mode `ro` and the `[[runtime.server.mount]]` grant state (`internal/sandbox/spec.go:373`).
- Network attachment: `none`; the manifest declares no egress and the Runtime Profile entry requests none.
- Resource limits: memory 536870912 bytes, 1 CPU, 128 PIDs, 64 MiB tmpfs, 1024 open files: the Runtime Profile defaults (CP-24), chosen per field from the server entry or the profile (`internal/sandbox/spec.go:288`).
- Sandbox profile: read-only root, no new privileges, all capabilities dropped, default seccomp, `userns=auto:size=2048`, user `1000:1000`, `allow_spawn` false because the manifest declares `spawns_processes` false (`internal/sandbox/spec.go:298`), deviation action `alert`.
- The Podman argument vector printed with it carries the same values (`--read-only`, `--cap-drop=all`, `--network=none`, `--memory=536870912`, `--pids-limit=128`, the two `--mount` options).

Deviation: none. The specification was generated without starting a container; the Linux integration test `TestIntegrationSandboxConfinesServer` inspects the effective configuration of a running one.

## SR-2.13-2 Plaintext lifetime

| Field | Content |
|---|---|
| Requirement or scenario | SR-2.13-2 |
| Commit | `bc3e25ad60133c5e89694c8373cda59d8dba8a54` |
| Profile and platform | Not profile-specific; darwin/arm64 (source inspection and `go test ./internal/secrets ./internal/filters`) |
| Date | 2026-10-17 |
| Executor | Claude Code agent (security-final task) |
| Method | Inspection |
| Result | pass |

Steps: read every path from the vault's decryption to the end of a delivery (launch-time S1, S3 and S4 in `Resolve`, redelivery after rotation, per-call S2) and every consumer of a delivered value (the broker's own leak fingerprints, the inspector's fingerprint set, the Egress Broker's S1 grant), listing each byte buffer that holds a decrypted value or an encoding of one and each immutable copy; ran `TestDeliveryBuffersOverwritten` and `TestRegisterBytesForms`.

Observations:

- The vault decrypts into one buffer sized from the ciphertext, so no growing copy is made, and overwrites it on every error path (`internal/secrets/vault.go:388`, `internal/secrets/vault.go:397`, `internal/secrets/vault.go:401`). The value lives only in memory; nothing writes it to the vault files or logs.
- Launch-time delivery overwrites the decrypted value when the delivery returns (`internal/secrets/broker.go:424`); redelivery after rotation does the same (`internal/secrets/broker.go:588`), and per-call S2 delivery overwrites it after the call file is written and on the suspension path (`internal/secrets/filters.go:206`, `internal/secrets/filters.go:211`). `TestDeliveryBuffersOverwritten` keeps the buffers handed to the fingerprint sinks and finds them all zeros after `Resolve` returns.
- The broker's leak fingerprints keep only keyed HMACs and overwrite the encoded forms they build (`internal/secrets/fingerprint.go:154`).
- The inspector's fingerprint set now receives the broker's byte slice (`internal/app/app.go:262`) and builds the Base64, hex and URL-encoded forms in buffers it overwrites after hashing (`internal/filters/fingerprints.go:118`, `internal/filters/fingerprints.go:127`, `internal/filters/fingerprints.go:130`); before this change it took a string and built the forms as strings, leaving nine immutable copies per delivered value. `TestRegisterBytesForms` checks the forms and that they are overwritten.
- S1: the broker hands the Egress Broker a copy of the value (`internal/secrets/broker.go:466`), which the Egress Broker overwrites when the grant is replaced or withdrawn (`internal/egress/inject.go:85`, `internal/egress/inject.go:97`); the test checks it is all zeros after teardown.
- The only immutable copy the Secret Broker makes is the S4 environment string (`internal/secrets/broker.go:444`), which the statement allows.

Deviation: as the narrowed statement records, three copies outside the Secret Broker's byte buffers cannot be overwritten in Go: the `NAME=value` entry built for the child process (`internal/pipeline/launch.go:147`) and the runtime's copy at process start, the header string the Egress Broker sets on each S1 request (`internal/egress/inject.go:129`), and the age library's internal decryption buffers. S3 files are removed at teardown (`internal/secrets/broker.go:752` writes them owner-only) but their blocks are not overwritten on disk. No memory snapshot was taken: the garbage collector does not clear freed memory, so a snapshot cannot show the absence of stale copies; the statement no longer asks for one.

## FR-14.5 Provenance statements of the reference packages

| Field | Content |
|---|---|
| Requirement or scenario | FR-14.5 |
| Commit | `1ff838b8305f73af5234cb2c61a4ad6fac353909` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64, Node 22.23.1, Python 3.11.15 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Method | Inspection |
| Result | pass |

Steps: built the four reference packages from their recipes with `SMCP_PYTHON=python3.11 scripts/build-reference-packages.sh <dir>` (19:07Z; build, test-key signature, import, enable and one tool call each, all `PASS`; journal `OK: 1 segments, 47 events`), then read each package's `provenance.json`, `manifest.json` and `index.json`, recomputed the SHA-256 of the artifact and of the provenance file, downloaded each source reference from its registry and recomputed its SHA-256, and read the license files and metadata in the sources.

Observations:

| Package | Source reference (kind, digest) | Licenses | Artifact digest in the statement | Recomputed |
|---|---|---|---|---|
| `mcp-filesystem@2026.8.31` | `registry-tarball` `https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/-/server-filesystem-2026.8.31.tgz`, `a239da27...491b1a` | `Apache-2.0`, `MIT` | `a8d56c56...983fca` | artifact equal; source download equal |
| `mcp-memory@2026.8.31` | `registry-tarball` `.../server-memory-2026.8.31.tgz`, `53a606a0...eb504c` | `Apache-2.0`, `MIT` | `6d2c786b...ddbca65` | artifact equal; source download equal |
| `mcp-git@2026.8.18` | `sdist` `https://files.pythonhosted.org/.../mcp_server_git-2026.8.18.tar.gz`, `96894ca6...08f173f` | `MIT` | `c3d47d2a...12d9c86c` | artifact equal; source download equal |
| `mcp-fetch@2026.8.18` | `sdist` `.../mcp_server_fetch-2026.8.18.tar.gz`, `da12533c...b7254` | `MIT` | `84e62b7d...640ab9a` | artifact equal; source download equal |

- The statement is written by `smcpctl package build` with the source reference, the licenses and the artifact (`internal/packaging/build.go:255`); its SHA-256 is recorded in the manifest (`internal/packaging/build.go:265`) and in the index that the test key signs (`internal/packaging/build.go:289`). For each package the recomputed SHA-256 of `provenance.json` equals the manifest's `statement_sha256` and the index's `provenance.sha256` (for example memory `af5c2cb1db13b5c47b836a08e67055fe28927c33feff339299784dcb5aec3b5f`), so the signature over the index covers the binding.
- Verification refuses a statement without a source reference, a 64-hex source digest or license identifiers (`internal/packaging/index.go:233`).
- License identifiers: the git and fetch sdists contain an MIT `LICENSE` and `License: MIT` in `PKG-INFO`. The filesystem and memory npm tarballs contain no license file; their `package.json` says `SEE LICENSE IN LICENSE`, and the `LICENSE` of `github.com/modelcontextprotocol/servers` states a transition from MIT to Apache-2.0 with code under both. The recipes listed only `MIT`; commit `1ff838b` lists `Apache-2.0` and `MIT` with an operator note (`packaging/reference/filesystem/recipe.json:42`, `packaging/reference/memory/recipe.json:45`), and the packages above were built after that change.

Deviation: the packages were built on a workstation, not by the `reference-packages` workflow of a release tag; the workflow's last successful run (39047692294, 2026-10-17, branch `test/partials-a`) produced statements of the same form, with `MIT` alone for filesystem and memory. The commit above is on branch `docs/verification-records` before it was squash-merged.

## FR-3.18 Approval evidence in G-13 for an anomaly-obligated approval

| Field | Content |
|---|---|
| Requirement or scenario | FR-3.18 |
| Commit | `771cadc7fcb24d18f21215615cebcaf8f5e0d364` |
| Profile and platform | Standalone; macOS 26.6.2, darwin/arm64; console in Playwright Chromium 1.64.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification records task) |
| Method | Inspection |
| Result | pass |

Steps (19:26:12Z to 19:26:49Z):

1. Bootstrapped a fresh instance (`smcpctl bootstrap --dir inst3 --port 28673 --admin-port 28674 --notify off ...`) and appended to `smcp.toml`: `[limits] principal_calls_per_minute = 100000`; `[observation] sampling_rate = 1.0`, `scoring = "sync"`, `require_approval_band = "abnormal"`, `withhold_band = "off"`; `[observation.baseline] n_min = 20`, `snapshot_records = 0`, `snapshot_interval = "1000h"`; features `request_bytes` and `response_bytes` with `transform = "log1p"`, `sigma_floor = 0.05`. `smcpctl config validate`: `configuration OK`.
2. Started `smcpd` and made 40 `ref_echo` calls with `{"text":"v000"}` in one session (`itest-client ... -call ref_echo -repeat 40`); `smcpctl observe status`: `assembled 40 captured 40`, `contexts 1 characterized 1`.
3. `smcpctl observe baseline build` (snapshot `01a14b54-4782-78e9-848f-99fd5724ac42`, 40 records, context `principal=claude-code-local|tool=echo`), then `smcpctl observe baseline promote 01a14b54-4782-78e9-848f-99fd5724ac42`.
4. Called `ref_echo` with a 50,000-character text. The call was held: the journal recorded `APPROVAL_REQUESTED` for approval `01a14b54-48b8-7bd3-9de0-810da8683185` (`hold_seconds` 120). The template `read-only` has no approval rule for `echo`, so the hold came from the anomaly obligation.
5. Opened `https://127.0.0.1:28674/approvals/01a14b54-48b8-7bd3-9de0-810da8683185` in the console as the administrator and read the view; then denied the approval (`smcpctl approvals deny ... --yes`), and the held call ended with `approval denied: A person reviewing this call denied it.`

Observations (the G-13 approval view, as displayed):

| Item the requirement lists | Displayed | Source |
|---|---|---|
| Public tool name | `Public tool: ref_echo` | `console/src/views/Approvals.tsx:136` |
| Server revision | `Server revision: smcp-ref-filesystem@0.0.0-dev+9c2c3169cf1c` (and `Tool revision: .../echo`) | `console/src/views/Approvals.tsx:138` |
| Canonical arguments | `Arguments (canonical, as the server will receive them)` with `{"text": "BBBB..."}`, and `Argument digest: sha256:80ec57db...` | `console/src/views/Approvals.tsx:167` |
| Decisive rules | `Decisive rules: ro-ref` | `console/src/views/Approvals.tsx:142` |
| Anomaly band | `Anomaly band: critical` | `console/src/views/Approvals.tsx:149` |
| Contributing feature | `Contributing feature: request_bytes` | `console/src/views/Approvals.tsx:152` |
| z-score | `z-score: 160.95` (and `Baseline snapshot: 01a14b54-4782-...`) | `console/src/views/Approvals.tsx:153` |

The Approval Service supplies the anomaly evidence with the approval record (`internal/approval/record.go:66`); `GET /api/v1/approvals/{id}` returned `"anomaly": {"band": "critical", "context": "principal=claude-code-local|tool=echo", "contributing_feature": "request_bytes", "snapshot_id": "01a14b54-4782-78e9-848f-99fd5724ac42", "z_score": 160.94859066750217}`.

Deviation: `smcpctl approvals show` printed `Anomaly  none reported` for this approval: the command printed that text for every approval. It now prints the band, feature, z-score and snapshot (`TestApprovalsShowAnomalyEvidence`); the requirement concerns the approval view, which displayed every item.

## FR-15.9 Cloud agent matrix record

| Field | Content |
|---|---|
| Requirement or scenario | FR-15.9 |
| Commit | `6078b21c5b5ee82df3f5fcde254ad266efe0ab12` |
| Profile and platform | Not profile-specific; documentation inspected on macOS 26.6.2, darwin/arm64 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (remote-agents partials task) |
| Method | Inspection |
| Result | pass |

Steps: read the `vendor-cloud` entries of `docs/clients/matrix.json` against FR-15.9 as changed on 2026-10-18 (live cloud-agent runs descoped from release 1.x; a `not-run` entry records its review date, documented modes and reason) and against Appendix K.2, which lists three cloud agents.

Observations:

| Agent | Entry | Result | Connection mode | Registration mode | Reviewed | Reason |
|---|---|---|---|---|---|---|
| Grok Bot (xAI) | `docs/clients/matrix.json:161` | `not-run` | remote-access (tunnel), fallback smcp-connect | dynamic registration with operator approval, or pre-registered | 2026-10-18 (`docs/clients/matrix.json:182`) | no vendor account; descoped (`docs/clients/matrix.json:183`) |
| ChatGPT agent (dots) (OpenAI) | `docs/clients/matrix.json:188` | `not-run` | remote-access (tunnel, including the vendor MCP tunnel where offered) | as above | 2026-10-18 (`docs/clients/matrix.json:209`) | as above (`docs/clients/matrix.json:210`) |
| Meta Muse (Meta) | `docs/clients/matrix.json:215` | `not-run` | remote-access (tunnel) | as above | 2026-10-18 (`docs/clients/matrix.json:236`) | as above |

- One entry per Appendix K.2 agent; no entry claims a run, so `lastRun`, `tunnelProvider` and `agentBuild` are null, which the matrix note explains (`docs/clients/matrix.json:4`).
- The quick start says the agents are documented but not live-tested (`docs/clients/cloud-agents.md:5`).
- `docs.TestCloudAgentEntries` (`docs/clients_test.go:18`) keeps every cloud entry in one of the two accepted forms.

Deviation: none from the changed statement. No cloud agent has been connected; the support claim rests on the tests against a local test tunnel named in each reason.

## FR-16.10 Vendor allowlist guidance

| Field | Content |
|---|---|
| Requirement or scenario | FR-16.10 |
| Commit | `6078b21c5b5ee82df3f5fcde254ad266efe0ab12` |
| Profile and platform | Not profile-specific; documentation inspected on macOS 26.6.2, darwin/arm64 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (remote-agents partials task) |
| Method | Inspection |
| Result | pass |

Steps: on 2026-10-18 searched the vendors' public documentation for an administrator setting that restricts each cloud agent's MCP servers to one URL (xAI developer documentation, OpenAI help center, Meta developer documentation, and third-party guides found by web search), wrote the result into each agent's section of the quick start, then read each section against FR-16.10 as changed on 2026-10-18.

Observations:

| Agent | Quick start line | Setting | Date checked | Sources |
|---|---|---|---|---|
| Grok Bot | `docs/clients/cloud-agents.md:31` | none confirmed in xAI documentation (per-request `allowed_tools` only; a team allowlist described only by a third-party guide) | 2026-10-18 | docs.x.ai remote MCP page, composio.dev guide |
| ChatGPT | `docs/clients/cloud-agents.md:38` | none that limits connectors to one URL confirmed; workspace controls over who creates and publishes custom MCP apps described, with the nearest restriction stated | 2026-10-18 | OpenAI help article (search excerpt; page returned HTTP 403), two third-party administrator guides |
| Meta Muse | `docs/clients/cloud-agents.md:45` | none found | 2026-10-18 | Meta developer MCP page, two third-party guides |

- The introduction states that vendor administration consoles were not reachable and that the lines report public documentation (`docs/clients/cloud-agents.md:7`).

Deviation: the OpenAI primary page could not be read in full (HTTP 403); its content is taken from the search excerpt, and the line says so.

## FR-12.1 Open-source components (v1.1.0)

| Field | Content |
|---|---|
| Requirement or scenario | FR-12.1 |
| Commit | `935dc4d0849e118ccb3f033cd577a5e34875e101` |
| Profile and platform | Not profile-specific; the GitHub Release v1.1.0, inspected on macOS 26.6.2, darwin/arm64 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 release task) |
| Method | Inspection |
| Result | pass |

Steps: v1.1.0 was tagged on main `935dc4d` and published by the release workflow (run 39178207151), which ran its SBOM license check (`.github/workflows/release.yml:116`) and passed. Downloaded every asset with `gh release download v1.1.0 -R ethan03805/Secure-MCP-Gateway`, checked the minisign signature and the checksums, unpacked the four archives, and ran `go run ./tools/sbomcheck -review packaging/sbom-review.json <linux_amd64>/sbom.spdx.json smcp_1.1.0_*.tar.gz.sbom.json` locally. Then read the license fields of every SBOM entry (`licenseConcluded`, `licenseDeclared`) with a short script.

Observations:

- The SBOM inside the archives (`sbom.spdx.json`, SPDX-2.3, written by `scripts/release-sbom.sh:36` with the module license search on) is the same file in all four archives (SHA-256 `e17002f1...`). It has 51 entries. 44 Go modules carry a concluded license: BSD-3-Clause 19, MIT 16, Apache-2.0 4, BSD-2-Clause 1, and four compound expressions of these. The five npm packages carry a declared license (`react`, `react-dom` and `scheduler` MIT; `@fontsource/ibm-plex-sans` and `@fontsource/ibm-plex-mono` OFL-1.1), as does the console package itself. The only entry without a license is `smcp` 1.1.0, the document's subject (the scanned source), not a component. `tools/sbomcheck`: 50 packages accepted, 0 refused.
- The per-archive SBOMs (`smcp_1.1.0_<os>_<arch>.tar.gz.sbom.json`, syft over each archive, `.goreleaser.yaml:144`) have 129 entries (darwin) and 135 (linux): the Go modules compiled into each binary, once per binary. Every entry carries a license except the archive itself (the document's subject). `tools/sbomcheck`: 128 and 134 packages accepted per archive, 0 refused.
- Every license is OSI-approved (`tools/sbomcheck/main.go:39`) or one of the reviewed exceptions in `packaging/sbom-review.json`, each matching the module's own license files: the CC-BY-4.0 documentation license of `github.com/modelcontextprotocol/go-sdk` (`packaging/sbom-review.json:5`), the vendored MCP specification's LICENSE and a test file that syft takes for a NOTICE file in the Gateway's own module (`packaging/sbom-review.json:11`, `packaging/sbom-review.json:17`), and the NOTICE.txt of `github.com/apache/arrow-go/v18` (`packaging/sbom-review.json:23`). None needs a non-OSI license.
- Compared with v1.0.0, whose inner SBOM had no license for 45 of its 50 entries, every component entry now has one.

Deviation: none for the release. The first candidate, v1.1.0-rc.1, failed this check because syft also took the review file itself (then `packaging/license-review.json`) for a license file of the Gateway's module; it was renamed (PR #121) before v1.1.0-rc.2 and v1.1.0.

## FR-12.8 Release provenance (v1.1.0)

| Field | Content |
|---|---|
| Requirement or scenario | FR-12.8 |
| Commit | `935dc4d0849e118ccb3f033cd577a5e34875e101` |
| Profile and platform | Not profile-specific; the GitHub Release v1.1.0, inspected on macOS 26.6.2, darwin/arm64 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 release task) |
| Method | Inspection |
| Result | pass |

Steps: downloaded the v1.1.0 assets (release run 39178207151), verified the checksum file with minisign against the key in `SECURITY.md:33` and with cosign against the release workflow identity, checked every SHA-256, unpacked the four archives, compared the recipe and lockfiles in the archive with the files at the tag (`git show v1.1.0:<path> | shasum -a 256`), read `PROVENANCE.md` and `THIRD_PARTY_NOTICES.txt`, and ran `go version -m` on `smcpd`.

Observations, for each item of the statement:

- Source commit IDs: `PROVENANCE.md` names source commit `935dc4d0849e118ccb3f033cd577a5e34875e101`, its date, the Go toolchain go1.26.9 and the build run (`tools/provenance/main.go:284`). The release workflow refuses an archive whose `PROVENANCE.md` names another commit (`.github/workflows/release.yml:112`). `smcpd` records `vcs.revision=935dc4d0849e118ccb3f033cd577a5e34875e101` and `vcs.modified=false`. The tag v1.1.0 and the Sigstore certificate name the same commit.
- Artifact digests: `smcp_1.1.0_checksums.txt` (`.goreleaser.yaml:138`) lists the SHA-256 of the four archives and their SBOMs; every line verified. It is signed with minisign (`.goreleaser.yaml:149`; "Signature and comment signature verified") and by cosign keyless ("Verified OK"). `PROVENANCE.md` lists the SHA-256 of each recipe file and lockfile in the archive.
- Build recipes: `.goreleaser.yaml` and `scripts/release-sbom.sh` are in every archive (`.goreleaser.yaml:128`, `.goreleaser.yaml:129`), byte-identical to the tag, and `PROVENANCE.md` says how to rebuild from them.
- Dependency lockfiles: `go.mod`, `go.sum` and `console/package-lock.json` are in every archive (`.goreleaser.yaml:130` to `.goreleaser.yaml:132`), byte-identical to the tag.
- SBOM: `sbom.spdx.json` (SPDX-2.3) in every archive and an SPDX SBOM per archive as a release asset (see the FR-12.1 record above).
- License notices: `LICENSE` (Apache-2.0, `.goreleaser.yaml:116`) and `THIRD_PARTY_NOTICES.txt` (`tools/provenance/main.go:80`, 1,873 lines) in every archive. The notices hold the license files of the Go standard library, the 23 Go modules linked into the binaries and the five bundled console npm packages, unchanged. Each archive is checked for all these files by the release workflow (`.github/workflows/release.yml:95`).

Deviation: none. v1.0.0 lacked the recipe, the lockfiles and the notices; v1.1.0 is the first release built by the fixed pipeline.

## FR-13.1 Release archives (v1.1.0)

| Field | Content |
|---|---|
| Requirement or scenario | FR-13.1 |
| Commit | `935dc4d0849e118ccb3f033cd577a5e34875e101` |
| Profile and platform | Not profile-specific; the GitHub Release v1.1.0, inspected on macOS 26.6.2, darwin/arm64 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (v1.1.0 release task) |
| Method | Inspection |
| Result | pass |

Steps: as for FR-12.8 above. In addition, `install.sh` without `--version` was run from `main` into an empty directory, and every installed binary was run with `--version` (`smcpctl version --short`).

Observations:

- Four archives, `smcp_1.1.0_darwin_arm64.tar.gz`, `_darwin_amd64`, `_linux_amd64` and `_linux_arm64` (`.goreleaser.yaml:106`). Each holds `smcpd`, `smcpctl`, `smcp-refserver`, `smcp-session`, `smcp-stdio`, `smcp-connect`, `smcp-workload`, `LICENSE`, `README.md`, `CHANGELOG.md`, the two ICDs, `sbom.spdx.json`, `PROVENANCE.md`, `THIRD_PARTY_NOTICES.txt`, the recipe and the lockfiles.
- The checksum file, its `.minisig` and `.sigstore.json`, the four per-archive SBOMs and `release-label.md` are published beside them. The release notes end with the label "enforced" (21 of 21 scenarios in the Enforced profile).
- `install.sh` resolved the latest release to v1.1.0, verified the minisign signature, the Sigstore bundle and the checksum, and installed six binaries. All six report `1.1.0`, including `smcp-refserver --version` (new in this release).
- `smcpctl upgrade` from v1.0.0 to the candidate v1.1.0-rc.2 (same commit) reported `release verified`, the backup, `upgrade complete` and version `1.1.0-rc.2`; the journal verified afterwards.

Deviation: none.
