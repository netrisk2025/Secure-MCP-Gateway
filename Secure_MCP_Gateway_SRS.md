# Secure MCP Gateway — Software Requirements Specification

| Field | Value |
|---|---|
| File | `Secure_MCP_Gateway_SRS.md` |
| Baseline | V1.2 draft (implementation SRS; re-baselined so that the product built as specified is a finished, shippable v1) |
| Date | 2026-10-16 (America/Chicago) |
| Owner | netrisk |
| System of Interest | Secure MCP Gateway (local, single computer) |
| Architecture | `ArchitectureV2.md` V2.3 draft — elements E-01…E-33, functions F-01…F-99, interfaces X-01…X-17 and I-01…I-39, GUI modules G-01…G-14, data stores D-01…D-15 |
| Security control root | `MCP_Gateway_Security_SRS.md` (V1 security-control baseline; cited as `SEC`) |
| Protocol baseline | MCP specification and schema 2026-07-28 (`mcp-spec/2026-07-28/`; cited as `MCP:` and `SCHEMA:`) |
| Skill | `Skills.md` (INCOSE GtWR + project rules) |
| Status | Draft. Implementation is in progress. This document does not state which requirements are met; the requirement report (FR-12.10) does, and `docs/status/elements.json` records the implementation state of each element. |

## Contents

1. Purpose, scope and intended use
2. Conventions and traceability rules
3. Recommended technology stack (open source only)
4. Functional requirements (FR-1 … FR-19)
5. Security requirements (SR, parented to `SEC` MUSTs)
6. Appendix A — Controlled parameters (CP)
7. Appendix B — Gateway error codes and reason codes
8. Appendix C — Application role matrix
9. Appendix D — Graph data model (mirror)
10. Appendix E — Security-control coverage (SEC → SR)
11. Appendix F — Allocation matrix (element → requirements)
12. Appendix G — Architecture coverage (functions, interfaces, data stores, GUI modules)
13. Appendix H — Requirement index
14. Appendix I — Requirement-set checks
15. Appendix J — Server package manifest schema
16. Appendix K — Client matrix
17. Appendix L — Hostile backend fixture suite
18. Appendix M — Acceptance scenarios and the enforced label
19. Appendix N — Requirements deferred from release 1.0

## 1. Purpose, scope and intended use

### 1.1 Purpose

This SRS is the **implementation baseline** for coding the Secure MCP Gateway. It states what each architectural element must do (functional requirements, **FR**) and which concrete security controls each element must enforce (security requirements, **SR**). Every requirement is allocated to an element, a function and, where one is crossed, an interface in `ArchitectureV2.md`, and every SR traces to a parent **MUST** in `MCP_Gateway_Security_SRS.md`.

Baseline V1.2 adds what a person needs to install, operate, upgrade and remove the product, admit servers without an external curation system, connect every supported agent (including agents that run on a vendor's cloud computer), approve calls, and judge from published evidence whether enforcement claims hold.

### 1.2 Intended use of the Gateway

Per the owner, the Gateway is a local secure MCP gateway on a single computer whose **primary purpose is research**. It is a vehicle for developing effective security policies, new run-time policies and longer-term trend-analysis techniques. That is why this SRS gives first-class functional weight to the policy studio and simulation, observation capture, behavior baselines, meta-metrics and dataset export, alongside enforcement.

### 1.3 Scope

**In scope:** all elements E-01…E-33 of `ArchitectureV2.md` and their interfaces, on the platforms of Section 1.6.

**Outside the SoI (interfaces only):** an external MCP Curation System, when one is used instead of the packaging command (X-02), package registries (X-17), agentic frameworks (X-12), tunnel providers (X-13), offline analytics tools (X-11), and the host platform (X-07). The reference harness adapters and harness tooling (E-33) and the packaging command (F-96) are inside the SoI and are delivered with the release.

**Out of scope for v1 (refused or not provided):**

| Item | Behavior in v1 |
|---|---|
| Remote (hosted) MCP servers as backends | Not supported. Every backend is a packaged local server launched by E-15. A manifest naming a remote URL as the server endpoint is rejected (FR-14.4). |
| MCP resources and prompts | Not served northbound and not requested southbound. The Gateway relays tools only (FR-1.11, SR-5.6-1). |
| Sampling, elicitation and roots | Refused unless the MRTR Relay Profile is enabled (Section 1.5). |
| Windows hosts | Not supported. |
| An agent's non-MCP native tools | Not mediated. Built-in shell, file, browser and connector tools of an agent bypass the Gateway; the lockdown profiles (FR-15) reduce this for local harnesses and the Security Limitations document (FR-18.2) states it. |
| Running the Gateway inside a vendor's cloud agent machine | Not a control and not supported; cloud agents use the Remote Access profile. |

### 1.4 Relationship to other documents

| Document | Role |
|---|---|
| `MCP_Gateway_Security_SRS.md` | **Root of security controls.** Its MUSTs parent the SRs in Section 5. Its SHALL roots 8, 9 and 10 are cited as sources of FRs. Its Appendices A and F supply controlled values and frozen semantics reused here. Its Appendix B acceptance scenarios are mapped in Appendix M. |
| `ArchitectureV2.md` | Element, function and interface definitions used for allocation. |
| `architecture.md` rev 2.0 | Problem-space analysis (cited as `A2`). |
| `Client-Compatibility-Brief.md` | Evidence for client hooks and the client matrix (cited as `CCB`). |
| `docs/` | Normative data files referenced by requirements: `docs/schemas/manifest.schema.json` (Appendix J), `docs/parameters.json` (Parameter Catalog, FR-10.37) and `docs/status/elements.json` (implementation state). |
| `mcp-spec/2026-07-28/` | Normative protocol text and schema. When this SRS and the MCP specification disagree on protocol behavior, the specification governs unless an SR intentionally restricts it. |

### 1.5 Profiles

A **platform profile** is always active; exactly one of the two applies to an installation. **Conditional profiles** are disabled in the baseline configuration and are enabled only after their requirements pass verification.

#### 1.5.1 Platform profiles

| Aspect | Enforced profile | Standalone (unconfined) profile |
|---|---|---|
| Platforms | Linux x86_64 or arm64, kernel 6.8 or later, cgroup v2, unprivileged user namespaces, rootless Podman with `crun`, nftables, systemd, AppArmor or SELinux, subordinate UID and GID ranges | macOS arm64 (macOS 14 or later); Linux x86_64 or arm64 without one or more Enforced prerequisites |
| Selection | `profile = "enforced"` in the configuration. The daemon refuses to start when a prerequisite is missing; it never falls back silently (FR-13.9). | `profile = "standalone"` in the configuration, written by the installer when Enforced prerequisites are absent or when the operator chooses it. |
| Backend execution | One rootless Podman container per instance under the E-16 sandbox profile; egress only through E-18 | Ordinary child process of the daemon with the environment allowlist (SR-2.14-1), a private working directory and the CP-24 resource limits the operating system supports; no namespace, LSM or network isolation |
| Server admission | All risk classes, subject to trust-anchor scope | Packages whose manifest risk class is `high` are refused at enablement (SR-4-1) |
| Egress | Default deny; E-18 mediates each operation | Not mediated; a server's network access is the host's |
| Service identities and layout | Distinct system identities; `/etc/smcp`, `/var/lib/smcp`, `/run/smcp`, `/var/log/smcp` (FR-12.4) | The installing user's identity; per-user directories (FR-12.4) |
| Service manager | systemd system units | launchd user agent (macOS); systemd user unit (Linux) |
| Health | `healthy`, `degraded` or `fail-closed` (FR-7.12) | Never `healthy`: at best `degraded` with cause `unconfined` (FR-13.10) |
| Release label | "enforced", only when the Appendix M acceptance evidence is complete and passing (FR-19.3); otherwise "not enforced" | "not enforced" in `smcpctl health`, `smcpctl version`, the console banner and the startup log (FR-13.10) |
| Controls that still hold | All | Authentication, sessions, policy decisions, catalog filtering, request and response inspection, approvals, session taint, the evidence journal, secret storage and delivery modes S2 to S4 |

#### 1.5.2 Conditional profiles

| Profile | Enables | Requirements |
|---|---|---|
| UDS Harness Profile | Unix-domain-socket harness transport | FR-1.47, FR-2.15, SR-2.8-3 |
| MRTR Relay Profile | Relaying backend `InputRequiredResult` (elicitation, sampling, roots). Deferred from release 1.0 (Appendix N); release 1.0 refuses such results with `-31010`. | FR-5.25 (deferred), SR-5.6-2 |
| mTLS Harness Profile | Client-certificate authentication on the TLS harness listener, in addition to the bearer token. Deferred from release 1.0 (Appendix N). | FR-2.14, SR-2.8-2 (both deferred) |
| Remote Access Profile | A second loopback listener reached only through an authenticated tunnel (Cloudflare Tunnel, Tailscale Funnel or a vendor MCP tunnel), operator-approved Dynamic Client Registration, remote rate limits and lockout, and the `smcp-connect` relay, for agents that run on a vendor's computer. It replaces the V1.1 Overlay Profile. | FR-16.1 to FR-16.12, SR-2.9-3, SR-2.11-2, SR-4.14-1, SR-4.14-2 |

### 1.6 Platform and distribution matrix

| Platform | Profile | Distribution | Service manager | Sandbox (E-16) | Egress broker (E-18) |
|---|---|---|---|---|---|
| macOS arm64 | Standalone | GitHub Releases archive, `install.sh`, Homebrew tap | launchd user agent | No | No |
| Linux x86_64 | Enforced, or Standalone when prerequisites are absent | GitHub Releases archive, `install.sh`, Homebrew tap | systemd (system units for Enforced, user unit for Standalone) | Enforced only | Enforced only |
| Linux arm64 | Enforced, or Standalone when prerequisites are absent | GitHub Releases archive, `install.sh`, Homebrew tap | systemd | Enforced only | Enforced only |
| macOS amd64 | Standalone (archive built; not part of the qualified set) | GitHub Releases archive | launchd user agent | No | No |

The continuous-integration qualification of the Enforced profile runs on GitHub-hosted Ubuntu runners. The supported client matrix is Appendix K.

## 2. Conventions and traceability rules

### 2.1 Imperatives

Imperatives follow `Skills.md` §2.2 and the owner's `Resource.md` (not in this repository). **SHALL** is binding and verified. **MUST** appears in this document only when quoting parent controls of `MCP_Gateway_Security_SRS.md`; it is never used as a requirement imperative here. Every requirement in this SRS is a **SHALL**.

> **Note on the parent document:** `MCP_Gateway_Security_SRS.md` writes some measurable leaf controls as MUST at the owner's earlier request. This SRS treats every MUST in that document as a parent control and realizes it with one or more SHALL children allocated to V2 elements.

### 2.2 Requirement IDs and parents

| Class | ID pattern | Parent | Example |
|---|---|---|---|
| Functional root | `FR-n` | none (root) | `FR-4` |
| Functional requirement | `FR-n.m` | `FR-n` | `FR-4.13` |
| Security requirement | `SR-<SEC id>-k` | `SEC-<SEC id>` — a MUST in `MCP_Gateway_Security_SRS.md` | `SR-1.18-2` is the 2nd child of SEC 1.18 |

IDs are stable. Later revisions retire IDs rather than reuse them.

### 2.3 Record fields

Every requirement record carries: **ID**, **Parent ID**, **Statement**, **Allocation** (element E-xx; function F-xx; interface X-xx/I-xx; data store D-xx where relevant), **Verification Method** (Inspection, Analysis, Demonstration or Test), **Verification Statement**, **Source** and **Rationale**.

### 2.4 Source citations

| Prefix | Meaning |
|---|---|
| `ARCH §x` | `ArchitectureV2.md` section x |
| `SEC n.n` | `MCP_Gateway_Security_SRS.md` requirement or appendix |
| `A2 §x` | `architecture.md` rev 2.0 section x |
| `CCB §x` | `Client-Compatibility-Brief.md` section x |
| `MCP:<page>` | `mcp-spec/2026-07-28/specification/<page>.mdx` |
| `SCHEMA:<type>` | `mcp-spec/2026-07-28/schema/schema.ts` type |
| `CP-nn` | Appendix A controlled parameter |
| `OWNER` | Owner direction in the tasking for this SRS, including the owner decisions of 2026-10-16 recorded in `CHANGELOG.md` |
| `REVIEW` | A gap found by the V1.1 completeness review and closed in V1.2 (`CHANGELOG.md`) |

### 2.5 Subjects

Each statement names its allocated element as the subject, for example *"The Session Manager (E-04) SHALL …"*. Requirements on the release, rather than on run-time behavior, name *"The Gateway release"* or the delivered command.

### 2.6 Verification claims

A requirement is **verified** only when at least one passing automated test claims it in full and no claiming test fails, or when its Inspection, Analysis or Demonstration record is checked in under `docs/verification/` and passes. A test that exercises part of a requirement claims it as **partial**. The requirement report lists verified, partial, failing and unverified requirements separately (FR-12.10). Nothing in this document is a claim that a requirement is met.

### 2.7 Deferred requirements

A requirement record that carries a deferral rationale is **deferred from release 1.0**. It keeps its ID and text, and Appendix N lists it with the reason it is deferred and what release 1.0 does instead. A deferred requirement is not part of the requirement set of release 1.0: Appendices E to I, the requirement report (FR-12.10) and the release label (FR-19.3) leave it out. No requirement of release 1.0 has a deferred parent. Deferring a requirement, or restoring one, is a controlled change recorded in `CHANGELOG.md`.

## 3. Recommended technology stack (open source only)

All selections carry OSI-approved licenses. Exact versions, digests and transitive licenses are frozen at qualification (FR-12.1, FR-12.8). License statements here describe the upstream projects and must be re-verified at the pinned version. The Gateway's own source is licensed Apache-2.0.

### 3.1 Selections

| Layer | Recommendation | License | Elements | Why |
|---|---|---|---|---|
| Host OS (Enforced profile) | Linux, kernel ≥ 6.8 (for example Ubuntu 24.04 LTS or Debian 13), x86_64 or arm64, with cgroup v2 and unprivileged user namespaces | GPL-2.0 | All, X-07 | Isolation primitives the Enforced profile relies on |
| Host OS (Standalone profile) | macOS 14 or later on arm64; Linux without the Enforced prerequisites | Proprietary (macOS); GPL-2.0 | All except E-16, E-18 network mediation | Owner decision: the product runs on the developer's own computer, labelled "not enforced" |
| Service management | systemd (Linux); launchd user agent (macOS) | LGPL-2.1+; part of macOS | All | Ordering, restart, sandboxing directives |
| Implementation language | **Go** 1.26 | BSD-3-Clause | E-01…E-33 except E-24 front end | One memory-safe language for the core; strong concurrency, static binaries |
| MCP protocol | Official MCP Go SDK (`modelcontextprotocol/go-sdk`) in stateless mode (Section 3.3, risk 1) | Apache-2.0 (with retained MIT notices) | E-02, E-10, E-33 | Serves both protocol eras on one handler |
| JSON Schema validation | `santhosh-tekuri/jsonschema` v6 | Apache-2.0 | E-05, E-09, E-11, E-13, E-14 | Supports 2020-12 and draft-07; no remote `$ref` by default |
| HTTP | Go `net/http` | BSD-3 | E-01, E-03, E-04, E-07, E-23, E-24 | Mature HTTP/1.1 and HTTP/2 with TLS 1.3 |
| Cryptography | Go `crypto/*` (TLS 1.3, Ed25519, HMAC-SHA-256), `golang.org/x/crypto/argon2` | BSD-3 | E-03, E-05, E-21, E-22, E-24 | Standard library primitives |
| Secret, payload and backup encryption | `filippo.io/age` | BSD-3 | E-19, E-21, E-28 | Simple, audited file encryption |
| TPM sealing | `google/go-tpm` | Apache-2.0 | E-22 | Hardware-backed key sealing where available |
| Package and release signatures | minisign format via `aead.dev/minisign` (OD-1 decided) | MIT | E-13, E-24 (installer) | Offline Ed25519 signatures with a small key format the operator can manage |
| Graph database (mirror, optional) | **Neo4j Community Edition** (pinned release) on an OpenJDK 21 build | GPL-3.0 (Neo4j CE); GPL-2.0 + Classpath Exception (OpenJDK) | E-25 | Owner-selected graph DB for graph views and the behavior model; not on the enforcement path (A-9) |
| Graph driver | Neo4j Go driver | Apache-2.0 | E-26 | Parameterized queries, managed transactions |
| Columnar Observation Store | **DuckDB** with Parquet files, via the official DuckDB Go driver | MIT | E-27 | Embedded, fast aggregation, native Parquet export |
| Statistics | `gonum` (stats), `influxdata/tdigest` (quantile sketches) | BSD-3 / Apache-2.0 | E-30, E-31 | Welford, transforms, robust statistics in Go |
| Internal tracing | OpenTelemetry Go SDK with an in-process exporter to E-29 (no network exporter) | Apache-2.0 | E-29, all instrumented | Standard span model; matches MCP `_meta` trace keys |
| Operational metrics | Prometheus text exposition format via `prometheus/client_golang` | Apache-2.0 | E-23 | Loopback scrape endpoint (X-15) |
| Sandbox | **Podman** (rootless) with `crun`, `conmon`, `netavark`; default seccomp; AppArmor or SELinux | Apache-2.0; GPL-2.0+ / LGPL-2.1+; GPL-2.0 | E-15, E-16 | Rootless OCI isolation without a privileged daemon socket |
| Network enforcement | nftables (via `google/nftables` Go library) | GPL-2.0 (nftables); Apache-2.0 (library) | E-16, E-18, E-25 | Per-identity and per-namespace rules |
| Desktop notification | macOS `osascript` or `terminal-notifier`; Linux `notify-send` (libnotify) | Part of macOS; MIT; LGPL-2.1+ | E-07 | Approval notices on the operator's desktop (X-14) |
| Tunnel connectors (Remote Access profile, operator-installed) | `cloudflared`; Tailscale client; a vendor MCP tunnel where the vendor offers one | Apache-2.0; BSD-3-Clause; vendor terms | X-13 | Reach a loopback listener from a vendor cloud without opening an inbound port. Not bundled with the release. |
| Configuration | TOML (`pelletier/go-toml` v2) validated by JSON Schema, with a `schema_version` field | MIT | All | Readable, schema-validated, versioned configuration |
| IDs | UUIDv7 (`google/uuid`) | BSD-3 | All | Time-ordered unique IDs |
| GUI | **React** + **TypeScript** + **Vite**, hand-built components (no component kit), TanStack Query | MIT; Apache-2.0; MIT; MIT | E-24 | Mainstream, local-bundled SPA with full control of density, typography and accessibility |
| Graph visualization | Cytoscape.js | MIT | E-24 (G-05, G-14) | Bounded graph rendering |
| Charts | Apache ECharts | Apache-2.0 | E-24 (G-05, G-07, G-08) | Distributions, timelines, heatmaps |
| API contract | OpenAPI 3.1; `oapi-codegen` (Go), `openapi-typescript` (TS) | Apache-2.0 / MIT | E-24 | Generated, consistent client and server |
| Testing | Go `testing`; Playwright (GUI end-to-end and accessibility with `axe-core`); `vegeta` (load) | BSD-3; Apache-2.0; MPL-2.0; MIT | All | Requirement-tagged automated verification (FR-12.10) |
| Supply chain | Syft (SBOM), Grype and `govulncheck` (vulnerabilities), minisign (release signing) | Apache-2.0; Apache-2.0; BSD-3; ISC | Release | FR-12.8 provenance |
| Distribution | GitHub Releases, `install.sh`, a Homebrew tap | — | Release | Owner decision (FR-13) |

### 3.2 Explicitly excluded

| Excluded | Reason |
|---|---|
| Neo4j Enterprise, Aura, APOC/GDS plugins | Paid, cloud or unnecessary attack surface (SEC 9.2, SR-7.4-1) |
| Memgraph, FalkorDB | Licenses are source-available rather than OSI-approved (verify at evaluation; ARCH OD-4) |
| HashiCorp Vault | Business Source License (not OSI-approved); OpenBao (MPL-2.0) remains a future option |
| Docker Desktop | Proprietary distribution terms; privileged daemon socket model |
| Mantine and other component kits | Owner decision: console components are hand-built |
| External telemetry, SaaS logging or hosted identity | Violates local, offline baseline (FR-12.2) |

### 3.3 Stack risks to retire in the first prototype phase

1. **MCP SDK revision support.** *Retired 2026-10-16.* The 2026-07-28 revision removed `initialize`, sessions and the GET stream. The spike in `spikes/go-sdk-dual-era/` shows that `modelcontextprotocol/go-sdk` v1.8.0 serves both eras on one `StreamableHTTPHandler` when `Stateless` is set: 2026-07-28 `server/discover`, `tools/list`, `tools/call` and `subscriptions/listen` (with `notifications/tools/list_changed` delivered on the listen stream) and 2025-11-25 `initialize`, `notifications/initialized`, `tools/list` and `tools/call`, with an `initialize` naming an older version answered with `2025-11-25` as FR-1.17 requires. In the default stateful mode the handler rejects every 2026-07-28 request, so the Gateway uses stateless mode. Legacy clients receive no `Mcp-Session-Id`, which revision 2025-11-25 permits; FR-1.46 is worded accordingly. The SDK's default `cacheScope`, `ttlMs` and `logging` capability must be overridden to meet FR-1.12, FR-1.13 and FR-1.42.
2. **Journal flush latency.** *Replaces the V1.1 Neo4j write-throughput risk*, which no longer applies because the graph is off the enforcement path (A-9). SR-6.2-1 and SR-6.3-1 put two flushes to stable storage on every call. Measure them on the reference hosts at the FR-11 load. If the CP-32 overhead target is missed, use group commit: concurrent intents share one flush, and no capability is issued before the flush that covers its intent returns.
3. **Rootless Podman start latency.** Measure per-session instance cold start. If it is excessive, prefer the `shared` scope for stateless, read-only servers (ARCH OD-3).
4. **No containment on macOS.** The Standalone profile has no sandbox. This is accepted by the owner and stated in the Security Limitations document (FR-18.2); it is not a risk to retire but a limit to keep visible.
5. **Cloud agent vendor features.** Whether Grok Bot, ChatGPT "dots" and Meta Muse offer an admin MCP allowlist, Dynamic Client Registration or a command-launched relay is recorded per version in Appendix K and confirmed by the client matrix runs (FR-15.8). Any feature a vendor lacks is listed as a limitation rather than assumed.

## 4. Functional requirements (FR)

Functional requirements make the Gateway work. Each is allocated to the element that implements it, the function it realizes and the interface it uses. Security controls that realize a **MUST** in `MCP_Gateway_Security_SRS.md` are in Section 5, not here, even when they act on the same element.

### FR-1 Harness Edge and northbound MCP server

#### FR-1 — Northbound MCP server

| Field | Value |
|---|---|
| ID | FR-1 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** provide an MCP 2026-07-28 server interface to authenticated harness adapters through the Harness Edge subsystem (SS-1). |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-02 Protocol Mediator; Functions: F-01, F-02, F-03, F-22; External interfaces: X-01 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-1 child requirement; confirm each has passed. |
| Source | ARCH §2.1 item 2; ARCH §4 SS-1; MCP:basic/index |
| Rationale | Harness adapters reach the Gateway only through this interface, so it must be a conforming MCP server. |

#### FR-1.1 — Harness listeners

| Field | Value |
|---|---|
| ID | FR-1.1 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** accept harness connections only on the TLS TCP listener and the optional Unix-domain-socket listener configured by CP-02. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-01; Internal interfaces: I-01 |
| Verification Method | Test |
| Verification Statement | Enumerate listening sockets owned by the Gateway service identity; confirm only the CP-02 harness listeners and the CP-03 admin listener exist. |
| Source | ARCH §4 E-01; MCP:basic/transports/streamable-http §Security |
| Rationale | A fixed listener set is a precondition for transport and Origin controls. |

#### FR-1.2 — Single MCP endpoint

| Field | Value |
|---|---|
| ID | FR-1.2 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** serve MCP traffic at the single endpoint path defined by CP-01 using HTTP POST. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | POST a valid `server/discover` request to the CP-01 path and to another path; confirm a result from CP-01 and `404 Not Found` elsewhere. |
| Source | MCP:basic/transports/streamable-http (single MCP endpoint) |
| Rationale | The specification requires one MCP endpoint that supports POST. |

#### FR-1.3 — GET and DELETE rejection

| Field | Value |
|---|---|
| ID | FR-1.3 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When the Harness Interface Endpoint (E-01) receives an HTTP GET or DELETE on the MCP endpoint, the Harness Interface Endpoint **SHALL** respond with `405 Method Not Allowed`. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send GET and DELETE requests to the CP-01 path; confirm each returns 405 with no SSE stream opened. |
| Source | MCP:basic/transports/streamable-http §Earlier Streamable HTTP Revisions |
| Rationale | Revision 2026-07-28 removed the GET stream and session DELETE. |

#### FR-1.4 — Single message per POST

| Field | Value |
|---|---|
| ID | FR-1.4 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** reject a POST body that is not exactly one JSON-RPC 2.0 request or notification object with HTTP 400 and JSON-RPC error `-32600`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01; Internal interfaces: I-01 |
| Verification Method | Test |
| Verification Statement | Send a JSON array batch, a JSON-RPC response object and a scalar; confirm each is rejected with 400 and code -32600. |
| Source | MCP:basic/transports/streamable-http §Sending Messages; MCP:basic/index §Messages |
| Rationale | MCP Streamable HTTP carries one request or notification per POST and clients do not send responses. |

#### FR-1.5 — Notification acceptance

| Field | Value |
|---|---|
| ID | FR-1.5 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a POST body is a well-formed JSON-RPC notification, the Protocol Mediator (E-02) **SHALL** return HTTP `202 Accepted` with an empty body and discard the notification. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | POST `notifications/cancelled` and an unknown notification; confirm 202 with empty body and no state change. |
| Source | MCP:basic/transports/streamable-http §Sending Messages item 5 |
| Rationale | The 2026-07-28 core protocol defines no client-to-server notification over Streamable HTTP. |

#### FR-1.6 — Response content type selection

| Field | Value |
|---|---|
| ID | FR-1.6 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** respond to a request with `Content-Type: text/event-stream` when the method is `subscriptions/listen` or the request carries a `progressToken`, and with `Content-Type: application/json` otherwise. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send `tools/call` with and without `progressToken` and a `subscriptions/listen`; confirm the content type for each. |
| Source | MCP:basic/transports/streamable-http §Sending Messages item 6 |
| Rationale | Gives harness adapters a predictable response shape. |

#### FR-1.7 — SSE stream conduct

| Field | Value |
|---|---|
| ID | FR-1.7 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When the Protocol Mediator (E-02) returns an SSE response stream, the Protocol Mediator **SHALL** set `X-Accel-Buffering: no`, emit only notifications related to the originating request, and close the stream after the final JSON-RPC response. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Capture an SSE `tools/call` exchange with progress; confirm the header, that every event relates to the request, and that the stream closes after the response. |
| Source | MCP:basic/transports/streamable-http §Receiving Messages |
| Rationale | Required SSE behavior for request-scoped streams. |

#### FR-1.8 — Required request metadata

| Field | Value |
|---|---|
| ID | FR-1.8 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** reject a request lacking `_meta.io.modelcontextprotocol/protocolVersion` or `_meta.io.modelcontextprotocol/clientCapabilities` with HTTP 400 and JSON-RPC error `-32602`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send requests omitting each required `_meta` field; confirm 400 with code -32602. |
| Source | MCP:basic/index §Per-request protocol fields |
| Rationale | Every 2026-07-28 request is self-describing; missing fields make it malformed. |

#### FR-1.9 — Unsupported protocol version

| Field | Value |
|---|---|
| ID | FR-1.9 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a request names a protocol version absent from CP-04, the Protocol Mediator (E-02) **SHALL** respond with HTTP 400 and an `UnsupportedProtocolVersionError` (`-32022`) whose `data.supported` lists the CP-04 versions and whose `data.requested` echoes the requested version. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-03; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send a request with version `1900-01-01`; confirm status, code and data fields. |
| Source | MCP:basic/versioning §Protocol Version Negotiation; SCHEMA:UnsupportedProtocolVersionError |
| Rationale | Clients rely on the supported list to retry with a mutual version. |

#### FR-1.10 — Unknown method

| Field | Value |
|---|---|
| ID | FR-1.10 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a request names a method that the Gateway does not implement or has not enabled, the Protocol Mediator (E-02) **SHALL** respond with HTTP `404 Not Found` and JSON-RPC error `-32601`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send `prompts/list`, `resources/read` and `foo/bar` with the baseline profile; confirm 404 with code -32601 for each. |
| Source | MCP:basic/transports/streamable-http §Protocol Version Header |
| Rationale | Distinguishes modern unknown-method responses from legacy 404s. |

#### FR-1.11 — Baseline northbound method set

| Field | Value |
|---|---|
| ID | FR-1.11 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** implement the northbound methods `server/discover`, `tools/list`, `tools/call` and `subscriptions/listen` in the baseline profile. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01; Internal interfaces: I-03 |
| Verification Method | Test |
| Verification Statement | Exercise each method against a session with one granted tool; confirm a conforming result for each. |
| Source | MCP:server/discover; MCP:server/tools; MCP:basic/patterns/subscriptions; ARCH §6.1 X-01 |
| Rationale | These methods are the minimum for tool discovery, invocation and change notification. |

#### FR-1.12 — server/discover result

| Field | Value |
|---|---|
| ID | FR-1.12 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** answer `server/discover` with a `DiscoverResult` containing `supportedVersions` equal to CP-04, `capabilities` limited to `tools` with `listChanged: true`, and `_meta.io.modelcontextprotocol/serverInfo` naming the Gateway and its release version. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-03; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Call `server/discover`; validate the result against `DiscoverResult` in schema.json and confirm the listed values. |
| Source | MCP:server/discover; SCHEMA:DiscoverResult |
| Rationale | Servers must implement discovery and advertise only implemented features. |

#### FR-1.13 — Cacheable result hints

| Field | Value |
|---|---|
| ID | FR-1.13 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** include `ttlMs` from CP-19 and `cacheScope: "private"` in every `server/discover` and `tools/list` result with `resultType: "complete"`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Call both methods; confirm `ttlMs` equals CP-19 and `cacheScope` is `private`. |
| Source | MCP:server/utilities/caching §Cacheable Results; SCHEMA:CacheableResult |
| Rationale | Results are per session, so they must not be shared by intermediaries. |

#### FR-1.14 — resultType on results

| Field | Value |
|---|---|
| ID | FR-1.14 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** set `resultType` to `"complete"` in every result the Gateway originates for a 2026-07-28 request. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Collect results from all baseline methods; confirm each carries `resultType: "complete"`. |
| Source | MCP:basic/index §ResultType |
| Rationale | `resultType` is mandatory on 2026-07-28 results. The 2025-11-25 schema does not define it, so legacy-era results (FR-1.46) do not carry it. |

#### FR-1.15 — Result serverInfo

| Field | Value |
|---|---|
| ID | FR-1.15 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** include `_meta.io.modelcontextprotocol/serverInfo` identifying the Gateway in every result the Gateway returns for a 2026-07-28 request. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Inspection |
| Verification Statement | Inspect results from each baseline method; confirm the field is present and names the Gateway. |
| Source | MCP:basic/index §Per-response protocol fields |
| Rationale | Lets harness adapters identify the Gateway without connection state. In the 2025-11-25 era the Gateway is identified once, by `serverInfo` in the `initialize` result (FR-1.46), and the per-response field does not exist. |

#### FR-1.16 — Legacy session headers ignored

| Field | Value |
|---|---|
| ID | FR-1.16 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** ignore `Mcp-Session-Id` and `Last-Event-ID` request headers on requests whose `_meta` declares protocol version 2026-07-28 and **SHALL** omit both headers from 2026-07-28 responses. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send 2026-07-28 requests carrying both headers; confirm processing is unchanged and responses contain neither header. |
| Source | MCP:basic/transports/streamable-http §Earlier Streamable HTTP Revisions |
| Rationale | Sessions and resumable streams were removed in 2026-07-28. Legacy requests are handled by the legacy handler of FR-1.46. |

#### FR-1.17 — initialize version negotiation

| Field | Value |
|---|---|
| ID | FR-1.17 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When an `initialize` request names a protocol version absent from CP-04, the Protocol Mediator (E-02) **SHALL** respond with an `initialize` result whose `protocolVersion` is `2025-11-25`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-03; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send `initialize` with version `2025-03-26`; confirm the result offers 2025-11-25 and the handshake completes. |
| Source | MCP:basic/versioning §Backward Compatibility; CP-04 |
| Rationale | The legacy handshake lets a server offer a version it supports. 2025-11-25 is the only qualified legacy era. |

#### FR-1.18 — JSON-RPC response conformance

| Field | Value |
|---|---|
| ID | FR-1.18 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** echo the request `id` in every response and **SHALL** use integer error codes. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Fuzz requests with string and integer IDs; confirm every response echoes the ID and every error code is an integer. |
| Source | MCP:basic/index §Responses |
| Rationale | JSON-RPC correlation correctness. |

#### FR-1.19 — Reserved error codes

| Field | Value |
|---|---|
| ID | FR-1.19 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** emit codes in the range `-32020` to `-32099` only with the meanings defined in the MCP 2026-07-28 schema, and **SHALL** use codes from Appendix B for Gateway-specific errors. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Inspection |
| Verification Statement | Inspect the error-code table in source and the conformance-test log; confirm no undefined reserved codes, `-32002` or `-32042` are emitted. |
| Source | MCP:basic/index §Error Codes; Appendix B |
| Rationale | The specification reserves this sub-range and forbids undefined use. |

#### FR-1.20 — Gateway error data

| Field | Value |
|---|---|
| ID | FR-1.20 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** include `data.reasonCode`, `data.correlationId` and, when a decision exists, `data.decisionId` in every Gateway-specific error from Appendix B. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Trigger each Appendix B error; confirm the data members are present. |
| Source | ARCH §4 E-02; ARCH §11 F-16 |
| Rationale | Operators and researchers trace a harness-visible error to its audit record. |

#### FR-1.21 — Duplicate in-flight request ID

| Field | Value |
|---|---|
| ID | FR-1.21 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a session sends a request whose `id` equals the `id` of another in-flight request of that session, the Protocol Mediator (E-02) **SHALL** reject the new request with JSON-RPC error `-32600`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Issue two concurrent `tools/call` requests with the same ID in one session; confirm the second is rejected and the first completes. |
| Source | MCP:basic/index §Requests |
| Rationale | Request IDs must not collide while in flight. |

#### FR-1.22 — UTF-8 and JSON parsing

| Field | Value |
|---|---|
| ID | FR-1.22 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** reject a body that is not valid UTF-8 JSON with HTTP 400 and JSON-RPC error `-32700`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send invalid UTF-8 and truncated JSON; confirm 400 with code -32700. |
| Source | MCP:basic/transports/index §Messages |
| Rationale | JSON-RPC messages must be UTF-8. |

#### FR-1.23 — tools/list pagination

| Field | Value |
|---|---|
| ID | FR-1.23 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Access Enforcement Point (E-08) **SHALL** return `tools/list` results in pages of at most CP-19 tools with an opaque `nextCursor` when further tools remain. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19; External interfaces: X-01; Internal interfaces: I-03 |
| Verification Method | Test |
| Verification Statement | Grant 250 tools to a session; page through `tools/list`; confirm page sizes, `nextCursor` behavior and a complete, duplicate-free union. |
| Source | MCP:server/utilities/pagination |
| Rationale | Large catalogs need bounded responses. |

#### FR-1.24 — Invalid cursor

| Field | Value |
|---|---|
| ID | FR-1.24 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When `tools/list` receives a cursor that the Gateway did not issue for the current session and policy revision, the Access Enforcement Point (E-08) **SHALL** return JSON-RPC error `-32602`. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send a random cursor, a cursor from another session and a cursor from a superseded revision; confirm -32602 for each. |
| Source | MCP:server/utilities/pagination §Error Handling |
| Rationale | Invalid cursors yield Invalid Params. |

#### FR-1.25 — Deterministic tool order

| Field | Value |
|---|---|
| ID | FR-1.25 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Access Enforcement Point (E-08) **SHALL** order `tools/list` entries by ascending public tool name so that repeated listings of an unchanged catalog are identical. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | List the same catalog ten times; confirm identical ordered output. |
| Source | MCP:server/tools §Capabilities |
| Rationale | Deterministic ordering supports client caching and prompt-cache stability. |

#### FR-1.26 — Public tool names

| Field | Value |
|---|---|
| ID | FR-1.26 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Access Enforcement Point (E-08) **SHALL** present each tool under the public name `<serverAlias>_<toolName>` within the CP-42 character set and length limit, replacing each character of the backend tool name outside `A-Z a-z 0-9 _` with `_`. |
| Allocation | Elements: E-08 Access Enforcement Point, E-14 Local Server Registry; Functions: F-19; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Register two servers exposing a `search` tool and one exposing `files.read`; confirm public names `a_search`, `b_search` and `c_files_read` within CP-42 and successful calls to each. |
| Source | MCP:server/tools §Tool Names; ARCH §4 E-14; CP-42; Client-Compatibility-Brief §4.4 |
| Rationale | Claude Code drops a tool whose prefixed name exceeds 128 characters and Hermes rewrites `.` and `-` to `_`. The public name must survive both. |

#### FR-1.27 — Tool definition source

| Field | Value |
|---|---|
| ID | FR-1.27 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Access Enforcement Point (E-08) **SHALL** build each presented tool definition (`title`, `description`, `inputSchema`, `outputSchema`, `annotations`) from the verified manifest of the enabled server revision. |
| Allocation | Elements: E-08 Access Enforcement Point, E-14 Local Server Registry; Functions: F-19; External interfaces: X-01; Internal interfaces: I-07 |
| Verification Method | Test |
| Verification Statement | Compare a packaged server's presented tool definitions with its verified manifest; then change the backend's live tool description without changing the manifest; confirm the changed description is never presented (the drift check of SR-3.8-1 suspends the revision and withdraws its tools). |
| Source | ARCH §6.3; SEC 3.7 |
| Rationale | Presented definitions must be the curated, signed definitions. A changed live description is drift, so the revision is suspended (SR-3.8-1) rather than presented with the manifest's description; either way the live text never reaches the harness. |

#### FR-1.28 — x-mcp-header removal

| Field | Value |
|---|---|
| ID | FR-1.28 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Access Enforcement Point (E-08) **SHALL** remove `x-mcp-header` annotations from presented `inputSchema` documents, and the Protocol Mediator (E-02) **SHALL** ignore `Mcp-Param-*` request headers. |
| Allocation | Elements: E-08 Access Enforcement Point, E-02 Protocol Mediator; Functions: F-19, F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Present a manifest tool with an `x-mcp-header` property; confirm it is absent from `tools/list` and that a supplied `Mcp-Param-X` header has no effect. |
| Source | MCP:basic/transports/streamable-http §Custom Headers from Tool Parameters |
| Rationale | Header mirroring is unnecessary on the local northbound hop and exposes argument values to intermediaries. |

#### FR-1.29 — tools/call routing

| Field | Value |
|---|---|
| ID | FR-1.29 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Access Enforcement Point (E-08) **SHALL** resolve the public tool name in `tools/call` to exactly one backend server revision and backend tool name before policy evaluation. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-20; External interfaces: X-01; Internal interfaces: I-08 |
| Verification Method | Test |
| Verification Statement | Call a public tool; confirm the dispatched southbound request uses the backend tool name of the resolved revision. |
| Source | ARCH §11.3; ARCH §4 E-08 |
| Rationale | Policy is evaluated against exact server and tool revisions. |

#### FR-1.30 — Unknown public tool

| Field | Value |
|---|---|
| ID | FR-1.30 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When `tools/call` names a public tool absent from the session catalog, the Access Enforcement Point (E-08) **SHALL** return JSON-RPC error `-32602` with message `Unknown tool`. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-20; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Call a tool that exists in the registry but is not granted to the session; confirm -32602 and the same message as for a nonexistent tool. |
| Source | MCP:server/tools §Error Handling |
| Rationale | An ungranted tool must look the same as a nonexistent one. |

#### FR-1.31 — Tool result relay

| Field | Value |
|---|---|
| ID | FR-1.31 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** return each release-authorized `CallToolResult` with its `content`, `structuredContent` and `isError` members as transformed by the Response Inspection Pipeline (E-11). |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01; Internal interfaces: I-16 |
| Verification Method | Test |
| Verification Statement | Call tools returning text, structured and error results; confirm the harness receives the post-filter members unchanged otherwise. |
| Source | MCP:server/tools §Tool Result |
| Rationale | Harness adapters require the standard result shape. |

#### FR-1.32 — Backend protocol error mapping

| Field | Value |
|---|---|
| ID | FR-1.32 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a backend returns a JSON-RPC error for `tools/call`, the Protocol Mediator (E-02) **SHALL** return Gateway error `-31007` with the backend code in `data.backendCode` and without the backend error message text. |
| Allocation | Elements: E-02 Protocol Mediator, E-10 Tool Dispatcher; Functions: F-22, F-24; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Make a fixture backend return -32603 with a long message; confirm the harness receives -31007, the backend code and no backend text. |
| Source | ARCH §4 E-11; Appendix B |
| Rationale | Backend error text is untrusted content that has not been filtered. |

#### FR-1.33 — subscriptions/listen support

| Field | Value |
|---|---|
| ID | FR-1.33 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** accept `subscriptions/listen` and **SHALL** acknowledge only the `toolsListChanged` notification type. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Request toolsListChanged, promptsListChanged and resourceSubscriptions; confirm the acknowledgment lists only `toolsListChanged`. |
| Source | MCP:basic/patterns/subscriptions §Acknowledgment |
| Rationale | Only tool-list changes are meaningful in the baseline profile. |

#### FR-1.34 — Subscription acknowledgment ordering

| Field | Value |
|---|---|
| ID | FR-1.34 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** send `notifications/subscriptions/acknowledged` as the first message of each listen stream, carrying `io.modelcontextprotocol/subscriptionId` equal to the listen request ID. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Open a listen stream; confirm the first event is the acknowledgment with the correct subscription ID. |
| Source | MCP:basic/patterns/subscriptions §Acknowledgment |
| Rationale | Specification ordering rule. |

#### FR-1.35 — Tool list change notification

| Field | Value |
|---|---|
| ID | FR-1.35 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a session's effective catalog changes, the Protocol Mediator (E-02) **SHALL** send `notifications/tools/list_changed` tagged with the subscription ID on each open listen stream of that session within 2 seconds. |
| Allocation | Elements: E-02 Protocol Mediator, E-08 Access Enforcement Point; Functions: F-19, F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Publish a revision that removes a granted tool; confirm the notification arrives on the session's listen stream within 2 s. |
| Source | MCP:server/tools §List Changed Notification; ARCH §18.8 |
| Rationale | Clients must refresh catalogs after policy or server changes. |

#### FR-1.36 — Listen keep-alive

| Field | Value |
|---|---|
| ID | FR-1.36 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** emit an SSE comment line on each idle listen stream at the CP-20 keep-alive interval. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Hold an idle listen stream for 60 s; confirm comment lines at the CP-20 interval. |
| Source | MCP:basic/transports/streamable-http §Receiving Messages (keep-alive note) |
| Rationale | Prevents idle-timeout disconnection. |

#### FR-1.37 — Graceful listen closure

| Field | Value |
|---|---|
| ID | FR-1.37 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When the Gateway ends a listen stream because of session end or shutdown, the Protocol Mediator (E-02) **SHALL** send an empty `resultType: "complete"` response carrying the subscription ID before closing the stream. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Terminate the session with an open listen stream; confirm the empty result precedes stream closure. |
| Source | MCP:basic/patterns/subscriptions §Graceful Closure |
| Rationale | Lets the client distinguish a graceful end from a dropped connection. |

#### FR-1.38 — Listen stream limit

| Field | Value |
|---|---|
| ID | FR-1.38 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** limit each session to the CP-20 maximum number of concurrent listen streams and reject excess requests with Gateway error `-31005`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Open CP-20 plus one streams; confirm the last is rejected with -31005. |
| Source | ARCH §4 E-01 (bounds) |
| Rationale | Bounds long-lived resource use. |

#### FR-1.39 — Progress relay

| Field | Value |
|---|---|
| ID | FR-1.39 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a northbound `tools/call` carries a `progressToken`, the Tool Dispatcher (E-10) **SHALL** relay backend progress as `notifications/progress` using the northbound token with strictly increasing `progress` values. |
| Allocation | Elements: E-10 Tool Dispatcher, E-02 Protocol Mediator; Functions: F-24, F-22; External interfaces: X-01; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Call a fixture tool emitting progress; confirm the harness receives the northbound token and increasing values. |
| Source | MCP:basic/patterns/progress |
| Rationale | Long tool calls need progress, and tokens must not leak between hops. |

#### FR-1.40 — Progress rate bound

| Field | Value |
|---|---|
| ID | FR-1.40 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Tool Dispatcher (E-10) **SHALL** forward no more than the CP-21 number of progress notifications per second per request and **SHALL** stop progress relay once the final response is released. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-24; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Make a fixture emit 1,000 progress notifications per second; confirm the forwarded rate and that none follow the response. |
| Source | MCP:basic/patterns/progress §Implementation Notes |
| Rationale | Prevents notification flooding. |

#### FR-1.41 — Northbound cancellation detection

| Field | Value |
|---|---|
| ID | FR-1.41 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When the harness closes the SSE response stream of an in-flight request, the Harness Interface Endpoint (E-01) **SHALL** signal cancellation of that request to the Tool Dispatcher (E-10) within 1 second. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-10 Tool Dispatcher; Functions: F-01, F-25; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Close the stream during a slow fixture call; confirm a southbound cancellation is issued within 1 s. |
| Source | MCP:basic/patterns/cancellation §Transport-Specific Cancellation |
| Rationale | Stream closure is the cancellation signal on Streamable HTTP. |

#### FR-1.42 — No log notifications northbound

| Field | Value |
|---|---|
| ID | FR-1.42 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** omit the `logging` capability and **SHALL** withhold `notifications/message` from harness-bound streams. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send requests with `io.modelcontextprotocol/logLevel` set to `debug` against a backend that logs; confirm no `notifications/message` reaches the harness. |
| Source | MCP:server/utilities/logging (Deprecated); MCP:deprecated |
| Rationale | Logging is deprecated, and backend log text is untrusted. |

#### FR-1.43 — Client deadline

| Field | Value |
|---|---|
| ID | FR-1.43 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When a northbound request has not completed within the CP-13 client deadline, the Tool Dispatcher (E-10) **SHALL** cancel the backend call and the Protocol Mediator (E-02) **SHALL** return Gateway error `-31008`. |
| Allocation | Elements: E-10 Tool Dispatcher, E-02 Protocol Mediator; Functions: F-25, F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Call a fixture that sleeps beyond the deadline; confirm -31008 at the deadline and a southbound cancellation. |
| Source | MCP:basic/patterns/cancellation §Timeouts; SEC Appendix A |
| Rationale | Bounded request lifetime. |

#### FR-1.44 — Trace context handling

| Field | Value |
|---|---|
| ID | FR-1.44 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** record a valid W3C `traceparent` from request `_meta` as an observation attribute and **SHALL** exclude harness `traceparent`, `tracestate` and `baggage` values from southbound requests. |
| Allocation | Elements: E-02 Protocol Mediator, E-29 Observation Collector; Functions: F-02, F-80; External interfaces: X-01; Internal interfaces: I-29 |
| Verification Method | Test |
| Verification Statement | Send a request with trace keys; confirm they appear in the observation record and are absent southbound. |
| Source | MCP:basic/index §OpenTelemetry trace context |
| Rationale | Supports research correlation without letting the agent inject context into backends. |

#### FR-1.45 — Self-asserted clientInfo

| Field | Value |
|---|---|
| ID | FR-1.45 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** record `io.modelcontextprotocol/clientInfo` as a self-asserted observation attribute only. |
| Allocation | Elements: E-02 Protocol Mediator, E-29 Observation Collector; Functions: F-02, F-80; Internal interfaces: I-29 |
| Verification Method | Inspection |
| Verification Statement | Inspect the decision inputs and the observation record for a request with forged clientInfo; confirm clientInfo appears only in the observation record. |
| Source | MCP:basic/index §Per-response protocol fields (note) |
| Rationale | clientInfo is unverified and must not affect behavior. |

#### FR-1.46 — Legacy era service

| Field | Value |
|---|---|
| ID | FR-1.46 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** serve 2025-11-25 clients on the CP-01 endpoint by answering the `initialize` handshake of that revision and accepting their subsequent requests without requiring an `Mcp-Session-Id` header, binding each request to the Gateway session of its bearer token. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-03; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Run the 2025-11-25 conformance fixtures against the baseline configuration, with and without an `Mcp-Session-Id` header; confirm they pass and that concurrent 2026-07-28 requests on the same endpoint are unaffected. |
| Source | SEC 5.1; MCP:basic/versioning §Backward Compatibility; CP-04; Client-Compatibility-Brief §2; spikes/go-sdk-dual-era |
| Rationale | Codex CLI and Cursor have no published 2026-07-28 support. A baseline that rejects them cannot be used. Revision 2025-11-25 makes the transport session ID optional, and the Gateway session is the bearer token, so the stateless mode of the MCP Go SDK, which serves both eras on one handler without issuing `Mcp-Session-Id`, satisfies this requirement. |

#### FR-1.47 — Unix-domain-socket harness transport

| Field | Value |
|---|---|
| ID | FR-1.47 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When the UDS Harness Profile is enabled, the Harness Interface Endpoint (E-01) **SHALL** carry MCP over the CP-02 Unix-domain socket using newline-delimited JSON-RPC framing, `notifications/cancelled` cancellation and `subscriptionId` correlation as defined for the stdio binding. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-02 Protocol Mediator; Functions: F-01, F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Run the northbound conformance suite over the socket; confirm framing, cancellation and subscription correlation. |
| Source | MCP:basic/transports/index §Custom Transports; MCP:basic/transports/stdio |
| Rationale | Same-host harnesses can avoid TCP while keeping standard framing. |

#### FR-1.48 — Harness interface specification

| Field | Value |
|---|---|
| ID | FR-1.48 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Gateway release **SHALL** include an X-01 interface control document specifying the OAuth endpoints and scopes, the session API, required headers, error codes, both protocol eras and conformance fixtures, and an X-12 interface control document specifying the adapter hooks for each supported framework. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-02 Protocol Mediator, E-04 Session Manager, E-33 Harness Adapter Kit; External interfaces: X-01, X-12 |
| Verification Method | Inspection |
| Verification Statement | Inspect the release; confirm both ICDs exist and cover each listed topic. |
| Source | ARCH §6.1 X-01; ARCH §6.1 X-12; ARCH §17 item 4 |
| Rationale | Frameworks and third-party adapters need a controlled contract on both sides of the adapter. |

#### FR-1.49 — Public name collisions

| Field | Value |
|---|---|
| ID | FR-1.49 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | When two tools of one server revision map to the same public name under FR-1.26, the Local Server Registry (E-14) **SHALL** refuse to enable that revision and **SHALL** report both backend tool names. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36; Data stores: D-02 |
| Verification Method | Test |
| Verification Statement | Import a manifest with tools `a.b` and `a_b`; confirm enablement is refused with both names reported. |
| Source | CP-42; Client-Compatibility-Brief §4.4 |
| Rationale | Name sanitization must not silently merge two tools. |

#### FR-1.50 — Approval hint on presented tools

| Field | Value |
|---|---|
| ID | FR-1.50 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Access Enforcement Point (E-08) **SHALL** set `_meta["anthropic/requiresUserInteraction"]` to `true` on each `tools/list` entry whose effective session policy carries an approval obligation for that tool, and **SHALL** omit the key otherwise. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19; External interfaces: X-01; Internal interfaces: I-08 |
| Verification Method | Test |
| Verification Statement | Publish a template that requires approval for one of two tools; list tools in a session under it; confirm the key is present and `true` on that tool only, and that calling either tool is still decided by the Policy Decision Service (E-06). |
| Source | Client-Compatibility-Brief §4.5; ARCH §4 E-08; MCP:server/tools §Tool |
| Rationale | Claude Code prompts the person before each call of a tool carrying this hint, so the person sees the approval in the harness as well as in the Approvals view. The hint is presentation only and never substitutes for the decision. |

#### FR-1.51 — Plain-language error message

| Field | Value |
|---|---|
| ID | FR-1.51 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | The Protocol Mediator (E-02) **SHALL** include in every Gateway-specific error a `data.message` string taken from the Appendix B reason-code table that states in one or two plain sentences what happened and what the person can do next, and, for `-31002`, the console URL of the pending approval in `data.approvalUrl`. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Trigger every Appendix B code and every listed reason code that a request can produce (Table B.3 lists the codes no request reaches); confirm each error carries the table's message text, and that `-31002` carries an `approvalUrl` that opens the approval in G-13. For the Table B.3 codes, confirm the error builder produces the table's message text. |
| Source | REVIEW (C5); OWNER (approvals: plain-language retry text and a console deep link) |
| Rationale | The harness shows error text to a person who may not know the Gateway exists. A code alone does not tell them to approve and retry. |

#### FR-1.52 — Tool metadata presentation scan

| Field | Value |
|---|---|
| ID | FR-1.52 |
| Parent ID | FR-1 — Northbound MCP server |
| Statement | Before presenting a tool in a session catalog, the Access Enforcement Point (E-08) **SHALL** re-apply the active metadata rule set (SR-5.9-2) to the tool's name, title, description and every schema property description, and **SHALL** omit from the catalog any tool with a blocking finding. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19, F-34; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Import a fixture server, then activate a rule set version that blocks one of its descriptions; list tools; confirm that tool is absent, the others are present, and a `metadata_blocked` event names the rule. |
| Source | REVIEW (I2); SEC 5.9; ARCH §4 E-14 |
| Rationale | Rule sets change after import. Scanning again at presentation applies the current rules to every tool an agent can see. |

### FR-2 Identity and sessions

#### FR-2 — Identity and sessions

| Field | Value |
|---|---|
| ID | FR-2 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** authenticate each framework instance and bind its MCP traffic to a Gateway session governed by a selected Allow policy. |
| Allocation | Elements: E-03 Identity & Authentication Service, E-04 Session Manager; Functions: F-04, F-05, F-06, F-07, F-08, F-09 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-2 child requirement; confirm each has passed. |
| Source | ARCH §2.1 items 2–3; ARCH §4 SS-2 |
| Rationale | Sessions carry the tailored Allow policy. |

#### FR-2.1 — Principal registry

| Field | Value |
|---|---|
| ID | FR-2.1 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Identity & Authentication Service (E-03) **SHALL** maintain a principal record for each framework instance containing principal ID, framework type, display name, enabled state, Framework Profile ID and credential references. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04; Internal interfaces: I-07; Data stores: D-01 |
| Verification Method | Inspection |
| Verification Statement | Create a principal through G-11; inspect the stored record for every listed field. |
| Source | ARCH §4 E-03; A2 §4.1 |
| Rationale | Policy layers key on principal and framework type. |

#### FR-2.2 — Session API

| Field | Value |
|---|---|
| ID | FR-2.2 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** establish sessions through the OAuth 2.1 token endpoint of FR-2.20 and **SHALL** additionally expose the session API operations `POST /smcp/v1/sessions` (create), `GET /smcp/v1/sessions/{id}` (status) and `DELETE /smcp/v1/sessions/{id}` (terminate) on the harness listener for header-helper adapters. |
| Allocation | Elements: E-04 Session Manager; Functions: F-06, F-08, F-09; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Establish a session through the token endpoint and through the session API with a valid credential; confirm each returns its documented response and that the two sessions behave identically. |
| Source | ARCH §18.2; ARCH §6.1 X-01; Client-Compatibility-Brief §4.1 |
| Rationale | MCP 2026-07-28 has no protocol sessions. Shipping clients obtain credentials through OAuth, so the token endpoint is the primary path. The session API remains for the `smcp-session` adapter. |

#### FR-2.3 — Session create request

| Field | Value |
|---|---|
| ID | FR-2.3 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** accept session creation, through the token endpoint of FR-2.20 or the session API of FR-2.2, with harness type, harness version, purpose tag and, optionally, project root, end-user claim and requested template ID. |
| Allocation | Elements: E-04 Session Manager; Functions: F-06; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Submit create requests with and without each optional field; confirm acceptance and stored values. |
| Source | ARCH §7.1 layer 4; ARCH §18.2 |
| Rationale | These claims select and narrow the Allow policy. |

#### FR-2.4 — Session create response

| Field | Value |
|---|---|
| ID | FR-2.4 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** return the session ID, session token, expiry time, Allow-policy template ID, policy revision ID and Observation Policy ID in each successful session create response. |
| Allocation | Elements: E-04 Session Manager; Functions: F-06, F-07; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Create a session; confirm each field in the response. |
| Source | ARCH §4 E-04 |
| Rationale | The harness needs the token and the policy context for diagnostics. |

#### FR-2.5 — Session token presentation

| Field | Value |
|---|---|
| ID | FR-2.5 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Identity & Authentication Service (E-03) **SHALL** read the session token from the `Authorization: Bearer` request header on the TLS listener, never from a query parameter, and on the UDS listener **SHALL** bind the session to the connection that authenticated under FR-2.15, reading no token from the messages it carries. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-05; External interfaces: X-01; Internal interfaces: I-02 |
| Verification Method | Test |
| Verification Statement | Send MCP requests with the token in the header, as a query parameter and without a token; confirm acceptance of the header form and rejection with -31006 otherwise; on the UDS listener confirm that messages on an authenticated connection are served without a token. |
| Source | Appendix A CP-23; RFC 6750; Client-Compatibility-Brief §3 |
| Rationale | Every shipping client sends bearer tokens in the Authorization header. None can send a custom session header without a helper. On the UDS socket the kernel peer credentials and the key authenticate the connection once (FR-2.15); a per-message token would add no assurance and would stop relays such as smcp-stdio from forwarding messages unchanged (FR-12.13). |

#### FR-2.6 — Template selection

| Field | Value |
|---|---|
| ID | FR-2.6 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** select the requested Session Allow Policy template when the principal's Framework Profile permits it, select the profile's default template when none is requested, and reject the create request with Gateway error `-31001` otherwise. |
| Allocation | Elements: E-04 Session Manager, E-03 Identity & Authentication Service; Functions: F-07; Internal interfaces: I-04, I-05 |
| Verification Method | Test |
| Verification Statement | Request a permitted template, no template and a non-permitted template; confirm selection, default and rejection. |
| Source | ARCH §7.1; ARCH §18.2 step 2 |
| Rationale | Implements Allow-policy layers 2 and 3. |

#### FR-2.7 — Claim narrowing

| Field | Value |
|---|---|
| ID | FR-2.7 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** apply the project-root claim as a narrowing parameter of the selected template, so that path arguments are confined to the project root within the granted roots, and **SHALL** record the purpose and end-user claims with the session and its creation evidence. |
| Allocation | Elements: E-04 Session Manager; Functions: F-07; Internal interfaces: I-05 |
| Verification Method | Test |
| Verification Statement | Create a session with project root `/p/a` under a template allowing `/p`; confirm paths outside `/p/a` are denied. |
| Source | ARCH §7.1 layer 4 |
| Rationale | Session context tailors the Allow policy. The project root narrows what the template grants (the path roots of `path-canonicalize`); a project root outside every granted root leaves no path granted. Release 1.0 policy rules have no purpose or end-user predicates, so those claims do not narrow a template; they are recorded with the session, in its creation event and in the observation context key (FR-2.13), where policy authors and analytics can use them. |

#### FR-2.8 — Session state model

| Field | Value |
|---|---|
| ID | FR-2.8 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** maintain each session in exactly one of the states `active`, `suspended`, `terminated` or `expired`, and **SHALL** accept MCP requests only for `active` sessions. |
| Allocation | Elements: E-04 Session Manager; Functions: F-08; Data stores: D-07 |
| Verification Method | Test |
| Verification Statement | Drive a session through each state; confirm only active sessions are served and others receive -31006 with the state as reason. |
| Source | ARCH §4 E-04 |
| Rationale | A defined lifecycle is required for suspension and revocation. |

#### FR-2.9 — Session lifetime

| Field | Value |
|---|---|
| ID | FR-2.9 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** expire a session at the CP-18 maximum lifetime and after the CP-18 idle timeout. |
| Allocation | Elements: E-04 Session Manager; Functions: F-08 |
| Verification Method | Test |
| Verification Statement | Configure short test values; confirm expiry at each limit. |
| Source | ARCH §4 E-04; Appendix A CP-18 |
| Rationale | Bounds the exposure of a stolen session token. |

#### FR-2.10 — Concurrent session limit

| Field | Value |
|---|---|
| ID | FR-2.10 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** reject a session create request that would exceed the CP-18 concurrent-session limit for the principal with Gateway error `-31005`. |
| Allocation | Elements: E-04 Session Manager; Functions: F-06 |
| Verification Method | Test |
| Verification Statement | Create sessions up to the limit plus one; confirm the last is rejected. |
| Source | ARCH §4 E-04 |
| Rationale | Bounds per-principal resource use. |

#### FR-2.11 — Session termination effects

| Field | Value |
|---|---|
| ID | FR-2.11 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | When a session terminates, expires or is revoked, the Session Manager (E-04) **SHALL** close its listen streams and cancel its in-flight calls. |
| Allocation | Elements: E-04 Session Manager; Functions: F-09; Internal interfaces: I-20 |
| Verification Method | Test |
| Verification Statement | Terminate, expire and revoke sessions that each have an open listen stream and an in-flight call; confirm each stream is closed and each call is cancelled. |
| Source | ARCH §4 E-04; ARCH §18.7 |
| Rationale | Prevents orphaned authority after session end. In release 1.0 server instances are shared per server revision, not owned by a session, and secret deliveries are bound to server instances and withdrawn at instance teardown (FR-6.8), so a session holds no instance or secret grant of its own to release. |

#### FR-2.12 — Revision change handling

| Field | Value |
|---|---|
| ID | FR-2.12 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | When a new policy revision is activated, the Session Manager (E-04) **SHALL** rebind each active session to the new revision before that session's next request is evaluated. |
| Allocation | Elements: E-04 Session Manager; Functions: F-07; Internal interfaces: I-05 |
| Verification Method | Test |
| Verification Statement | Activate a revision during an active session; confirm the next decision records the new revision ID. |
| Source | ARCH §4 E-04; SEC 1.17 |
| Rationale | Sessions must not keep obsolete authority. |

#### FR-2.13 — Baseline context key

| Field | Value |
|---|---|
| ID | FR-2.13 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** compute and store the session's baseline context key from the context dimensions of its Observation Policy at session creation. |
| Allocation | Elements: E-04 Session Manager; Functions: F-07; Internal interfaces: I-05; Data stores: D-07 |
| Verification Method | Test |
| Verification Statement | Create sessions under policies with different context dimensions; confirm the stored keys. |
| Source | ARCH §9.3 |
| Rationale | Scoring needs a stable context key per session. |

#### FR-2.15 — UDS peer mapping

| Field | Value |
|---|---|
| ID | FR-2.15 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | When the UDS Harness Profile is enabled, the Identity & Authentication Service (E-03) **SHALL** require both a registered peer UID and the principal's bearer key on the socket before establishing a session. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Connect with a registered UID and wrong key, and with an unregistered UID and right key; confirm both are rejected. |
| Source | ARCH §19 OD-2 |
| Rationale | Same-host harnesses use kernel peer credentials plus a key. |

#### FR-2.17 — Authorization metadata

| Field | Value |
|---|---|
| ID | FR-2.17 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Identity & Authentication Service (E-03) **SHALL** publish protected-resource metadata at `/.well-known/oauth-protected-resource` and authorization-server metadata at `/.well-known/oauth-authorization-server` on the harness listener, naming the CP-41 resource URI, the Gateway's own authorization and token endpoints, `S256` as the only code-challenge method and the CP-41 scope set. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Fetch both documents; validate them against RFC 9728 and RFC 8414; confirm the listed values. |
| Source | MCP:basic/authorization/authorization-server-discovery; RFC 9728; RFC 8414; CP-41 |
| Rationale | Clients discover the Gateway's authorization server from these documents without manual configuration. |

#### FR-2.18 — Client registration

| Field | Value |
|---|---|
| ID | FR-2.18 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Identity & Authentication Service (E-03) **SHALL** accept a framework instance as an OAuth client by one of: a Client ID Metadata Document URL that is pre-registered in the configuration or matches the CP-52 allowlist; a client ID and secret issued through G-11 or `smcpctl clients add`; or, under the Remote Access Profile only, an operator-approved Dynamic Client Registration (FR-16.5); and **SHALL** bind each client ID to exactly one principal record. |
| Allocation | Elements: E-03 Identity & Authentication Service, E-22 Key & Trust Anchor Manager; Functions: F-04, F-59; External interfaces: X-01; Internal interfaces: I-06; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Register one instance by an allowlisted metadata URL, one by issued secret and, with the Remote Access Profile enabled, one by approved registration; confirm each maps to its principal, that a second principal cannot claim the same client ID, and that a metadata URL outside the allowlist is refused without any outbound fetch. |
| Source | MCP:basic/authorization/client-registration; ARCH §19 OD-2; Client-Compatibility-Brief §4.2 |
| Rationale | The client registration is the framework credential that every shipping client can present. |

#### FR-2.19 — Authorization endpoint

| Field | Value |
|---|---|
| ID | FR-2.19 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** implement the authorization-code grant at the authorization endpoint with PKCE `S256` required, a `resource` parameter equal to the CP-41 resource URI required, the `iss` parameter in every authorization response, and a sign-in by a person holding a Session Approver account (F-63), refusing the Administrator account, that records the approving person on the resulting session. |
| Allocation | Elements: E-04 Session Manager, E-24 Management Console & Control API; Functions: F-06, F-63; External interfaces: X-01, X-04 |
| Verification Method | Test |
| Verification Statement | Run the flow without PKCE, with a wrong `resource`, and correctly as a Session Approver; confirm the first two are refused, `iss` is present, the approver is recorded on the session, and the Administrator, Auditor or Researcher account cannot complete the sign-in. |
| Source | MCP:basic/authorization; RFC 9207; RFC 8707; SEC 2.11; CP-41 |
| Rationale | Claude Code's v2 runtime validates `iss`. PKCE and resource binding are what the MCP authorization specification requires. |

#### FR-2.20 — Token endpoint as session creation

| Field | Value |
|---|---|
| ID | FR-2.20 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | When the token endpoint redeems a valid authorization code, the Session Manager (E-04) **SHALL** create the session of FR-2.3 from the granted scopes, return the session token as the access token with `expires_in` equal to the CP-18 idle timeout, and return a refresh token valid for the CP-18 maximum lifetime. |
| Allocation | Elements: E-04 Session Manager; Functions: F-06, F-07; External interfaces: X-01; Data stores: D-07 |
| Verification Method | Test |
| Verification Statement | Redeem a code; confirm a session exists with the scope-derived fields and that the access token is accepted as a session token on the MCP endpoint. |
| Source | ARCH §4 E-04; CP-18; CP-41; Client-Compatibility-Brief §4.1 |
| Rationale | The access token is the session, so clients need no second mechanism. |

#### FR-2.21 — Scope mapping

| Field | Value |
|---|---|
| ID | FR-2.21 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Session Manager (E-04) **SHALL** map the scopes `smcp:template:<id>`, `smcp:purpose:<tag>`, `smcp:project:<path>` and `smcp:user:<claim>` to the template selection and narrowing parameters of FR-2.6 and FR-2.7, and **SHALL** reject any other `smcp:` scope with `invalid_scope`. |
| Allocation | Elements: E-04 Session Manager; Functions: F-07; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Request each scope and an unknown `smcp:` scope; confirm the session fields and the `invalid_scope` error. |
| Source | ARCH §7.1 layer 4; CP-41 |
| Rationale | Scopes carry the session context claims and, like the claims, can only narrow policy. |

#### FR-2.22 — Token refresh

| Field | Value |
|---|---|
| ID | FR-2.22 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | When a valid refresh token is presented, the Session Manager (E-04) **SHALL** issue a new access token and a new refresh token for the same session, invalidate the presented refresh token, extend the idle deadline, and leave the CP-18 maximum lifetime unchanged. |
| Allocation | Elements: E-04 Session Manager; Functions: F-08; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Refresh repeatedly past the idle timeout; confirm the session stays active, each refresh returns a new refresh token, the previous one no longer works, and the session still expires at the maximum lifetime. |
| Source | CP-18; CP-41; OWNER (rotate refresh tokens) |
| Rationale | Refresh keeps long interactive sessions alive within the owner's bounds. Rotation limits a stolen refresh token to one use before the theft is detected (SR-2.11-4). |

#### FR-2.23 — Session Approver sign-in account

| Field | Value |
|---|---|
| ID | FR-2.23 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | The Management Console & Control API (E-24) **SHALL** let an Administrator create Session Approver accounts whose password is distinct from the Administrator password, and the sign-in page of FR-2.19 **SHALL** identify the client, principal, requested template and scopes before the person approves. |
| Allocation | Elements: E-24 Management Console & Control API, E-03 Identity & Authentication Service; Functions: F-63, F-64; External interfaces: X-01, X-04 |
| Verification Method | Test |
| Verification Statement | Create a Session Approver; sign in a harness with it; confirm the page lists client, principal, template and scopes, the session records the Session Approver, and the Session Approver cannot reach any other control API operation. |
| Source | OWNER (harness sign-in uses a lower-privilege Session Approver role); REVIEW (I4) |
| Rationale | Signing in a harness is a daily action. Doing it with the Administrator password exposes the most powerful credential on every sign-in. |

### FR-3 Policy administration, decision and approval

#### FR-3 — Policy capability

| Field | Value |
|---|---|
| ID | FR-3 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** author, validate, simulate, publish and evaluate immutable policy revisions and **SHALL** manage human approvals required by them. |
| Allocation | Elements: E-05 Policy Administration Service, E-06 Policy Decision Service, E-07 Approval Service; Functions: F-10, F-11, F-12, F-13, F-14, F-15, F-16, F-17, F-18 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-3 child requirement; confirm each has passed. |
| Source | ARCH §4 SS-3; ARCH §7 |
| Rationale | Developing and testing policy is the owner's primary research purpose. |

#### FR-3.1 — Policy object types

| Field | Value |
|---|---|
| ID | FR-3.1 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Gateway **SHALL** support the policy object types Framework Profile and Session Allow Policy Template in the signed policy document of the Policy Administration Service (E-05), Secret Use Policy in the Secret Broker (E-20), Audit Profile, Observation Policy and Anomaly Response Policy as published observation objects of the Management Console & Control API (E-24), and Research Campaign in the Research Dataset Service (E-32), each validated before it takes effect and kept under a revision or object identifier. |
| Allocation | Elements: E-05 Policy Administration Service, E-20 Secret Broker, E-24 Management Console & Control API, E-32 Research Dataset Service; Functions: F-10; Internal interfaces: I-06, I-07; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Create, validate and publish or activate one object of each type; confirm each is stored under its identifier and evaluated by its element. |
| Source | ARCH §7.2; OWNER (release 1.0 object homes) |
| Rationale | These objects compose the Allow-policy model. Release 1.0 keeps each object with the element that evaluates it rather than in one document: the policy document holds what the decision path evaluates, and secret-use, observation and research objects are validated and versioned by their own services with their own control API routes and roles (Appendix C). Response Policy and Runtime Profile objects are deferred (FR-3.26). |

#### FR-3.2 — Policy schema

| Field | Value |
|---|---|
| ID | FR-3.2 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** validate every policy object against a versioned JSON Schema for its type before storing it. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10; Internal interfaces: I-07 |
| Verification Method | Test |
| Verification Statement | Submit objects with a missing field, a wrong type and an unknown enumeration value; confirm each is rejected with a field-level message. |
| Source | ARCH §4 E-05; SEC 7.3 |
| Rationale | Typed records make evaluation deterministic. |

#### FR-3.4 — Revision record

| Field | Value |
|---|---|
| ID | FR-3.4 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** record for each published revision its ID, parent revision ID, content digest, policy-schema version, evaluator version, publishing actor, publication time, simulation result reference and policy-signing key ID. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-12; Data stores: D-01 |
| Verification Method | Inspection |
| Verification Statement | Publish a revision; inspect the record in the Policy Store for each field. |
| Source | A2 §4.1 PolicyRevision; SEC 1.14 |
| Rationale | Supports reproducible research and audit linkage. |

#### FR-3.5 — Policy simulation

| Field | Value |
|---|---|
| ID | FR-3.5 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** evaluate a draft against a stored fixture set and report, per fixture, the decision under the draft, the decision under the active revision and the difference. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-11; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Run a 50-fixture set against a draft that removes one grant; confirm exactly the affected fixtures report a changed decision. |
| Source | ARCH §4 E-05; ARCH §11 item 8 |
| Rationale | Authors must see the effect of a change before publishing it. |

#### FR-3.6 — Effective permission report

| Field | Value |
|---|---|
| ID | FR-3.6 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** produce, for a selected principal and template, the list of tools and argument constraints the draft or active revision permits. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-11; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Generate the report for a fixture principal; compare against hand-computed expected permissions. |
| Source | A2 §7.2 (Effective tools by principal) |
| Rationale | Makes the tailored Allow policy reviewable. |

#### FR-3.8 — Policy export and import

| Field | Value |
|---|---|
| ID | FR-3.8 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** export any revision as a canonical JSON document and **SHALL** import such a document as a new draft. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Export a revision, import it into a clean instance and publish; confirm identical decisions over the fixture set. |
| Source | OWNER (policy development and research reproducibility) |
| Rationale | Policies are the research artifact and must be portable. |

#### FR-3.9 — Policy rollback

| Field | Value |
|---|---|
| ID | FR-3.9 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** roll back by publishing the content of a selected earlier revision as a new revision. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-12; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Roll back to revision N-2; confirm a new revision ID with N-2 content becomes active. |
| Source | ARCH §4 E-05; SEC 7.9 |
| Rationale | Rollback keeps history linear and immutable. |

#### FR-3.10 — Compiled decision snapshot

| Field | Value |
|---|---|
| ID | FR-3.10 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Decision Service (E-06) **SHALL** compile the active revision into an in-memory decision snapshot when the revision is activated, and **SHALL** evaluate requests against that snapshot. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13; Internal interfaces: I-07 |
| Verification Method | Test |
| Verification Statement | Activate a revision; stop the graph database and the Observation Store; confirm decisions continue unchanged for 60 seconds with no Data Server access per decision. |
| Source | ARCH §15 E-05/E-06; ARCH §14 |
| Rationale | Decision latency must not depend on a database round-trip. |

#### FR-3.11 — Decision record

| Field | Value |
|---|---|
| ID | FR-3.11 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Decision Service (E-06) **SHALL** return for each evaluation a decision ID, outcome, reason code, considered, applicable and decisive rule IDs, effective obligations, selected route, policy revision ID, baseline snapshot ID and evaluation duration. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13, F-14; Internal interfaces: I-08 |
| Verification Method | Test |
| Verification Statement | Evaluate permit, deny and default-deny fixtures; confirm all fields are present and correct. |
| Source | A2 §4.1 Decision; SEC 1.19 |
| Rationale | Decisions are the primary audit and research record. |

#### FR-3.12 — Obligation types

| Field | Value |
|---|---|
| ID | FR-3.12 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Decision Service (E-06) **SHALL** express obligations using the types request filters, response filters, approval, audit profile, observation policy, rate limit, size limit, timeout, egress grants, secret grants, runtime profile and anomaly response. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-14; Internal interfaces: I-08 |
| Verification Method | Test |
| Verification Statement | Evaluate a fixture rule carrying every obligation type; confirm each appears in the decision. |
| Source | ARCH §4 E-06; ARCH §7.2 |
| Rationale | Enforcement elements consume a closed set of obligation types. |

#### FR-3.13 — Rate limit counters

| Field | Value |
|---|---|
| ID | FR-3.13 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Decision Service (E-06) **SHALL** maintain sliding-window call counters per principal, per session and per tool, and **SHALL** apply the smallest applicable rate bound, with CP-11 as the default principal bound. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-14; Internal interfaces: I-08 |
| Verification Method | Test |
| Verification Statement | Exceed a session limit lower than the principal limit; confirm -31005 at the session bound. |
| Source | SEC Appendix A (principal tool rate); SEC Appendix F (resource limits) |
| Rationale | Rate limits are a policy obligation. |

#### FR-3.14 — Approval request creation

| Field | Value |
|---|---|
| ID | FR-3.14 |
| Parent ID | FR-3 — Policy capability |
| Statement | When a decision carries an approval obligation and no matching unconsumed approval exists, the Approval Service (E-07) **SHALL** create a pending approval record bound per SR-1.18-2, notify approvers (FR-3.23) and hold the call (FR-3.19). |
| Allocation | Elements: E-07 Approval Service, E-02 Protocol Mediator; Functions: F-17; External interfaces: X-01; Internal interfaces: I-10 |
| Verification Method | Test |
| Verification Statement | Call a tool that requires approval; confirm a pending record visible in G-13 and in `smcpctl approvals list`, a desktop notification through the test notifier, and that the call is held rather than answered. |
| Source | ARCH §4 E-07; SEC 1.18; OWNER (approvals: hold mode) |
| Rationale | Approval is out-of-band. Holding the call lets an approved call finish in the same turn of the agent; the retry path remains for calls that outlast the hold. |

#### FR-3.15 — Approval consumption on retry

| Field | Value |
|---|---|
| ID | FR-3.15 |
| Parent ID | FR-3 — Policy capability |
| Statement | When a session retries a call whose canonical arguments digest matches an approved, unexpired, unconsumed approval for that session, the Approval Service (E-07) **SHALL** mark the approval consumed and permit dispatch to proceed. |
| Allocation | Elements: E-07 Approval Service; Functions: F-18; Internal interfaces: I-10 |
| Verification Method | Test |
| Verification Statement | Approve a pending request and retry the identical call; confirm dispatch, and confirm a second retry is denied. |
| Source | ARCH §4 E-07; SEC 1.18 |
| Rationale | One-use approval bound to the exact request. |

#### FR-3.16 — Approval status query

| Field | Value |
|---|---|
| ID | FR-3.16 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Approval Service (E-07) **SHALL** report the state `pending`, `approved`, `denied`, `expired` or `consumed` of an approval through `GET /smcp/v1/approvals/{id}` to the session that created it. |
| Allocation | Elements: E-07 Approval Service; Functions: F-18; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Query an approval from the creating session and from another session; confirm the state and a 404 for the other session. |
| Source | ARCH §4 E-07 |
| Rationale | Harness adapters need to know when to retry. |

#### FR-3.17 — Approver decision

| Field | Value |
|---|---|
| ID | FR-3.17 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Approval Service (E-07) **SHALL** record each approve or deny decision with approver identity, decision time and an optional comment. |
| Allocation | Elements: E-07 Approval Service; Functions: F-18; External interfaces: X-05; Internal interfaces: I-18 |
| Verification Method | Test |
| Verification Statement | Approve and deny requests through G-13; confirm the stored fields and audit events. |
| Source | ARCH §4 E-07; ARCH §6.1 X-05 |
| Rationale | Approvals are attributable. |

#### FR-3.18 — Approval evidence display

| Field | Value |
|---|---|
| ID | FR-3.18 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Approval Service (E-07) **SHALL** supply to the approval view the public tool name, server revision, canonical arguments, decisive rules and any anomaly band with contributing feature and z-score. |
| Allocation | Elements: E-07 Approval Service; Functions: F-17; External interfaces: X-05 |
| Verification Method | Inspection |
| Verification Statement | Open a pending approval triggered by an anomaly obligation in G-13; confirm each item is displayed. |
| Source | ARCH §4 E-07; ARCH §9.6 |
| Rationale | Approvers need the evidence to decide. |

#### FR-3.19 — Approval hold mode

| Field | Value |
|---|---|
| ID | FR-3.19 |
| Parent ID | FR-3 — Policy capability |
| Statement | While an approval-obligated call is pending, the Approval Service (E-07) **SHALL** keep the call parked for at most the CP-45 hold bound, and the Protocol Mediator (E-02) **SHALL** send a keep-alive every CP-45 keep-alive interval: a `notifications/progress` message when the request carries a progress token, and an SSE comment line otherwise. |
| Allocation | Elements: E-07 Approval Service, E-02 Protocol Mediator; Functions: F-17; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Call an approval-obligated tool with and without a progress token and leave it pending; confirm keep-alives at the interval in both forms and no response before the hold bound. |
| Source | OWNER (approvals: hold mode with progress keep-alives); MCP:basic/utilities/progress |
| Rationale | Harnesses close idle requests. Keep-alives hold the call open while a person decides. |

#### FR-3.20 — Approval during hold

| Field | Value |
|---|---|
| ID | FR-3.20 |
| Parent ID | FR-3 — Policy capability |
| Statement | When a held call's approval is granted before the CP-45 hold bound, the Approval Service (E-07) **SHALL** consume the approval and continue the same call to launch authorization (F-29), so that the harness receives the tool result as the response to its original request. |
| Allocation | Elements: E-07 Approval Service, E-12 Enforcement Coordinator; Functions: F-18, F-17; Internal interfaces: I-10, I-11 |
| Verification Method | Test |
| Verification Statement | Hold a call; approve it from G-13; confirm the original request returns the tool result, the approval is `consumed`, and a second identical call creates a new approval. |
| Source | OWNER (approvals: hold mode) |
| Rationale | The agent's turn completes without a retry when the person answers in time. |

#### FR-3.21 — Denial during hold

| Field | Value |
|---|---|
| ID | FR-3.21 |
| Parent ID | FR-3 — Policy capability |
| Statement | When a held call's approval is denied, the Approval Service (E-07) **SHALL** end the call with Gateway error `-31001` and reason code `APPROVAL_DENIED`. |
| Allocation | Elements: E-07 Approval Service, E-02 Protocol Mediator; Functions: F-18; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Hold a call; deny it; confirm `-31001` with `APPROVAL_DENIED` and no dispatch event. |
| Source | OWNER (approvals: approve or deny) |
| Rationale | A denial is a policy outcome and is reported as one. |

#### FR-3.22 — Hold bound fallback

| Field | Value |
|---|---|
| ID | FR-3.22 |
| Parent ID | FR-3 — Policy capability |
| Statement | When a held call reaches the CP-45 hold bound without a decision, the Protocol Mediator (E-02) **SHALL** end the call with Gateway error `-31002` carrying `data.approvalId`, `data.expiresAt`, the plain-language `data.message` and `data.approvalUrl` (FR-1.51), and the Approval Service (E-07) **SHALL** keep the approval pending until its CP-17 expiry so that a retry after approval consumes it (FR-3.15). |
| Allocation | Elements: E-07 Approval Service, E-02 Protocol Mediator; Functions: F-17; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Hold a call past the bound; confirm the `-31002` data members; approve; retry the identical call; confirm dispatch. |
| Source | OWNER (approvals: fallback to -31002 with plain-language retry text and a console deep link) |
| Rationale | The hold is bounded so a harness never waits indefinitely; the approval survives the fallback. |

#### FR-3.23 — Approver notification

| Field | Value |
|---|---|
| ID | FR-3.23 |
| Parent ID | FR-3 — Policy capability |
| Statement | Within 2 seconds of creating a pending approval, the Approval Service (E-07) **SHALL** notify approvers in the Approvals view (G-13), in the `smcpctl approvals watch` stream and through an OS desktop notification (X-14) whose text contains only the public tool name, the server alias, the approval ID and the console URL. |
| Allocation | Elements: E-07 Approval Service, E-24 Management Console & Control API; Functions: F-17; External interfaces: X-05, X-14 |
| Verification Method | Test |
| Verification Statement | Create an approval with the test notifier attached; confirm the three notices within 2 seconds and that the desktop notification text contains no argument value; remove the notifier binary and confirm the approval flow is unaffected and a diagnostic log warning is written. |
| Source | OWNER (approvals: console, CLI and OS desktop notification) |
| Rationale | A held call is only useful if a person learns about it while the hold lasts. Arguments stay out of OS notifications because notification centers persist and display them outside the Gateway's control. |

#### FR-3.24 — Approval CLI

| Field | Value |
|---|---|
| ID | FR-3.24 |
| Parent ID | FR-3 — Policy capability |
| Statement | The `smcpctl approvals` command **SHALL** provide `list`, `show`, `approve`, `deny` and `watch` subcommands that authenticate to the control API as a person holding the Approver or Administrator role and display the FR-3.18 evidence before an approve or deny takes effect. |
| Allocation | Elements: E-24 Management Console & Control API, E-07 Approval Service; Functions: F-18; External interfaces: X-05 |
| Verification Method | Test |
| Verification Statement | Approve and deny held calls with the CLI as an Approver; confirm the evidence is printed, the decisions are recorded with the approver identity, and an Auditor account is refused. |
| Source | OWNER (approve and deny via smcpctl approvals) |
| Rationale | Operators who work in a terminal need an approval path that does not require the browser. |

#### FR-3.25 — Real-harness approval acceptance

| Field | Value |
|---|---|
| ID | FR-3.25 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Gateway project **SHALL** verify the approval flow end to end with Claude Code at its Appendix K pinned version, covering a held call approved from G-13, a held call approved with `smcpctl approvals`, a denied call and a call that reaches the hold bound, and **SHALL** record the harness-visible text of each outcome. |
| Allocation | Elements: E-07 Approval Service, E-02 Protocol Mediator, E-24 Management Console & Control API; Functions: F-17, F-18; External interfaces: X-01, X-05 |
| Verification Method | Demonstration |
| Verification Statement | Run the four cases with the pinned Claude Code build against a Gateway at the release commit; confirm each outcome and file the recorded transcript in `docs/verification/`. |
| Source | REVIEW (C5) |
| Rationale | Hold mode depends on harness timeout and progress behavior that unit tests cannot show. |

### FR-4 Enforcement pipeline

#### FR-4 — Enforcement pipeline

| Field | Value |
|---|---|
| ID | FR-4 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** process each tool call through ordered access-time, run-time and response-time enforcement stages. |
| Allocation | Elements: E-08 Access Enforcement Point, E-09 Request Inspection Pipeline, E-10 Tool Dispatcher, E-11 Response Inspection Pipeline, E-12 Enforcement Coordinator |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-4 child requirement; confirm each has passed. |
| Source | ARCH §2.1 item 4; ARCH §4 SS-4; ARCH §18.3 |
| Rationale | The owner's three control points. |

#### FR-4.1 — Canonical request object

| Field | Value |
|---|---|
| ID | FR-4.1 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Protocol Mediator (E-02) **SHALL** convert each `tools/call` into a canonical request containing correlation ID, session ID, principal ID, public tool name, resolved server and tool revision IDs, canonicalized arguments, argument digest and receipt time. |
| Allocation | Elements: E-02 Protocol Mediator, E-08 Access Enforcement Point; Functions: F-02; Internal interfaces: I-03 |
| Verification Method | Test |
| Verification Statement | Submit equivalent calls differing only in JSON key order and whitespace; confirm identical argument digests. |
| Source | ARCH §4 E-02; A2 §4.2 step 1 |
| Rationale | Policy, approval and audit bind to one canonical form. |

#### FR-4.2 — Correlation ID

| Field | Value |
|---|---|
| ID | FR-4.2 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Protocol Mediator (E-02) **SHALL** assign each northbound request a UUIDv7 correlation ID that every element attaches to the records and events it produces for that request. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; Internal interfaces: I-29, I-18 |
| Verification Method | Test |
| Verification Statement | Trace one call through audit, observation and span records; confirm all share the correlation ID. |
| Source | ARCH §10.4; A2 §5 |
| Rationale | Joins records across elements. |

#### FR-4.3 — Stage order

| Field | Value |
|---|---|
| ID | FR-4.3 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Access Enforcement Point (E-08) **SHALL** execute the stages authenticate, session check, decision, request inspection, request scoring, approval, launch authorization, dispatch, response validation, response inspection, response scoring and release authorization in that order. |
| Allocation | Elements: E-08 Access Enforcement Point, E-09 Request Inspection Pipeline, E-10 Tool Dispatcher, E-11 Response Inspection Pipeline, E-12 Enforcement Coordinator; Functions: F-20, F-21, F-29, F-30 |
| Verification Method | Test |
| Verification Statement | Instrument a call and record stage-entry times; confirm the order. |
| Source | ARCH §18.3 |
| Rationale | Each stage depends on the results of the previous ones. |

#### FR-4.4 — Filter interface

| Field | Value |
|---|---|
| ID | FR-4.4 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Request Inspection Pipeline (E-09) and the Response Inspection Pipeline (E-11) **SHALL** execute filters through one versioned filter interface returning `pass`, `transform` or `block` with findings, timing and filter version. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline; Functions: F-21, F-27 |
| Verification Method | Inspection |
| Verification Statement | Inspect the filter interface definition and the registered filters; confirm every filter implements it. |
| Source | ARCH §4 E-09; ARCH §4 E-11 |
| Rationale | Researchers add and compare filters without changing the pipeline. |

#### FR-4.5 — Built-in request filters

| Field | Value |
|---|---|
| ID | FR-4.5 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Request Inspection Pipeline (E-09) **SHALL** provide the request filters `schema-validate`, `path-canonicalize`, `url-canonicalize`, `size-limit`, `secret-fingerprint`, `injection-detect` and `unicode-control`. |
| Allocation | Elements: E-09 Request Inspection Pipeline; Functions: F-21 |
| Verification Method | Test |
| Verification Statement | Run each filter against its positive and negative fixture corpus; confirm the expected disposition for each fixture. |
| Source | ARCH §4 E-09 |
| Rationale | The baseline request controls. |

#### FR-4.6 — Built-in response filters

| Field | Value |
|---|---|
| ID | FR-4.6 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Response Inspection Pipeline (E-11) **SHALL** provide the response filters `output-schema`, `secret-fingerprint`, `pii-detect`, `injection-marker`, `unicode-control`, `content-type-gate` and `size-limit`. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-27 |
| Verification Method | Test |
| Verification Statement | Run each filter against its positive and negative fixture corpus; confirm the expected disposition for each fixture. |
| Source | ARCH §4 E-11 |
| Rationale | The baseline response controls. |

#### FR-4.7 — Filter findings

| Field | Value |
|---|---|
| ID | FR-4.7 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Request Inspection Pipeline (E-09) and the Response Inspection Pipeline (E-11) **SHALL** emit each filter's findings and duration to the Observation Collector (E-29). |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline; Functions: F-21, F-27; Internal interfaces: I-29 |
| Verification Method | Test |
| Verification Statement | Trigger an `injection-detect` finding; confirm an observation record with the filter ID, finding and duration. |
| Source | ARCH §10.3 P-140; ARCH §10.4 |
| Rationale | Filter behavior and cost are research data. |

#### FR-4.8 — Dispatch queue

| Field | Value |
|---|---|
| ID | FR-4.8 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Tool Dispatcher (E-10) **SHALL** enforce the CP-10 per-principal and total concurrency limits using a bounded FIFO waiting queue and **SHALL** reject calls arriving at a full queue with Gateway error `-31005`. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23 |
| Verification Method | Test |
| Verification Statement | Submit 60 concurrent calls from one principal; confirm the concurrency, queue length and rejections. |
| Source | SEC Appendix A (tool concurrency) |
| Rationale | Bounded concurrency on a single PC. |

#### FR-4.9 — Upstream execution timeout

| Field | Value |
|---|---|
| ID | FR-4.9 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Tool Dispatcher (E-10) **SHALL** cancel a backend call that has not responded within the CP-13 upstream execution limit. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-25; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Call a fixture that never responds; confirm cancellation at the limit. |
| Source | SEC Appendix A |
| Rationale | Leaves time for filtering and release within the client deadline. |

#### FR-4.10 — Response buffering

| Field | Value |
|---|---|
| ID | FR-4.10 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Tool Dispatcher (E-10) **SHALL** buffer each backend response completely, up to the CP-08 expanded-size and depth limits, before passing it to the Response Inspection Pipeline (E-11). |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-24; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Return responses at, and 1 byte above, the limit; confirm the first is processed and the second is rejected with -31003. |
| Source | SEC 5.11; SEC Appendix A |
| Rationale | Response filters need the complete representation. |

#### FR-4.11 — Release disposition

| Field | Value |
|---|---|
| ID | FR-4.11 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Response Inspection Pipeline (E-11) **SHALL** assign each response exactly one disposition: `release`, `redact` or `withhold`. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-27; Internal interfaces: I-15 |
| Verification Method | Test |
| Verification Statement | Run fixtures for each disposition; confirm that a withheld response produces -31003 and a redacted one carries redaction markers. |
| Source | ARCH §4 E-11 |
| Rationale | A closed set of outcomes feeds audit and research. |

#### FR-4.12 — Provenance metadata

| Field | Value |
|---|---|
| ID | FR-4.12 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Response Inspection Pipeline (E-11) **SHALL** add `_meta["local.smcpgw/provenance"]` to each released result, containing server ID, server revision, tool revision, decision ID, applied filter IDs and `untrusted: true`. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-28; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Call a tool and inspect the released result's `_meta`. |
| Source | ARCH §4 E-11 F-28; SEC 5.13 |
| Rationale | Downstream consumers can identify unverified content. |

#### FR-4.13 — Launch capability

| Field | Value |
|---|---|
| ID | FR-4.13 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Enforcement Coordinator (E-12) **SHALL** issue for each authorized call a single-use launch capability bound to the correlation ID, decision ID and policy revision, and the Tool Dispatcher (E-10) **SHALL** refuse to dispatch without a valid unused capability. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-10 Tool Dispatcher; Functions: F-29, F-23; Internal interfaces: I-11 |
| Verification Method | Test |
| Verification Statement | Attempt dispatch with no capability, a used capability and a capability from another call; confirm each is refused. |
| Source | ARCH §4 E-12; A2 §4.3 |
| Rationale | Makes dispatch impossible without a recorded permit. |

#### FR-4.14 — Emergency stop control

| Field | Value |
|---|---|
| ID | FR-4.14 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Enforcement Coordinator (E-12) **SHALL** enter the `stopped` state on an emergency-stop command and **SHALL** leave it only on an authenticated administrator resume command. |
| Allocation | Elements: E-12 Enforcement Coordinator; Functions: F-31; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Stop, attempt calls, then resume as a non-administrator and as an administrator; confirm the state transitions. |
| Source | ARCH §4 E-12; SEC 7.6 |
| Rationale | The operator must be able to halt the Gateway. |

#### FR-4.15 — Synchronous scoring integration

| Field | Value |
|---|---|
| ID | FR-4.15 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | When the Observation Policy selects synchronous scoring, the Request Inspection Pipeline (E-09) and the Response Inspection Pipeline (E-11) **SHALL** obtain the anomaly band from the Anomaly Scorer (E-31) before launch authorization and before release authorization respectively. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline, E-31 Anomaly Scorer; Functions: F-21, F-27, F-88, F-89; Internal interfaces: I-31 |
| Verification Method | Test |
| Verification Statement | Enable synchronous scoring; confirm that an abnormal fixture's obligations apply before dispatch and before release. |
| Source | ARCH §9.5 (Scoring mode); ARCH §18.3 |
| Rationale | Anomaly obligations must act at the control points. |

#### FR-4.16 — Versioned detection rule sets

| Field | Value |
|---|---|
| ID | FR-4.16 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The Request Inspection Pipeline (E-09) and the Response Inspection Pipeline (E-11) **SHALL** load the rules of the `secret-fingerprint`, `injection-detect`, `injection-marker`, `pii-detect` and `unicode-control` filters and of the metadata scan from versioned rule-set files, each with an ID, version and SHA-256 digest, and **SHALL** record the rule-set ID and version in every finding. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline, E-14 Local Server Registry; Functions: F-21, F-27, F-34 |
| Verification Method | Test |
| Verification Statement | Load two versions of a rule set; run the same input under each; confirm the findings name the version in effect and that a rule-set file whose digest does not match its index is refused at load. |
| Source | REVIEW (I1); SEC 5.14 |
| Rationale | Detection quality can only be measured and compared per version (FR-19.5). |

#### FR-4.17 — Injection findings as tags

| Field | Value |
|---|---|
| ID | FR-4.17 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | The `injection-detect` and `injection-marker` filters **SHALL** record each finding as a provenance tag on the released result and as observation parameters P-043 and P-143, and **SHALL** leave the release disposition unchanged. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline; Functions: F-21, F-27, F-28 |
| Verification Method | Test |
| Verification Statement | Run the injection corpus through both filters; confirm every positive sample yields a tag and parameter value and that each result is released with the same disposition as without the filter. |
| Source | OWNER (injection-marker tags only in v1); REVIEW (I1) |
| Rationale | Prompt-injection detection has false positives and false negatives that are not yet measured well enough to block on. Tags give the agent and the researcher the signal without claiming a control. |

#### FR-4.18 — Untrusted-content delimiting

| Field | Value |
|---|---|
| ID | FR-4.18 |
| Parent ID | FR-4 — Enforcement pipeline |
| Statement | When the Response Policy carries the `delimit-untrusted` obligation, the Response Inspection Pipeline (E-11) **SHALL** enclose each text content item from a tool whose manifest `source_trust` is `untrusted` between delimiter lines that carry a per-response random nonce of at least 96 bits, and **SHALL** remove from the enclosed text any line matching the delimiter pattern. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-27, F-28 |
| Verification Method | Test |
| Verification Statement | Enable the obligation; return text containing a forged delimiter line from an untrusted-source fixture; confirm the released text is enclosed with a fresh nonce and the forged line is removed. |
| Source | REVIEW (I2) |
| Rationale | An optional, deterministic way to mark where untrusted text begins and ends for agents that honor it. It is not a control on its own. |

### FR-5 Server trust, runtime and southbound MCP client

#### FR-5 — Server trust and execution

| Field | Value |
|---|---|
| ID | FR-5 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** import verified server packages from the Trusted MCP Server Library and **SHALL** run them as contained local MCP servers reached through a Gateway MCP client. |
| Allocation | Elements: E-10 Tool Dispatcher, E-13 Library Trust Verifier, E-14 Local Server Registry, E-15 Server Runtime Manager, E-16 Execution Sandbox, E-17 Runtime Monitor, E-18 Egress Broker |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-5 child requirement; confirm each has passed. |
| Source | ARCH §2.1 item 1; ARCH §4 SS-5 |
| Rationale | Hosting curated, signed servers locally is the core vision. |

#### FR-5.1 — Library sources

| Field | Value |
|---|---|
| ID | FR-5.1 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Library Trust Verifier (E-13) **SHALL** retrieve packages from a configured local directory library. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-33; External interfaces: X-03 |
| Verification Method | Test |
| Verification Statement | Import a package from the directory library; confirm it succeeds. |
| Source | ARCH §6.1 X-03; ARCH §19 OD-7 |
| Rationale | The library location is a deployment choice. Release 1.0 packages are signed directory trees, so a directory (local, or a mounted share) is the one library type; the local OCI registry library of ARCH §19 OD-7 is not part of release 1.0. OCI images remain a supported artifact type inside a package (FR-14.1). |

#### FR-5.2 — Package contents

| Field | Value |
|---|---|
| ID | FR-5.2 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Library Trust Verifier (E-13) **SHALL** require each package to contain an artifact, a package index listing the artifact, manifest and provenance digests, a minisign signature over that index, a manifest conforming to the Appendix J schema, a provenance statement and the signer key identifier. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-33, F-34; External interfaces: X-03 |
| Verification Method | Test |
| Verification Statement | Import packages each missing one component; confirm each is rejected with a reason naming the missing component. |
| Source | ARCH §6.3 |
| Rationale | Verification needs all four components. |

#### FR-5.3 — Library polling

| Field | Value |
|---|---|
| ID | FR-5.3 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Library Trust Verifier (E-13) **SHALL** scan the library for new packages and revocation entries at a configurable interval with a default of 300 seconds, and on operator command. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-33, F-35; External interfaces: X-03 |
| Verification Method | Test |
| Verification Statement | Add a package and a revocation entry; confirm both are processed within the interval and immediately on command. |
| Source | ARCH §4 E-13 |
| Rationale | Timely import and revocation. |

#### FR-5.4 — Import receipt

| Field | Value |
|---|---|
| ID | FR-5.4 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Library Trust Verifier (E-13) **SHALL** write an import receipt containing package identity, artifact digests, signer identity, verification results and import time for every import attempt. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-33; Internal interfaces: I-21; Data stores: D-02 |
| Verification Method | Inspection |
| Verification Statement | Import a valid and an invalid package; inspect both receipts. |
| Source | ARCH §4 E-13 |
| Rationale | Imports are auditable. |

#### FR-5.5 — Manifest registration

| Field | Value |
|---|---|
| ID | FR-5.5 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Local Server Registry (E-14) **SHALL** register each verified manifest's tools, schemas, capability ceiling, secret slots, behavior hints, instance scopes and curation attestations as an immutable server revision. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36; Internal interfaces: I-21; Data stores: D-02 |
| Verification Method | Inspection |
| Verification Statement | Register a fixture manifest; inspect the stored revision for every manifest field group. |
| Source | ARCH §6.3; ARCH §4 E-14 |
| Rationale | The registry is the source of the capability ceiling and the catalog. |

#### FR-5.6 — Server alias

| Field | Value |
|---|---|
| ID | FR-5.6 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Local Server Registry (E-14) **SHALL** assign each server a unique alias of 1 to 16 characters drawn from `a-z 0-9` (CP-42), defaulting to the manifest `server.alias` and editable by an administrator. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Register two servers whose default aliases collide; confirm enablement of the second is blocked until a unique alias is set. |
| Source | FR-1.26; MCP:server/tools §Tool Names |
| Rationale | Aliases form public tool names. |

#### FR-5.7 — Enablement state

| Field | Value |
|---|---|
| ID | FR-5.7 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Local Server Registry (E-14) **SHALL** keep each server revision in one of the states `verified-disabled`, `enabled`, `suspended`, `revoked` or `retired`. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36; Data stores: D-02 |
| Verification Method | Test |
| Verification Statement | Drive a revision through each transition (enable, disable and retire through the G-10 control API routes, suspension by drift, revocation by a signed revocation entry applied by a library scan); confirm the state and that only `enabled` revisions appear in catalogs. |
| Source | ARCH §4 E-14; SEC 8.1 |
| Rationale | Verified does not mean enabled. Suspension and revocation are not operator buttons in release 1.0: the Gateway suspends a revision on drift, tampering or repeated crashes, and a signed revocation entry revokes it, so the test reaches those states the way they occur. |

#### FR-5.8 — Expiry suspension

| Field | Value |
|---|---|
| ID | FR-5.8 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Local Server Registry (E-14) **SHALL** suspend a server revision when its manifest re-curation date or signature expiry passes. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-37; Data stores: D-02 |
| Verification Method | Test |
| Verification Statement | Import a package expiring in 2 minutes; confirm suspension after expiry. |
| Source | ARCH §4 E-14; SEC Appendix A (re-review) |
| Rationale | Curation evidence has a bounded validity. |

#### FR-5.9 — Launch specification

| Field | Value |
|---|---|
| ID | FR-5.9 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Server Runtime Manager (E-15) **SHALL** launch each server instance from a launch specification containing the artifact digest, argument vector, environment allowlist, mounts, network attachment, resource limits and sandbox profile derived from the manifest and the Runtime Profile. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-38; Internal interfaces: I-22, I-23 |
| Verification Method | Inspection |
| Verification Statement | Inspect a generated launch specification against its manifest and Runtime Profile. |
| Source | ARCH §4 E-15 |
| Rationale | Instances are reproducible from declared inputs. |

#### FR-5.12 — Crash handling

| Field | Value |
|---|---|
| ID | FR-5.12 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When an instance exits unexpectedly, the Server Runtime Manager (E-15) **SHALL** mark its in-flight calls indeterminate or failed, restart it on next use, and suspend the server revision after 3 unexpected exits within 5 minutes. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-39; Internal interfaces: I-19 |
| Verification Method | Test |
| Verification Statement | Make a fixture crash four times in 5 minutes; confirm the call outcomes, the restarts and the suspension. |
| Source | MCP:basic/transports/stdio §Unexpected Termination; SEC 7.2 |
| Rationale | Restart is expected, but a crash loop is a fault. |

#### FR-5.13 — stdio framing

| Field | Value |
|---|---|
| ID | FR-5.13 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Tool Dispatcher (E-10) **SHALL** exchange stdio-transport messages with instances as single-line UTF-8 JSON-RPC messages delimited by newline. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23, F-24; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Run the southbound stdio conformance fixtures; confirm framing in both directions. |
| Source | MCP:basic/transports/stdio |
| Rationale | stdio binding framing. |

#### FR-5.14 — Invalid stdout

| Field | Value |
|---|---|
| ID | FR-5.14 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When an instance writes a stdout line that is not a valid JSON-RPC message, the Tool Dispatcher (E-10) **SHALL** fail the affected in-flight calls and request instance termination. |
| Allocation | Elements: E-10 Tool Dispatcher, E-15 Server Runtime Manager; Functions: F-24, F-40; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Make a fixture print a non-JSON line; confirm the call fails with -31007 and the instance is terminated. |
| Source | MCP:basic/transports/stdio |
| Rationale | Servers must write only valid MCP messages to stdout. |

#### FR-5.15 — stderr capture

| Field | Value |
|---|---|
| ID | FR-5.15 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Server Runtime Manager (E-15) **SHALL** capture instance stderr into a diagnostic buffer bounded by CP-37 and **SHALL** exclude stderr content from harness-bound traffic. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-39; Internal interfaces: I-29 |
| Verification Method | Test |
| Verification Statement | Make a fixture write 10 MiB to stderr; confirm the bound and that nothing reaches the harness. |
| Source | MCP:basic/transports/stdio |
| Rationale | stderr is diagnostic, untrusted and potentially large. |

#### FR-5.19 — Legacy southbound handshake

| Field | Value |
|---|---|
| ID | FR-5.19 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | For a legacy instance, the Tool Dispatcher (E-10) **SHALL** send `initialize` with protocol version 2025-11-25, empty capabilities and Gateway `clientInfo`, followed by `notifications/initialized`, before any other request. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Connect to a legacy fixture; confirm the handshake sequence and the negotiated version. |
| Source | CP-05; MCP:basic/versioning §Backward Compatibility |
| Rationale | Dual-era client behavior. |

#### FR-5.20 — Legacy server-initiated requests

| Field | Value |
|---|---|
| ID | FR-5.20 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When a legacy instance sends `ping`, the Tool Dispatcher (E-10) **SHALL** reply with an empty result, and when it sends any other request, the Tool Dispatcher **SHALL** reply with JSON-RPC error `-32601`. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-24; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Make a legacy fixture send ping, sampling, elicitation and roots requests; confirm the replies. |
| Source | SEC 5.6; MCP:basic/patterns/mrtr |
| Rationale | The Gateway declares no client capabilities southbound. |

#### FR-5.21 — Startup tool list

| Field | Value |
|---|---|
| ID | FR-5.21 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | After the era probe, the Tool Dispatcher (E-10) **SHALL** retrieve the instance's complete `tools/list` across all pages and pass it to the Local Server Registry (E-14) for comparison with the manifest. |
| Allocation | Elements: E-10 Tool Dispatcher, E-14 Local Server Registry; Functions: F-24, F-37; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Start a fixture with 3 pages of tools; confirm all pages are retrieved and compared. |
| Source | SEC 3.8; MCP:server/utilities/pagination |
| Rationale | Detects tool drift before first use. |

#### FR-5.22 — Backend tool definition validity

| Field | Value |
|---|---|
| ID | FR-5.22 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Local Server Registry (E-14) **SHALL** treat as drift a backend tool whose `inputSchema` is null or invalid, whose `inputSchema` declares a property name outside 1 to 64 characters of `A-Z a-z 0-9 _ . -`, or whose `x-mcp-header` annotations violate MCP constraints. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-37 |
| Verification Method | Test |
| Verification Statement | Serve fixtures with each defect, including a 65-character property name and a name containing a space; confirm drift handling. |
| Source | MCP:server/tools §Tool; MCP:basic/transports/streamable-http §Schema Extension; Client-Compatibility-Brief §3 |
| Rationale | The Gateway must not present invalid tool definitions, and Claude Code drops a tool whose property names fall outside this set. Root-level schema combinators are not treated as drift because Claude Code flattens them itself and the Gateway validates arguments against the manifest schema regardless of presentation. |

#### FR-5.23 — Result type handling

| Field | Value |
|---|---|
| ID | FR-5.23 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Tool Dispatcher (E-10) **SHALL** treat a backend result without `resultType` as `"complete"` and a result with an unrecognized `resultType` as invalid. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-24; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Return results with no, known and unknown `resultType`; confirm handling. |
| Source | MCP:basic/index §ResultType |
| Rationale | Backward compatibility and strictness. |

#### FR-5.24 — InputRequiredResult without MRTR profile

| Field | Value |
|---|---|
| ID | FR-5.24 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When the MRTR Relay Profile is disabled and a backend returns an `InputRequiredResult`, the Tool Dispatcher (E-10) **SHALL** return Gateway error `-31010` to the harness. |
| Allocation | Elements: E-10 Tool Dispatcher, E-02 Protocol Mediator; Functions: F-24, F-22; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Make a fixture return `input_required`; confirm -31010 and an audit event. |
| Source | SEC 5.6; MCP:basic/patterns/mrtr |
| Rationale | Sampling, elicitation and roots are not qualified. |

#### FR-5.26 — Southbound cancellation

| Field | Value |
|---|---|
| ID | FR-5.26 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Tool Dispatcher (E-10) **SHALL** cancel a southbound call to a stdio instance by sending `notifications/cancelled` with the request ID. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-25; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Cancel a call to a stdio fixture; confirm the instance receives `notifications/cancelled` naming the request ID. |
| Source | MCP:basic/patterns/cancellation |
| Rationale | Transport-specific cancellation rules. Release 1.0 runs stdio instances only; cancellation on Streamable HTTP instances returns with the southbound HTTP client (Appendix N, FR-5.28). |

#### FR-5.27 — Instance shutdown

| Field | Value |
|---|---|
| ID | FR-5.27 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Server Runtime Manager (E-15) **SHALL** stop an stdio instance by closing its stdin, waiting 5 seconds, sending SIGTERM, waiting 5 seconds and sending SIGKILL. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-40; Internal interfaces: I-23 |
| Verification Method | Test |
| Verification Statement | Stop a fixture that ignores EOF and SIGTERM; confirm the escalation timing. |
| Source | MCP:basic/transports/stdio §Shutdown |
| Rationale | Graceful but bounded shutdown. |

#### FR-5.32 — Southbound progress token

| Field | Value |
|---|---|
| ID | FR-5.32 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When a northbound call requests progress, the Tool Dispatcher (E-10) **SHALL** send a Gateway-generated progress token southbound that is unique among active southbound requests. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Make concurrent progress-enabled calls; confirm unique southbound tokens. |
| Source | MCP:basic/patterns/progress |
| Rationale | Tokens must be unique, and northbound tokens are not forwarded. |

#### FR-5.33 — Runtime observables

| Field | Value |
|---|---|
| ID | FR-5.33 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Runtime Monitor (E-17) **SHALL** collect, per instance, process creations, memory peak, CPU time and OOM or limit events. |
| Allocation | Elements: E-17 Runtime Monitor; Functions: F-42; Internal interfaces: I-24 |
| Verification Method | Test |
| Verification Statement | Run a fixture performing each behavior; confirm each event is collected. |
| Source | ARCH §4 E-17; ARCH §10.3 P-100–P-108 |
| Rationale | Run-time controls and characterization need these observables. Release 1.0 reads them from the instance's cgroup and the Podman event stream, which rootless Podman provides without privileges. File opens outside the declared mounts and network connection attempts are not observed: they need privileged tracing (fanotify or eBPF) that the rootless Enforced profile does not have. They are prevented instead: an instance sees only its granted mounts (SR-4.6-1) and reaches only its Egress Broker endpoints (SR-4.5-1), and the broker records every operation (FR-5.36). |

#### FR-5.34 — Declared-behavior rules

| Field | Value |
|---|---|
| ID | FR-5.34 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Runtime Monitor (E-17) **SHALL** evaluate each runtime event against the manifest's declared behavior rules and **SHALL** emit a deviation event for each violation. |
| Allocation | Elements: E-17 Runtime Monitor; Functions: F-43; Internal interfaces: I-18 |
| Verification Method | Test |
| Verification Statement | Make a fixture spawn an undeclared process; confirm a deviation event. |
| Source | ARCH §4 E-17 |
| Rationale | Rule-based run-time detection. |

#### FR-5.35 — Containment actions

| Field | Value |
|---|---|
| ID | FR-5.35 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When a deviation event matches a containment rule, the Runtime Monitor (E-17) **SHALL** perform the rule's action (`alert` or `kill-instance`) within 1 second. |
| Allocation | Elements: E-17 Runtime Monitor; Functions: F-44; Internal interfaces: I-19 |
| Verification Method | Test |
| Verification Statement | Trigger each action; confirm effect and latency. |
| Source | ARCH §4 E-17 |
| Rationale | Bounded response to run-time misbehavior. The `suspend-revision` and `suspend-session` actions of ARCH §4 E-17 are not part of release 1.0: a killed instance is restarted on next use and a revision whose instance keeps ending is suspended by the Server Runtime Manager (FR-5.12), and an operator suspends a revision or ends a session from the console (G-10, G-08). |

#### FR-5.36 — Egress endpoints

| Field | Value |
|---|---|
| ID | FR-5.36 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Egress Broker (E-18) **SHALL** expose, per instance, one local plain-HTTP endpoint for each egress destination granted to that instance and **SHALL** originate the TLS connection to the bound HTTPS destination. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45; External interfaces: X-06; Internal interfaces: I-25 |
| Verification Method | Test |
| Verification Statement | Grant two destinations; confirm two endpoints exist and that requests reach the destinations over validated TLS. |
| Source | ARCH §4 E-18; ARCH §8.2 S1 |
| Rationale | TLS origination at the broker enables credential injection and inspection. |

#### FR-5.37 — Egress configuration injection

| Field | Value |
|---|---|
| ID | FR-5.37 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Server Runtime Manager (E-15) **SHALL** provide each instance with the base URLs of its egress endpoints through the environment variables named in the manifest. |
| Allocation | Elements: E-15 Server Runtime Manager, E-18 Egress Broker; Functions: F-38; Internal interfaces: I-22 |
| Verification Method | Inspection |
| Verification Statement | Inspect a launched instance's environment; confirm the endpoint variables and the absence of any secret value. |
| Source | ARCH §4 E-18 |
| Rationale | Servers find their egress paths without holding credentials. |

#### FR-5.38 — Egress limits

| Field | Value |
|---|---|
| ID | FR-5.38 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Egress Broker (E-18) **SHALL** bound each outbound operation's request size, response size and duration by the smallest of the manifest, Runtime Profile and decision obligations. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45; External interfaces: X-06 |
| Verification Method | Test |
| Verification Statement | Exceed each bound with a fixture; confirm termination and an event. |
| Source | SEC Appendix F (resource limits) |
| Rationale | Bounded egress resource use. Release 1.x reads the Runtime Profile from the `[egress]` limits and grant of the configuration (FR-3.26), the manifest limits from the optional `request_bytes`, `response_bytes` and `timeout_ms` of its egress rules (Appendix J), and the decision obligation from the optional `egress_limits` of the permit rule, which travels with the call's egress capabilities. |

#### FR-5.39 — Artifact cache

| Field | Value |
|---|---|
| ID | FR-5.39 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Local Server Registry (E-14) **SHALL** store each verified artifact in a content-addressed cache keyed by its SHA-256 digest and **SHALL** retain it while any non-retired revision references it. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36; Internal interfaces: I-21; Data stores: D-03 |
| Verification Method | Test |
| Verification Statement | Import two revisions sharing an artifact, retire one, then the other; confirm single storage and removal only after both retire. |
| Source | ARCH §13 D-03 |
| Rationale | Launches use local verified artifacts without re-fetching. |

#### FR-5.40 — Era agreement with the manifest

| Field | Value |
|---|---|
| ID | FR-5.40 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When the protocol version an instance negotiates in the FR-5.19 handshake differs from the era its verified manifest declares, the Tool Dispatcher (E-10) **SHALL** refuse to use the instance and the Local Server Registry (E-14) **SHALL** suspend the server revision. |
| Allocation | Elements: E-10 Tool Dispatcher, E-14 Local Server Registry; Functions: F-23; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Launch a fixture whose manifest declares 2026-07-28 while the instance negotiates 2025-11-25; confirm the instance is not used and the revision is suspended. |
| Source | SEC 5.1; MCP:basic/versioning |
| Rationale | Release 1.0 speaks only the 2025-11-25 era southbound (Appendix N lists the deferred modern-era requirements); a revision packaged as modern must not be driven with legacy behavior. |

### FR-6 Secrets

#### FR-6 — Secret management

| Field | Value |
|---|---|
| ID | FR-6 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** store server secrets and deliver each secret only through a policy-selected delivery mode for an authorized use. |
| Allocation | Elements: E-19 Secret Vault, E-20 Secret Broker; Functions: F-47, F-48, F-49, F-50, F-51, F-52 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-6 child requirement; confirm each has passed. |
| Source | ARCH §2.1 item 5; ARCH §8 |
| Rationale | Managed secrets are an owner capability. |

#### FR-6.1 — Secret record

| Field | Value |
|---|---|
| ID | FR-6.1 |
| Parent ID | FR-6 — Secret management |
| Statement | The Secret Vault (E-19) **SHALL** store for each secret a reference ID, name, type, version, owner, creation time, rotation time, expiry and the encrypted value. |
| Allocation | Elements: E-19 Secret Vault; Functions: F-47; Data stores: D-04 |
| Verification Method | Inspection |
| Verification Statement | Create a secret through G-12; inspect the stored record and confirm the value field is ciphertext. |
| Source | ARCH §4 E-19 |
| Rationale | Secrets need versioned, attributable records. |

#### FR-6.2 — Write-only values

| Field | Value |
|---|---|
| ID | FR-6.2 |
| Parent ID | FR-6 — Secret management |
| Statement | The Secret Vault (E-19) **SHALL** accept secret values on create and rotate operations and **SHALL** return only metadata on every read operation. |
| Allocation | Elements: E-19 Secret Vault; Functions: F-47; External interfaces: X-08; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Call every secret read operation of the control API; confirm no value or ciphertext is returned. |
| Source | ARCH §4 E-19; SEC 8.5 |
| Rationale | Values can be written but never read back. |

#### FR-6.3 — Rotation

| Field | Value |
|---|---|
| ID | FR-6.3 |
| Parent ID | FR-6 — Secret management |
| Statement | The Secret Vault (E-19) **SHALL** rotate a secret by creating a new version, keeping the previous version deliverable for at most the CP-15 overlap, and then retiring it. |
| Allocation | Elements: E-19 Secret Vault; Functions: F-48 |
| Verification Method | Test |
| Verification Statement | Rotate a secret; confirm delivery of the new version and that the old version stops at the overlap limit. |
| Source | ARCH §4 E-19; SEC Appendix A |
| Rationale | Rotation without downtime. |

#### FR-6.4 — Retirement zeroization

| Field | Value |
|---|---|
| ID | FR-6.4 |
| Parent ID | FR-6 — Secret management |
| Statement | When a secret version is retired, the Secret Vault (E-19) **SHALL** delete its ciphertext and record a retirement event. |
| Allocation | Elements: E-19 Secret Vault; Functions: F-48; Internal interfaces: I-18 |
| Verification Method | Test |
| Verification Statement | Retire a version; confirm the ciphertext is absent from the store and a retirement event exists. |
| Source | ARCH §4 E-19 |
| Rationale | Retired material must not remain recoverable from the vault. |

#### FR-6.5 — Secret slot binding

| Field | Value |
|---|---|
| ID | FR-6.5 |
| Parent ID | FR-6 — Secret management |
| Statement | A secret **SHALL** be bound to a server only through a Secret Use Policy naming a declared secret slot, the permitted tools, destination, delivery mode, purpose, rate, time window and approval requirement, and the Policy Administration Service (E-05) **SHALL** show each binding in the effective permission report. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Publish a Secret Use Policy for a declared slot; confirm the binding appears in the effective permission report. |
| Source | ARCH §7.2 Secret Use Policy |
| Rationale | Secret use is governed by policy. Release 1.0 declares secret slots in the Secret Use Policy document (or as `secret_env` entries of the server configuration); the secret slots of a signed manifest (Appendix J) are recorded with the package but not read by the Secret Broker. |

#### FR-6.6 — Delivery mode S1

| Field | Value |
|---|---|
| ID | FR-6.6 |
| Parent ID | FR-6 — Secret management |
| Statement | For delivery mode S1, the Secret Broker (E-20) **SHALL** pass the secret to the Egress Broker (E-18), which **SHALL** insert it into the header template declared by the slot on each authorized request to the bound destination. |
| Allocation | Elements: E-20 Secret Broker, E-18 Egress Broker; Functions: F-50, F-46; Internal interfaces: I-26 |
| Verification Method | Test |
| Verification Statement | Call a fixture API through S1; confirm the destination receives the header and the instance environment, memory dump and mounts lack the value. |
| Source | ARCH §8.2 S1 |
| Rationale | The preferred mode keeps the secret outside the sandbox. |

#### FR-6.7 — Delivery mode S2

| Field | Value |
|---|---|
| ID | FR-6.7 |
| Parent ID | FR-6 — Secret management |
| Statement | For delivery mode S2, the Secret Broker (E-20) **SHALL** write the secret to a per-call file in an instance-private tmpfs mount before dispatch and **SHALL** delete the file when the call completes. |
| Allocation | Elements: E-20 Secret Broker; Functions: F-50, F-52; Internal interfaces: I-28 |
| Verification Method | Test |
| Verification Statement | Call an S2 fixture; confirm the file exists during the call and not after. |
| Source | ARCH §8.2 S2 |
| Rationale | Short exposure for protocols the broker cannot proxy. |

#### FR-6.8 — Delivery mode S3

| Field | Value |
|---|---|
| ID | FR-6.8 |
| Parent ID | FR-6 — Secret management |
| Statement | For delivery mode S3, the Secret Broker (E-20) **SHALL** write the secret to an instance-private tmpfs file at instance launch and **SHALL** delete it at instance teardown. |
| Allocation | Elements: E-20 Secret Broker; Functions: F-50, F-52; Internal interfaces: I-28 |
| Verification Method | Test |
| Verification Statement | Launch and tear down an S3 instance; confirm the file lifetime. |
| Source | ARCH §8.2 S3 |
| Rationale | Long-lived connections need instance-lifetime secrets. |

#### FR-6.9 — Delivery mode S4

| Field | Value |
|---|---|
| ID | FR-6.9 |
| Parent ID | FR-6 — Secret management |
| Statement | The Secret Broker (E-20) **SHALL** deliver a secret through a launch environment variable only when the secret slot declares no other mode and the Secret Use Policy carries an approved S4 waiver. |
| Allocation | Elements: E-20 Secret Broker, E-05 Policy Administration Service; Functions: F-50, F-10 |
| Verification Method | Test |
| Verification Statement | Attempt S4 with and without a waiver and with another supported mode; confirm only the waiver-without-alternative case is accepted. |
| Source | ARCH §8.2 S4 |
| Rationale | Environment delivery is the most exposing mode. Release 1.0 declares secret slots in the Secret Use Policy document (or as `secret_env` entries of the server configuration); the secret slots of a signed manifest (Appendix J) are recorded with the package but not read by the Secret Broker. |

#### FR-6.10 — Leak fingerprints

| Field | Value |
|---|---|
| ID | FR-6.10 |
| Parent ID | FR-6 — Secret management |
| Statement | The Secret Broker (E-20) **SHALL** derive keyed HMAC-SHA-256 fingerprints over each delivered secret's full value and every 12-character substring of its raw, Base64, hex and URL-encoded forms, and **SHALL** register them with the Response Inspection Pipeline (E-11) and the Observation Collector (E-29). |
| Allocation | Elements: E-20 Secret Broker; Functions: F-51; Internal interfaces: I-14 |
| Verification Method | Test |
| Verification Statement | Deliver a secret and return it raw, Base64-encoded and as a 12-character fragment in a response; confirm each is detected. |
| Source | ARCH §8.5 |
| Rationale | Leak detection without holding plaintext in the filters. |

#### FR-6.11 — Secret use event

| Field | Value |
|---|---|
| ID | FR-6.11 |
| Parent ID | FR-6 — Secret management |
| Statement | The Secret Broker (E-20) **SHALL** record each delivery and each denial with secret reference, version, slot, mode, server revision, tool, correlation ID and decision ID, and without the secret value. |
| Allocation | Elements: E-20 Secret Broker; Functions: F-49, F-50; Internal interfaces: I-18 |
| Verification Method | Test |
| Verification Statement | Deliver and deny secrets; inspect the events and search them for the value. |
| Source | ARCH §4 E-20 |
| Rationale | Every secret use is attributable. |

#### FR-6.12 — Reference impact preview

| Field | Value |
|---|---|
| ID | FR-6.12 |
| Parent ID | FR-6 — Secret management |
| Statement | The Secret Vault (E-19) **SHALL** report every Secret Use Policy, server revision and slot that references a selected secret. |
| Allocation | Elements: E-19 Secret Vault; Functions: F-47; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Bind a secret in two policies; confirm both appear in the impact report. |
| Source | SEC 8.5 |
| Rationale | Operators see the effect of rotation or revocation. |

### FR-7 Audit, keys and health

#### FR-7 — Assurance services

| Field | Value |
|---|---|
| ID | FR-7 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** record security evidence, manage its cryptographic keys and monitor the health of enforcement dependencies. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-22 Key & Trust Anchor Manager, E-23 Health & Safety Monitor |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-7 child requirement; confirm each has passed. |
| Source | ARCH §4 SS-7 |
| Rationale | Assurance services support every control. |

#### FR-7.1 — Event schema

| Field | Value |
|---|---|
| ID | FR-7.1 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Audit & Evidence Service (E-21) **SHALL** record each security event with event ID, timestamp, event class, phase, origin, correlation ID, session ID, principal ID, decision ID, policy revision, server revision, tool revision, outcome, reason code and policy status. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-53; Internal interfaces: I-18 |
| Verification Method | Inspection |
| Verification Statement | Inspect events of each class; confirm each field is present or explicitly null. |
| Source | A2 §4.1; SEC 6.4; SEC 6.19 |
| Rationale | A uniform schema enables linkage and query. |

#### FR-7.2 — Event phases

| Field | Value |
|---|---|
| ID | FR-7.2 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Audit & Evidence Service (E-21) **SHALL** support the call phases `requested`, `denied`, `authorized`, `dispatched`, `completed`, `failed`, `indeterminate`, `filtered`, `delivered` and `withheld`. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-53 |
| Verification Method | Test |
| Verification Statement | Drive calls to each terminal outcome; confirm the recorded phase sequence. |
| Source | A2 §5 |
| Rationale | Observed phases, not inferred success. |

#### FR-7.3 — Audit query API

| Field | Value |
|---|---|
| ID | FR-7.3 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Audit & Evidence Service (E-21) **SHALL** answer audit queries filtered by time range, principal, session, server, tool, rule, outcome, event class and policy revision, with cursor pagination of at most 500 events per page. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-57; Internal interfaces: I-06, I-30 |
| Verification Method | Test |
| Verification Statement | Run each filter over the reference dataset; confirm correct results and page bounds. |
| Source | SEC 8.4 |
| Rationale | Investigation needs bounded, structured queries. |

#### FR-7.4 — Journal segment format

| Field | Value |
|---|---|
| ID | FR-7.4 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Audit & Evidence Service (E-21) **SHALL** write the evidence journal as JSON Lines segments closed at 1,000 events or 60 seconds, each holding the SHA-256 of the previous segment and an Ed25519 signature. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-55; Data stores: D-06 |
| Verification Method | Inspection |
| Verification Statement | Inspect three consecutive segments; confirm the chaining and signatures. |
| Source | ARCH §4 E-21; SEC 6.12 |
| Rationale | Tamper evidence that is independent of the Data Server. |

#### FR-7.5 — Journal verification

| Field | Value |
|---|---|
| ID | FR-7.5 |
| Parent ID | FR-7 — Assurance services |
| Statement | The `smcpctl journal verify` command **SHALL** validate the hash chain and the signature of every segment in a journal directory and report the first failure. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-55; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Verify an intact journal and one with a modified byte; confirm a pass and a precise failure. |
| Source | ARCH §4 E-21 |
| Rationale | Evidence must be checkable offline. |

#### FR-7.7 — Local certificate authorities

| Field | Value |
|---|---|
| ID | FR-7.7 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Key & Trust Anchor Manager (E-22) **SHALL** operate a local certificate authority for Gateway TLS server certificates whose key is used for no other purpose, and **SHALL** issue from it only certificates limited to TLS server authentication. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-59, F-60; Data stores: D-08 |
| Verification Method | Inspection |
| Verification Statement | Inspect the CA certificate, an issued server certificate and the key inventory; confirm the CA key has one purpose and the issued certificate allows server authentication only. |
| Source | ARCH §4 E-22; OWNER (mTLS Harness Profile deferred) |
| Rationale | Separates client identity from server identity. Release 1.0 issues no client certificates (the mTLS Harness Profile, FR-2.14, is deferred), so the separate client CA is deferred with it (FR-7.15). |

#### FR-7.8 — Key purposes

| Field | Value |
|---|---|
| ID | FR-7.8 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Gateway **SHALL** use a separate key for each of the purposes server CA, server TLS, policy signing, vault master, backup encryption, evidence signing, cursor protection, leak-fingerprint keying, research pseudonymization and Data Server credentials, and **SHALL** use no key for more than one purpose. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-60; Data stores: D-08 |
| Verification Method | Inspection |
| Verification Statement | Inspect the key inventory; confirm one key per purpose and no reuse. |
| Source | ARCH §4 E-22 |
| Rationale | Compromise of one purpose must not affect others. Release 1.0 has no client CA (the mTLS Harness Profile, FR-2.14, is deferred), no MRTR state protection key (the MRTR Relay Profile, FR-5.25, is deferred) and no payload encryption (no payload is stored encrypted outside the vault and backups, which have their own keys). Backup encryption uses the operator's passphrase or age recipients, never a Gateway key. Leak-fingerprint keying (FR-6.10) is listed because it is a key purpose of its own. |

#### FR-7.10 — Trust anchor enrollment

| Field | Value |
|---|---|
| ID | FR-7.10 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Key & Trust Anchor Manager (E-22) **SHALL** enroll a curation trust anchor only after an administrator confirms its displayed fingerprint and assigns its permitted risk classes and expiry. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-58; Internal interfaces: I-06 |
| Verification Method | Demonstration |
| Verification Statement | Enroll an anchor through G-10; confirm the fingerprint confirmation step and the stored scope. |
| Source | ARCH §4 E-22 |
| Rationale | The trust root is set by a deliberate operator ceremony. |

#### FR-7.11 — Health checks

| Field | Value |
|---|---|
| ID | FR-7.11 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Health & Safety Monitor (E-23) **SHALL** evaluate once per second, as critical causes, decision-snapshot currency, Evidence Journal writability and signing lag, mandatory-audit capacity, vault availability, clock sanity and trust-anchor validity, and, as non-critical causes, graph mirror reachability, Observation Store reachability, memory degradation stage and, in the Standalone profile, `unconfined`. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61; Internal interfaces: I-32 |
| Verification Method | Test |
| Verification Statement | Fault each dependency in turn; confirm detection within 2 seconds, `fail-closed` for each critical cause and `degraded` for each non-critical cause. |
| Source | ARCH §4 E-23; ARCH §2.2 A-8, A-9; OWNER (authority decoupling) |
| Rationale | Enforcement depends on the policy snapshot and the journal, not on the graph or the Observation Store, whose loss degrades analytics only. |

#### FR-7.12 — Health states

| Field | Value |
|---|---|
| ID | FR-7.12 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Health & Safety Monitor (E-23) **SHALL** report the Gateway health as `healthy`, `degraded` or `fail-closed` together with the list of active causes. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61, F-62; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Induce a non-critical and a critical fault; confirm `degraded` and `fail-closed` with causes. |
| Source | ARCH §4 E-23 |
| Rationale | Distinguishes degraded observation from unsafe enforcement. |

#### FR-7.13 — Fail-closed recovery

| Field | Value |
|---|---|
| ID | FR-7.13 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Health & Safety Monitor (E-23) **SHALL** return from `fail-closed` to `healthy` only after every critical cause has cleared for 10 consecutive seconds and, for integrity causes, after an administrator acknowledgment. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-62; Internal interfaces: I-19 |
| Verification Method | Test |
| Verification Statement | Clear an availability cause and an integrity cause; confirm the automatic and the acknowledged recovery. |
| Source | ARCH §4 E-23; SEC 7.3 |
| Rationale | Prevents flapping and requires review after integrity failures. |

#### FR-7.14 — Evidence export

| Field | Value |
|---|---|
| ID | FR-7.14 |
| Parent ID | FR-7 — Assurance services |
| Statement | When evidence export is configured, the Audit & Evidence Service (E-21) **SHALL** copy each closed journal segment and checkpoint to the configured local export directory within 60 seconds of segment closure. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-55; External interfaces: X-09; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Configure an export directory; close segments; confirm copies within 60 s and that the copies verify with `smcpctl journal verify`. |
| Source | ARCH §6.1 X-09 |
| Rationale | Offline archival of evidence without a network service. |

### FR-8 Management console and control API

#### FR-8 — Management product

| Field | Value |
|---|---|
| ID | FR-8 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** provide a local graphical console and control API for controlling the Gateway, managing policy and tuning audit, observation and research capture. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-63, F-64, F-65, F-67, F-68, F-69; External interfaces: X-04 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-8 child requirement; confirm each has passed. |
| Source | ARCH §2.1 item 10; SEC 8 |
| Rationale | The owner requires one GUI for control, policy and audit tuning. |

#### FR-8.1 — Control API

| Field | Value |
|---|---|
| ID | FR-8.1 |
| Parent ID | FR-8 — Management product |
| Statement | The Management Console & Control API (E-24) **SHALL** expose a versioned REST/JSON control API at `/api/v1` on the CP-03 admin listener, described by an OpenAPI 3.1 document served at `/api/v1/openapi.json`. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04; Internal interfaces: I-06 |
| Verification Method | Inspection |
| Verification Statement | Retrieve the OpenAPI document; confirm that every console operation maps to a documented endpoint. |
| Source | A2 §7.2; ARCH §6.1 X-04 |
| Rationale | The GUI and scripts share one contract. |

#### FR-8.2 — Application roles

| Field | Value |
|---|---|
| ID | FR-8.2 |
| Parent ID | FR-8 — Management product |
| Statement | The Management Console & Control API (E-24) **SHALL** implement the roles Administrator, Operator, Policy Author, Approver, Session Approver, Auditor and Researcher with the permissions of Appendix C. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-64; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Exercise every API operation as each role; confirm results match the Appendix C matrix. |
| Source | SEC 8.10; ARCH §4 E-24 |
| Rationale | Separation of duties, including research use. |

#### FR-8.3 — G-01 Gateway Control

| Field | Value |
|---|---|
| ID | FR-8.3 |
| Parent ID | FR-8 — Management product |
| Statement | The Gateway Control view (G-01) **SHALL** display enforcement state, health causes, active policy revision and active session count, and **SHALL** provide emergency stop and resume actions. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65, F-31; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Use G-01 to stop and resume the Gateway; confirm the state display updates within 2 seconds. |
| Source | ARCH §4 G-01; SEC 8.7 |
| Rationale | The operator's primary control surface. |

#### FR-8.4 — G-02 Policy Studio

| Field | Value |
|---|---|
| ID | FR-8.4 |
| Parent ID | FR-8 — Management product |
| Statement | The Policy Studio view (G-02) **SHALL** provide structured editors for the policy object types Framework Profile, Session Allow Policy Template and Secret Use Policy, draft diff against the active revision, simulation results and publish and rollback actions; the other object types of FR-3.1 are edited in their own views (Audit Profile in G-03, Observation Policy in G-04, Anomaly Response Policy in G-06, Research Campaign in G-09). |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65, F-10, F-11, F-12; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Author, simulate and publish a Session Allow Policy template entirely in G-02. |
| Source | ARCH §4 G-02; SEC 8.2 |
| Rationale | Policy development is the owner's primary purpose. ARCH §4 assigns G-02 the Framework Profiles, Session Allow templates, Response and Secret Use Policies; the Response Policy is deferred (FR-3.26). |

#### FR-8.5 — G-03 Audit Profile Tuning

| Field | Value |
|---|---|
| ID | FR-8.5 |
| Parent ID | FR-8 — Management product |
| Statement | The Audit Profile Tuning view (G-03) **SHALL** display the mandatory audit floor as read-only and **SHALL** edit optional capture, retention and alert settings of Audit Profiles. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Edit an Audit Profile in G-03; confirm the floor is not editable and the profile publishes. |
| Source | ARCH §4 G-03; ARCH §11 item 9 |
| Rationale | Audit tuning without weakening the floor. |

#### FR-8.6 — G-04 Observation & Parameter Workbench

| Field | Value |
|---|---|
| ID | FR-8.6 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** present the Parameter Catalog grouped by category with search, description, unit, sensitivity class and cost indicator for each parameter. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67; External interfaces: X-04; Data stores: D-11 |
| Verification Method | Demonstration |
| Verification Statement | Search the catalog for "latency"; confirm grouped results with each attribute shown. |
| Source | ARCH §11 item 1; ARCH §10.1 |
| Rationale | The owner requires a user-friendly parameter selection GUI. |

#### FR-8.7 — Catalog-driven GUI

| Field | Value |
|---|---|
| ID | FR-8.7 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** generate its parameter controls from the Parameter Catalog data so that a catalog parameter added by release appears without GUI code change. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67; Data stores: D-11 |
| Verification Method | Test |
| Verification Statement | Add a parameter to a test catalog version; confirm it appears in G-04 with no GUI rebuild. |
| Source | ARCH §10.1 |
| Rationale | The catalog must grow to capture as many parameters as possible. |

#### FR-8.8 — Observation presets

| Field | Value |
|---|---|
| ID | FR-8.8 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** provide the editable presets Minimal security floor, Security standard, Behavior characterization, Performance profiling and Research — full capture, and **SHALL** save user-defined presets. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67; Data stores: D-11 |
| Verification Method | Demonstration |
| Verification Statement | Apply each preset, modify one and save it as a new preset. |
| Source | ARCH §11 item 2 |
| Rationale | Presets make capture tuning approachable. |

#### FR-8.9 — Scope builder

| Field | Value |
|---|---|
| ID | FR-8.9 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** select Observation Policy scope from lists of registered principals, framework types, session templates, servers and tools. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Build a scope of one principal and two tools without free-text entry. |
| Source | ARCH §11 item 3 |
| Rationale | Prevents scope typos. |

#### FR-8.10 — Sampling and baseline controls

| Field | Value |
|---|---|
| ID | FR-8.10 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** edit the normal-band sampling rate, per-band escalation parameters, baseline context dimensions, per-feature statistics options and sigma-band thresholds. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Set each control and publish; confirm the stored Observation Policy values. |
| Source | ARCH §9.5; ARCH §11 items 4–5 |
| Rationale | These are the research tuning parameters. |

#### FR-8.11 — Cost preview display

| Field | Value |
|---|---|
| ID | FR-8.11 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** display a cost preview of the draft (the selected parameters, bytes per captured record, content scans and payload copies, the sampling rate in force and the store growth at the recorded call volume), refreshed with each edit, and **SHALL** keep the publish action disabled while the draft has no cost preview. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67, F-66; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Edit a draft; confirm the preview refreshes with each edit and publish remains disabled while the draft has no preview. |
| Source | ARCH §11 item 6 |
| Rationale | Cost awareness before capture. The F-66 forecast of records, storage and added latency per day from seven days of call rates is deferred with FR-3.7; release 1.0 previews the cost from the catalog's data types and cost classes and the recorded call volume. |

#### FR-8.12 — Live record preview

| Field | Value |
|---|---|
| ID | FR-8.12 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** display up to 20 sensitivity-masked sample records that the draft would have produced from the most recent stored records: the records within the draft's scope, with a value for each of the draft's parameters that the Observation Policy in force captured. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Preview a draft; confirm masked sample records appear. |
| Source | ARCH §11 item 7 |
| Rationale | Researchers verify the capture before publishing. Release 1.0 stores no payloads (SR-6.6-1), so a parameter the policy in force did not capture cannot be derived again for the preview; the preview marks it. |

#### FR-8.13 — G-05 Behavior Analytics

| Field | Value |
|---|---|
| ID | FR-8.13 |
| Parent ID | FR-8 — Management product |
| Statement | The Behavior Analytics view (G-05) **SHALL** display per-context feature distributions, z-score timelines, abnormal-event lists with drill-down, and baseline snapshot diffs with promote and rollback actions. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-68, F-86; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Inspect a context, open an abnormal event and promote a snapshot from G-05. |
| Source | ARCH §4 G-05 |
| Rationale | Characterization results must be inspectable. |

#### FR-8.14 — G-06 Anomaly Response Policy

| Field | Value |
|---|---|
| ID | FR-8.14 |
| Parent ID | FR-8 — Management product |
| Statement | The Anomaly Response Policy view (G-06) **SHALL** map each sigma band and the uncharacterized state to actions selected from the restrict-only action set. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Configure each band and publish; confirm only restrict-only actions are selectable. |
| Source | ARCH §9.6 |
| Rationale | Run-time policy development. |

#### FR-8.15 — G-07 Performance & Meta-metrics

| Field | Value |
|---|---|
| ID | FR-8.15 |
| Parent ID | FR-8 — Management product |
| Statement | The Performance & Meta-metrics view (G-07) **SHALL** display throughput, p50/p95/p99 gateway-added overhead, per-stage latency and per-rule and per-filter time cost, filterable by policy revision. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-69; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Compare two policy revisions' cost in G-07. |
| Source | ARCH §10.4 |
| Rationale | The owner requires policy time-cost measurement. |

#### FR-8.16 — G-08 Data Server & Memory

| Field | Value |
|---|---|
| ID | FR-8.16 |
| Parent ID | FR-8 — Management product |
| Statement | The Data Server & Memory view (G-08) **SHALL** display per-component memory use against budget, cache hit ratios, store sizes, quota percentage, degradation stage and last backup result, and **SHALL** edit memory budgets. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-69; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Change a budget in G-08; confirm it is applied and displayed. |
| Source | ARCH §4 G-08 |
| Rationale | The owner requires memory management. |

#### FR-8.17 — G-09 Research Campaigns & Export

| Field | Value |
|---|---|
| ID | FR-8.17 |
| Parent ID | FR-8 — Management product |
| Statement | The Research Campaigns & Export view (G-09) **SHALL** create, submit, approve, monitor and export research campaigns and **SHALL** display the data dictionary of each dataset. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65, F-91, F-93; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Run a campaign through its full lifecycle in G-09. |
| Source | ARCH §18.5 |
| Rationale | Research-instrument use. |

#### FR-8.18 — G-10 Servers & Library

| Field | Value |
|---|---|
| ID | FR-8.18 |
| Parent ID | FR-8 — Management product |
| Statement | The Servers & Library view (G-10) **SHALL** list server revisions with state, alias, manifest, attestations, drift and revocation status, and **SHALL** provide enable, suspend, retire, alias and trust-anchor actions. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Enable, suspend and retire a server from G-10. |
| Source | ARCH §4 G-10; SEC 8.1 |
| Rationale | Server lifecycle control. |

#### FR-8.19 — G-11 Sessions & Principals

| Field | Value |
|---|---|
| ID | FR-8.19 |
| Parent ID | FR-8 — Management product |
| Statement | The Sessions & Principals view (G-11) **SHALL** manage principals and their credentials and **SHALL** list, inspect, suspend and terminate sessions. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Create a principal, issue a credential and terminate one of its sessions from G-11. |
| Source | ARCH §4 G-11 |
| Rationale | Identity and session control. |

#### FR-8.20 — G-12 Secrets

| Field | Value |
|---|---|
| ID | FR-8.20 |
| Parent ID | FR-8 — Management product |
| Statement | The Secrets view (G-12) **SHALL** provide write-only secret creation and rotation, reference-impact preview, and revocation. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Create, rotate and revoke a secret from G-12; confirm no value is ever displayed. |
| Source | ARCH §4 G-12; SEC 8.5 |
| Rationale | Secret administration. |

#### FR-8.21 — G-13 Approvals

| Field | Value |
|---|---|
| ID | FR-8.21 |
| Parent ID | FR-8 — Management product |
| Statement | The Approvals view (G-13) **SHALL** list pending approvals with remaining validity and **SHALL** provide approve and deny actions. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65, F-18; External interfaces: X-05 |
| Verification Method | Demonstration |
| Verification Statement | Approve and deny requests from G-13. |
| Source | ARCH §4 G-13 |
| Rationale | Out-of-band approval channel. |

#### FR-8.22 — G-14 Audit Investigation

| Field | Value |
|---|---|
| ID | FR-8.22 |
| Parent ID | FR-8 — Management product |
| Statement | The Audit Investigation view (G-14) **SHALL** navigate from an event to its decision, rule revisions, route, server revision, baseline snapshot and related phases, and **SHALL** render the path as a bounded graph. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65, F-57; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Start from a withheld event and navigate to its decisive rule and server revision. |
| Source | SEC 8.3; A2 §7.2 |
| Rationale | Graph-led investigation. |

#### FR-8.23 — Live updates

| Field | Value |
|---|---|
| ID | FR-8.23 |
| Parent ID | FR-8 — Management product |
| Statement | The Management Console & Control API (E-24) **SHALL** push state changes to open console views through a server-sent-events channel within 2 seconds of the change. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Change health state and add a pending approval; confirm both views update within 2 seconds. |
| Source | ARCH §4 E-24 |
| Rationale | The operator must see current state. |

#### FR-8.24 — Usability

| Field | Value |
|---|---|
| ID | FR-8.24 |
| Parent ID | FR-8 — Management product |
| Statement | The Observation & Parameter Workbench view (G-04) **SHALL** allow a first-time user who has the in-console help to create and publish a scoped Observation Policy of at least 10 parameters within 10 minutes. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-67; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Run a timed task with three first-time users; confirm at least two complete within 10 minutes. |
| Source | OWNER ("user-friendly GUI"); ARCH §11 |
| Rationale | Makes "user friendly" measurable. |

#### FR-8.25 — Inline help

| Field | Value |
|---|---|
| ID | FR-8.25 |
| Parent ID | FR-8 — Management product |
| Statement | The Management Console & Control API (E-24) **SHALL** provide a help entry for every view, policy field and catalog parameter, loaded from local storage. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65, F-67 |
| Verification Method | Inspection |
| Verification Statement | Inspect each view and a sample of 30 parameters; confirm help is present. |
| Source | SEC 8.8; ARCH §11 |
| Rationale | Supports unaided use. |

#### FR-8.26 — Local assets

| Field | Value |
|---|---|
| ID | FR-8.26 |
| Parent ID | FR-8 — Management product |
| Statement | The Management Console & Control API (E-24) **SHALL** load all production scripts, styles, fonts and help from the local installation. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Load every view with outbound network blocked; confirm full function and no external requests. |
| Source | SEC 8.8 |
| Rationale | Offline local product. |

#### FR-8.27 — Filter test workbench

| Field | Value |
|---|---|
| ID | FR-8.27 |
| Parent ID | FR-8 — Management product |
| Statement | The Policy Studio view (G-02) **SHALL** run a selected request or response filter profile against operator-supplied synthetic input and display each filter's matches, transformations, timing and final disposition. |
| Allocation | Elements: E-24 Management Console & Control API, E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline; Functions: F-65, F-21, F-27; External interfaces: X-04 |
| Verification Method | Demonstration |
| Verification Statement | Test a redaction profile on synthetic text in G-02; confirm matches, transformed output and disposition are shown. |
| Source | SEC 8.6 |
| Rationale | Filter development is part of policy research. |

#### FR-8.28 — Navigation and deep links

| Field | Value |
|---|---|
| ID | FR-8.28 |
| Parent ID | FR-8 — Management product |
| Statement | The Management Console & Control API (E-24) **SHALL** present a persistent navigation listing every view G-01 to G-14 that the signed-in role may open, and **SHALL** give each view and each approval, session, server revision, decision and policy revision its own URL that opens it directly after sign-in. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Sign in as each role; confirm the navigation lists exactly the permitted views; open the URL of an approval, session, server revision, decision and policy revision in a new browser session; confirm each opens after sign-in. |
| Source | REVIEW (I5); OWNER (console deep link from approval fallback) |
| Rationale | The approval fallback text and the notifications link to a specific record; the console must open it. |

#### FR-8.29 — Empty, error and loading states

| Field | Value |
|---|---|
| ID | FR-8.29 |
| Parent ID | FR-8 — Management product |
| Statement | Each view G-01 to G-14 **SHALL** show a loading state within 200 ms of navigation, an empty state that names the action that would populate it, and an error state that shows the control API error message and reason code with a retry action. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | For each view, run the Playwright suite against an empty installation, a delayed API and a failing API; confirm the three states. |
| Source | REVIEW (I5) |
| Rationale | A blank or frozen view gives the operator no way to tell an empty system from a broken one. |

#### FR-8.30 — Supported browsers

| Field | Value |
|---|---|
| ID | FR-8.30 |
| Parent ID | FR-8 — Management product |
| Statement | The console **SHALL** support the two most recent major versions, at release time, of Chromium-based browsers, Firefox and Safari on macOS. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Run the per-view Playwright suite on Chromium, Firefox and WebKit at the release commit; confirm all pass. |
| Source | REVIEW (I5) |
| Rationale | States what the release is tested against. |

#### FR-8.31 — First-run checklist

| Field | Value |
|---|---|
| ID | FR-8.31 |
| Parent ID | FR-8 — Management product |
| Statement | The Gateway Control view (G-01) **SHALL** show a first-run checklist with the items administrator created, Session Approver created, first server packaged and enabled, first policy revision published, first harness connected, approval tested and backup configured, each marked done from Gateway state and linked to the view that completes it. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Start from a fresh installation; complete each item; confirm each is marked done from Gateway state and not from a manual tick. |
| Source | REVIEW (I5) |
| Rationale | A new operator needs the order of first steps; deriving completion from state keeps the list truthful. |

#### FR-8.32 — Accessibility conformance

| Field | Value |
|---|---|
| ID | FR-8.32 |
| Parent ID | FR-8 — Management product |
| Statement | Each console view **SHALL** conform to WCAG 2.2 Level AA. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Run `axe-core` with the WCAG 2.2 AA rule set on every view and state of the Playwright suite; confirm zero violations; record a manual check of focus order, target size and contrast in `docs/verification/`. |
| Source | OWNER (WCAG 2.2 AA) |
| Rationale | Owner decision; the console is the primary control surface for every role. |

#### FR-8.33 — Keyboard operation

| Field | Value |
|---|---|
| ID | FR-8.33 |
| Parent ID | FR-8 — Management product |
| Statement | Each console action **SHALL** be operable with the keyboard alone, with a visible focus indicator and no keyboard trap. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | For each view, drive every action in the Playwright suite with keyboard events only; confirm completion and a visible focus indicator at each step. |
| Source | OWNER (keyboard operable) |
| Rationale | Owner decision; operators who live in terminals expect keyboard control. |

#### FR-8.34 — Per-view acceptance tests

| Field | Value |
|---|---|
| ID | FR-8.34 |
| Parent ID | FR-8 — Management product |
| Statement | The Gateway source **SHALL** include a Playwright acceptance test for each view G-01 to G-14 that exercises the view's primary actions against a running Gateway and claims the view's requirements through the requirement report. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Inspection |
| Verification Statement | Inspect the Playwright suite and the requirement report; confirm one passing test per view that claims that view's FR-8 requirement. |
| Source | REVIEW (I5); SEC 10.6 |
| Rationale | Each view's requirements need test evidence, not a screenshot. |

#### FR-8.35 — Visual rules

| Field | Value |
|---|---|
| ID | FR-8.35 |
| Parent ID | FR-8 — Management product |
| Statement | The console **SHALL** present lists as tables with sortable column headers, **SHALL** use a single typeface family with a fixed type scale, and **SHALL** use no gradients, emoji, decorative icon grids or card grids. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65; External interfaces: X-04 |
| Verification Method | Inspection |
| Verification Statement | Inspect every view against the visual rule checklist in `docs/console-style.md`; confirm each rule. |
| Source | OWNER (dense, stark, typographic, tables over cards, no gradients, emoji or icon grids) |
| Rationale | Owner decision; dense tables suit audit and operations work. |

### FR-9 Data Server

#### FR-9 — Data Server

| Field | Value |
|---|---|
| ID | FR-9 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** hold the behavior model and observation data, and mirrors of policy, registry, session and audit data, in a Data Server consisting of a graph database, a columnar Observation Store, a Data Access Service and a Data Lifecycle & Memory Manager, with no enforcement decision depending on the Data Server's availability. |
| Allocation | Elements: E-25 Graph Database Engine, E-26 Data Access Service, E-27 Observation Store, E-28 Data Lifecycle & Memory Manager |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-9 child requirement and of FR-9.17; confirm each has passed. |
| Source | ARCH §4 SS-9; ARCH §2.2 A-9; OWNER (graph database; authority decoupling) |
| Rationale | The owner requires a graph database for graph views and characterization, and decided that its unavailability degrades analytics but never opens or blocks enforcement. |

#### FR-9.1 — Graph data model

| Field | Value |
|---|---|
| ID | FR-9.1 |
| Parent ID | FR-9 — Data Server |
| Statement | The Graph Database Engine (E-25) **SHALL** store the node labels and relationship types defined in Appendix D with a uniqueness constraint on the `id` property of every label. |
| Allocation | Elements: E-25 Graph Database Engine; Functions: F-70; Data stores: D-01, D-02, D-05, D-07, D-10, D-11 |
| Verification Method | Inspection |
| Verification Statement | Inspect the deployed schema; confirm every Appendix D label, relationship and constraint. |
| Source | A2 §4.1; ARCH §13.1 |
| Rationale | A defined graph model is required for code and queries. |

#### FR-9.2 — Schema migrations

| Field | Value |
|---|---|
| ID | FR-9.2 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Access Service (E-26) **SHALL** apply versioned, ordered schema migrations at startup and **SHALL** refuse to start when the database schema version is newer than the release supports. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-72; Internal interfaces: I-36 |
| Verification Method | Test |
| Verification Statement | Start against an older schema and a newer schema; confirm migration and refusal respectively. |
| Source | ARCH §4 E-26 |
| Rationale | Controlled data-model evolution. |

#### FR-9.3 — Typed operation catalog

| Field | Value |
|---|---|
| ID | FR-9.3 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Access Service (E-26) **SHALL** expose to other elements only the typed operations listed in its versioned operation catalog, each mapped to one fixed parameterized query template. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-72; Internal interfaces: I-07, I-30, I-33, I-34, I-35, I-06 |
| Verification Method | Inspection |
| Verification Statement | Inspect the operation catalog and its templates; confirm a one-to-one mapping and no dynamic query construction. |
| Source | ARCH §4 E-26; SEC 1.13 |
| Rationale | Fixed operations keep query cost and authority reviewable. |

#### FR-9.5 — Observation batching

| Field | Value |
|---|---|
| ID | FR-9.5 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Access Service (E-26) **SHALL** write observation records to the Observation Store in batches of at most 1,000 records or 200 milliseconds, whichever occurs first. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-73; Internal interfaces: I-37 |
| Verification Method | Test |
| Verification Statement | Generate 5,000 records per second; confirm batch sizes and maximum batch latency. |
| Source | ARCH §4 E-26 |
| Rationale | Batching sustains ingest rate. |

#### FR-9.6 — Backpressure

| Field | Value |
|---|---|
| ID | FR-9.6 |
| Parent ID | FR-9 — Data Server |
| Statement | When the P2 write queue exceeds 80% of its capacity, the Data Access Service (E-26) **SHALL** signal backpressure to the Observation Collector (E-29). |
| Allocation | Elements: E-26 Data Access Service; Functions: F-74; Internal interfaces: I-33, I-38 |
| Verification Method | Test |
| Verification Statement | Stall the Observation Store; confirm the backpressure signal at 80% queue occupancy. |
| Source | ARCH §4 E-26; ARCH §18.6 |
| Rationale | Optional capture yields before resources are exhausted. |

#### FR-9.7 — Observation tables

| Field | Value |
|---|---|
| ID | FR-9.7 |
| Parent ID | FR-9 — Data Server |
| Statement | The Observation Store (E-27) **SHALL** store observation records, timing spans and system metrics in separate tables partitioned by UTC day, with one column per Parameter Catalog parameter. |
| Allocation | Elements: E-27 Observation Store; Functions: F-75; Data stores: D-09, D-13 |
| Verification Method | Inspection |
| Verification Statement | Inspect the store layout after one day of fixture traffic. |
| Source | ARCH §13 D-09, D-13 |
| Rationale | Columnar layout gives fast aggregation. |

#### FR-9.8 — Schema evolution

| Field | Value |
|---|---|
| ID | FR-9.8 |
| Parent ID | FR-9 — Data Server |
| Statement | When a new Parameter Catalog version adds a parameter, the Observation Store (E-27) **SHALL** add a nullable column for it without rewriting existing partitions. |
| Allocation | Elements: E-27 Observation Store; Functions: F-75; Data stores: D-09 |
| Verification Method | Test |
| Verification Statement | Upgrade the catalog; confirm the new column and that old partitions are unchanged. |
| Source | ARCH §4 E-27 |
| Rationale | The parameter set grows over time. |

#### FR-9.9 — Aggregate queries

| Field | Value |
|---|---|
| ID | FR-9.9 |
| Parent ID | FR-9 — Data Server |
| Statement | The Observation Store (E-27) **SHALL** answer aggregate queries (count, mean, variance, quantiles, histograms) grouped by baseline context and time bucket for the Baseline Engine, the console and the Research Dataset Service. |
| Allocation | Elements: E-27 Observation Store; Functions: F-76; Internal interfaces: I-37 |
| Verification Method | Test |
| Verification Statement | Compare query results with an independent computation over a fixture dataset. |
| Source | ARCH §4 E-27 |
| Rationale | Baselines, analytics and research all need aggregates. |

#### FR-9.10 — Memory budget application

| Field | Value |
|---|---|
| ID | FR-9.10 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Lifecycle & Memory Manager (E-28) **SHALL** apply the CP-33 memory budget to the graph engine heap and page cache, the Observation Store memory limit, the baseline cache and the capture queues at startup and on change. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-77; Internal interfaces: I-38 |
| Verification Method | Test |
| Verification Statement | Change budgets through G-08; confirm each component's configured limit. |
| Source | ARCH §4 E-28; OWNER (manage memory) |
| Rationale | The owner requires memory management. |

#### FR-9.11 — Memory accounting

| Field | Value |
|---|---|
| ID | FR-9.11 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Lifecycle & Memory Manager (E-28) **SHALL** measure each budgeted component's memory use every 5 seconds. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-77; Internal interfaces: I-32, I-38 |
| Verification Method | Test |
| Verification Statement | Compare reported use with operating-system accounting under load; confirm agreement within 10%. |
| Source | ARCH §4 E-28 |
| Rationale | Budgets need measurement. |

#### FR-9.12 — Degradation order

| Field | Value |
|---|---|
| ID | FR-9.12 |
| Parent ID | FR-9 — Data Server |
| Statement | When a component exceeds 90% of its budget or the host has less than 10% available memory, the Data Lifecycle & Memory Manager (E-28) **SHALL** apply, in order, reduced normal-band sampling, suspension of S3 payload capture, pausing of research campaigns and cache shrinking to configured floors. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-77; Internal interfaces: I-38, I-32 |
| Verification Method | Test |
| Verification Statement | Induce memory pressure; confirm the stages in order and the reported stage. |
| Source | ARCH §4 E-28; ARCH §18.6 |
| Rationale | Optional work yields first. |

#### FR-9.14 — Retention execution

| Field | Value |
|---|---|
| ID | FR-9.14 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Lifecycle & Memory Manager (E-28) **SHALL** delete observation and research data whose policy retention has expired, at least once per day. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-78; Data stores: D-09, D-12 |
| Verification Method | Test |
| Verification Statement | Set a 1-day retention; confirm deletion after expiry. |
| Source | ARCH §4 E-28 |
| Rationale | Retention is a policy obligation. |

#### FR-9.15 — Quota thresholds

| Field | Value |
|---|---|
| ID | FR-9.15 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Lifecycle & Memory Manager (E-28) **SHALL** warn at 80% of each storage quota and **SHALL** report quota levels to the Health & Safety Monitor (E-23). |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-78; Internal interfaces: I-32 |
| Verification Method | Test |
| Verification Statement | Fill a test quota to 80% and 95%; confirm the warning and the reported levels. |
| Source | SEC Appendix A (audit storage) |
| Rationale | Capacity awareness. |

#### FR-9.16 — Backup scheduling

| Field | Value |
|---|---|
| ID | FR-9.16 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Lifecycle & Memory Manager (E-28) **SHALL** perform scheduled and on-demand backups containing the Policy Store, the Server Registry, the configuration, the encrypted vault, the Evidence Journal, key material and trust anchors, and optionally the Observation Store and a graph dump, as one encrypted archive (D-15), and **SHALL** record each backup's result and checksum. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-79; Data stores: D-01, D-02, D-04, D-06, D-08, D-15 |
| Verification Method | Test |
| Verification Statement | Run an on-demand backup with and without the optional parts; confirm every component is present after decryption and the recorded checksum matches. |
| Source | ARCH §4 E-28; SEC 7.7 |
| Rationale | Recoverability of all stores. |

#### FR-9.17 — Startup gating

| Field | Value |
|---|---|
| ID | FR-9.17 |
| Parent ID | FR-9 — Data Server |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** refuse harness MCP requests with Gateway error `-31004` until a decision snapshot compiled from a signature-verified Policy Store revision is loaded and the Evidence Journal is open for writing, and **SHALL** serve requests without waiting for the graph mirror or the Observation Store. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-05 Policy Administration Service, E-21 Audit & Evidence Service; Functions: F-01, F-62 |
| Verification Method | Test |
| Verification Statement | Start the Gateway with an unsigned policy revision, then with a read-only journal directory, then correctly with the graph database stopped; confirm -31004 in the first two cases and normal service in the third with health `degraded`. |
| Source | ARCH §4 E-23; ARCH §2.2 A-9; SEC 1.2 |
| Rationale | No service without verified policy and a writable evidence record; the graph is a mirror (OWNER, authority decoupling). |

#### FR-9.18 — Decision and event indexes

| Field | Value |
|---|---|
| ID | FR-9.18 |
| Parent ID | FR-9 — Data Server |
| Statement | The Graph Database Engine (E-25) **SHALL** maintain indexes on decision timestamp, event timestamp, event correlation ID, session ID and server revision ID. |
| Allocation | Elements: E-25 Graph Database Engine; Functions: F-70, F-71 |
| Verification Method | Inspection |
| Verification Statement | Inspect the index list; confirm each index is online. |
| Source | ARCH §14 (GUI query target) |
| Rationale | Investigation query performance. |

### FR-10 Observation, behavior characterization and research

#### FR-10 — Observation and analytics

| Field | Value |
|---|---|
| ID | FR-10 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** capture policy-selected observation parameters and meta-metrics, learn statistical baselines of normal behavior, classify activity by standard-deviation distance from those baselines, and export research datasets. |
| Allocation | Elements: E-29 Observation Collector, E-30 Behavior Baseline Engine, E-31 Anomaly Scorer, E-32 Research Dataset Service |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-10 child requirement; confirm each has passed. |
| Source | ARCH §2.1 items 6–9; ARCH §9; ARCH §10 |
| Rationale | The Gateway is a vehicle for developing run-time policy and trend-analysis techniques. |

#### FR-10.1 — Observable emission

| Field | Value |
|---|---|
| ID | FR-10.1 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | Each instrumented element (E-01, E-02, E-04, E-06, E-08, E-09, E-10, E-11, E-12, E-15, E-17, E-18) **SHALL** emit its catalog-defined raw observables keyed by correlation ID to the Observation Collector (E-29) without blocking its processing path. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-80; Internal interfaces: I-29 |
| Verification Method | Test |
| Verification Statement | Stall E-29 consumption; confirm that instrumented elements continue processing and that drops are counted. |
| Source | ARCH §4 E-29; ARCH §6.2 I-29 |
| Rationale | Observation must not change enforcement timing. |

#### FR-10.2 — Timing spans

| Field | Value |
|---|---|
| ID | FR-10.2 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | Each instrumented element **SHALL** emit a timing span per stage containing stage ID, monotonic start and end, CPU time, correlation ID and the ID of the policy object that caused the work. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-83; External interfaces: X-10; Internal interfaces: I-29 |
| Verification Method | Test |
| Verification Statement | Trace a call; confirm a span for every FR-4.3 stage with each field. |
| Source | ARCH §10.4 |
| Rationale | Enables per-policy time-cost attribution. |

#### FR-10.3 — Record assembly

| Field | Value |
|---|---|
| ID | FR-10.3 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** assemble one observation record per call from the observables sharing its correlation ID, after the call's release or failure. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-80, F-81 |
| Verification Method | Test |
| Verification Statement | Make 1,000 calls; confirm 1,000 records, each joined correctly. |
| Source | ARCH §4 E-29 |
| Rationale | Per-call records are the analysis unit. |

#### FR-10.4 — Parameter selection

| Field | Value |
|---|---|
| ID | FR-10.4 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** include in each record only the parameters named by the effective Observation Policy or Research Campaign plus the identifiers P-001, P-004, P-022, P-023, P-080 and P-087. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-82 |
| Verification Method | Test |
| Verification Statement | Publish a policy selecting 5 parameters; confirm records contain exactly those plus the identifiers. |
| Source | ARCH §4 E-29; ARCH §10.3 |
| Rationale | Capture follows policy. |

#### FR-10.5 — Feature extraction

| Field | Value |
|---|---|
| ID | FR-10.5 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** compute each derived parameter according to its Parameter Catalog definition. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-81; Data stores: D-11 |
| Verification Method | Test |
| Verification Statement | Compare computed features for a fixture call set with reference values; confirm exact match for integer features and agreement within 1e-9 relative error for real-valued features. |
| Source | ARCH §10.3 |
| Rationale | Feature correctness underlies the research. |

#### FR-10.6 — Deterministic sampling

| Field | Value |
|---|---|
| ID | FR-10.6 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** select normal-band calls for capture by comparing a hash of the correlation ID with the policy sampling rate. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-82 |
| Verification Method | Test |
| Verification Statement | Replay a fixed call set twice at 10%; confirm the same calls are selected and the fraction is 10% ± 1% over 10,000 calls. |
| Source | ARCH §9.5 (Sampling) |
| Rationale | Reproducible sampling. |

#### FR-10.7 — Capture escalation

| Field | Value |
|---|---|
| ID | FR-10.7 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | When a call's anomaly band is `elevated` or worse, the Observation Collector (E-29) **SHALL** capture that call in full with the escalation parameters of its band. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-82; Internal interfaces: I-31 |
| Verification Method | Test |
| Verification Statement | Trigger an abnormal fixture during 10% sampling; confirm full capture with escalation parameters. |
| Source | ARCH §9.5 (Capture escalation) |
| Rationale | Abnormal behavior is always recorded. |

#### FR-10.8 — Drop accounting

| Field | Value |
|---|---|
| ID | FR-10.8 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** count every observable or record dropped or sampled down, by reason, and **SHALL** report the counts as parameter P-246. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-82, F-83 |
| Verification Method | Test |
| Verification Statement | Induce backpressure; confirm the counts match the injected drop volume. |
| Source | ARCH §4 E-29 |
| Rationale | Silent loss would bias research. |

#### FR-10.9 — System meta-metrics

| Field | Value |
|---|---|
| ID | FR-10.9 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** sample the system meta-metrics P-240 to P-250 every 10 seconds. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-83; Data stores: D-13 |
| Verification Method | Test |
| Verification Statement | Run for 5 minutes; confirm 30 samples per metric. |
| Source | ARCH §10.3 (system meta-metrics) |
| Rationale | Throughput and resource trends. |

#### FR-10.10 — Gateway-added overhead

| Field | Value |
|---|---|
| ID | FR-10.10 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** compute parameter P-213 for each call as end-to-end latency minus server execution time minus approval wait time. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-83 |
| Verification Method | Test |
| Verification Statement | Compare P-213 with an independent harness-side measurement for fixture calls; confirm agreement within 1 ms. |
| Source | ARCH §10.3 P-213 |
| Rationale | The owner's cost-in-time metric. |

#### FR-10.11 — Policy cost attribution

| Field | Value |
|---|---|
| ID | FR-10.11 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Observation Collector (E-29) **SHALL** aggregate span time by policy revision, rule ID, filter ID and Observation Policy ID. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-83; Data stores: D-13 |
| Verification Method | Test |
| Verification Statement | Run fixture traffic with a deliberately slow filter; confirm that filter ranks first in aggregated cost. |
| Source | ARCH §10.4 |
| Rationale | Identifies which policy elements cost the most time. |

#### FR-10.12 — Context key computation

| Field | Value |
|---|---|
| ID | FR-10.12 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** group observation records by the baseline context dimensions selected in the Observation Policy. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-84; Internal interfaces: I-34 |
| Verification Method | Test |
| Verification Statement | Configure (principal, tool) contexts; confirm one context per observed pair. |
| Source | ARCH §9.3 |
| Rationale | Baselines are per context. |

#### FR-10.13 — Streaming statistics

| Field | Value |
|---|---|
| ID | FR-10.13 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** maintain per context and feature the count, mean and M2 accumulator using Welford's online algorithm, with optional exponential decay at the policy half-life. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-84; Data stores: D-10 |
| Verification Method | Test |
| Verification Statement | Feed a 1,000,000-value fixture series; confirm mean and variance agree with two-pass computation within 1e-9 relative error. |
| Source | ARCH §9.2 |
| Rationale | Numerically stable streaming mean and standard deviation. |

#### FR-10.14 — Feature transforms

| Field | Value |
|---|---|
| ID | FR-10.14 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** apply the per-feature transform selected in the Observation Policy, from `none`, `log1p` and `box-cox(λ)`, before updating statistics. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-84 |
| Verification Method | Test |
| Verification Statement | Configure each transform; confirm the stored statistics are of transformed values. |
| Source | ARCH §9.2 (Skewed features) |
| Rationale | Sizes and latencies are right-skewed. |

#### FR-10.15 — Robust statistics option

| Field | Value |
|---|---|
| ID | FR-10.15 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | When robust scoring is selected for a feature, the Behavior Baseline Engine (E-30) **SHALL** maintain a t-digest sketch from which median and MAD are derived. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-84; Data stores: D-10 |
| Verification Method | Test |
| Verification Statement | Compare sketch median and MAD with exact values over a fixture; confirm agreement within 1%. |
| Source | ARCH §9.2 (Robust option) |
| Rationale | Heavy-tailed features. |

#### FR-10.16 — Categorical and sequence features

| Field | Value |
|---|---|
| ID | FR-10.16 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** maintain category and tool-transition frequencies per context and **SHALL** baseline the surprise value −log p of each observed category or transition. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-84; Data stores: D-10 |
| Verification Method | Test |
| Verification Statement | Feed a fixed transition sequence; confirm the stored frequencies and surprise statistics. |
| Source | ARCH §9.2; ARCH §13.1 NEXT_TOOL |
| Rationale | Detects unusual tool sequences. |

#### FR-10.17 — Learning exclusions

| Field | Value |
|---|---|
| ID | FR-10.17 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** exclude from learning the records of denied calls, records classified `abnormal` or `critical`, records from flagged sessions and records outside the learning window. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-84 |
| Verification Method | Test |
| Verification Statement | Feed a mix of excluded and included records; confirm only the included records change the statistics. |
| Source | ARCH §9.4 step 1; ARCH §2.2 A-6 |
| Rationale | Defends against baseline poisoning. |

#### FR-10.18 — Snapshot build

| Field | Value |
|---|---|
| ID | FR-10.18 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** build an immutable baseline snapshot, containing snapshot ID, digest, contexts, per-feature statistics, sample counts and learning window, at the policy interval or record count and on operator command. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-85; Data stores: D-10 |
| Verification Method | Test |
| Verification Statement | Trigger a snapshot by each method; inspect the contents and confirm immutability. |
| Source | ARCH §9.4 step 2 |
| Rationale | Scoring uses fixed, versioned baselines. |

#### FR-10.19 — Drift report

| Field | Value |
|---|---|
| ID | FR-10.19 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** report, for a candidate snapshot against the promoted snapshot, the per-context mean shift in promoted-σ units, the σ ratio and the list of newly characterized contexts. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-87; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Build a candidate from shifted fixture data; confirm the reported shift values. |
| Source | ARCH §9.4 step 3 |
| Rationale | Reviewers see what promotion changes. |

#### FR-10.20 — Promotion

| Field | Value |
|---|---|
| ID | FR-10.20 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** promote a candidate snapshot on authorized operator approval, or automatically when every drift value is within the policy's automatic-promotion limits. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-86; Internal interfaces: I-39 |
| Verification Method | Test |
| Verification Statement | Promote manually; then configure limits and confirm automatic promotion within limits and none beyond them. |
| Source | ARCH §9.4 step 4; ARCH §19 OD-11 |
| Rationale | Controlled change of the enforcement baseline. |

#### FR-10.21 — Rollback

| Field | Value |
|---|---|
| ID | FR-10.21 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** re-promote any earlier snapshot on authorized operator command. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-86; Internal interfaces: I-39 |
| Verification Method | Test |
| Verification Statement | Roll back to a prior snapshot; confirm subsequent scores record its ID. |
| Source | ARCH §9.4 step 5 |
| Rationale | Recover from a bad baseline. |

#### FR-10.22 — Snapshot loading

| Field | Value |
|---|---|
| ID | FR-10.22 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Anomaly Scorer (E-31) **SHALL** load a promoted snapshot into memory, verify its digest and atomically replace the previous snapshot. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-88; Internal interfaces: I-39 |
| Verification Method | Test |
| Verification Statement | Promote during load; confirm no score uses a partially loaded snapshot and that a corrupted snapshot is rejected. |
| Source | ARCH §4 E-31 |
| Rationale | Consistent scoring. |

#### FR-10.23 — z-score computation

| Field | Value |
|---|---|
| ID | FR-10.23 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Anomaly Scorer (E-31) **SHALL** compute each selected feature's score as z = (x − μ) / max(σ, σ_floor) using the snapshot statistics of the session's context and the same transform used in learning. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-88, F-89 |
| Verification Method | Test |
| Verification Statement | Score fixture values against a known snapshot; confirm z-scores agree with reference computation within 1e-9. |
| Source | ARCH §9.2 (Distance) |
| Rationale | The owner's standard-deviation distance measure. |

#### FR-10.24 — Robust score

| Field | Value |
|---|---|
| ID | FR-10.24 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | When robust scoring is selected for a feature, the Anomaly Scorer (E-31) **SHALL** compute z_robust = 0.6745 (x − median) / max(MAD, σ_floor). |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-88, F-89 |
| Verification Method | Test |
| Verification Statement | Score fixture values; confirm agreement with reference values. |
| Source | ARCH §9.2 (Robust option) |
| Rationale | Alternative distance for heavy tails. |

#### FR-10.25 — Score combination

| Field | Value |
|---|---|
| ID | FR-10.25 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Anomaly Scorer (E-31) **SHALL** combine feature scores by maximum absolute z and **SHALL** record the contributing feature. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-90 |
| Verification Method | Test |
| Verification Statement | Score a fixture with several elevated features; confirm the maximum and the named feature. |
| Source | ARCH §9.2 (Multi-feature); ARCH §19 OD-12 |
| Rationale | Explainable combination. |

#### FR-10.26 — Band classification

| Field | Value |
|---|---|
| ID | FR-10.26 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Anomaly Scorer (E-31) **SHALL** classify the combined score into `normal`, `elevated`, `abnormal` or `critical` using the Observation Policy thresholds, with CP-30 as defaults. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-90 |
| Verification Method | Test |
| Verification Statement | Score values at each boundary; confirm the band. |
| Source | ARCH §9.2 (Default sigma bands) |
| Rationale | Bands drive actions and capture. |

#### FR-10.27 — Uncharacterized context

| Field | Value |
|---|---|
| ID | FR-10.27 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | When a session's context has fewer than n_min samples in the promoted snapshot, the Anomaly Scorer (E-31) **SHALL** return the band `uncharacterized`. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-90 |
| Verification Method | Test |
| Verification Statement | Score a new context; confirm `uncharacterized` until n_min is reached in a promoted snapshot. |
| Source | ARCH §9.2 (Cold start) |
| Rationale | No scoring without sufficient data. |

#### FR-10.28 — Asynchronous scoring

| Field | Value |
|---|---|
| ID | FR-10.28 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | When the Observation Policy selects asynchronous scoring, the Anomaly Scorer (E-31) **SHALL** score the assembled observation record after release and **SHALL** apply only alert and capture-escalation actions. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-90; Internal interfaces: I-31 |
| Verification Method | Test |
| Verification Statement | Configure asynchronous scoring; trigger an abnormal call; confirm an alert, unchanged release timing and no blocking action. |
| Source | ARCH §9.5 (Scoring mode); ARCH §19 OD-10 |
| Rationale | Zero hot-path cost option. |

#### FR-10.29 — Scoring record

| Field | Value |
|---|---|
| ID | FR-10.29 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Anomaly Scorer (E-31) **SHALL** record for each score the snapshot ID, context key, per-feature values and z-scores, combined score, band and resulting actions. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-90; Internal interfaces: I-29, I-18 |
| Verification Method | Inspection |
| Verification Statement | Inspect the scoring record of an abnormal call. |
| Source | ARCH §9.4 step 6 |
| Rationale | Reproducible classification. |

#### FR-10.30 — Campaign record

| Field | Value |
|---|---|
| ID | FR-10.30 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Research Dataset Service (E-32) **SHALL** manage each research campaign with scope, parameter set, sampling, start, end, storage quota, export grant and state (`draft`, `submitted`, `approved`, `active`, `completed`, `exported`, `expired`). |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-91; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Move a campaign through every state; confirm transitions and recorded fields. |
| Source | ARCH §7.2 Research Campaign; ARCH §18.5 |
| Rationale | Bounded, governed research capture. |

#### FR-10.31 — Campaign activation

| Field | Value |
|---|---|
| ID | FR-10.31 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Research Dataset Service (E-32) **SHALL** activate an approved campaign at its start time and deactivate it at its end time or when its storage quota is reached. |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-91 |
| Verification Method | Test |
| Verification Statement | Run a campaign with a small quota; confirm deactivation at the quota. |
| Source | ARCH §18.5 step 3 |
| Rationale | Time-boxed and bounded capture. |

#### FR-10.32 — Dataset extraction

| Field | Value |
|---|---|
| ID | FR-10.32 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Research Dataset Service (E-32) **SHALL** extract a dataset containing only records within the campaign's scope and time window. |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-92; Internal interfaces: I-35 |
| Verification Method | Test |
| Verification Statement | Extract a dataset with out-of-scope traffic present; confirm exclusion. |
| Source | ARCH §4 E-32 |
| Rationale | Datasets reflect the approved campaign. |

#### FR-10.33 — Pseudonymization

| Field | Value |
|---|---|
| ID | FR-10.33 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Research Dataset Service (E-32) **SHALL** replace principal, session, end-user and S2 identifiers with HMAC-SHA-256 pseudonyms under a per-dataset key from the Key & Trust Anchor Manager (E-22). |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-92; Internal interfaces: I-35 |
| Verification Method | Test |
| Verification Statement | Extract two datasets; confirm consistent pseudonyms within each dataset and different pseudonyms across them. |
| Source | ARCH §4 E-32; CP-40 |
| Rationale | Research data protection. |

#### FR-10.34 — Export formats

| Field | Value |
|---|---|
| ID | FR-10.34 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Research Dataset Service (E-32) **SHALL** export datasets in Parquet, CSV and JSON Lines, and the behavior-model and audit subgraphs in GraphML. |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-93; External interfaces: X-11 |
| Verification Method | Test |
| Verification Statement | Export in each format; confirm each loads in pyarrow, pandas and NetworkX with identical row counts. |
| Source | ARCH §4 E-32; ARCH §6.1 X-11 |
| Rationale | Offline analysis with common tools. |

#### FR-10.35 — Dataset manifest

| Field | Value |
|---|---|
| ID | FR-10.35 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Research Dataset Service (E-32) **SHALL** include with every export a data dictionary generated from the Parameter Catalog, a provenance manifest (campaign, policy revisions, baseline snapshots, catalog version, time range, filters) and a SHA-256 checksum file. |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-93; External interfaces: X-11; Data stores: D-12 |
| Verification Method | Inspection |
| Verification Statement | Inspect an export package for the three files and verify the checksums. |
| Source | ARCH §4 E-32 |
| Rationale | Reproducible research. |

#### FR-10.36 — Export destination

| Field | Value |
|---|---|
| ID | FR-10.36 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Research Dataset Service (E-32) **SHALL** write exports to the configured local export directory and **SHALL** offer them for download through G-09. |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-93; External interfaces: X-11; Data stores: D-12 |
| Verification Method | Test |
| Verification Statement | Export a dataset; confirm the files exist and download through G-09. |
| Source | ARCH §6.1 X-11 |
| Rationale | Local delivery to analysis tools. |

#### FR-10.37 — Parameter Catalog content

| Field | Value |
|---|---|
| ID | FR-10.37 |
| Parent ID | FR-10 — Observation and analytics |
| Statement | The Gateway release **SHALL** include the versioned Parameter Catalog file `docs/parameters.json` containing every parameter ID defined in ArchitectureV2 §10.3, each with ID, name, description, unit, data type, source element, capture point, derivation, sensitivity class, baselinable flag and cost class. |
| Allocation | Elements: E-29 Observation Collector, E-05 Policy Administration Service; Data stores: D-11 |
| Verification Method | Inspection |
| Verification Statement | Run the SRS build, which checks that `docs/parameters.json` holds every §10.3 parameter ID with every attribute; confirm the build reports the catalog count and no catalog error. |
| Source | ARCH §10.1; ARCH §10.3; OWNER (as many parameters as possible); REVIEW (I8) |
| Rationale | The catalog is the research data dictionary. The V1.1 text implied 250 parameters, while §10.3 defines a sparse ID range; the requirement now names the file and the IDs that exist, and the build checks it mechanically. |

### FR-11 Performance and resources

#### FR-11 — Performance

| Field | Value |
|---|---|
| ID | FR-11 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** meet the CP-32 performance targets on recorded reference hardware with the reference dataset. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-06 Policy Decision Service, E-29 Observation Collector, E-31 Anomaly Scorer, E-27 Observation Store, E-24 Management Console & Control API, E-28 Data Lifecycle & Memory Manager |
| Verification Method | Analysis |
| Verification Statement | Review the performance test report; confirm each FR-11 child passed on the recorded hardware. |
| Source | SEC 10.5; SEC Appendix A; ARCH §14 |
| Rationale | Speed is important to the owner. |

#### FR-11.1 — Reference workload

| Field | Value |
|---|---|
| ID | FR-11.1 |
| Parent ID | FR-11 — Performance |
| Statement | The Gateway release **SHALL** include a reference workload generator producing the reference dataset (10,000 rule and registry nodes, 100,000 event nodes, 256 candidate rules per decision) and eight concurrent callers. |
| Allocation | Elements: E-25 Graph Database Engine, E-26 Data Access Service, E-27 Observation Store |
| Verification Method | Inspection |
| Verification Statement | Run the generator; confirm the dataset counts. |
| Source | SEC Appendix A (test reference dataset) |
| Rationale | Repeatable performance measurement. |

#### FR-11.2 — Decision latency

| Field | Value |
|---|---|
| ID | FR-11.2 |
| Parent ID | FR-11 — Performance |
| Statement | The Policy Decision Service (E-06) **SHALL** return decisions with p95 latency of at most 10 ms under the reference workload. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Measure 100,000 decisions under the reference workload; confirm p95 ≤ 10 ms. |
| Source | ARCH §14; SEC Appendix A (≤100 ms ceiling) |
| Rationale | In-memory snapshots make 10 ms achievable; the security SRS ceiling is 100 ms. |

#### FR-11.3 — Scoring latency

| Field | Value |
|---|---|
| ID | FR-11.3 |
| Parent ID | FR-11 — Performance |
| Statement | The Anomaly Scorer (E-31) **SHALL** score a 64-feature vector with p95 latency of at most 2 ms. |
| Allocation | Elements: E-31 Anomaly Scorer; Functions: F-88, F-89 |
| Verification Method | Test |
| Verification Statement | Measure 100,000 scores; confirm p95 ≤ 2 ms. |
| Source | ARCH §14 |
| Rationale | Synchronous scoring must be cheap. |

#### FR-11.4 — Capture overhead

| Field | Value |
|---|---|
| ID | FR-11.4 |
| Parent ID | FR-11 — Performance |
| Statement | The Observation Collector (E-29) **SHALL** add at most 1 ms p95 to the processing path of a call. |
| Allocation | Elements: E-29 Observation Collector; Functions: F-80 |
| Verification Method | Test |
| Verification Statement | Compare P-213 with capture enabled and disabled under the reference workload; confirm the p95 difference ≤ 1 ms. |
| Source | ARCH §14 |
| Rationale | Observation must not distort what it measures. |

#### FR-11.5 — Total overhead

| Field | Value |
|---|---|
| ID | FR-11.5 |
| Parent ID | FR-11 — Performance |
| Statement | The Gateway **SHALL** add at most 50 ms p95 gateway-added overhead (P-213) for a 64 KiB result at eight concurrent calls with synchronous scoring enabled. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-02 Protocol Mediator, E-08 Access Enforcement Point, E-09 Request Inspection Pipeline, E-10 Tool Dispatcher, E-11 Response Inspection Pipeline, E-12 Enforcement Coordinator |
| Verification Method | Test |
| Verification Statement | Measure P-213 under the reference workload; confirm p95 ≤ 50 ms. |
| Source | ARCH §14; SEC Appendix A (≤250 ms ceiling) |
| Rationale | Interactive agent use. |

#### FR-11.6 — Observation ingest

| Field | Value |
|---|---|
| ID | FR-11.6 |
| Parent ID | FR-11 — Performance |
| Statement | The Observation Store (E-27) **SHALL** sustain ingest of at least 2,000 observation records per second for 10 minutes without backpressure. |
| Allocation | Elements: E-27 Observation Store, E-26 Data Access Service; Functions: F-75, F-73 |
| Verification Method | Test |
| Verification Statement | Replay records at 2,000/s for 10 minutes; confirm no backpressure signal. |
| Source | ARCH §14 |
| Rationale | Research capture volumes. |

#### FR-11.7 — Snapshot build time

| Field | Value |
|---|---|
| ID | FR-11.7 |
| Parent ID | FR-11 — Performance |
| Statement | The Behavior Baseline Engine (E-30) **SHALL** build a baseline snapshot of 10,000 contexts in at most 60 seconds. |
| Allocation | Elements: E-30 Behavior Baseline Engine; Functions: F-85 |
| Verification Method | Test |
| Verification Statement | Build a snapshot from a 10,000-context fixture; confirm duration. |
| Source | ARCH §14 |
| Rationale | Timely baseline refresh. |

#### FR-11.8 — GUI query latency

| Field | Value |
|---|---|
| ID | FR-11.8 |
| Parent ID | FR-11 — Performance |
| Statement | The Management Console & Control API (E-24) **SHALL** return bounded audit and analytics queries over 30 days of reference data with p95 latency of at most 2 seconds. |
| Allocation | Elements: E-24 Management Console & Control API, E-26 Data Access Service; Functions: F-57, F-76 |
| Verification Method | Test |
| Verification Statement | Run the standard query set 100 times; confirm p95 ≤ 2 s. |
| Source | SEC Appendix A; ARCH §14 |
| Rationale | Usable investigation and analytics. |

#### FR-11.9 — Idle footprint

| Field | Value |
|---|---|
| ID | FR-11.9 |
| Parent ID | FR-11 — Performance |
| Statement | The Gateway core processes, excluding server instances, browsers and models, **SHALL** use at most 4 GiB combined resident memory when idle. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-77 |
| Verification Method | Test |
| Verification Statement | Measure combined RSS 10 minutes after start with no traffic. |
| Source | SEC Appendix A (core idle footprint) |
| Rationale | Single-PC deployment. |

#### FR-11.10 — Stop latency

| Field | Value |
|---|---|
| ID | FR-11.10 |
| Parent ID | FR-11 — Performance |
| Statement | The Enforcement Coordinator (E-12) **SHALL** deny all launch authorizations within 1 second of an emergency-stop command. |
| Allocation | Elements: E-12 Enforcement Coordinator; Functions: F-31 |
| Verification Method | Test |
| Verification Statement | Issue a stop under load; confirm no launch authorization is issued later than 1 s after the command. |
| Source | SEC 7.6; ARCH §4 E-12 |
| Rationale | Prompt halt. |

### FR-12 Software, build and deployment constraints

#### FR-12 — Implementation constraints

| Field | Value |
|---|---|
| ID | FR-12 |
| Parent ID | — (root) |
| Statement | The Gateway implementation **SHALL** conform to the open-source, local, single-PC deployment constraints of this section. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API, E-25 Graph Database Engine, E-27 Observation Store, E-28 Data Lifecycle & Memory Manager |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-12 child requirement; confirm each has passed. |
| Source | SEC 9; OWNER (single PC; open source only) |
| Rationale | Owner deployment constraints. |

#### FR-12.1 — Open-source components

| Field | Value |
|---|---|
| ID | FR-12.1 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | Each software component and bundled dependency of the Gateway release **SHALL** carry an OSI-approved license or public-domain status. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API, E-25 Graph Database Engine, E-27 Observation Store |
| Verification Method | Inspection |
| Verification Statement | Inspect the release SBOM license fields; confirm every entry is OSI-approved or public domain. |
| Source | SEC 9.1; Section 1 |
| Rationale | Open source only. |

#### FR-12.2 — No external service dependency

| Field | Value |
|---|---|
| ID | FR-12.2 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway **SHALL** perform every baseline function with outbound Internet access blocked, except brokered egress explicitly granted by policy. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-18 Egress Broker, E-24 Management Console & Control API, E-25 Graph Database Engine |
| Verification Method | Test |
| Verification Statement | Run the acceptance suite with an outbound-deny firewall; confirm all baseline functions pass. |
| Source | SEC 9; SEC 9.3 |
| Rationale | Local, non-SaaS operation. |

#### FR-12.3 — Host platform

| Field | Value |
|---|---|
| ID | FR-12.3 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway **SHALL** run in the Enforced profile on a single Linux host (x86_64 or arm64) meeting the Section 1.5.1 prerequisites, and in the Standalone profile on macOS arm64 and on Linux hosts without those prerequisites. |
| Allocation | Elements: E-15 Server Runtime Manager, E-16 Execution Sandbox, E-23 Health & Safety Monitor; External interfaces: X-07 |
| Verification Method | Demonstration |
| Verification Statement | Install and run the acceptance suite on a GitHub-hosted Ubuntu runner in the Enforced profile and on a macOS arm64 host in the Standalone profile; confirm both installations reach their expected health state. |
| Source | OWNER (single PC; platform profiles); ARCH §2.2 A-8; ARCH §15 |
| Rationale | Defines the isolation features each profile relies on and the platforms the release supports. |

#### FR-12.4 — Filesystem layout

| Field | Value |
|---|---|
| ID | FR-12.4 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway **SHALL** keep its configuration, persistent state, runtime sockets, diagnostic logs and exports in the directories that CP-46 assigns to the active platform profile, with the ownership and modes CP-46 states. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager, E-32 Research Dataset Service, E-24 Management Console & Control API; Functions: F-97; External interfaces: X-07 |
| Verification Method | Inspection |
| Verification Statement | Inspect an Enforced installation and a Standalone installation on macOS and on Linux; confirm each directory, owner and mode against CP-46. |
| Source | A2 §3; OWNER (per-user layout for the Standalone profile) |
| Rationale | Separates protected state from agent-writable locations where the platform allows it, and keeps a per-user installation out of system directories. |

#### FR-12.6 — Configuration file

| Field | Value |
|---|---|
| ID | FR-12.6 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway **SHALL** read its configuration from TOML files validated against a published schema at startup, and **SHALL** refuse to start on a validation error. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-28 Data Lifecycle & Memory Manager |
| Verification Method | Test |
| Verification Statement | Start with an invalid key and an out-of-range value; confirm refusal with a precise message. |
| Source | ARCH §15 |
| Rationale | Predictable configuration. |

#### FR-12.7 — Administrative CLI

| Field | Value |
|---|---|
| ID | FR-12.7 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway release **SHALL** include the `smcpctl` command providing the subcommands `bootstrap`, `install`, `upgrade`, `uninstall`, `version`, `health`, `stop`, `resume`, `reload`, `backup`, `restore`, `journal verify`, `config validate`, `config migrate`, `keys rotate`, `trust`, `clients`, `approvals`, `package`, `doctor`, `lockdown`, `client setup` and `remote`. |
| Allocation | Elements: E-24 Management Console & Control API, E-28 Data Lifecycle & Memory Manager, E-21 Audit & Evidence Service; Functions: F-97 |
| Verification Method | Demonstration |
| Verification Statement | Exercise each subcommand on an Enforced and a Standalone installation; confirm each completes its documented operation. |
| Source | SEC 10.9; REVIEW (C1, C2, C4, C5, I6) |
| Rationale | Procedures that do not depend on the GUI. The list names every command another requirement relies on. |

#### FR-12.8 — Release provenance

| Field | Value |
|---|---|
| ID | FR-12.8 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway release **SHALL** include source commit IDs, artifact digests, build recipes, dependency lockfiles, an SPDX or CycloneDX SBOM and license notices. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API, E-25 Graph Database Engine |
| Verification Method | Inspection |
| Verification Statement | Inspect the release bundle for each item. |
| Source | SEC 10.7 |
| Rationale | Traceable, reproducible releases. |

#### FR-12.9 — MCP conformance suite

| Field | Value |
|---|---|
| ID | FR-12.9 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway source **SHALL** include an automated conformance suite that exercises northbound and southbound behavior against the message examples in `mcp-spec/2026-07-28/schema/examples` and validates messages against `schema.json`. |
| Allocation | Elements: E-02 Protocol Mediator, E-10 Tool Dispatcher; External interfaces: X-01; Internal interfaces: I-13 |
| Verification Method | Inspection |
| Verification Statement | Run the suite in CI; confirm it executes and reports results for every example directory. |
| Source | MCP:schema; SEC 10.6 |
| Rationale | Continuous verification of protocol conformance. |

#### FR-12.10 — Requirement-tagged tests

| Field | Value |
|---|---|
| ID | FR-12.10 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | Each automated test **SHALL** declare each requirement it claims as a full or a partial claim, and the build **SHALL** produce a report that lists every requirement of this SRS with the status verified, partial, failing or unverified as defined in Section 2.6, together with the claiming tests. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API |
| Verification Method | Inspection |
| Verification Statement | Run the report on the release commit; confirm it lists exactly the requirements of Appendix H, that every requirement without a claim is listed as unverified, that a requirement with only partial claims is listed as partial, and that the totals match the published status data. |
| Source | SEC 10.3; SEC 10.6; REVIEW (C7) |
| Rationale | Verification traceability for coding. A report that lists only claimed requirements hides the unverified ones and overstates completion. |

#### FR-12.11 — No paid database features

| Field | Value |
|---|---|
| ID | FR-12.11 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Data Server **SHALL** operate using only self-hosted, OSI-licensed editions of its database components, without Neo4j Enterprise, Aura or other paid features. |
| Allocation | Elements: E-25 Graph Database Engine, E-27 Observation Store; External interfaces: X-07 |
| Verification Method | Inspection |
| Verification Statement | Inspect installed database packages, configuration and licenses. |
| Source | SEC 9.2; ARCH §15 |
| Rationale | Open-source local baseline. |

#### FR-12.12 — Session helper adapter

| Field | Value |
|---|---|
| ID | FR-12.12 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway release **SHALL** include the `smcp-session` command, which obtains or refreshes a session as the principal named by its CP-43 credential file through the token endpoint (FR-2.20) or the session API (FR-2.2), and prints a JSON object of request headers on standard output in the form consumed by the Claude Code `headersHelper` hook, or, with `--env NAME`, the line `NAME=<Authorization value>` for clients that read a header value from an environment variable (Codex CLI `env_http_headers`, which at the Appendix K version has no header-helper hook). |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-94; External interfaces: X-01, X-12 |
| Verification Method | Demonstration |
| Verification Statement | Configure Claude Code with the helper as its `headersHelper`, and Codex CLI with an `env_http_headers` entry whose variable `smcp-session --env` set; confirm each connects and lists tools through the Gateway. |
| Source | ARCH §4 E-33; Client-Compatibility-Brief §4.1 |
| Rationale | Neither client can call a session API itself. Both can run a header helper. |

#### FR-12.13 — Stdio bridge adapter

| Field | Value |
|---|---|
| ID | FR-12.13 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway release **SHALL** include the `smcp-stdio` command, which runs as a stdio MCP server for a framework, obtains a session (F-94), and forwards each JSON-RPC message unchanged between its standard streams and the Gateway harness listener, attaching the session credential and preserving the framework's protocol era; by default it connects to the CP-02 TLS listener and trusts only the Gateway server CA named in its CP-43 credential file, and it uses the UDS listener when the UDS Harness Profile is enabled and the credential file names the socket. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-95; External interfaces: X-01, X-12 |
| Verification Method | Test |
| Verification Statement | Run the northbound conformance fixtures for both eras through the bridge; confirm results identical to a direct connection. |
| Source | ARCH §4 E-33; Client-Compatibility-Brief §4.1 |
| Rationale | Every shipping client can launch a stdio server. This is the adapter the architecture assumed and now delivers. |

### FR-13 Distribution, installation, upgrade and platform profiles

#### FR-13 — Installation lifecycle

| Field | Value |
|---|---|
| ID | FR-13 |
| Parent ID | — (root) |
| Statement | The Gateway release **SHALL** be installable, upgradable and removable on each platform of Section 1.6 by the procedures of this section, in the platform profile of Section 1.5.1 that the host supports. |
| Allocation | Elements: E-24 Management Console & Control API, E-22 Key & Trust Anchor Manager, E-23 Health & Safety Monitor, E-28 Data Lifecycle & Memory Manager; Functions: F-97; External interfaces: X-16, X-07 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-13 child requirement; confirm each has passed on the Enforced CI host and on a macOS arm64 host. |
| Source | OWNER (distribution: GitHub Releases, install.sh, Homebrew tap; platform profiles); REVIEW (C2, C3) |
| Rationale | A product that cannot be installed, upgraded and removed by its documented procedure is not finished. |

#### FR-13.1 — Release archives

| Field | Value |
|---|---|
| ID | FR-13.1 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The Gateway release **SHALL** publish, for each of darwin-arm64, darwin-amd64, linux-amd64 and linux-arm64, a compressed archive containing `smcpd`, `smcpctl`, `smcp-session`, `smcp-stdio`, `smcp-connect`, the console assets, the license notices and the SBOM, together with one SHA-256 checksum file and a minisign signature over that checksum file. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97; External interfaces: X-16 |
| Verification Method | Inspection |
| Verification Statement | Inspect a GitHub Release; confirm the four archives and their contents, the checksum file and its signature, and that the signature verifies with the release public key published in `SECURITY.md`. |
| Source | OWNER (distribution); SEC 10.7 |
| Rationale | Every install path starts from signed, checksummed archives. |

#### FR-13.2 — Installer verification

| Field | Value |
|---|---|
| ID | FR-13.2 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The `install.sh` script **SHALL** download the archive for the host platform, verify the checksum file's minisign signature with the release public key embedded in the script and the archive's SHA-256 against that file, and **SHALL** install nothing when either verification fails. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97; External interfaces: X-16 |
| Verification Method | Test |
| Verification Statement | Run the script against a release with a modified archive and against one with a modified checksum file; confirm both are refused with no file written outside a temporary directory; run it against the intact release and confirm installation. |
| Source | OWNER (install.sh); SEC 10.7 |
| Rationale | A `curl \| sh` installer is only as trustworthy as its verification step. |

#### FR-13.3 — Homebrew formula

| Field | Value |
|---|---|
| ID | FR-13.3 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The Gateway release **SHALL** publish a formula in the project's Homebrew tap whose URLs and SHA-256 values match the release archives for darwin and linux. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97; External interfaces: X-16 |
| Verification Method | Test |
| Verification Statement | In CI, install from the tap on macOS and Linux runners; confirm the installed binaries' digests equal those in the release archives. |
| Source | OWNER (Homebrew tap) |
| Rationale | Homebrew is the expected install path on macOS. |

#### FR-13.4 — Idempotent install

| Field | Value |
|---|---|
| ID | FR-13.4 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The `smcpctl install` command **SHALL** be idempotent: a repeated run on an installed host **SHALL** leave configuration, keys, policy and evidence byte-for-byte unchanged and **SHALL** report each step as `present` or `created`. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97; External interfaces: X-07 |
| Verification Method | Test |
| Verification Statement | Run `smcpctl install` twice in each profile; confirm the second run reports every step `present` and that digests of configuration, keys, policy and journal files are unchanged. |
| Source | OWNER (idempotent installer) |
| Rationale | Operators re-run installers after partial failures and upgrades; a re-run must never rotate keys or reset policy. |

#### FR-13.5 — Enforced profile installation

| Field | Value |
|---|---|
| ID | FR-13.5 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | When installing the Enforced profile, the `smcpctl install` command **SHALL** verify every Section 1.5.1 prerequisite before changing the host, and **SHALL** then create the CP-46 service identities with their subordinate UID and GID ranges, the CP-46 directories with their owners and modes, the nftables table `smcp`, the AppArmor or SELinux profiles and the systemd units. |
| Allocation | Elements: E-24 Management Console & Control API, E-16 Execution Sandbox; Functions: F-97; External interfaces: X-07 |
| Verification Method | Test |
| Verification Statement | On a GitHub-hosted Ubuntu runner, run the install; confirm each identity, subordinate range, directory, nftables table, LSM profile and unit; on a host missing a prerequisite, confirm the install stops before any change and names the prerequisite. |
| Source | OWNER (installer creating service identities, nftables, LSM and subuid on Linux enforced); SEC 4.1 |
| Rationale | The Enforced profile's separation depends on these host objects existing with the right ownership. |

#### FR-13.6 — Standalone profile installation

| Field | Value |
|---|---|
| ID | FR-13.6 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | When installing the Standalone profile, the `smcpctl install` command **SHALL** create the CP-46 per-user directories, install a launchd user agent on macOS or a systemd user unit on Linux, write `profile = "standalone"` to the configuration and print that the installation is not enforced. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97; External interfaces: X-07 |
| Verification Method | Test |
| Verification Statement | Run the install on a macOS arm64 runner and on a Linux runner without Podman; confirm the directories, the service unit, the configuration value and the printed notice. |
| Source | OWNER (Standalone profile; per-user path layout) |
| Rationale | Developers on macOS need a supported install that never pretends to contain servers. |

#### FR-13.7 — Upgrade procedure

| Field | Value |
|---|---|
| ID | FR-13.7 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The `smcpctl upgrade` command **SHALL** verify the new release as in FR-13.2, create an encrypted backup (FR-17.6), stop dispatch, install the new binaries, apply configuration and state migrations, start the new version and wait up to the CP-47 bound for a health state other than `fail-closed`. |
| Allocation | Elements: E-24 Management Console & Control API, E-28 Data Lifecycle & Memory Manager, E-23 Health & Safety Monitor; Functions: F-97, F-79; External interfaces: X-16 |
| Verification Method | Test |
| Verification Statement | Upgrade from the previous release to the release candidate in each profile; confirm the backup exists, dispatch was stopped during the swap, migrations ran and health returned within the bound. |
| Source | OWNER (smcpctl upgrade with pre-upgrade backup) |
| Rationale | Upgrades must not lose policy, keys or evidence. |

#### FR-13.8 — Upgrade rollback

| Field | Value |
|---|---|
| ID | FR-13.8 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | When a migration fails or the upgraded Gateway does not leave `fail-closed` within the CP-47 bound, the `smcpctl upgrade` command **SHALL** restore the previous binaries and the pre-upgrade backup, start the previous version and record an `upgrade_rolled_back` event in the Evidence Journal. |
| Allocation | Elements: E-24 Management Console & Control API, E-28 Data Lifecycle & Memory Manager, E-21 Audit & Evidence Service; Functions: F-97, F-79 |
| Verification Method | Test |
| Verification Statement | Upgrade to a fault-injected release whose migration fails, and to one that never becomes healthy; confirm in both cases that the previous version runs with its policy, keys and journal intact and that the event is recorded. |
| Source | OWNER (rollback on failed health) |
| Rationale | A failed upgrade must leave the operator where they started. |

#### FR-13.9 — No silent profile downgrade

| Field | Value |
|---|---|
| ID | FR-13.9 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | When the configuration selects the Enforced profile and a Section 1.5.1 prerequisite is missing, the Health & Safety Monitor (E-23) **SHALL** refuse to start the Gateway and **SHALL** name each missing prerequisite. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61, F-62; External interfaces: X-07 |
| Verification Method | Test |
| Verification Statement | Configure the Enforced profile on a host without rootless Podman and with nftables removed; confirm the daemon exits with a message naming both. |
| Source | OWNER (platform profiles); ARCH §2.2 A-8 |
| Rationale | Running unconfined while configured as enforced would make the label false. |

#### FR-13.10 — Standalone labelling

| Field | Value |
|---|---|
| ID | FR-13.10 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | In the Standalone profile, the Health & Safety Monitor (E-23) **SHALL** report health `degraded` with cause `unconfined`, and the Gateway **SHALL** show the label `not enforced` in `smcpctl health`, `smcpctl version`, the console banner and the startup diagnostic log entry. |
| Allocation | Elements: E-23 Health & Safety Monitor, E-24 Management Console & Control API; Functions: F-61, F-65 |
| Verification Method | Test |
| Verification Statement | Start a Standalone installation with every other dependency healthy; confirm health `degraded` with only `unconfined`, and the label in each of the four places. |
| Source | OWNER (health reports degraded:unconfined; release label "not enforced") |
| Rationale | The operator must see, everywhere they look, that servers are not contained. |

#### FR-13.11 — Uninstall

| Field | Value |
|---|---|
| ID | FR-13.11 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The `smcpctl uninstall` command **SHALL** stop and remove the Gateway services, binaries, units, the nftables table and the LSM profiles, and **SHALL** keep the Evidence Journal, the evidence public key and the backup archives in place. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97; External interfaces: X-07; Data stores: D-06, D-15 |
| Verification Method | Test |
| Verification Statement | Uninstall each profile; confirm the removed objects are gone and that `smcpctl journal verify` from a fresh install, pointed at the kept journal and key, succeeds. |
| Source | OWNER (smcpctl uninstall preserving evidence unless purged) |
| Rationale | Evidence outlives the installation that produced it. |

#### FR-13.12 — Purge

| Field | Value |
|---|---|
| ID | FR-13.12 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The `smcpctl uninstall --purge` command **SHALL** require the operator to type the installation ID, **SHALL** print the SHA-256 of the last journal segment, and **SHALL** then delete configuration, state, keys, the journal and the service identities. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97; External interfaces: X-07; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Run the purge with a wrong and with the correct installation ID; confirm refusal, then the printed digest and complete removal. |
| Source | OWNER (uninstall --purge) |
| Rationale | Deleting evidence is deliberate and leaves the operator a digest to compare against any copy. |

#### FR-13.13 — Configuration schema version

| Field | Value |
|---|---|
| ID | FR-13.13 |
| Parent ID | FR-13 — Installation lifecycle |
| Statement | The Gateway **SHALL** read an integer `schema_version` from the configuration file, **SHALL** refuse to start when that value is greater than the highest version it supports, naming both versions, and **SHALL** accept an older version only after `smcpctl config migrate` or `smcpctl upgrade` has rewritten it. |
| Allocation | Elements: E-23 Health & Safety Monitor, E-24 Management Console & Control API; Functions: F-97, F-62 |
| Verification Method | Test |
| Verification Statement | Start with a configuration one version newer and current; confirm refusal naming both versions and normal start. Release 1.0 has one schema version (a file without the key is version 1), so no real file is older: register a next version with a migration step in the test, start with a version-1 file and confirm refusal with a migrate instruction, then confirm that `smcpctl config migrate` (which `smcpctl upgrade` runs with the new binary) rewrites the file, keeps the original and the rewritten file loads. |
| Source | OWNER (config schema version field and refusal of unknown newer versions) |
| Rationale | A downgrade must not misread a configuration written by a newer release. |

### FR-14 Server packaging and admission

#### FR-14 — Operator self-curation

| Field | Value |
|---|---|
| ID | FR-14 |
| Parent ID | — (root) |
| Statement | The Gateway release **SHALL** let an operator admit a local MCP server without an external curation system by packaging it from a pinned artifact, signing it with an operator key and importing it through the Library Trust Verifier (E-13). |
| Allocation | Elements: E-13 Library Trust Verifier, E-14 Local Server Registry, E-22 Key & Trust Anchor Manager; Functions: F-96; External interfaces: X-02, X-03, X-17 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-14 child requirement; confirm each has passed. |
| Source | OWNER (server admission without the external curation system: operator self-curation); REVIEW (C1) |
| Rationale | V1.1 assumed an external curation system that does not exist; without this path no server could be admitted. |

#### FR-14.1 — Package build

| Field | Value |
|---|---|
| ID | FR-14.1 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl package build` command **SHALL** accept an artifact reference of type `npm`, `pypi`, `oci` or `binary` that names an exact version and a SHA-256 or registry-integrity digest, fetch the artifact over X-17, verify the digest and store the artifact in the package directory under its SHA-256. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96; External interfaces: X-17; Data stores: D-03 |
| Verification Method | Test |
| Verification Statement | Build packages from one reference of each type and from a reference with a wrong digest; confirm the four succeed with artifacts stored by SHA-256 and the wrong digest is refused. |
| Source | OWNER (smcpctl package build materializes a pinned artifact by digest) |
| Rationale | The digest pins the exact code the operator chose to trust. |

#### FR-14.2 — Pinned references only

| Field | Value |
|---|---|
| ID | FR-14.2 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl package build` command **SHALL** refuse an artifact reference that lacks an exact version or a digest, including version ranges, dist-tags such as `latest` and image tags without a digest. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96; External interfaces: X-17 |
| Verification Method | Test |
| Verification Statement | Submit a range, a `latest` tag, an OCI tag without digest and a reference without digest; confirm each is refused with the reason. |
| Source | SEC 3.6; OWNER (runtime launch of unpinned commands is refused) |
| Rationale | A floating reference would let the registry change the code after review. |

#### FR-14.3 — Manifest from live tool list

| Field | Value |
|---|---|
| ID | FR-14.3 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl package build` command **SHALL** start the artifact once in a throwaway working directory with no secrets, the environment allowlist of the manifest and, in the Enforced profile, no network, read its tool list through the legacy handshake of FR-5.19 and `tools/list`, and **SHALL** write a manifest conforming to Appendix J containing the tools, their schemas, description digests and era, and the operator-supplied risk class, side-effect classes, `source_trust`, capability ceiling and secret slots. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96, F-34; External interfaces: X-02 |
| Verification Method | Test |
| Verification Statement | Package each reference server; validate each manifest against `docs/schemas/manifest.schema.json`; confirm the tools equal the live `tools/list` and that no secret or network access was available to the packaging run in the Enforced profile. |
| Source | OWNER (generate the manifest from a live tools/list at packaging time); SEC 3.5; SEC 3.7 |
| Rationale | The manifest records exactly what the operator reviewed; the throwaway run is the quarantine probe. The era probe of FR-5.16 is deferred, so release 1.0 probes with the 2025-11-25 `initialize` handshake and records that era in the manifest. |

#### FR-14.4 — Local servers only

| Field | Value |
|---|---|
| ID | FR-14.4 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The Library Trust Verifier (E-13) **SHALL** reject a manifest whose server entrypoint is a network URL rather than a local executable or image. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-34; External interfaces: X-03 |
| Verification Method | Test |
| Verification Statement | Import a manifest with an `https` endpoint; confirm rejection with the reason `REMOTE_BACKEND_UNSUPPORTED`. |
| Source | OWNER (remote hosted MCP servers as backends out of scope for v1); REVIEW (I9) |
| Rationale | Remote backends need a different trust and transport design that v1 does not provide. |

#### FR-14.5 — Provenance statement

| Field | Value |
|---|---|
| ID | FR-14.5 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl package build` command **SHALL** write a provenance statement that binds the source reference (registry tarball or sdist digest, OCI image source label, or an operator-supplied source archive URL and digest) and the SPDX license identifiers to the artifact digest. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96; External interfaces: X-02 |
| Verification Method | Inspection |
| Verification Statement | Inspect the provenance statement of each reference package; confirm the source reference, license identifiers and artifact digest. |
| Source | SEC 3.1; SEC 3.2 |
| Rationale | Supplies the source and license evidence that SR-3.1-1 and SR-3.2-1 check at import. |

#### FR-14.6 — Package signing

| Field | Value |
|---|---|
| ID | FR-14.6 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl package sign` command **SHALL** sign the package index, which lists the digests of the artifact, manifest and provenance statement, with a minisign secret key read from a file or an interactive prompt, and **SHALL** refuse a key or passphrase supplied as a command-line argument. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96; External interfaces: X-02 |
| Verification Method | Test |
| Verification Statement | Sign a package with a key file and with a prompted passphrase; attempt to pass the key on the command line; confirm two valid signatures and one refusal. |
| Source | OWNER (sign with minisign, offline) |
| Rationale | Command-line arguments are visible to other processes and shell history. |

#### FR-14.7 — Offline package verification

| Field | Value |
|---|---|
| ID | FR-14.7 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl package verify` command **SHALL** verify, without network access, the package index signature against a given public key or enrolled trust anchor, every listed digest and the manifest schema, and **SHALL** exit with status 0 only when every check passes, naming the first failed check otherwise. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96, F-33 |
| Verification Method | Test |
| Verification Statement | Verify an intact package with networking disabled, then packages with a modified artifact, a modified manifest and a wrong key; confirm status 0 only for the intact one and the named failures. |
| Source | OWNER (smcpctl package verify; offline) |
| Rationale | The operator can check a package before copying it into the library. |

#### FR-14.8 — Operator key as a scoped trust anchor

| Field | Value |
|---|---|
| ID | FR-14.8 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl trust add` command **SHALL** enroll an operator minisign public key as a trust anchor only with an explicit list of permitted risk classes and an expiry, defaulting to the classes `low` and `moderate` when the operator names none. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-58; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Enroll a key without classes and with `high` named; import a `high` package signed by each; confirm rejection for the first and acceptance for the second. |
| Source | OWNER (operator-local key enrolled as a trust anchor limited to operator-chosen risk classes); SEC 3.13 |
| Rationale | A compromised operator key should not admit high-risk servers unless the operator chose to allow it. |

#### FR-14.9 — Reference packages

| Field | Value |
|---|---|
| ID | FR-14.9 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The Gateway release **SHALL** include packaging recipes, each with a pinned artifact reference and an operator classification, for the reference filesystem, git, fetch and memory MCP servers, and the release pipeline **SHALL** build, sign with a test key, import, enable and call one tool of each. |
| Allocation | Elements: E-13 Library Trust Verifier, E-14 Local Server Registry; Functions: F-96, F-36; External interfaces: X-02 |
| Verification Method | Test |
| Verification Statement | Run the reference-package job on the release commit; confirm each of the four packages imports, enables and answers one tool call through the Gateway. |
| Source | OWNER (reference packaged servers: filesystem, git, fetch, memory); SEC 9.5 |
| Rationale | Gives every installation working servers on day one and keeps the packaging path tested. |

#### FR-14.10 — Bootstrap uses a packaged server

| Field | Value |
|---|---|
| ID | FR-14.10 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl bootstrap` command **SHALL** write an example configuration whose only backend is the packaged reference filesystem server and whose launch specification names a content-addressed local artifact. |
| Allocation | Elements: E-24 Management Console & Control API, E-15 Server Runtime Manager; Functions: F-38, F-96 |
| Verification Method | Inspection |
| Verification Statement | Run bootstrap; inspect the written configuration; confirm one backend referencing the reference package by digest and no `npx`, `uvx`, `pip` or other installer in any launch specification. |
| Source | OWNER (the bootstrap example must use a packaged server); SEC 3.6 |
| Rationale | The first experience must follow the same rule as production: no runtime package resolution. |

#### FR-14.11 — Manifest schema

| Field | Value |
|---|---|
| ID | FR-14.11 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The Library Trust Verifier (E-13) **SHALL** validate each manifest against the JSON Schema `docs/schemas/manifest.schema.json` (Appendix J) of the manifest's declared `manifest_version`, and **SHALL** reject a manifest that declares an unsupported version. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-34; External interfaces: X-03 |
| Verification Method | Test |
| Verification Statement | Import a valid manifest, one violating each required field rule, and one with an unsupported `manifest_version`; confirm acceptance and the specific rejections. |
| Source | REVIEW (C1); ARCH §6.3 |
| Rationale | One published schema is the contract between packaging and import. |

#### FR-14.12 — Revocation entries

| Field | Value |
|---|---|
| ID | FR-14.12 |
| Parent ID | FR-14 — Operator self-curation |
| Statement | The `smcpctl package revoke` command **SHALL** write into the library a revocation entry naming the server ID and revision, signed with the same key type as packages, which the Library Trust Verifier (E-13) processes under FR-5.3. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96, F-35; External interfaces: X-02 |
| Verification Method | Test |
| Verification Statement | Revoke an enabled revision; confirm that within the FR-5.3 interval it is `revoked`, its tools leave every catalog and running instances stop. |
| Source | SEC 3; ARCH §18.8 |
| Rationale | An operator who curates must also be able to withdraw. |

### FR-15 Harness integration, lockdown and client matrix

#### FR-15 — Harness integration

| Field | Value |
|---|---|
| ID | FR-15 |
| Parent ID | — (root) |
| Statement | The Gateway release **SHALL** connect each client of Appendix K through a documented, tested mode and **SHALL** provide the tooling that reduces each local client's ability to bypass the Gateway. |
| Allocation | Elements: E-33 Harness Adapter Kit, E-01 Harness Interface Endpoint; Functions: F-94, F-95, F-98; External interfaces: X-01, X-12 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-15 child requirement and the latest client matrix run; confirm each has passed. |
| Source | OWNER (client matrix); REVIEW (C4, I4) |
| Rationale | A gateway that an agent can route around protects nothing; the clients that matter must be named and tested. |

#### FR-15.1 — Lockdown profiles

| Field | Value |
|---|---|
| ID | FR-15.1 |
| Parent ID | FR-15 — Harness integration |
| Statement | The Gateway release **SHALL** include a lockdown profile for each local client of Appendix K that, using the mechanism Appendix K records for that client, restricts the client's MCP servers to the Gateway and denies the client's own file tools read and write access to the CP-46 Gateway paths and the CP-43 credential file. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | For each local client at its pinned version, apply the profile; attempt to add a second MCP server and to read the Gateway state directory through the client's file tool; confirm each attempt is refused where Appendix K lists a mechanism, and that `smcpctl doctor` reports each case where it lists none. |
| Source | OWNER (harness bypass: lockdown profiles per client); REVIEW (C4); SEC 4.9; SEC 4.11 |
| Rationale | Lockdown uses the clients' own enforcement points. Where a client has none, the gap is reported rather than hidden. |

#### FR-15.2 — Claude Code lockdown profile

| Field | Value |
|---|---|
| ID | FR-15.2 |
| Parent ID | FR-15 — Harness integration |
| Statement | The Claude Code lockdown profile **SHALL** be a managed settings file at the platform's managed-settings path that sets `allowedMcpServers` to the Gateway entry alone, restricts MCP server allowlisting to the managed source where the pinned client version supports it, and adds `permissions.deny` rules for `Read` and `Edit` on the CP-46 Gateway paths and the CP-43 credential file. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | Install the profile with the pinned Claude Code; confirm a user-added MCP server does not load and that a request to read the Gateway state directory is denied by the client. |
| Source | OWNER (Claude Code managed settings allowedMcpServers and permissions deny on SMCP state paths); CCB §7 |
| Rationale | Claude Code's managed settings cannot be overridden from user or project settings, which makes them the right enforcement point. |

#### FR-15.3 — Doctor: MCP server inventory

| Field | Value |
|---|---|
| ID | FR-15.3 |
| Parent ID | FR-15 — Harness integration |
| Statement | The `smcpctl doctor` command **SHALL** list, for each client of Appendix K installed for the current user whose configuration location Appendix K records, every MCP server configured in the client's user, project and managed scopes, **SHALL** flag each server that is not the Gateway, and **SHALL** state for each other installed client that its servers are not listed. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | Create fixture configurations for each client with one Gateway entry and one other server in each scope; confirm every other server is listed and flagged, and that a client without a recorded location is reported as not listed. |
| Source | OWNER (smcpctl doctor reporting non-Gateway MCP servers); REVIEW (C4) |
| Rationale | The operator cannot remove a bypass they do not know about. A client whose configuration location is still to be confirmed at pinning (Grok Build in Appendix K) cannot be read, so doctor says so instead of reporting it clean. |

#### FR-15.4 — Doctor: readable paths

| Field | Value |
|---|---|
| ID | FR-15.4 |
| Parent ID | FR-15 — Harness integration |
| Statement | The `smcpctl doctor` command **SHALL** report each CP-46 Gateway path and the CP-43 credential file that the user identity running a client can read, and in the Standalone profile **SHALL** state that the client runs under the Gateway's own identity. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-07 |
| Verification Method | Test |
| Verification Statement | Run doctor on an Enforced host as the harness user and on a Standalone host; confirm no findings for the Enforced key directory, findings for every readable path, and the Standalone statement. |
| Source | OWNER (readable credential and state paths); REVIEW (C4) |
| Rationale | In the Standalone profile the operating system does not separate agent and Gateway; the operator must be told. |

#### FR-15.5 — Doctor output

| Field | Value |
|---|---|
| ID | FR-15.5 |
| Parent ID | FR-15 — Harness integration |
| Statement | The `smcpctl doctor` command **SHALL** exit with a non-zero status when it reports any finding of FR-15.3 or FR-15.4, and **SHALL** produce the same findings as JSON with `--json`. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98 |
| Verification Method | Test |
| Verification Statement | Run doctor with and without findings, with and without `--json`; confirm the exit status and that the JSON findings equal the text findings. |
| Source | REVIEW (C4) |
| Rationale | Lets CI and scripts gate on a clean harness configuration. |

#### FR-15.6 — Reversible lockdown

| Field | Value |
|---|---|
| ID | FR-15.6 |
| Parent ID | FR-15 — Harness integration |
| Statement | The `smcpctl lockdown apply` and `smcpctl lockdown remove` commands **SHALL** copy each client file they change to a timestamped backup before the change and **SHALL** restore that copy on removal. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | Apply and remove the lockdown for each local client; confirm the client files after removal equal the originals byte for byte. |
| Source | REVIEW (C4) |
| Rationale | Operators must be able to undo a change to a tool they use daily. |

#### FR-15.7 — Per-client CA trust setup

| Field | Value |
|---|---|
| ID | FR-15.7 |
| Parent ID | FR-15 — Harness integration |
| Statement | The `smcpctl client setup` command **SHALL** configure each local client of Appendix K to trust the Gateway server CA by the client's own mechanism recorded in Appendix K, and **SHALL** add the CA to the operating-system trust store only when the operator passes `--system-trust`. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | Run setup for each client; confirm each connects over TLS without certificate errors and that the system trust store is unchanged unless `--system-trust` was given. |
| Source | REVIEW (I4) |
| Rationale | Each client reads trust roots differently; a system-wide CA is a broader change than the Gateway needs. |

#### FR-15.8 — Client matrix regression

| Field | Value |
|---|---|
| ID | FR-15.8 |
| Parent ID | FR-15 — Harness integration |
| Statement | The continuous-integration pipeline **SHALL** run, for each local client of Appendix K at its pinned version, an automated test that obtains a session, lists tools, calls one permitted tool, receives a denial for one unpermitted tool and records the result `pass`, `fail` or `not-run` with the client version and connection mode in the published status data. |
| Allocation | Elements: E-33 Harness Adapter Kit, E-01 Harness Interface Endpoint; Functions: F-94, F-95; External interfaces: X-01, X-12 |
| Verification Method | Test |
| Verification Statement | Run the matrix job; confirm one result per local client in the status data `agents` array and that a deliberately broken Gateway build turns the results to `fail`. |
| Source | REVIEW (I4); OWNER (client matrix) |
| Rationale | Client releases change MCP behavior often; the matrix catches a break before users do. |

#### FR-15.9 — Cloud agent matrix record

| Field | Value |
|---|---|
| ID | FR-15.9 |
| Parent ID | FR-15 — Harness integration |
| Statement | The Gateway project **SHALL** keep, for each cloud agent of Appendix K, an entry in `docs/clients/matrix.json` that records either a manual connection run against the Remote Access Profile, with its date, agent version or build where shown, tunnel provider, registration mode and result, or, while no run has been made, the result `not-run`, the date the entry was last reviewed, the documented connection and registration modes and the reason no run was made. |
| Allocation | Elements: E-33 Harness Adapter Kit, E-01 Harness Interface Endpoint; Functions: F-95; External interfaces: X-13 |
| Verification Method | Inspection |
| Verification Statement | Inspect `docs/clients/matrix.json`; confirm one entry per cloud agent, each either a dated run with every run field or a `not-run` entry with its review date, documented modes and reason. |
| Source | OWNER (cloud agents: Grok Bot, ChatGPT dots, Meta Muse; live runs descoped from release 1.x on 2026-10-18) |
| Rationale | Cloud agents cannot run in CI, so their support claim rests on dated manual records. The owner descoped live cloud-agent runs from release 1.x: the agents are documented and the Remote Access Profile is tested against a local test tunnel, and a `not-run` entry states that plainly instead of implying a run. |

#### FR-15.10 — Pinned client matrix file

| Field | Value |
|---|---|
| ID | FR-15.10 |
| Parent ID | FR-15 — Harness integration |
| Statement | The Gateway source **SHALL** keep the Appendix K client matrix as `docs/clients/matrix.json`, listing for each client its pinned version, connection mode, session mechanism, lockdown mechanism and CA trust mechanism, and the matrix job of FR-15.8 **SHALL** read the pinned versions from that file. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Inspection |
| Verification Statement | Inspect the file and the CI job; confirm every Appendix K client is present and the job reads its versions from the file. |
| Source | REVIEW (I4) |
| Rationale | One file keeps the documentation, the tests and the status data in step. |

### FR-16 Remote Access Profile

#### FR-16 — Remote Access Profile

| Field | Value |
|---|---|
| ID | FR-16 |
| Parent ID | — (root) |
| Statement | When the Remote Access Profile is enabled, the Gateway **SHALL** serve agents that run on a vendor's computer through an authenticated tunnel to a dedicated loopback listener, with the controls of this section. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-03 Identity & Authentication Service, E-33 Harness Adapter Kit; Functions: F-01, F-59, F-95; External interfaces: X-13 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-16 child requirement and the cloud agent records of FR-15.9; confirm each has passed. |
| Source | OWNER (cloud agents via a Remote Access profile); ARCH §2.2 A-10 |
| Rationale | Cloud agents cannot reach the user's loopback address; installing the Gateway in the vendor's machine is not a control. |

#### FR-16.1 — Remote listener

| Field | Value |
|---|---|
| ID | FR-16.1 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | When the Remote Access Profile is enabled, the Harness Interface Endpoint (E-01) **SHALL** open a second TLS listener on the CP-48 loopback address, separate from the CP-02 harness listener, and **SHALL** treat every request received on it as remote origin. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Enable the profile; confirm the second listener on the CP-48 address only; send identical requests to both listeners; confirm only the second is marked remote. |
| Source | OWNER (Remote Access profile); ARCH §6.1 X-13 |
| Rationale | A separate listener makes remote origin a property of the socket, which a remote client cannot forge with a header. |

#### FR-16.2 — Tunnel providers

| Field | Value |
|---|---|
| ID | FR-16.2 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The `smcpctl remote check` command **SHALL** validate a Cloudflare Tunnel, Tailscale Funnel or vendor MCP tunnel configuration that forwards one public HTTPS name to the CP-48 listener, and **SHALL** report the public name, the provider and whether a request through the public name reaches the remote listener. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-33 Harness Adapter Kit; Functions: F-01; External interfaces: X-13 |
| Verification Method | Demonstration |
| Verification Statement | Configure each of Cloudflare Tunnel and Tailscale Funnel on a test host; run the check; confirm it reports the provider, the name and a reachable listener, and that a tunnel pointed at the local harness listener is reported as misconfigured. |
| Source | OWNER (Cloudflare Tunnel, Tailscale Funnel, or OpenAI Secure MCP Tunnel) |
| Rationale | Misrouting a tunnel to the local listener would erase the remote/local distinction. |

#### FR-16.3 — Public name binding

| Field | Value |
|---|---|
| ID | FR-16.3 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** accept on the remote listener only requests whose `Host` equals the configured public name, and the Identity & Authentication Service (E-03) **SHALL** publish on that listener OAuth metadata whose issuer and resource name the public URL. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-03 Identity & Authentication Service; Functions: F-01, F-04; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Send requests with the public name and with another name; fetch both metadata documents through the tunnel; confirm 421 for the other name and public URLs in the metadata. |
| Source | SEC 2.9; MCP:basic/authorization |
| Rationale | Tokens must be audience-bound to the URL the agent actually uses. |

#### FR-16.4 — Remote endpoint set

| Field | Value |
|---|---|
| ID | FR-16.4 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** serve on the remote listener only the MCP endpoint and the OAuth metadata, authorization, token, registration, device authorization and device verification endpoints, and **SHALL** answer every other path with HTTP 404. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Request the session API, health, metrics and console paths through the remote listener; confirm 404 for each. |
| Source | OWNER (Remote Access profile); SEC 2.5 |
| Rationale | Minimizes what a remote caller can reach. |

#### FR-16.5 — Operator-approved dynamic registration

| Field | Value |
|---|---|
| ID | FR-16.5 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Identity & Authentication Service (E-03) **SHALL** accept RFC 7591 Dynamic Client Registration requests only on the remote listener, **SHALL** store each registration as `pending`, and **SHALL** activate it only after a Session Approver or Administrator approves it in G-11 or with `smcpctl clients approve`. |
| Allocation | Elements: E-03 Identity & Authentication Service, E-24 Management Console & Control API; Functions: F-59; External interfaces: X-13, X-04 |
| Verification Method | Test |
| Verification Statement | Register a client through the remote listener; attempt authorization while pending; approve; repeat; confirm the pending attempt fails with an OAuth error stating that operator approval is pending and the approved attempt proceeds; confirm a registration request on the local listener is refused. |
| Source | OWNER (DCR supported only for the Remote Access profile with operator approval of each registration); RFC 7591 |
| Rationale | Cloud agents register dynamically; approval keeps an unknown registrant from obtaining a session. |

#### FR-16.6 — Remote rate limits and lockout

| Field | Value |
|---|---|
| ID | FR-16.6 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** apply the CP-49 remote rate limits per client ID and per forwarded source address, and the Identity & Authentication Service (E-03) **SHALL** lock a client ID and source address for the CP-49 lockout period after the CP-49 number of consecutive failed sign-ins or token requests. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-03 Identity & Authentication Service; Functions: F-01, F-04; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Exceed each rate through the remote listener; fail sign-in the lockout number of times; confirm `-31005` or HTTP 429 at the limits and refusal during the lockout period with an event recorded. |
| Source | OWNER (strict rate limits and lockout) |
| Rationale | A public name is reachable by anyone on the Internet. |

#### FR-16.7 — Remote request bounds

| Field | Value |
|---|---|
| ID | FR-16.7 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** apply the CP-49 remote body, header and concurrency bounds on the remote listener before parsing. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Send requests exceeding each remote bound; confirm rejection before parsing. |
| Source | OWNER (request bounds); SEC 7.11 |
| Rationale | Tighter bounds for an Internet-reachable endpoint. |

#### FR-16.8 — Remote origin evidence

| Field | Value |
|---|---|
| ID | FR-16.8 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Audit & Evidence Service (E-21) **SHALL** record on every event from a remote-listener request the field `channel = "remote"`, the client ID and the tunnel-supplied client address as a server-asserted value. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-01 Harness Interface Endpoint; Functions: F-53; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Make calls through the tunnel; confirm the three fields on every event and that the client address is labelled server-asserted. |
| Source | OWNER (audit of remote origin); SEC 6.18 |
| Rationale | Investigators must separate remote from local activity; the forwarded address is a claim of the tunnel provider, not a verified fact. |

#### FR-16.9 — smcp-connect relay

| Field | Value |
|---|---|
| ID | FR-16.9 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Gateway release **SHALL** include `smcp-connect`, distributed as a release binary and as an npm package of the same name, which runs as a stdio MCP server, obtains and refreshes a session against a configured Remote Access URL through the OAuth flow, stores its tokens in the CP-43 credential file, and forwards each JSON-RPC message unchanged. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-95; External interfaces: X-13, X-12 |
| Verification Method | Test |
| Verification Statement | Run the northbound conformance fixtures through `smcp-connect` against a Gateway behind a test tunnel; confirm results identical to a direct connection and the credential file mode 0600. |
| Source | OWNER (a small npx stdio relay package, smcp-connect); ARCH §4 E-33 |
| Rationale | Some agents accept only a command to launch, not a URL. |

#### FR-16.10 — Vendor allowlist guidance

| Field | Value |
|---|---|
| ID | FR-16.10 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The per-client quick start for each cloud agent of Appendix K **SHALL** name the vendor administration setting that restricts the agent's MCP servers to the Gateway URL where the vendor's public documentation names one, and otherwise **SHALL** state that no such setting was confirmed in the vendor's public documentation, with the date checked and the sources reviewed. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-13 |
| Verification Method | Inspection |
| Verification Statement | Inspect each cloud agent quick start; confirm the setting is named, or the absence of a confirmed setting stated, with the date checked and the sources reviewed. |
| Source | OWNER (the vendor admin MCP allowlist restricts the agent to the Gateway URL; live cloud-agent runs descoped from release 1.x on 2026-10-18) |
| Rationale | The vendor's allowlist is the only control that keeps a cloud agent from using other MCP servers. Vendor administration consoles are not reachable without vendor business accounts, which the project does not hold, so the quick start reports what the vendor's public documentation states and says so when it states nothing. |

#### FR-16.11 — Disabled by default

| Field | Value |
|---|---|
| ID | FR-16.11 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The configuration written by `smcpctl bootstrap` and `smcpctl install` **SHALL** leave the Remote Access Profile disabled, and enabling it **SHALL** require an Administrator action that records a `remote_access_enabled` event. |
| Allocation | Elements: E-24 Management Console & Control API, E-01 Harness Interface Endpoint; Functions: F-97; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Inspect a fresh configuration; enable the profile as an Operator and as an Administrator; confirm it is off by default, refused for the Operator and recorded for the Administrator. |
| Source | OWNER (Remote Access profile) |
| Rationale | Exposure to the Internet is an explicit, attributable decision. |

#### FR-16.12 — Remote session limits

| Field | Value |
|---|---|
| ID | FR-16.12 |
| Parent ID | FR-16 — Remote Access Profile |
| Statement | The Session Manager (E-04) **SHALL** create sessions through the remote listener only for Session Allow Policy templates that the Framework Profile marks `remote_allowed`, and **SHALL** apply the CP-49 remote session lifetime. |
| Allocation | Elements: E-04 Session Manager; Functions: F-06, F-07; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Request a template without `remote_allowed` and one with it through the remote listener; confirm refusal of the first and the shorter lifetime on the second. |
| Source | OWNER (Remote Access profile) |
| Rationale | The operator decides which tools a cloud agent may ever use, separately from local agents. |

### FR-17 Operations

#### FR-17 — Operations

| Field | Value |
|---|---|
| ID | FR-17 |
| Parent ID | — (root) |
| Statement | The Gateway **SHALL** provide the logging, metrics, key rotation, backup and configuration reload functions of this section for day-to-day operation. |
| Allocation | Elements: E-23 Health & Safety Monitor, E-22 Key & Trust Anchor Manager, E-28 Data Lifecycle & Memory Manager; Functions: F-61, F-79, F-60 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-17 child requirement; confirm each has passed. |
| Source | REVIEW (I6) |
| Rationale | An operator needs to diagnose, observe, rotate and recover the Gateway without reading its source. |

#### FR-17.1 — Diagnostic log

| Field | Value |
|---|---|
| ID | FR-17.1 |
| Parent ID | FR-17 — Operations |
| Statement | The Health & Safety Monitor (E-23) **SHALL** write a diagnostic log (D-14), separate from the Evidence Journal, as JSON Lines with the levels `error`, `warn`, `info` and `debug`, defaulting to `info`. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61; Data stores: D-14 |
| Verification Method | Test |
| Verification Statement | Run a session at each level; confirm the log's location, format and level filtering, and that no diagnostic entry appears in the journal. |
| Source | REVIEW (I6) |
| Rationale | Troubleshooting messages and evidence have different audiences, retention and integrity needs. |

#### FR-17.2 — Diagnostic log rotation

| Field | Value |
|---|---|
| ID | FR-17.2 |
| Parent ID | FR-17 — Operations |
| Statement | The Health & Safety Monitor (E-23) **SHALL** rotate the diagnostic log at the CP-50 file size and keep at most the CP-50 number of rotated files. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61; Data stores: D-14 |
| Verification Method | Test |
| Verification Statement | Generate log volume beyond several rotations; confirm file sizes and count stay within CP-50. |
| Source | REVIEW (I6) |
| Rationale | Logs must not fill the disk that holds the journal. |

#### FR-17.3 — Diagnostic log content limits

| Field | Value |
|---|---|
| ID | FR-17.3 |
| Parent ID | FR-17 — Operations |
| Statement | The Health & Safety Monitor (E-23) **SHALL** exclude from the diagnostic log, at every level, secret values, bearer and refresh tokens, passwords, tool arguments and tool results. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61; Data stores: D-14 |
| Verification Method | Test |
| Verification Statement | Run calls carrying registered secret fingerprints, tokens and marker arguments at `debug` level; scan the log; confirm none appear. |
| Source | SEC 6.7; REVIEW (I6) |
| Rationale | Diagnostic logs are copied into bug reports. |

#### FR-17.4 — Metrics endpoint

| Field | Value |
|---|---|
| ID | FR-17.4 |
| Parent ID | FR-17 — Operations |
| Statement | When the configuration enables metrics, the Health & Safety Monitor (E-23) **SHALL** serve Prometheus text exposition at `/metrics` on the CP-51 loopback address only. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61; External interfaces: X-15 |
| Verification Method | Test |
| Verification Statement | Enable metrics; scrape the endpoint; attempt to bind it to a non-loopback address; confirm valid exposition and refusal of the non-loopback address. |
| Source | REVIEW (I6) |
| Rationale | Operators use standard tooling to watch throughput and latency. |

#### FR-17.5 — Metric set and labels

| Field | Value |
|---|---|
| ID | FR-17.5 |
| Parent ID | FR-17 — Operations |
| Statement | The metrics endpoint **SHALL** expose call counts by outcome and reason code, decision latency, journal flush latency, health state, active sessions, pending approvals and running backend instances, with labels limited to server alias, public tool name, outcome, reason code and channel. |
| Allocation | Elements: E-23 Health & Safety Monitor; Functions: F-61; External interfaces: X-15 |
| Verification Method | Inspection |
| Verification Statement | Scrape the endpoint after a test run; confirm each metric and that no other label names occur. |
| Source | REVIEW (I6); SEC 6.7 |
| Rationale | Bounded labels keep arguments, principal names and secrets out of a monitoring system. |

#### FR-17.6 — Encrypted backups

| Field | Value |
|---|---|
| ID | FR-17.6 |
| Parent ID | FR-17 — Operations |
| Statement | The `smcpctl backup` command **SHALL** encrypt each backup archive (D-15) to an operator passphrase or an age recipient key and **SHALL** refuse to write an unencrypted archive. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-79; Data stores: D-15 |
| Verification Method | Test |
| Verification Statement | Back up with a passphrase and with a recipient; attempt a backup with neither; confirm two encrypted archives that restore and one refusal. |
| Source | OWNER (backups including key material and trust anchors, encrypted); SEC 7.7 |
| Rationale | The archive contains private keys; it must not be readable where it is stored. |

#### FR-17.7 — Key rotation

| Field | Value |
|---|---|
| ID | FR-17.7 |
| Parent ID | FR-17 — Operations |
| Statement | The `smcpctl keys rotate` command **SHALL** rotate the server TLS certificate without dropping sessions, rotate the server CA with an overlap period during which the published trust bundle holds both CAs and the listeners present the certificate issued by the outgoing CA until they switch to one issued by the incoming CA when the overlap ends, and rotate the evidence-signing key by closing the open segment and writing a key-transition record signed by the outgoing key. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager, E-21 Audit & Evidence Service; Functions: F-60, F-55; Data stores: D-08 |
| Verification Method | Test |
| Verification Statement | Rotate each key type under traffic; confirm sessions continue across TLS rotation and the CA switch, clients trusting the outgoing CA or the published bundle connect during the overlap, clients trusting the incoming CA connect after the switch, and the journal records the transition. |
| Source | REVIEW (I6); SEC 6.12 |
| Rationale | Keys expire and can be exposed; rotation must not require reinstalling. A TLS server presents one certificate chain per handshake, and the CP-53 path length 0 rules out a cross-certificate between the two CAs, so a client that trusts only the incoming CA cannot be served before the switch; clients import the published bundle during the overlap instead. |

#### FR-17.8 — Verification across key transitions

| Field | Value |
|---|---|
| ID | FR-17.8 |
| Parent ID | FR-17 — Operations |
| Statement | The `smcpctl journal verify` command **SHALL** follow evidence-key transition records and verify each segment with the key in force when it was signed. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-55; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Verify a journal spanning two rotations; tamper with a transition record; confirm success before and failure after the tamper. |
| Source | SEC 6.12 |
| Rationale | Rotation must not break the evidence chain. |

#### FR-17.9 — Configuration reload

| Field | Value |
|---|---|
| ID | FR-17.9 |
| Parent ID | FR-17 — Operations |
| Statement | On `smcpctl reload` or SIGHUP, the Gateway **SHALL** validate the new configuration, keep the running configuration when validation fails, apply the CP-50 reloadable keys without ending sessions, and report each changed non-reloadable key as requiring a restart. |
| Allocation | Elements: E-23 Health & Safety Monitor, E-24 Management Console & Control API; Functions: F-61, F-97 |
| Verification Method | Test |
| Verification Statement | Reload with an invalid file, with a changed rate limit and with a changed listener address; confirm the old configuration kept, the new limit applied with sessions intact, and the restart notice for the address. |
| Source | REVIEW (I6) |
| Rationale | Operators tune limits and clients without interrupting agents. |

### FR-18 Documentation

#### FR-18 — Documentation set

| Field | Value |
|---|---|
| ID | FR-18 |
| Parent ID | — (root) |
| Statement | The Gateway release **SHALL** include under `docs/` the documents of this section, versioned with the release. |
| Allocation | Elements: E-24 Management Console & Control API, E-33 Harness Adapter Kit; Functions: F-65, F-98 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-18 child requirement; confirm each has passed. |
| Source | REVIEW (I7); SEC 10.9 |
| Rationale | The product is used by people who did not build it. |

#### FR-18.1 — Install guide

| Field | Value |
|---|---|
| ID | FR-18.1 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include an install guide covering installation, upgrade, rollback and uninstall for each platform and profile of Section 1.6, including the release-signature check. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-97 |
| Verification Method | Inspection |
| Verification Statement | Follow the guide on a clean macOS arm64 host and a clean Ubuntu host; confirm each step works as written. |
| Source | REVIEW (I7) |
| Rationale | Installation is the first task every user performs. |

#### FR-18.2 — Security Limitations

| Field | Value |
|---|---|
| ID | FR-18.2 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include a Security Limitations document that states at least: the Standalone profile contains no server; an agent's non-MCP native tools bypass the Gateway; in the Standalone profile the agent runs as the Gateway's identity; a tunnel provider can read remote traffic; detection filters have measured false-positive and false-negative rates; injection findings are tags only; lockdown profiles are only as strong as each client's settings enforcement; remote backends, resources and prompts are not supported; and running the Gateway inside a vendor's agent machine is not a control. |
| Allocation | Elements: E-24 Management Console & Control API, E-33 Harness Adapter Kit; Functions: F-98 |
| Verification Method | Inspection |
| Verification Statement | Inspect the document; confirm each listed limitation is stated with its consequence and any mitigation. |
| Source | OWNER (documentation that non-MCP native tools bypass the Gateway); REVIEW (C4) |
| Rationale | Users decide how far to trust the Gateway from what it does not do. |

#### FR-18.3 — Per-client quick starts

| Field | Value |
|---|---|
| ID | FR-18.3 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include a quick start for each client of Appendix K that covers connection, session sign-in, CA trust, lockdown and verification with `smcpctl doctor`, and for cloud agents the Remote Access Profile setup. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-94, F-98, F-95; External interfaces: X-12, X-13 |
| Verification Method | Inspection |
| Verification Statement | For each client, follow the quick start at the pinned version; confirm the client lists tools through the Gateway. |
| Source | REVIEW (I7); OWNER (client matrix) |
| Rationale | Each client configures MCP differently. |

#### FR-18.4 — Operator guide

| Field | Value |
|---|---|
| ID | FR-18.4 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include an operator guide covering roles and accounts, approvals, sessions, server enablement and suspension, emergency stop, backups and restore, key rotation, configuration reload, logs and metrics. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65 |
| Verification Method | Inspection |
| Verification Statement | Inspect the guide; confirm a section for each topic referencing the commands and views that perform it. |
| Source | REVIEW (I7); SEC 10.9 |
| Rationale | Daily operation needs one reference. |

#### FR-18.5 — Policy reference

| Field | Value |
|---|---|
| ID | FR-18.5 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include a policy reference describing every policy object type, field, predicate operator and obligation, with examples that the build validates against the policy schema. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10 |
| Verification Method | Test |
| Verification Statement | Run the documentation check; confirm every example validates against the policy schema and every schema field is described. |
| Source | REVIEW (I7) |
| Rationale | Policy authors write policy from the reference, so its examples must be valid. |

#### FR-18.6 — Packaging guide

| Field | Value |
|---|---|
| ID | FR-18.6 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include a packaging guide covering artifact references, classification, building, signing, verifying, importing, enabling and revoking a server package, using a reference server as the worked example. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96 |
| Verification Method | Inspection |
| Verification Statement | Follow the guide to package one server that is not a reference server; confirm it imports and runs. |
| Source | REVIEW (I7); OWNER (operator self-curation) |
| Rationale | Packaging is the only way to admit a server. |

#### FR-18.7 — Troubleshooting and reason codes

| Field | Value |
|---|---|
| ID | FR-18.7 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include a troubleshooting guide that explains every Appendix B error code and every reason code the Gateway emits, with its meaning and the operator's next action, and the build **SHALL** fail when a reason code in the source is missing from the guide. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-22 |
| Verification Method | Test |
| Verification Statement | Add an undocumented reason code to a test branch; confirm the build fails; confirm the release commit passes. |
| Source | REVIEW (I7) |
| Rationale | Reason codes are what users paste into bug reports. |

#### FR-18.8 — Tested runbooks

| Field | Value |
|---|---|
| ID | FR-18.8 |
| Parent ID | FR-18 — Documentation set |
| Statement | The documentation **SHALL** include runbooks for emergency stop, revocation, backup, restore, upgrade rollback and key rotation, each with a recorded execution against the release commit. |
| Allocation | Elements: E-24 Management Console & Control API, E-28 Data Lifecycle & Memory Manager, E-12 Enforcement Coordinator; Functions: F-31, F-79 |
| Verification Method | Inspection |
| Verification Statement | Inspect each runbook and its execution record in `docs/verification/`; confirm the record names the commit, date and observed result. |
| Source | SEC 10.9 |
| Rationale | A recovery procedure that was never run is not a procedure. |

#### FR-18.9 — Scope statement

| Field | Value |
|---|---|
| ID | FR-18.9 |
| Parent ID | FR-18 — Documentation set |
| Statement | The repository README and the documentation index **SHALL** state that remote MCP servers as backends are not supported in v1 and that the Gateway relays tools only, without resources or prompts. |
| Allocation | Elements: E-24 Management Console & Control API, E-02 Protocol Mediator; Functions: F-02 |
| Verification Method | Inspection |
| Verification Statement | Inspect the README and `docs/README.md`; confirm both statements. |
| Source | REVIEW (I9, I10); OWNER (remote hosted MCP servers out of scope for v1) |
| Rationale | Users must learn the scope before they try to connect an unsupported server. |

### FR-19 Verification evidence

#### FR-19 — Verification evidence

| Field | Value |
|---|---|
| ID | FR-19 |
| Parent ID | — (root) |
| Statement | The Gateway project **SHALL** produce the verification evidence of this section for each release and **SHALL** publish its results with the release status data. |
| Allocation | Elements: E-24 Management Console & Control API, E-11 Response Inspection Pipeline, E-09 Request Inspection Pipeline; Functions: F-27, F-21 |
| Verification Method | Analysis |
| Verification Statement | Review the verification results of every FR-19 child requirement; confirm each has passed. |
| Source | SEC 10.6; REVIEW (C7, C8) |
| Rationale | Claims about enforcement are only as good as the evidence published with them. |

#### FR-19.1 — Hostile backend fixture suite

| Field | Value |
|---|---|
| ID | FR-19.1 |
| Parent ID | FR-19 — Verification evidence |
| Statement | The Gateway source **SHALL** include a hostile backend MCP server fixture that implements each attack of Appendix L and an automated test for each Appendix L row that asserts the row's expected outcome in the profile the row names. |
| Allocation | Elements: E-11 Response Inspection Pipeline, E-09 Request Inspection Pipeline, E-14 Local Server Registry, E-15 Server Runtime Manager, E-16 Execution Sandbox, E-18 Egress Broker; Functions: F-27, F-21, F-37, F-41, F-45 |
| Verification Method | Test |
| Verification Statement | Run the hostile suite in both profiles; confirm one test per Appendix L row and that each passes in the profiles the row names. |
| Source | REVIEW (C8); SEC Appendix B AT-08, AT-09, AT-10 |
| Rationale | Each attack a malicious server can make should have a test that shows what the Gateway does about it. |

#### FR-19.2 — Hostile suite results

| Field | Value |
|---|---|
| ID | FR-19.2 |
| Parent ID | FR-19 — Verification evidence |
| Statement | The continuous-integration pipeline **SHALL** publish, for each Appendix L row, the fixture name, attack, expected outcome, observed outcome and pass flag in the `hostile` array of the status data. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65 |
| Verification Method | Inspection |
| Verification Statement | Inspect the status data of a main-branch run; confirm one entry per Appendix L row with each field. |
| Source | REVIEW (C8) |
| Rationale | Results, including failures, are visible to anyone deciding whether to trust the Gateway. |

#### FR-19.3 — Enforced label gating

| Field | Value |
|---|---|
| ID | FR-19.3 |
| Parent ID | FR-19 — Verification evidence |
| Statement | The release process **SHALL** label a release "enforced" only when every acceptance scenario AT-01 to AT-21 of Appendix M has an automated or recorded passing result for the release commit in the Enforced profile, and **SHALL** label it "not enforced" otherwise. |
| Allocation | Elements: E-24 Management Console & Control API, E-23 Health & Safety Monitor; Functions: F-61 |
| Verification Method | Inspection |
| Verification Statement | Inspect the release record of a candidate with one unexecuted scenario and of one with all scenarios passing; confirm the labels "not enforced" and "enforced" respectively. |
| Source | SEC 10.6; REVIEW (C7) |
| Rationale | A failed or unexecuted scenario means the enforcement claim is unsupported. |

#### FR-19.4 — Acceptance scenario records

| Field | Value |
|---|---|
| ID | FR-19.4 |
| Parent ID | FR-19 — Verification evidence |
| Statement | Each acceptance scenario of Appendix M **SHALL** have either automated tests that claim it by its `AT-nn` ID or a recorded execution file `docs/verification/AT-nn.md` stating the commit, date, executor, steps, observations and result. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65 |
| Verification Method | Inspection |
| Verification Statement | Inspect the requirement report and `docs/verification/`; confirm each AT ID has claiming tests or a complete record. |
| Source | SEC 10.6; SEC Appendix B |
| Rationale | Scenarios that need a person still need a record a reviewer can check. |

#### FR-19.5 — Labelled detection corpora

| Field | Value |
|---|---|
| ID | FR-19.5 |
| Parent ID | FR-19 — Verification evidence |
| Statement | Each detection rule set of FR-4.16 **SHALL** ship with a labelled corpus of positive and negative samples, and the continuous-integration pipeline **SHALL** measure and publish the false-positive and false-negative rate of each rule-set version against its corpus. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline, E-14 Local Server Registry; Functions: F-21, F-27, F-34 |
| Verification Method | Test |
| Verification Statement | Run the corpus job; confirm a rate pair per rule-set version in the published results and that a rule change that raises either rate beyond the recorded value is reported. |
| Source | REVIEW (I1); SEC 5.14 |
| Rationale | A detector's value is its measured error rates, not its rule count. |

## 5. Security requirements (SR)

Each security requirement is a **SHALL** control whose parent is a **MUST** in `MCP_Gateway_Security_SRS.md` (cited as `SEC-n.n`). The ID `SR-<parent>-<k>` is the k-th child of that parent. The security SRS was written against the V1 architecture. Where its wording names a V1 component (for example "graph service", "supervisor", "admission worker"), the child below states the V2 element that realizes the control. MUSTs with no Gateway realization are listed with a disposition in Appendix E.

### SEC-1 Policy and routing authority

#### SR-1-2 — Layer intersection

| Field | Value |
|---|---|
| ID | SR-1-2 |
| Parent ID | SEC-1 — Graph policy and routing authority (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** permit a call only when it is permitted by every one of the Framework Profile, the Session Allow Policy as narrowed by session claims, and the request-time conditions. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13; Internal interfaces: I-05, I-08 |
| Verification Method | Test |
| Verification Statement | Run fixtures permitted by all but one layer, for each layer; confirm each is denied. |
| Source | ARCH §7.1 |
| Rationale | Each layer can only remove authority. |

#### SR-1-3 — Template within profile

| Field | Value |
|---|---|
| ID | SR-1-3 |
| Parent ID | SEC-1 — Graph policy and routing authority (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** reject publication of a Session Allow Policy template that grants authority absent from every Framework Profile permitted to use it. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10 |
| Verification Method | Test |
| Verification Statement | Publish a template granting a tool its profiles lack; confirm rejection. |
| Source | ARCH §7.3 |
| Rationale | Templates cannot widen profile authority. |

#### SR-1.1-1 — Single policy source

| Field | Value |
|---|---|
| ID | SR-1.1-1 |
| Parent ID | SEC-1.1 — Authoritative graph (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** derive permit, deny and route rules and the optional filters a rule requires only from the active policy revision held by the Policy Administration Service (E-05) in the Policy Store (D-01), compiled into the in-memory decision snapshot. |
| Allocation | Elements: E-06 Policy Decision Service, E-05 Policy Administration Service; Functions: F-13; Data stores: D-01 |
| Verification Method | Inspection |
| Verification Statement | Inspect the evaluator's inputs and configuration loading; confirm that no other file, environment variable, API or the graph mirror supplies rules, and that editing the graph mirror changes no decision. |
| Source | SEC 1.1; ARCH §4 E-06; ARCH §2.2 A-9; OWNER (policy authority is the signed revision held by E-05) |
| Rationale | One authoritative source. SEC 1.1 names the graph; the owner moved the authority to the signed revision so that enforcement does not depend on a database service (CHANGELOG V1.2). Release 1.0 keeps the audit and observation settings in the published Audit Profile and Observation Policy objects and the mandatory filters in the `[filters]` configuration (FR-3.1, FR-3.26); the decision carries the audit and observation objects in force as obligations (FR-3.12) and evaluates no rule from them. |

#### SR-1.1-2 — Signed policy revisions

| Field | Value |
|---|---|
| ID | SR-1.1-2 |
| Parent ID | SEC-1.1 — Authoritative graph (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** sign each published revision with the policy-signing key held by the Key & Trust Anchor Manager (E-22), and the Policy Decision Service (E-06) **SHALL** compile only a revision whose signature verifies and whose content validates against the policy schema. |
| Allocation | Elements: E-05 Policy Administration Service, E-06 Policy Decision Service, E-22 Key & Trust Anchor Manager; Functions: F-12, F-13; Data stores: D-01, D-08 |
| Verification Method | Test |
| Verification Statement | Publish a revision; alter one byte of the stored file; restart; confirm the altered revision is refused and the Gateway is `fail-closed` with cause `policy_signature`; restore the file and confirm normal start. |
| Source | SEC 1.1; SEC 1.14; OWNER (signed, schema-validated policy revision) |
| Rationale | Files on disk can be edited by anyone with access to the state directory; the signature makes an unauthorized edit detectable before it takes effect. |

#### SR-1.2-1 — Snapshot unavailability denial

| Field | Value |
|---|---|
| ID | SR-1.2-1 |
| Parent ID | SEC-1.2 — Graph outage (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When no validated decision snapshot of the active revision is loaded, the Policy Decision Service (E-06) **SHALL** return deny, and the Access Enforcement Point (E-08) **SHALL** return Gateway error `-31004`. |
| Allocation | Elements: E-06 Policy Decision Service, E-08 Access Enforcement Point; Functions: F-13, F-20 |
| Verification Method | Test |
| Verification Statement | Corrupt the snapshot at load; confirm every call is answered with -31004. |
| Source | SEC 1.2 |
| Rationale | Fail closed. |

#### SR-1.2-2 — Data Server outage

| Field | Value |
|---|---|
| ID | SR-1.2-2 |
| Parent ID | SEC-1.2 — Graph outage (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the Audit & Evidence Service (E-21) cannot append and flush the decision intent to the Evidence Journal, the Enforcement Coordinator (E-12) **SHALL** refuse launch authorization with reason code `JOURNAL_UNAVAILABLE`. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-21 Audit & Evidence Service; Functions: F-29, F-55; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Make the journal directory unwritable and, separately, inject a flush failure during traffic; confirm no dispatch occurs and `-31004` with `JOURNAL_UNAVAILABLE` is returned; stop the graph database during traffic and confirm dispatch continues. |
| Source | SEC 1.2; SEC 6.2; OWNER (evidence authority is the journal) |
| Rationale | Dispatch requires durable intent; the journal, not the graph, is where intent becomes durable. |

#### SR-1.3-1 — Default deny

| Field | Value |
|---|---|
| ID | SR-1.3-1 |
| Parent ID | SEC-1.3 — Default denial (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When no applicable permit exists, the Policy Decision Service (E-06) **SHALL** return deny with reason code `NO_PERMIT`. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Evaluate a request matching no permit; confirm deny with `NO_PERMIT`. |
| Source | SEC 1.3 |
| Rationale | Allow-policy semantics. |

#### SR-1.4-1 — Deny precedence

| Field | Value |
|---|---|
| ID | SR-1.4-1 |
| Parent ID | SEC-1.4 — Deny precedence (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When an applicable deny rule exists, the Policy Decision Service (E-06) **SHALL** return deny regardless of applicable permits. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Evaluate fixtures with both a matching permit and a matching deny; confirm deny. |
| Source | SEC 1.4 |
| Rationale | Deny wins. |

#### SR-1.5-1 — Prerequisite checks

| Field | Value |
|---|---|
| ID | SR-1.5-1 |
| Parent ID | SEC-1.5 — Admission prerequisites (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** deny a call whose principal is disabled, whose credential is expired or revoked, whose session is not active, whose server revision is not `enabled`, or whose tool has no explicit grant. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13; Internal interfaces: I-05 |
| Verification Method | Test |
| Verification Statement | Run one fixture per prerequisite failure; confirm deny with the matching reason code. |
| Source | SEC 1.5; ARCH §4 E-14 |
| Rationale | Prerequisites gate evaluation. |

#### SR-1.7-1 — Predicate operator set

| Field | Value |
|---|---|
| ID | SR-1.7-1 |
| Parent ID | SEC-1.7 — Typed predicates (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** implement only the predicate operators exact equality, set membership, inclusive numeric range, canonical path containment, scheme/host/port membership, data-class membership, UTC expiry interval and approval state. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Run the operator fixture suite; confirm each operator's semantics and that an unknown operator in a draft is rejected at validation. |
| Source | SEC 1.7; SEC Appendix F |
| Rationale | Typed, deterministic predicates. |

#### SR-1.7-2 — Missing attribute denial

| Field | Value |
|---|---|
| ID | SR-1.7-2 |
| Parent ID | SEC-1.7 — Typed predicates (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a predicate references a missing or malformed attribute, the Policy Decision Service (E-06) **SHALL** evaluate the rule as not matching for permits and **SHALL** deny the request. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Omit an attribute referenced by a permit; confirm deny. |
| Source | SEC Appendix F |
| Rationale | Missing data cannot grant. |

#### SR-1.8-1 — Argument schema validation

| Field | Value |
|---|---|
| ID | SR-1.8-1 |
| Parent ID | SEC-1.8 — Argument scope (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Request Inspection Pipeline (E-09) **SHALL** validate tool arguments against the manifest `inputSchema` and **SHALL** block the call with reason `SCHEMA_INVALID` (Appendix B) on failure. |
| Allocation | Elements: E-09 Request Inspection Pipeline; Functions: F-21 |
| Verification Method | Test |
| Verification Statement | Send arguments violating type, required and additionalProperties constraints; confirm each is blocked. |
| Source | SEC 1.8; MCP:server/tools §Security Considerations |
| Rationale | Arguments must match the approved schema. |

#### SR-1.8-2 — Schema dialect handling

| Field | Value |
|---|---|
| ID | SR-1.8-2 |
| Parent ID | SEC-1.8 — Argument scope (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Request Inspection Pipeline (E-09) **SHALL** validate JSON Schema 2020-12 and draft-07, **SHALL** treat any other dialect as a validation failure, and **SHALL** never dereference a network `$ref`. |
| Allocation | Elements: E-09 Request Inspection Pipeline; Functions: F-21 |
| Verification Method | Test |
| Verification Statement | Validate against schemas of each dialect and one with an `https:` `$ref`; confirm the results and that no network access occurs. |
| Source | MCP:basic/index §JSON Schema Usage; §$ref Resolution |
| Rationale | Unsupported dialects and remote refs fail closed. |

#### SR-1.8-3 — Schema resource bounds

| Field | Value |
|---|---|
| ID | SR-1.8-3 |
| Parent ID | SEC-1.8 — Argument scope (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Request Inspection Pipeline (E-09) **SHALL** abort schema validation that exceeds the CP-36 depth, subschema count or time bound and **SHALL** block the call. |
| Allocation | Elements: E-09 Request Inspection Pipeline; Functions: F-21 |
| Verification Method | Test |
| Verification Statement | Validate against an exponential composition schema; confirm abort within the time bound. |
| Source | MCP:basic/index §Composition-Keyword Resource Use |
| Rationale | Schema denial-of-service defense. |

#### SR-1.8-4 — Path canonicalization

| Field | Value |
|---|---|
| ID | SR-1.8-4 |
| Parent ID | SEC-1.8 — Argument scope (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Request Inspection Pipeline (E-09) **SHALL** canonicalize every path-typed argument by resolving `.`, `..` and symbolic links against the granted roots before path-containment evaluation. |
| Allocation | Elements: E-09 Request Inspection Pipeline; Functions: F-21 |
| Verification Method | Test |
| Verification Statement | Submit traversal, symlink-escape and encoded-separator paths; confirm each is denied. |
| Source | SEC 1.8; A2 §8 ENG-01 |
| Rationale | Path scope must use the real target. |

#### SR-1.8-5 — URL canonicalization

| Field | Value |
|---|---|
| ID | SR-1.8-5 |
| Parent ID | SEC-1.8 — Argument scope (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Request Inspection Pipeline (E-09) **SHALL** canonicalize every URL-typed argument by normalizing scheme, IDNA host, port and IP-literal forms before destination-membership evaluation. |
| Allocation | Elements: E-09 Request Inspection Pipeline; Functions: F-21 |
| Verification Method | Test |
| Verification Statement | Submit equivalent URL encodings of a denied host; confirm each is denied. |
| Source | SEC 1.8 |
| Rationale | Destination scope must not be bypassed by encoding. |

#### SR-1.9-1 — Overlap rejection

| Field | Value |
|---|---|
| ID | SR-1.9-1 |
| Parent ID | SEC-1.9 — Unambiguous permits (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** reject publication of a revision containing overlapping permits whose argument scopes or obligations cannot be combined by the Appendix F precedence table. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10 |
| Verification Method | Test |
| Verification Statement | Publish two overlapping permits with conflicting routes; confirm rejection naming both rules. |
| Source | SEC 1.9 |
| Rationale | Unambiguous grants. |

#### SR-1.10-1 — Obligation precedence

| Field | Value |
|---|---|
| ID | SR-1.10-1 |
| Parent ID | SEC-1.10 — Obligation combination (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** combine the obligations that apply to a permitted call (from the permit rule, its template and Framework Profile, the CP-11 limits, the approval floor and session taint) as the union of required filters, the smallest rate, burst and session-quota bounds, and the most restrictive approval. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-14 |
| Verification Method | Test |
| Verification Statement | Evaluate requests whose permit rule, template, profile and configured limits carry differing obligations, with and without the approval floor and session taint; confirm the combined result. |
| Source | SEC 1.10; SEC Appendix F |
| Rationale | Conservative combination. Release 1.0 refuses overlapping permit rules at publication (SR-1.9-1), so a call has one permit rule and the layers above it; the size, time and resource bounds (CP-08, CP-13, CP-24) and the retention and capture settings (the Audit Profile and Observation Policy in force) have one source each and are carried into the decision unchanged (FR-3.12), so there is nothing to combine for them. The anomaly approval of FR-4.15 is added by the Anomaly Scorer after the decision and can only add the obligation. |

#### SR-1.11-1 — Single route

| Field | Value |
|---|---|
| ID | SR-1.11-1 |
| Parent ID | SEC-1.11 — Deterministic routing (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** select exactly one route bound to the evaluated server and tool revision and **SHALL** deny when zero or more than one route is eligible. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13, F-14 |
| Verification Method | Test |
| Verification Statement | Evaluate fixtures with zero, one and two eligible routes; confirm deny, permit and deny. |
| Source | SEC 1.11 |
| Rationale | Deterministic routing. |

#### SR-1.12-1 — No semantic authorization

| Field | Value |
|---|---|
| ID | SR-1.12-1 |
| Parent ID | SEC-1.12 — No semantic authorization (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** exclude full-text scores, vector similarity and model-generated content from permit and route selection. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Inspection |
| Verification Statement | Inspect the evaluator inputs; confirm none of the excluded sources is reachable. |
| Source | SEC 1.12 |
| Rationale | Authorization is deterministic. |

#### SR-1.12-2 — Restrict-only anomaly effect

| Field | Value |
|---|---|
| ID | SR-1.12-2 |
| Parent ID | SEC-1.12 — No semantic authorization (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** apply anomaly bands only by adding obligations from the restrict-only action set and **SHALL** never convert a deny into a permit because of a band. |
| Allocation | Elements: E-06 Policy Decision Service, E-31 Anomaly Scorer; Functions: F-14, F-90; Internal interfaces: I-31 |
| Verification Method | Test |
| Verification Statement | Evaluate denied requests with `normal` bands and permitted requests with `critical` bands; confirm the denials stand and the permits gain restrictions. |
| Source | ARCH §2.2 A-7; SEC 1.12 |
| Rationale | Statistics may restrict but never grant. |

#### SR-1.12-3 — Snapshot recording

| Field | Value |
|---|---|
| ID | SR-1.12-3 |
| Parent ID | SEC-1.12 — No semantic authorization (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** record the baseline snapshot ID used for any anomaly obligation in the decision record. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13, F-16 |
| Verification Method | Inspection |
| Verification Statement | Inspect a decision with an anomaly obligation; confirm the snapshot ID. |
| Source | ARCH §9.4 step 6 |
| Rationale | Reproducibility of statistical restrictions. |

#### SR-1.13-1 — Fixed query templates

| Field | Value |
|---|---|
| ID | SR-1.13-1 |
| Parent ID | SEC-1.13 — Fixed query templates (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Data Access Service (E-26) **SHALL** execute only parameterized query templates from its versioned template set and **SHALL** reject caller-supplied query text, labels, relationship types or procedure names. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-72; Internal interfaces: I-36, I-37 |
| Verification Method | Test |
| Verification Statement | Submit operations attempting to inject query text in each parameter; confirm rejection and no execution. |
| Source | SEC 1.13 |
| Rationale | Prevents query injection. |

#### SR-1.13-2 — Template integrity

| Field | Value |
|---|---|
| ID | SR-1.13-2 |
| Parent ID | SEC-1.13 — Fixed query templates (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Data Access Service (E-26) **SHALL** verify the digest of its template set against the release manifest at startup and **SHALL** refuse to start on mismatch. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-72 |
| Verification Method | Test |
| Verification Statement | Modify one template file; confirm startup refusal. |
| Source | SEC 1.13 |
| Rationale | Templates are reviewed code. |

#### SR-1.14-1 — Immutable revisions

| Field | Value |
|---|---|
| ID | SR-1.14-1 |
| Parent ID | SEC-1.14 — Immutable revisions (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** reject every modification of a published revision, rule or route record, and **SHALL** store each published revision as a read-only file named by its content digest. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-12; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Attempt updates to published records through every API; confirm rejection. |
| Source | SEC 1.14 |
| Rationale | Historical decisions remain explainable. |

#### SR-1.15-1 — Atomic activation

| Field | Value |
|---|---|
| ID | SR-1.15-1 |
| Parent ID | SEC-1.15 — Atomic activation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** activate a revision by writing the new policy-control record to a temporary file, flushing it, and atomically renaming it over the active record, and the Policy Decision Service (E-06) **SHALL** swap to the new snapshot only after the rename and the directory flush complete. |
| Allocation | Elements: E-05 Policy Administration Service, E-06 Policy Decision Service; Functions: F-12, F-13; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Crash the service at each step of activation; confirm the active revision is either the old or the new one, never mixed. |
| Source | SEC 1.15 |
| Rationale | No partial policy. |

#### SR-1.16-1 — Coordinator serialization

| Field | Value |
|---|---|
| ID | SR-1.16-1 |
| Parent ID | SEC-1.16 — Publication ordering (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Enforcement Coordinator (E-12) **SHALL** serialize policy activation, revocation, emergency stop, launch authorization and release authorization through one gate. |
| Allocation | Elements: E-12 Enforcement Coordinator; Functions: F-29, F-30, F-31, F-32 |
| Verification Method | Test |
| Verification Statement | Race publication, emergency stop and revocation against launches held inside launch authorization; confirm every launch is ordered entirely before or after each of them. |
| Source | SEC 1.16; SEC Appendix F (coordinator ordering) |
| Rationale | Closes policy races. A revocation in release 1.0 is a credential revocation, a principal suspension or a server revision suspension or revocation; each changes its records under the gate. |

#### SR-1.17-1 — Pre-launch recheck

| Field | Value |
|---|---|
| ID | SR-1.17-1 |
| Parent ID | SEC-1.17 — Pre-dispatch and release checks (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | Under the gate, the Enforcement Coordinator (E-12) **SHALL** recheck the policy revision, session state, principal state, credential state and server revision state before issuing a launch capability. |
| Allocation | Elements: E-12 Enforcement Coordinator; Functions: F-29 |
| Verification Method | Test |
| Verification Statement | Between decision and launch, activate a new policy revision, suspend the session, revoke the credential, suspend the principal and suspend the server revision, one per call; confirm each launch is refused. |
| Source | SEC 1.17 |
| Rationale | Decisions can become stale before launch. Release 1.0 keeps no revocation epochs: each revocation is a state record (a revoked credential, a suspended principal, an ended or suspended session, a suspended or revoked server revision) changed under the gate (SR-1.16-1) and read by this recheck, which gives the same ordering. |

#### SR-1.17-2 — Pre-release recheck

| Field | Value |
|---|---|
| ID | SR-1.17-2 |
| Parent ID | SEC-1.17 — Pre-dispatch and release checks (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | Under the gate, the Enforcement Coordinator (E-12) **SHALL** recheck session state, revocation epochs and emergency-stop state before issuing a release authorization. |
| Allocation | Elements: E-12 Enforcement Coordinator; Functions: F-30 |
| Verification Method | Test |
| Verification Statement | Terminate the session during backend execution; confirm the result is withheld. |
| Source | SEC 1.17 |
| Rationale | Authority can lapse during execution. |

#### SR-1.18-1 — Approval floor

| Field | Value |
|---|---|
| ID | SR-1.18-1 |
| Parent ID | SEC-1.18 — Bound human approval (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** require approval for every call to a tool whose manifest side-effect class is `write`, `external` or `execute`, or whose capability is in an Appendix F approval-trigger class. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-14 |
| Verification Method | Test |
| Verification Statement | Call a tool of each class under a policy without approval rules; confirm the approval obligation. |
| Source | SEC 1.18; SEC Appendix F (approval triggers) |
| Rationale | A policy cannot remove the approval floor. |

#### SR-1.18-2 — Approval binding

| Field | Value |
|---|---|
| ID | SR-1.18-2 |
| Parent ID | SEC-1.18 — Bound human approval (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Approval Service (E-07) **SHALL** bind each approval to session, principal, server, tool and route revisions, canonical argument digest and policy revision, with an expiry of at most CP-17 and single use. |
| Allocation | Elements: E-07 Approval Service; Functions: F-18 |
| Verification Method | Test |
| Verification Statement | Retry with a changed argument, another session, after a revision change and after expiry; confirm each is refused. |
| Source | SEC 1.18 |
| Rationale | Approval authorizes exactly one request. |

#### SR-1.18-3 — Approval after transformation

| Field | Value |
|---|---|
| ID | SR-1.18-3 |
| Parent ID | SEC-1.18 — Bound human approval (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a request filter changes action-defining arguments of an approved call, the Approval Service (E-07) **SHALL** require a new approval bound to the transformed arguments. |
| Allocation | Elements: E-07 Approval Service, E-09 Request Inspection Pipeline; Functions: F-17, F-21 |
| Verification Method | Test |
| Verification Statement | Redact a destination argument of an approved call; confirm a new approval is required. |
| Source | SEC 1.18; SEC 5.12 |
| Rationale | The approver must see the final request. |

#### SR-1.19-1 — Decision explanation API

| Field | Value |
|---|---|
| ID | SR-1.19-1 |
| Parent ID | SEC-1.19 — Rule explanation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** return, through `GET /api/v1/decisions/{id}/explanation`, the considered, applicable and decisive rule-revision IDs, selected route, effective obligations and anomaly evidence of a decision. |
| Allocation | Elements: E-06 Policy Decision Service, E-24 Management Console & Control API; Functions: F-16; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Request explanations for permit, deny and anomaly-restricted decisions; confirm the contents. |
| Source | SEC 1.19 |
| Rationale | Decisions are explainable. |

#### SR-1.20-1 — Evaluation bounds

| Field | Value |
|---|---|
| ID | SR-1.20-1 |
| Parent ID | SEC-1.20 — Bounded graph work (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** deny an evaluation that exceeds the CP-12 deadline or candidate-rule bound, with reason code `EVAL_BOUND`. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Construct a request matching 300 candidate rules and a slow-evaluation fixture; confirm deny with `EVAL_BOUND`. |
| Source | SEC 1.20 |
| Rationale | Bounded decision work. |

### SEC-2 Identity, credentials and administration

#### SR-2-1 — Secrets never northbound

| Field | Value |
|---|---|
| ID | SR-2-1 |
| Parent ID | SEC-2 — Identity and administration separation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Gateway **SHALL** exclude secret values from all X-01 traffic, including results, errors, progress notifications and session API responses. |
| Allocation | Elements: E-02 Protocol Mediator, E-11 Response Inspection Pipeline, E-20 Secret Broker; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Deliver fingerprinted secrets in every mode and echo them through fixture outputs; confirm none reaches the harness. |
| Source | ARCH §8.1 principle 1 |
| Rationale | The agent side never sees secrets. |

#### SR-2-2 — Researcher role limits

| Field | Value |
|---|---|
| ID | SR-2-2 |
| Parent ID | SEC-2 — Identity and administration separation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Management Console & Control API (E-24) **SHALL** deny the Researcher role policy publication, approval decisions, secret operations, credential operations and S3 payload access without a campaign grant. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-64 |
| Verification Method | Test |
| Verification Statement | Attempt each excluded operation as Researcher; confirm denial. |
| Source | ARCH §4 E-24; Appendix C |
| Rationale | Research access does not include control authority. |

#### SR-2.1-1 — Verified principal derivation

| Field | Value |
|---|---|
| ID | SR-2.1-1 |
| Parent ID | SEC-2.1 — Per-request authentication (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Identity & Authentication Service (E-03) **SHALL** derive the principal of each request only from the client registration bound to a verified access token (FR-2.18), from the verified client certificate when the mTLS Harness Profile is enabled, or from the verified UDS peer and bearer key. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04; Internal interfaces: I-02 |
| Verification Method | Test |
| Verification Statement | Send requests with forged clientInfo and session-claim principal fields; confirm the principal is unchanged. |
| Source | SEC 2.1 |
| Rationale | Identity from credentials only. |

#### SR-2.1-2 — Session token binding

| Field | Value |
|---|---|
| ID | SR-2.1-2 |
| Parent ID | SEC-2.1 — Per-request authentication (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Identity & Authentication Service (E-03) **SHALL** reject with HTTP 401 and Gateway error `-31006` a session token presented on a listener other than the one it was issued for, or, when the mTLS Harness Profile or the UDS Harness Profile is enabled, over a connection whose client certificate thumbprint or UDS peer differs from the one bound at session creation. |
| Allocation | Elements: E-03 Identity & Authentication Service, E-04 Session Manager; Functions: F-05; External interfaces: X-01; Internal interfaces: I-02, I-04 |
| Verification Method | Test |
| Verification Statement | Replay a valid TLS-listener token over the UDS listener, and, with the mTLS profile enabled, from another certificate; confirm rejection of both. |
| Source | SEC 2.1 |
| Rationale | Tokens are bound to their listener, and to the connection credential where one exists. |

#### SR-2.1-3 — Per-request authentication

| Field | Value |
|---|---|
| ID | SR-2.1-3 |
| Parent ID | SEC-2.1 — Per-request authentication (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Identity & Authentication Service (E-03) **SHALL** authenticate every MCP and session-API request individually. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04, F-05 |
| Verification Method | Test |
| Verification Statement | Revoke a certificate mid-stream on a kept-alive connection; confirm the next request is rejected. |
| Source | SEC 2.1 |
| Rationale | No connection-scoped trust. |

#### SR-2.2-1 — Independent credentials

| Field | Value |
|---|---|
| ID | SR-2.2-1 |
| Parent ID | SEC-2.2 — Distinct client credentials (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Key & Trust Anchor Manager (E-22) **SHALL** issue a distinct credential per framework instance, revocable without affecting other instances. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-59 |
| Verification Method | Test |
| Verification Statement | Revoke one of two instances' credentials; confirm the other continues. |
| Source | SEC 2.2 |
| Rationale | Containment of credential compromise. |

#### SR-2.3-1 — Bearer key generation

| Field | Value |
|---|---|
| ID | SR-2.3-1 |
| Parent ID | SEC-2.3 — Client-key protection (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Key & Trust Anchor Manager (E-22) **SHALL** generate UDS bearer keys, session tokens, access tokens, refresh tokens, authorization codes and client secrets from at least 256 bits of CSPRNG output and **SHALL** store only their verifiers: SHA-256 for session, access and refresh tokens and authorization codes, and Argon2id (CP-28) for client secrets and UDS bearer keys. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager, E-04 Session Manager; Functions: F-59, F-06 |
| Verification Method | Inspection |
| Verification Statement | Inspect the generation code and stored records; confirm entropy and verifier-only storage. |
| Source | SEC 2.3 |
| Rationale | Stored verifiers cannot be replayed. Client secrets and UDS bearer keys are long-lived and checked rarely, so they get the slower Argon2id verifier used for passwords; short-lived tokens are checked on every request and use SHA-256. |

#### SR-2.3-2 — Adapter credential storage

| Field | Value |
|---|---|
| ID | SR-2.3-2 |
| Parent ID | SEC-2.3 — Client-key protection (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Harness Adapter Kit (E-33) **SHALL** store the principal credential and refresh token only in the CP-43 credential file with mode 0600 and **SHALL** refuse to start when that file is readable or writable by other users. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-94; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | Set the file to mode 0644; confirm the adapter exits with an error naming the file and makes no connection. |
| Source | SEC 2.3; CP-43 |
| Rationale | The adapter holds the only copy of a framework credential on the harness host. |

#### SR-2.4-1 — Revocation latency

| Field | Value |
|---|---|
| ID | SR-2.4-1 |
| Parent ID | SEC-2.4 — Revocation deadline (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Enforcement Coordinator (E-12) **SHALL** prevent new launch authorization for a revoked credential, session or principal within CP-16 of the revocation. |
| Allocation | Elements: E-12 Enforcement Coordinator; Functions: F-32; Internal interfaces: I-20 |
| Verification Method | Test |
| Verification Statement | Revoke under load; confirm no launch for the revoked identity later than CP-16. |
| Source | SEC 2.4 |
| Rationale | Timely revocation. |

#### SR-2.5-1 — Admin endpoint separation

| Field | Value |
|---|---|
| ID | SR-2.5-1 |
| Parent ID | SEC-2.5 — Admin identity (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Management Console & Control API (E-24) **SHALL** serve the control API only on the CP-03 admin listener and **SHALL** reject harness client certificates and session tokens. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-63; External interfaces: X-04 |
| Verification Method | Test |
| Verification Statement | Present harness credentials to the control API; confirm rejection. |
| Source | SEC 2.5 |
| Rationale | Agents cannot reach administration. |

#### SR-2.6-1 — Admin session profile

| Field | Value |
|---|---|
| ID | SR-2.6-1 |
| Parent ID | SEC-2.6 — Protected admin session (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Management Console & Control API (E-24) **SHALL** implement administrative sessions with server-side random IDs, `Secure`, `HttpOnly` and `SameSite=Strict` cookies, ID rotation on login and privilege change, immediate logout invalidation, and the CP-29 idle and absolute limits. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-63 |
| Verification Method | Test |
| Verification Statement | Verify each property, including that a pre-login session ID is not preserved. |
| Source | SEC 2.6; SEC Appendix F |
| Rationale | Protected administrator sessions. |

#### SR-2.7-1 — Password hashing

| Field | Value |
|---|---|
| ID | SR-2.7-1 |
| Parent ID | SEC-2.7 — Password verification (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Management Console & Control API (E-24) **SHALL** store administrator passwords only as Argon2id verifiers with the CP-28 parameters. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-63 |
| Verification Method | Inspection |
| Verification Statement | Inspect stored verifiers and parameters. |
| Source | SEC 2.7 |
| Rationale | Password confidentiality. |

#### SR-2.8-1 — TLS profile

| Field | Value |
|---|---|
| ID | SR-2.8-1 |
| Parent ID | SEC-2.8 — Authenticated transport (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Harness Interface Endpoint (E-01) and the Management Console & Control API (E-24) **SHALL** accept only TLS 1.3 connections using certificates issued by the Gateway server CA for the configured listener names. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API; Functions: F-01; External interfaces: X-01, X-04 |
| Verification Method | Test |
| Verification Statement | Attempt TLS 1.2 and a mismatched name; confirm failure. |
| Source | SEC 2.8 |
| Rationale | Authenticated transport. |

#### SR-2.8-3 — UDS permissions

| Field | Value |
|---|---|
| ID | SR-2.8-3 |
| Parent ID | SEC-2.8 — Authenticated transport (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** create the UDS harness socket with mode 0660 owned by the `smcp-harness` group. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01 |
| Verification Method | Inspection |
| Verification Statement | Inspect the socket ownership and mode. |
| Source | SEC 2.8 |
| Rationale | Local transport access control. |

#### SR-2.9-1 — Origin validation

| Field | Value |
|---|---|
| ID | SR-2.9-1 |
| Parent ID | SEC-2.9 — Origin and Host (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a request carries an `Origin` header that is not in the configured allowlist, which is empty by default, and is not the Gateway's own origin on a request to the authorization endpoint, the Harness Interface Endpoint (E-01) **SHALL** respond with HTTP 403. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send MCP requests with a foreign Origin and with the Gateway's own origin, and submit the sign-in form from the Gateway's own page; confirm 403 for both MCP requests and acceptance of the sign-in form submission. |
| Source | SEC 2.9; MCP:basic/transports/streamable-http §Security |
| Rationale | DNS-rebinding defense. |

#### SR-2.9-2 — Host validation

| Field | Value |
|---|---|
| ID | SR-2.9-2 |
| Parent ID | SEC-2.9 — Origin and Host (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Harness Interface Endpoint (E-01) and the Management Console & Control API (E-24) **SHALL** reject requests whose `Host` header is not a configured listener name. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API; Functions: F-01; External interfaces: X-01, X-04 |
| Verification Method | Test |
| Verification Statement | Send requests with a foreign Host; confirm rejection. |
| Source | SEC 2.9 |
| Rationale | DNS-rebinding defense. |

#### SR-2.9-3 — Loopback binding

| Field | Value |
|---|---|
| ID | SR-2.9-3 |
| Parent ID | SEC-2.9 — Origin and Host (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Harness Interface Endpoint (E-01), including the Remote Access listener, and the Management Console & Control API (E-24) **SHALL** bind only to loopback addresses. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API; Functions: F-01 |
| Verification Method | Inspection |
| Verification Statement | Inspect bound addresses in the default configuration. |
| Source | MCP:basic/transports/streamable-http §Security; SEC 4.14; OWNER (Remote Access through a tunnel) |
| Rationale | Local-only exposure. Remote access arrives through a tunnel connector on the same host, so no listener needs a non-loopback address. |

#### SR-2.8-4 — Local CA constraints

| Field | Value |
|---|---|
| ID | SR-2.8-4 |
| Parent ID | SEC-2.8 — Authenticated transport (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Key & Trust Anchor Manager (E-22) **SHALL** issue the local server CA with the CP-53 name constraints, path length and validity, and **SHALL** issue listener certificates only for names inside those constraints with the CP-53 validity. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-60; Data stores: D-08 |
| Verification Method | Test |
| Verification Statement | Inspect the CA and a listener certificate; request a certificate for a name outside the constraints; confirm the constraints, validities and refusal; confirm that a TLS client rejects a certificate for an outside name even if it was signed by the CA. |
| Source | SEC 2.8; REVIEW (minor: local CA NameConstraints and shorter validity) |
| Rationale | Users add this CA to their clients' trust; name constraints keep a stolen CA key from impersonating other sites. |

#### SR-2.10-1 — Credential separation

| Field | Value |
|---|---|
| ID | SR-2.10-1 |
| Parent ID | SEC-2.10 — Credential separation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Tool Dispatcher (E-10) **SHALL** exclude northbound credentials, session tokens and `Authorization` headers from southbound requests. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Capture southbound traffic; confirm no northbound credential material. |
| Source | SEC 2.10 |
| Rationale | No credential forwarding. |

#### SR-2.11-1 — OAuth token validation

| Field | Value |
|---|---|
| ID | SR-2.11-1 |
| Parent ID | SEC-2.11 — OAuth boundary (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Identity & Authentication Service (E-03) **SHALL** validate access tokens per the MCP 2026-07-28 authorization specification, including audience binding to the CP-41 resource URI, and **SHALL** reject tokens failing validation. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Run the authorization conformance fixtures, including wrong-audience, expired and revoked tokens. |
| Source | SEC 2.11; MCP:basic/authorization; CP-41 |
| Rationale | Standards-based authorization is the baseline harness authentication. |

#### SR-2.11-2 — Dynamic registration approval

| Field | Value |
|---|---|
| ID | SR-2.11-2 |
| Parent ID | SEC-2.11 — OAuth boundary (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Identity & Authentication Service (E-03) **SHALL** refuse authorization and token requests from a dynamically registered client until a Session Approver or Administrator has approved its registration, and **SHALL** refuse Dynamic Client Registration requests outside the Remote Access Profile. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-59; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Register through the remote listener and request authorization before and after approval; send a registration request to the local listener; confirm refusal before approval, success after, and refusal on the local listener. |
| Source | SEC 2.11; RFC 7591; OWNER (DCR only for Remote Access with operator approval of each registration) |
| Rationale | Open registration on an Internet-reachable endpoint would let anyone obtain a client ID. |

#### SR-2.11-4 — Refresh token reuse

| Field | Value |
|---|---|
| ID | SR-2.11-4 |
| Parent ID | SEC-2.11 — OAuth boundary (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a refresh token that has already been rotated is presented, the Session Manager (E-04) **SHALL** terminate the session it belonged to and record a `refresh_token_reuse` event. |
| Allocation | Elements: E-04 Session Manager; Functions: F-09; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Refresh once; present the first refresh token again; confirm the session is terminated, the current access token receives `-31006` and the event is recorded. |
| Source | SEC 2.11; OWNER (rotate refresh tokens) |
| Rationale | Reuse of a rotated token means two parties hold it; ending the session limits the damage. |

#### SR-2.11-5 — Truthful authorization metadata

| Field | Value |
|---|---|
| ID | SR-2.11-5 |
| Parent ID | SEC-2.11 — OAuth boundary (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Identity & Authentication Service (E-03) **SHALL** advertise `client_id_metadata_document_supported` and `registration_endpoint` in its authorization-server metadata only when the corresponding mechanism is enabled. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Fetch the metadata with the Remote Access Profile off and on; confirm `registration_endpoint` appears only when it is on, and that `client_id_metadata_document_supported` never appears while metadata documents are not fetched (SR-2.11-3, Appendix N). |
| Source | SEC 2.11; REVIEW (minor: refuse misadvertised client_id_metadata_document_supported) |
| Rationale | Clients choose a registration path from the metadata; advertising a path that fails causes confusing sign-in errors. |

#### SR-2.13-1 — Vault encryption

| Field | Value |
|---|---|
| ID | SR-2.13-1 |
| Parent ID | SEC-2.13 — Encrypted secrets (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Secret Vault (E-19) **SHALL** encrypt each secret value with age to the vault master key, an age X25519 identity that is never stored in plaintext: it is kept in the macOS Keychain or age-encrypted under an scrypt passphrase. |
| Allocation | Elements: E-19 Secret Vault, E-22 Key & Trust Anchor Manager; Functions: F-47, F-60 |
| Verification Method | Inspection |
| Verification Statement | Inspect the vault store; confirm age ciphertext and no plaintext. |
| Source | SEC 2.13 |
| Rationale | Encrypted at rest. Release 1.0 keeps the vault master key with the vault's own key sources (Keychain or passphrase-wrapped file) rather than in the files of the Key & Trust Anchor Manager, so the key that decrypts the vault is never readable beside the TLS and evidence keys and needs its own unlock. |

#### SR-2.13-2 — Plaintext lifetime

| Field | Value |
|---|---|
| ID | SR-2.13-2 |
| Parent ID | SEC-2.13 — Encrypted secrets (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Secret Broker (E-20) **SHALL** hold decrypted secret values only in memory, **SHALL** overwrite every byte buffer it allocates for a decrypted value or for an encoding of one (the decrypted vault value after each delivery, the encoded forms built for leak fingerprints, the S1 header value when its grant ends), and **SHALL** make no copy of a value that cannot be overwritten other than the S4 environment string it hands to the launcher. |
| Allocation | Elements: E-20 Secret Broker; Functions: F-50 |
| Verification Method | Inspection |
| Verification Statement | Review the delivery code path for byte buffers holding a decrypted value or its encodings that are not overwritten after use, and for immutable copies other than the S4 environment string. |
| Source | SEC 2.13; OWNER (release 1.0 narrowed to what the Go runtime allows) |
| Rationale | Minimizes plaintext exposure. Narrowed in release 1.0 to what Go can guarantee: Go strings are immutable, so the S4 environment entry (`exec.Cmd.Env` takes strings, and the runtime copies it again when it starts the process), the header the Egress Broker (E-18) sets on each outbound S1 request (`net/http` header values are strings) and the age library's internal decryption buffers cannot be overwritten, and a memory snapshot cannot show that no stale copy exists because the garbage collector does not clear freed memory. The broker's own byte buffers are overwritten; Security Limitations lists the remaining copies. |

#### SR-2.13-3 — Vault isolation

| Field | Value |
|---|---|
| ID | SR-2.13-3 |
| Parent ID | SEC-2.13 — Encrypted secrets (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Secret Vault (E-19) **SHALL** be readable only by the Secret Broker (E-20) service identity. |
| Allocation | Elements: E-19 Secret Vault, E-20 Secret Broker; Internal interfaces: I-27 |
| Verification Method | Test |
| Verification Statement | Attempt vault reads as every other service identity; confirm denial. |
| Source | SEC 2.13; ARCH §4 E-19 |
| Rationale | Data Server compromise does not expose secrets. In release 1.x the Secret Broker runs inside smcpd, so its service identity is the one smcpd runs as (`smcp-core` in the Enforced profile); the vault directory and its key source are readable by that identity only, and every other CP-46 identity, `smcp-vault` and `smcp-srv` included, is denied. |

#### SR-2.14-1 — Backend environment allowlist

| Field | Value |
|---|---|
| ID | SR-2.14-1 |
| Parent ID | SEC-2.14 — Minimal backend environment (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Server Runtime Manager (E-15) **SHALL** build each instance environment only from the manifest variable allowlist, the Gateway-generated egress endpoint variables and approved S4 secrets. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-38 |
| Verification Method | Inspection |
| Verification Statement | Inspect a launched instance environment against its manifest. |
| Source | SEC 2.14 |
| Rationale | Minimal environment. |

### SEC-3 Verified server provenance

#### SR-3-1 — Signature verification

| Field | Value |
|---|---|
| ID | SR-3-1 |
| Parent ID | SEC-3 — Source-inspectable server admission (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Library Trust Verifier (E-13) **SHALL** accept a package only when the minisign signature over its package index verifies under an enrolled, unexpired trust anchor whose scope includes the manifest risk class. |
| Allocation | Elements: E-13 Library Trust Verifier, E-22 Key & Trust Anchor Manager; Functions: F-33; Internal interfaces: I-17 |
| Verification Method | Test |
| Verification Statement | Import packages signed by an unknown key, an expired anchor and an out-of-scope anchor; confirm rejection. |
| Source | ARCH §4 E-13; ARCH §2.1 item 1 |
| Rationale | Only curated servers run. |

#### SR-3-2 — Artifact digest verification

| Field | Value |
|---|---|
| ID | SR-3-2 |
| Parent ID | SEC-3 — Source-inspectable server admission (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Library Trust Verifier (E-13) **SHALL** verify that each artifact's SHA-256 digest equals the digest in the signed manifest, at import and at every instance launch. |
| Allocation | Elements: E-13 Library Trust Verifier, E-15 Server Runtime Manager; Functions: F-33, F-38; Data stores: D-03 |
| Verification Method | Test |
| Verification Statement | Alter an artifact after import; confirm the next launch is refused and the revision is suspended. |
| Source | ARCH §4 E-13; CP-35 |
| Rationale | The running artifact is the signed artifact. |

#### SR-3-3 — Revocation processing

| Field | Value |
|---|---|
| ID | SR-3-3 |
| Parent ID | SEC-3 — Source-inspectable server admission (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Library Trust Verifier (E-13) **SHALL** mark a revoked package's server revisions `revoked` within 60 seconds of reading the revocation entry. |
| Allocation | Elements: E-13 Library Trust Verifier, E-14 Local Server Registry; Functions: F-35 |
| Verification Method | Test |
| Verification Statement | Publish a revocation entry; confirm the state change and instance teardown within 60 s. |
| Source | ARCH §18.8 |
| Rationale | Curation revocation takes effect. |

#### SR-3-4 — Revocation feed staleness

| Field | Value |
|---|---|
| ID | SR-3-4 |
| Parent ID | SEC-3 — Source-inspectable server admission (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the revocation feed has not been successfully read within CP-34, the Library Trust Verifier (E-13) **SHALL** block new imports and raise an alert. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-35 |
| Verification Method | Test |
| Verification Statement | Make the feed unreadable beyond CP-34; confirm the blocked import and the alert. |
| Source | ARCH §4 E-13 |
| Rationale | Stale revocation data reduces assurance. |

#### SR-3-5 — Rollback protection

| Field | Value |
|---|---|
| ID | SR-3-5 |
| Parent ID | SEC-3 — Source-inspectable server admission (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Library Trust Verifier (E-13) **SHALL** reject a package whose version is lower than an installed version of the same server unless an administrator authorizes the downgrade. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-33 |
| Verification Method | Test |
| Verification Statement | Import an older version with and without authorization. |
| Source | ARCH §4 E-13 |
| Rationale | Prevents rollback to known-vulnerable releases. |

#### SR-3.1-1 — Source evidence presence

| Field | Value |
|---|---|
| ID | SR-3.1-1 |
| Parent ID | SEC-3.1 — Source availability (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Library Trust Verifier (E-13) **SHALL** reject a package whose manifest lacks a source archive reference with digest and SPDX license identifiers. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-34 |
| Verification Method | Test |
| Verification Statement | Import manifests missing each element; confirm rejection. |
| Source | SEC 3.1 |
| Rationale | Gateway-side check of curation evidence. |

#### SR-3.2-1 — Provenance binding

| Field | Value |
|---|---|
| ID | SR-3.2-1 |
| Parent ID | SEC-3.2 — Source-to-artifact binding (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Library Trust Verifier (E-13) **SHALL** verify a signed provenance attestation binding the source digest to the artifact digest. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-33, F-34 |
| Verification Method | Test |
| Verification Statement | Import a package whose attestation names a different artifact digest; confirm rejection. |
| Source | SEC 3.2 |
| Rationale | Source-to-artifact binding. |

#### SR-3.3-1 — Inert evidence display

| Field | Value |
|---|---|
| ID | SR-3.3-1 |
| Parent ID | SEC-3.3 — Safe source viewer (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Servers & Library view (G-10) **SHALL** render manifests, attestations, license texts and SBOMs as escaped text bounded to 256 KiB per page. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-65 |
| Verification Method | Test |
| Verification Statement | Display evidence containing HTML, script and very large files; confirm inert, bounded rendering. |
| Source | SEC 3.3; SEC Appendix A |
| Rationale | Evidence is untrusted content. |

#### SR-3.4-1 — Dependency visibility

| Field | Value |
|---|---|
| ID | SR-3.4-1 |
| Parent ID | SEC-3.4 — Dependency inspection (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Servers & Library view (G-10) **SHALL** display each revision's bill of materials as recorded in its signed provenance statement (artifact and source with their digests, licenses and the pinned dependency lock), launcher argument vector, mounts, egress destinations, secret slots and sandbox profile. |
| Allocation | Elements: E-24 Management Console & Control API, E-14 Local Server Registry; Functions: F-65 |
| Verification Method | Demonstration |
| Verification Statement | Open a revision in G-10; confirm each item. |
| Source | SEC 3.4 |
| Rationale | Privileges are visible beside the server. A release 1.0 package carries no separate SPDX document: its bill of materials is the signed provenance statement (FR-14.5), which binds the artifact and source digests, the licenses and the digest of the dependency lock file that pinned the transitive dependencies (FR-14.1). The Gateway's own release archives carry an SPDX SBOM (FR-13.1). |

#### SR-3.5-1 — Packaging probe isolation

| Field | Value |
|---|---|
| ID | SR-3.5-1 |
| Parent ID | SEC-3.5 — Quarantine execution (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The `smcpctl package build` command **SHALL** run the candidate server for its tool-list probe with no secrets, no mounts other than an empty throwaway directory and, in the Enforced profile, no network access. |
| Allocation | Elements: E-13 Library Trust Verifier; Functions: F-96; External interfaces: X-17 |
| Verification Method | Test |
| Verification Statement | Package a fixture server that tries to read the user's home directory, read environment secrets and open a network connection during startup; confirm each attempt fails in the Enforced profile and that the probe environment holds only the allowlisted variables. |
| Source | SEC 3.5; OWNER (operator self-curation) |
| Rationale | The packaging run is the quarantine probe of SEC 3.5; a candidate must not see production data before it is reviewed. |

#### SR-3.6-1 — No runtime bootstrap

| Field | Value |
|---|---|
| ID | SR-3.6-1 |
| Parent ID | SEC-3.6 — No runtime bootstrap (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Server Runtime Manager (E-15) **SHALL** launch only content-addressed local artifacts and **SHALL** reject launch specifications that invoke package installers or resolve packages at run time. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-38 |
| Verification Method | Test |
| Verification Statement | Submit a manifest whose entrypoint runs `npx`, `uvx` or `pip install`; confirm rejection. |
| Source | SEC 3.6 |
| Rationale | The executed code is the verified code. |

#### SR-3.7-1 — Manifest digest binding

| Field | Value |
|---|---|
| ID | SR-3.7-1 |
| Parent ID | SEC-3.7 — Manifest binding (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Local Server Registry (E-14) **SHALL** bind enablement to the digest of the manifest tool names, descriptions, schemas, annotations and declared capabilities. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36 |
| Verification Method | Inspection |
| Verification Statement | Inspect an enablement record; confirm the manifest digest. |
| Source | SEC 3.7 |
| Rationale | What was approved is what runs. |

#### SR-3.8-1 — Runtime drift suspension

| Field | Value |
|---|---|
| ID | SR-3.8-1 |
| Parent ID | SEC-3.8 — Drift suspension (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When an instance's tool list differs from the manifest in names, descriptions, schemas or annotations, the Local Server Registry (E-14) **SHALL** suspend the server revision and the Server Runtime Manager (E-15) **SHALL** tear down its instances. |
| Allocation | Elements: E-14 Local Server Registry, E-15 Server Runtime Manager; Functions: F-37, F-40 |
| Verification Method | Test |
| Verification Statement | Serve a changed description from a fixture; confirm suspension and teardown. |
| Source | SEC 3.8 |
| Rationale | Tool poisoning defense. |

#### SR-3.9-1 — Explicit enablement

| Field | Value |
|---|---|
| ID | SR-3.9-1 |
| Parent ID | SEC-3.9 — Explicit admission (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Local Server Registry (E-14) **SHALL** change a revision from `verified-disabled` to `enabled` only on an authenticated Administrator action. |
| Allocation | Elements: E-14 Local Server Registry, E-24 Management Console & Control API; Functions: F-36 |
| Verification Method | Test |
| Verification Statement | Attempt enablement as each non-Administrator role and automatically after import; confirm refusal. |
| Source | SEC 3.9 |
| Rationale | Human enablement. |

#### SR-3.10-1 — New tools denied

| Field | Value |
|---|---|
| ID | SR-3.10-1 |
| Parent ID | SEC-3.10 — New tools denied (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** deny tools of a newly enabled server revision until a published grant names them. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Enable a revision with a new tool; confirm the tool is absent from catalogs and denied when called. |
| Source | SEC 3.10 |
| Rationale | No implicit grants. |

#### SR-3.11-1 — Classification retention

| Field | Value |
|---|---|
| ID | SR-3.11-1 |
| Parent ID | SEC-3.11 — Capability classification (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Local Server Registry (E-14) **SHALL** retain for each tool the manifest locality, data sensitivity, side-effect class, file roots, egress scope and secret references, and **SHALL** permit operator overrides only toward greater restriction. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36 |
| Verification Method | Test |
| Verification Statement | Attempt to loosen and tighten a classification; confirm only tightening is accepted. |
| Source | SEC 3.11 |
| Rationale | Classification drives policy. |

#### SR-3.12-1 — No administrative tools

| Field | Value |
|---|---|
| ID | SR-3.12-1 |
| Parent ID | SEC-3.12 — No administrative tool exposure (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Access Enforcement Point (E-08) **SHALL** exclude from every catalog any tool whose manifest class is `gateway-admin` and every Gateway control operation. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19 |
| Verification Method | Test |
| Verification Statement | Import a fixture with an admin-class tool and grant it; confirm it never appears in a catalog. |
| Source | SEC 3.12 |
| Rationale | Agents cannot administer the Gateway. |

#### SR-3.13-1 — High-risk grants

| Field | Value |
|---|---|
| ID | SR-3.13-1 |
| Parent ID | SEC-3.13 — High-risk candidates (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** reject a grant of a tool in the high-risk classes general SQL, code execution, CAD scripting or browser automation unless both the Framework Profile and the template carry an explicit high-risk flag for that class. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10 |
| Verification Method | Test |
| Verification Statement | Grant a code-execution tool with and without the flags. |
| Source | SEC 3.13 |
| Rationale | Separate grants for high-risk capabilities. |

#### SR-3.14-1 — Stateful tool contract

| Field | Value |
|---|---|
| ID | SR-3.14-1 |
| Parent ID | SEC-3.14 — Stateful tool admission (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Local Server Registry (E-14) **SHALL** refuse enablement of a revision declaring a stateful tool that lacks a handle contract identifying creation outputs, consuming arguments, ownership scope and expiry. |
| Allocation | Elements: E-14 Local Server Registry; Functions: F-36 |
| Verification Method | Test |
| Verification Statement | Enable a revision with an uncontracted stateful tool; confirm refusal. |
| Source | SEC 3.14 |
| Rationale | Handle ownership must be enforceable. |

### SEC-4 Contained local execution

#### SR-4.1-1 — Service identities

| Field | Value |
|---|---|
| ID | SR-4.1-1 |
| Parent ID | SEC-4.1 — Separate OS identities (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | In the Enforced profile, the Gateway **SHALL** run its enforcement core process `smcpd` (which in release 1.x also hosts the Data Access Service, the vault and secret broker, the evidence exporter, the key manager and the console) as the CP-46 service identity `smcp-core`, and every MCP server process under the CP-46 server identity `smcp-srv` (as `smcp-srv` or a UID of its subordinate range); neither identity **SHALL** be root or the operator's account. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-25 Graph Database Engine, E-19 Secret Vault, E-21 Audit & Evidence Service, E-24 Management Console & Control API; External interfaces: X-07 |
| Verification Method | Inspection |
| Verification Statement | On an Enforced host, inspect the running `smcpd` process and the processes of a running MCP server and their UIDs. |
| Source | SEC 4.1; OWNER (release 1.x narrowed to the core and server identities) |
| Rationale | Separation of authority. Release 1.x narrows the statement to the boundary it enforces, between the Gateway and the servers it runs: the components that SEC 4.1 places under `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data` and `smcp-console` are packages of the one `smcpd` process, so they share `smcp-core`. `smcpctl install` still creates those identities (CP-46). Running each component as its own process under its own identity needs an inter-process interface between components that release 1.x does not have; it is left to a later release, together with the directory owners of CP-46 that depend on it. |

#### SR-4-1 — Standalone profile restrictions

| Field | Value |
|---|---|
| ID | SR-4-1 |
| Parent ID | SEC-4 — Contained local execution (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | In the Standalone profile, the Local Server Registry (E-14) **SHALL** refuse to enable a server revision whose manifest risk class, or any tool's risk class, is `high`. |
| Allocation | Elements: E-14 Local Server Registry, E-23 Health & Safety Monitor; Functions: F-36, F-61 |
| Verification Method | Test |
| Verification Statement | In a Standalone installation, import and attempt to enable a `high` package and a `moderate` package; confirm refusal of the first with reason `PROFILE_UNCONFINED` and enablement of the second. |
| Source | SEC 4; SEC 3.13; OWNER (Standalone profile: high-risk server classes refused) |
| Rationale | Without a sandbox, a high-risk server's capabilities are the user's capabilities. |

#### SR-4.1-2 — Instance identities

| Field | Value |
|---|---|
| ID | SR-4.1-2 |
| Parent ID | SEC-4.1 — Separate OS identities (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Execution Sandbox (E-16) **SHALL** run each server instance under a distinct unprivileged user-namespace UID mapping. |
| Allocation | Elements: E-16 Execution Sandbox; Functions: F-41; External interfaces: X-07 |
| Verification Method | Inspection |
| Verification Statement | Inspect UID maps of two concurrent instances. |
| Source | SEC 4.1 |
| Rationale | Instances cannot affect each other. |

#### SR-4.2-1 — Private database listeners

| Field | Value |
|---|---|
| ID | SR-4.2-1 |
| Parent ID | SEC-4.2 — Private graph access (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Graph Database Engine (E-25) **SHALL** listen only on loopback, with nftables rules admitting connections only from the Data Access Service (E-26) service identity. |
| Allocation | Elements: E-25 Graph Database Engine, E-26 Data Access Service; External interfaces: X-07; Internal interfaces: I-36 |
| Verification Method | Test |
| Verification Statement | Connect to the database port as other identities and from a sandbox; confirm refusal. |
| Source | SEC 4.2 |
| Rationale | Only the Data Access Service reaches the database. |

#### SR-4.2-2 — Observation file protection

| Field | Value |
|---|---|
| ID | SR-4.2-2 |
| Parent ID | SEC-4.2 — Private graph access (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Observation Store (E-27) **SHALL** keep its files owned by the Data Server identity with mode 0600 or stricter. |
| Allocation | Elements: E-27 Observation Store; Internal interfaces: I-37 |
| Verification Method | Inspection |
| Verification Statement | Inspect file modes. |
| Source | SEC 4.2 |
| Rationale | Store files are not readable by other identities. |

#### SR-4.9-1 — Single MCP endpoint per locked-down client

| Field | Value |
|---|---|
| ID | SR-4.9-1 |
| Parent ID | SEC-4.9 — Hermes endpoint (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | Each lockdown profile of FR-15.1 **SHALL** leave the Gateway as the only MCP server the client loads, and `smcpctl doctor` **SHALL** report any additional MCP server the client would load. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | For each local client with a lockdown mechanism, apply the profile, add a second server in user and project scope, start the client and list its MCP servers; confirm only the Gateway loads and doctor reports the added servers. |
| Source | SEC 4.9; OWNER (lockdown profiles per client) |
| Rationale | SEC 4.9 was written for Hermes; the same single-endpoint rule now applies to every local client. |

#### SR-4.11-1 — Protected client configuration

| Field | Value |
|---|---|
| ID | SR-4.11-1 |
| Parent ID | SEC-4.11 — Protected client configuration (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | Each lockdown profile of FR-15.1 **SHALL** deny the client's own file-editing tools write access to the client's MCP and permission settings files where the client provides such a rule, and `smcpctl doctor` **SHALL** report each client whose settings files are writable by its own tools. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Test |
| Verification Statement | For each local client, apply the profile and ask the agent to edit its own MCP settings file; confirm the edit is refused where Appendix K lists a mechanism and that doctor reports the remaining clients. |
| Source | SEC 4.11; OWNER (lockdown profiles) |
| Rationale | An agent that can edit its own configuration can remove the lockdown. |

#### SR-4.13-1 — Exclusive-gateway label

| Field | Value |
|---|---|
| ID | SR-4.13-1 |
| Parent ID | SEC-4.13 — Additional clients (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The client matrix (FR-15.10) **SHALL** mark a client `exclusive-gateway` only when its latest matrix run at the pinned version passed the FR-15.1 and SR-4.9-1 bypass tests, and **SHALL** mark every other client `gateway-available`. |
| Allocation | Elements: E-33 Harness Adapter Kit; Functions: F-98; External interfaces: X-12 |
| Verification Method | Inspection |
| Verification Statement | Inspect `docs/clients/matrix.json` and the latest matrix results; confirm that each `exclusive-gateway` client has passing bypass results for its pinned version. |
| Source | SEC 4.13; SEC 9.7 |
| Rationale | Users should not read "supported" as "cannot bypass". |

#### SR-4.5-1 — Sandbox network isolation

| Field | Value |
|---|---|
| ID | SR-4.5-1 |
| Parent ID | SEC-4.5 — Backend egress (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | In the Enforced profile, the Execution Sandbox (E-16) **SHALL** place each instance in a network namespace whose only reachable endpoints are its Egress Broker endpoints. |
| Allocation | Elements: E-16 Execution Sandbox, E-18 Egress Broker; Functions: F-41; Internal interfaces: I-25 |
| Verification Method | Test |
| Verification Statement | From a fixture instance, attempt connections to the Internet, LAN, loopback services and the database; confirm all fail except broker endpoints. |
| Source | SEC 4.5 |
| Rationale | Egress only through the broker. |

#### SR-4.5-2 — Per-call egress grant

| Field | Value |
|---|---|
| ID | SR-4.5-2 |
| Parent ID | SEC-4.5 — Backend egress (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Egress Broker (E-18) **SHALL** forward an operation only to a destination listed in the calling instance's current egress grants. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45; External interfaces: X-06 |
| Verification Method | Test |
| Verification Statement | Request an ungranted destination through a broker endpoint; confirm refusal. |
| Source | SEC 4.5 |
| Rationale | Policy-bound egress. |

#### SR-4.6-1 — Mount restriction

| Field | Value |
|---|---|
| ID | SR-4.6-1 |
| Parent ID | SEC-4.6 — Filesystem authority (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | In the Enforced profile, the Execution Sandbox (E-16) **SHALL** mount only paths in the intersection of manifest-declared and policy-granted roots, read-only unless a write grant applies. |
| Allocation | Elements: E-16 Execution Sandbox; Functions: F-41 |
| Verification Method | Test |
| Verification Statement | Attempt reads and writes outside and inside the granted roots from a fixture; confirm the results. |
| Source | SEC 4.6 |
| Rationale | File authority by operating-system enforcement. |

#### SR-4.7-1 — Host exclusion

| Field | Value |
|---|---|
| ID | SR-4.7-1 |
| Parent ID | SEC-4.7 — Host-management exclusion (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | In the Enforced profile, the Execution Sandbox (E-16) **SHALL** run instances with all capabilities dropped, `no-new-privileges`, the default seccomp profile, a read-only root filesystem, and without host PID, network or IPC namespaces, devices or host management sockets. |
| Allocation | Elements: E-16 Execution Sandbox; Functions: F-41 |
| Verification Method | Inspection |
| Verification Statement | Inspect the effective container configuration of an instance. |
| Source | SEC 4.7 |
| Rationale | No host-management reachability. |

#### SR-4.7-2 — Resource limits

| Field | Value |
|---|---|
| ID | SR-4.7-2 |
| Parent ID | SEC-4.7 — Host-management exclusion (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | In the Enforced profile, the Execution Sandbox (E-16) **SHALL** enforce cgroup memory, CPU and PID limits, with CP-24 as the default. |
| Allocation | Elements: E-16 Execution Sandbox; Functions: F-41 |
| Verification Method | Test |
| Verification Statement | Exceed each limit from a fixture; confirm enforcement. |
| Source | SEC Appendix A (worker budget) |
| Rationale | Contained resource use. |

#### SR-4.8-1 — No shell launch

| Field | Value |
|---|---|
| ID | SR-4.8-1 |
| Parent ID | SEC-4.8 — Safe process launch (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Server Runtime Manager (E-15) **SHALL** launch instances with an argument vector and **SHALL** never pass launch input to a shell interpreter. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-38 |
| Verification Method | Inspection |
| Verification Statement | Inspect launch code; confirm exec-style invocation only. |
| Source | SEC 4.8 |
| Rationale | No command injection. |

#### SR-4.14-1 — Remote Access host rules

| Field | Value |
|---|---|
| ID | SR-4.14-1 |
| Parent ID | SEC-4.14 — Overlay least privilege (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the Remote Access Profile is enabled, the `smcpctl remote enable` command **SHALL** add no inbound firewall exception, and in the Enforced profile **SHALL** install nftables rules that drop every non-loopback connection to the CP-02, CP-03, CP-48 and CP-51 ports. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-24 Management Console & Control API; Functions: F-97; External interfaces: X-07, X-13 |
| Verification Method | Test |
| Verification Statement | Enable the profile on an Enforced host; attempt connections to each port from another host on the network; confirm all are dropped and that the tunnel connector on the host reaches the CP-48 listener. |
| Source | SEC 4.14; OWNER (Remote Access through an authenticated tunnel) |
| Rationale | Remote access arrives only through the tunnel connector; no port is opened to the network. |

#### SR-4.14-2 — Remote authentication

| Field | Value |
|---|---|
| ID | SR-4.14-2 |
| Parent ID | SEC-4.14 — Overlay least privilege (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the Remote Access Profile is enabled, the Harness Interface Endpoint (E-01) **SHALL** require on the remote listener an access token issued to an approved client for every request except OAuth metadata, authorization, token, registration, device authorization and device verification requests. |
| Allocation | Elements: E-01 Harness Interface Endpoint, E-03 Identity & Authentication Service; Functions: F-01, F-04; External interfaces: X-13 |
| Verification Method | Test |
| Verification Statement | Send MCP requests through the tunnel without a token, with a token from a pending client and with a valid token; confirm `-31006` for the first two and success for the third. |
| Source | SEC 4.14; OWNER (OAuth 2.1 with per-client registration) |
| Rationale | Application authentication on every request in addition to the tunnel. |

### SEC-5 Protocol and content boundary

#### SR-5.1-1 — Profile separation

| Field | Value |
|---|---|
| ID | SR-5.1-1 |
| Parent ID | SEC-5.1 — Explicit protocol profiles (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Protocol Mediator (E-02) **SHALL** route 2026-07-28 requests and 2025-11-25 requests to separate protocol handlers selected only by the request's declared era: the `_meta` protocol version for modern requests, and an `initialize` request or a legacy session header for legacy requests. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-03 |
| Verification Method | Inspection |
| Verification Statement | Inspect the dispatch code; confirm separate handlers and era-only selection. |
| Source | SEC 5.1 |
| Rationale | Profiles must not leak behavior. |

#### SR-5.2-1 — Header/body agreement

| Field | Value |
|---|---|
| ID | SR-5.2-1 |
| Parent ID | SEC-5.2 — Header/body agreement (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Protocol Mediator (E-02) **SHALL** reject with HTTP 400 and error `-32020` a request whose `MCP-Protocol-Version`, `Mcp-Method` or `Mcp-Name` header value, after Base64-sentinel decoding, differs from the corresponding body field. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Send mismatches for each header, including encoded forms; confirm rejection. |
| Source | SEC 5.2; MCP:basic/transports/streamable-http §Server Validation |
| Rationale | Prevents split-view routing attacks. |

#### SR-5.2-2 — Required headers

| Field | Value |
|---|---|
| ID | SR-5.2-2 |
| Parent ID | SEC-5.2 — Header/body agreement (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Protocol Mediator (E-02) **SHALL** reject with HTTP 400 and error `-32020` a request missing `MCP-Protocol-Version`, `Mcp-Method`, or (for `tools/call`) `Mcp-Name`, or carrying invalid header characters. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Omit each header and inject control characters; confirm rejection. |
| Source | SEC 5.2; MCP:basic/transports/streamable-http §Server Validation |
| Rationale | Header presence is required for validation. |

#### SR-5.3-1 — No northbound downgrade

| Field | Value |
|---|---|
| ID | SR-5.3-1 |
| Parent ID | SEC-5.3 — No unsafe downgrade (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Protocol Mediator (E-02) **SHALL** process a request under legacy semantics only when the request is a legacy `initialize` or carries a legacy session, and **SHALL** never process a request under legacy semantics because of an authentication, authorization or modern protocol error. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-03 |
| Verification Method | Test |
| Verification Statement | Trigger each error class; confirm no legacy processing. |
| Source | SEC 5.3 |
| Rationale | Errors cannot open weaker paths. |

#### SR-5.4-1 — Authorized discovery

| Field | Value |
|---|---|
| ID | SR-5.4-1 |
| Parent ID | SEC-5.4 — Authorized discovery (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Access Enforcement Point (E-08) **SHALL** include in a session's `tools/list` only tools permitted by the session's effective policy for at least one argument value. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19 |
| Verification Method | Test |
| Verification Statement | Compare catalogs of two sessions with different templates; confirm each shows only its permitted tools. |
| Source | SEC 5.4 |
| Rationale | Discovery reflects authority. |

#### SR-5.5-1 — Independent call authorization

| Field | Value |
|---|---|
| ID | SR-5.5-1 |
| Parent ID | SEC-5.5 — Independent invocation check (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Access Enforcement Point (E-08) **SHALL** evaluate every `tools/call` against the current policy, whether or not the session has listed tools. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-20 |
| Verification Method | Test |
| Verification Statement | Call a tool directly without listing and after its grant is removed; confirm the current decision applies. |
| Source | SEC 5.5 |
| Rationale | Visibility is not authority. |

#### SR-5.6-1 — Unqualified features rejected

| Field | Value |
|---|---|
| ID | SR-5.6-1 |
| Parent ID | SEC-5.6 — Unqualified capabilities (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Protocol Mediator (E-02) **SHALL** reject resources, prompts, completion, task-extension and legacy server-initiated features until their profile is enabled, and **SHALL** advertise no capabilities or extensions for them. |
| Allocation | Elements: E-02 Protocol Mediator; Functions: F-02, F-03 |
| Verification Method | Test |
| Verification Statement | Call each feature's methods and inspect `server/discover`; confirm rejection and absence. |
| Source | SEC 5.6 |
| Rationale | Only qualified features. |

#### SR-5.6-2 — No southbound client capabilities

| Field | Value |
|---|---|
| ID | SR-5.6-2 |
| Parent ID | SEC-5.6 — Unqualified capabilities (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Tool Dispatcher (E-10) **SHALL** declare no `sampling`, `elicitation` or `roots` client capability southbound unless the MRTR Relay Profile is enabled. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23 |
| Verification Method | Inspection |
| Verification Statement | Inspect southbound `clientCapabilities` in captured traffic. |
| Source | SEC 5.6; MCP:basic/patterns/mrtr §Server Requirements |
| Rationale | Servers must not then send input requests. |

#### SR-5.7-1 — Private caches

| Field | Value |
|---|---|
| ID | SR-5.7-1 |
| Parent ID | SEC-5.7 — Private caches (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Access Enforcement Point (E-08) **SHALL** key every catalog cache entry by session ID and policy revision ID. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19 |
| Verification Method | Test |
| Verification Statement | List tools from two sessions with different grants in quick succession; confirm no cross-session reuse. |
| Source | SEC 5.7 |
| Rationale | No cross-principal leakage. |

#### SR-5.7-2 — Cursor integrity

| Field | Value |
|---|---|
| ID | SR-5.7-2 |
| Parent ID | SEC-5.7 — Private caches (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Access Enforcement Point (E-08) **SHALL** issue pagination cursors protected by HMAC and bound to session ID and policy revision. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19 |
| Verification Method | Test |
| Verification Statement | Modify a cursor byte; confirm `-32602`. |
| Source | SEC 5.7 |
| Rationale | Cursors cannot cross sessions. |

#### SR-5.7-3 — No result caching

| Field | Value |
|---|---|
| ID | SR-5.7-3 |
| Parent ID | SEC-5.7 — Private caches (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Gateway **SHALL** retain no `tools/call` result for reuse by another request. |
| Allocation | Elements: E-10 Tool Dispatcher, E-11 Response Inspection Pipeline |
| Verification Method | Inspection |
| Verification Statement | Inspect the dispatch and release code; confirm no result cache exists. |
| Source | SEC 5.7 |
| Rationale | Results are request-specific. |

#### SR-5.8-1 — Outbound argument filtering

| Field | Value |
|---|---|
| ID | SR-5.8-1 |
| Parent ID | SEC-5.8 — Outgoing filtering (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Request Inspection Pipeline (E-09) **SHALL** apply the `secret-fingerprint` filter and the effective data-class rules to all arguments before dispatch. |
| Allocation | Elements: E-09 Request Inspection Pipeline; Functions: F-21 |
| Verification Method | Test |
| Verification Statement | Send a call whose argument contains a registered secret fragment; confirm block. |
| Source | SEC 5.8 |
| Rationale | Prevents exfiltration through arguments. |

#### SR-5.8-2 — Egress content filtering

| Field | Value |
|---|---|
| ID | SR-5.8-2 |
| Parent ID | SEC-5.8 — Outgoing filtering (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Egress Broker (E-18) **SHALL** apply the `secret-fingerprint` filter to outbound URLs, headers and bodies, excluding only the header it inserts for S1 delivery. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45, F-46 |
| Verification Method | Test |
| Verification Statement | Make a fixture send a delivered secret in a query string; confirm the block. |
| Source | SEC 5.8 |
| Rationale | Prevents exfiltration through egress. |

#### SR-5.9-1 — Response surfaces

| Field | Value |
|---|---|
| ID | SR-5.9-1 |
| Parent ID | SEC-5.9 — Incoming filtering (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Response Inspection Pipeline (E-11) **SHALL** apply required response filters to text content, structured content, embedded resources, resource-link URIs, error results and progress messages. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-27 |
| Verification Method | Test |
| Verification Statement | Place a filter trigger in each surface; confirm detection. |
| Source | SEC 5.9 |
| Rationale | Every surface reaching the agent is filtered. |

#### SR-5.9-2 — Tool metadata scanning

| Field | Value |
|---|---|
| ID | SR-5.9-2 |
| Parent ID | SEC-5.9 — Incoming filtering (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When importing a server revision, the Library Trust Verifier (E-13) **SHALL** apply the active metadata rule set to every tool name, title, description and schema property description at any nesting depth, and the Local Server Registry (E-14) **SHALL** register each tool with a blocking finding as suspended and record a `metadata_blocked` event naming the rule and rule-set version. |
| Allocation | Elements: E-13 Library Trust Verifier, E-14 Local Server Registry; Functions: F-34, F-36; Internal interfaces: I-21, I-18 |
| Verification Method | Test |
| Verification Statement | Import the Appendix L poisoned-description and poisoned-property-description fixtures; confirm each affected tool is suspended with the event, and that a clean tool of the same server is presented. |
| Source | SEC 5.9; REVIEW (I2: metadata scanning of all presented tool metadata at import and presentation) |
| Rationale | Tool descriptions reach the model's context like tool results do; they are an injection surface. |

#### SR-5.10-1 — Filter failure

| Field | Value |
|---|---|
| ID | SR-5.10-1 |
| Parent ID | SEC-5.10 — Filter failure (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a required filter errors or exceeds CP-14, the Request Inspection Pipeline (E-09) or Response Inspection Pipeline (E-11) **SHALL** block the request or withhold the result. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline; Functions: F-21, F-27 |
| Verification Method | Test |
| Verification Statement | Inject a filter crash and a slow filter; confirm block and withhold. |
| Source | SEC 5.10 |
| Rationale | Fail closed. |

#### SR-5.11-1 — No partial release

| Field | Value |
|---|---|
| ID | SR-5.11-1 |
| Parent ID | SEC-5.11 — Buffered release (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Protocol Mediator (E-02) **SHALL** send no backend-derived content to the harness before release authorization of the complete result. |
| Allocation | Elements: E-02 Protocol Mediator, E-12 Enforcement Coordinator; Functions: F-22, F-30 |
| Verification Method | Test |
| Verification Statement | Stream a slow multi-part backend result; confirm no content reaches the harness before release. |
| Source | SEC 5.11 |
| Rationale | Buffered release. |

#### SR-5.12-1 — Re-authorization after transformation

| Field | Value |
|---|---|
| ID | SR-5.12-1 |
| Parent ID | SEC-5.12 — Safe transformation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a request filter transforms action-defining arguments, the Request Inspection Pipeline (E-09) **SHALL** obtain a new decision for the transformed request before launch. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-06 Policy Decision Service; Functions: F-21; Internal interfaces: I-09 |
| Verification Method | Test |
| Verification Statement | Redact a destination; confirm a second decision record. |
| Source | SEC 5.12 |
| Rationale | Decisions apply to the final request. |

#### SR-5.13-1 — Untrusted labeling

| Field | Value |
|---|---|
| ID | SR-5.13-1 |
| Parent ID | SEC-5.13 — Untrusted content treatment (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Response Inspection Pipeline (E-11) **SHALL** mark every released result as untrusted in its provenance metadata. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-28 |
| Verification Method | Inspection |
| Verification Statement | Inspect released results. |
| Source | SEC 5.13 |
| Rationale | Downstream consumers retain untrusted status. |

#### SR-5.13-2 — Session taint

| Field | Value |
|---|---|
| ID | SR-5.13-2 |
| Parent ID | SEC-5.13 — Untrusted content treatment (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a result from a tool whose manifest `source_trust` is `untrusted` is released to a session, the Session Manager (E-04) **SHALL** mark the session tainted until it ends, and while it is tainted the Policy Decision Service (E-06) **SHALL** add an approval obligation, or deny when the template's `taint_action` is `deny`, to every call of a tool whose side-effect class is `external` or `write`. |
| Allocation | Elements: E-04 Session Manager, E-06 Policy Decision Service; Functions: F-99, F-14 |
| Verification Method | Test |
| Verification Statement | In a session, call a `read` tool with untrusted source, then a `write` tool and an `external` tool; repeat with `taint_action = deny`; confirm approval obligations (`TAINT_APPROVAL`) and then denials (`TAINT_DENIED`), and that a fresh session is untainted. |
| Source | SEC 5.13; SEC 1.12; REVIEW (I3: deterministic restrict-only session taint) |
| Rationale | An agent that has read attacker-controlled text should not be able to act on the outside world without a person's approval. The rule is deterministic and can only restrict. |

#### SR-5.14-1 — Unicode corpus

| Field | Value |
|---|---|
| ID | SR-5.14-1 |
| Parent ID | SEC-5.14 — Context-sensitive text checks (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The `unicode-control` filter **SHALL** flag bidirectional overrides, zero-width joiners outside permitted scripts and Unicode tag characters, and **SHALL** pass the versioned corpus of legitimate multilingual and source-code samples. |
| Allocation | Elements: E-09 Request Inspection Pipeline, E-11 Response Inspection Pipeline; Functions: F-21, F-27 |
| Verification Method | Test |
| Verification Statement | Run the regression corpus; confirm zero false positives on legitimate samples and detection of every hostile sample. |
| Source | SEC 5.14 |
| Rationale | Context-sensitive text checks. |

#### SR-5.15-1 — Connection-time resolution

| Field | Value |
|---|---|
| ID | SR-5.15-1 |
| Parent ID | SEC-5.15 — Connection-time destination checks (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Egress Broker (E-18) **SHALL** resolve destination names itself, validate each resolved address at connection time, and re-validate each redirect target, following at most 3 redirects. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45; External interfaces: X-06 |
| Verification Method | Test |
| Verification Statement | Use a rebinding DNS fixture and a redirect chain to a private address; confirm refusal. |
| Source | SEC 5.15 |
| Rationale | DNS-rebinding and redirect defense. |

#### SR-5.15-2 — Reserved address denial

| Field | Value |
|---|---|
| ID | SR-5.15-2 |
| Parent ID | SEC-5.15 — Connection-time destination checks (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Egress Broker (E-18) **SHALL** refuse connections to loopback, private, link-local, CGNAT, multicast, reserved and cloud-metadata addresses for IPv4 and IPv6 unless the grant names the exact address. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45 |
| Verification Method | Test |
| Verification Statement | Attempt each address class; confirm refusal. |
| Source | SEC 5.15 |
| Rationale | SSRF defense. |

#### SR-5.16-1 — One-use egress capability

| Field | Value |
|---|---|
| ID | SR-5.16-1 |
| Parent ID | SEC-5.16 — One-use web authorization (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Egress Broker (E-18) **SHALL** require on each operation a one-use capability in the `Smcp-Egress-Auth` header bound to the correlation ID, decision ID, policy revision and destination, and **SHALL** remove the header before forwarding. |
| Allocation | Elements: E-18 Egress Broker, E-12 Enforcement Coordinator; Functions: F-45; Internal interfaces: I-25 |
| Verification Method | Test |
| Verification Statement | Replay a used capability and present one for another destination; confirm refusal and header removal. |
| Source | SEC 5.16 |
| Rationale | Each outbound operation is individually authorized. The capabilities of a call are minted when the call is dispatched to the instance and delivered in its `_meta` (CP-23); unused ones are revoked when the call returns. An operator may turn the check off (`[egress] require_capability = false`) for a server whose HTTP client cannot attach the header; the broker then authorizes each operation by instance and grant (SR-4.5-2) and reports the setting in its status. |

#### SR-5.17-1 — No ambient cookies

| Field | Value |
|---|---|
| ID | SR-5.17-1 |
| Parent ID | SEC-5.17 — Web content execution (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Egress Broker (E-18) **SHALL** strip `Cookie` and `Set-Cookie` headers from every operation it relays in clear (plain-HTTP proxy requests and endpoint requests, whose TLS the broker originates) and **SHALL** retain no cookie state between operations. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45 |
| Verification Method | Test |
| Verification Statement | Have a destination set a cookie; confirm it is not forwarded or replayed. |
| Source | SEC 5.17 |
| Rationale | No ambient credential state. An HTTPS request through `CONNECT` is a TLS tunnel that the broker relays without interception (it checks the server name, SR-4.5-2), so it cannot see the headers inside; the broker keeps no cookies of its own for any operation. |

#### SR-5.18-1 — Binary content gate

| Field | Value |
|---|---|
| ID | SR-5.18-1 |
| Parent ID | SEC-5.18 — Uninspected binary content (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The `content-type-gate` filter **SHALL** remove image, audio and binary embedded-resource content unless the content-type allowlist of the configuration (`[filters.content_types]`) allows the MIME type, the magic bytes match and the size is within its bound. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-27 |
| Verification Method | Test |
| Verification Statement | Return allowlisted, mismatched and oversize images; confirm the dispositions. |
| Source | SEC 5.18 |
| Rationale | Uninspected binaries are blocked. |

#### SR-5.18-2 — Icon handling

| Field | Value |
|---|---|
| ID | SR-5.18-2 |
| Parent ID | SEC-5.18 — Uninspected binary content (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Access Enforcement Point (E-08) **SHALL** remove `icons` entries from presented tool definitions except `data:` URIs of PNG or JPEG images no larger than 64 KiB whose magic bytes match. |
| Allocation | Elements: E-08 Access Enforcement Point; Functions: F-19 |
| Verification Method | Test |
| Verification Statement | Present tools with https, SVG and valid PNG icons; confirm only the valid PNG remains. |
| Source | SEC 5.18; MCP:basic/index §icons |
| Rationale | Icon URLs enable tracking and parser attacks. |

#### SR-5.19-1 — Public-fetch method profile

| Field | Value |
|---|---|
| ID | SR-5.19-1 |
| Parent ID | SEC-5.19 — Public-fetch method profile (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | For grants of the public-fetch class, the Egress Broker (E-18) **SHALL** permit only HTTPS GET without request bodies, `Authorization` headers, WebSocket upgrades or CONNECT. |
| Allocation | Elements: E-18 Egress Broker; Functions: F-45 |
| Verification Method | Test |
| Verification Statement | Attempt each prohibited operation; confirm refusal. |
| Source | SEC 5.19; SEC 9.6 |
| Rationale | Read-only public web access. |

#### SR-5.20-1 — Response envelope validation

| Field | Value |
|---|---|
| ID | SR-5.20-1 |
| Parent ID | SEC-5.20 — Response conformance (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Response Inspection Pipeline (E-11) **SHALL** validate each backend response's JSON-RPC envelope, request-ID correlation and `CallToolResult` schema before filtering. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-26 |
| Verification Method | Test |
| Verification Statement | Return malformed envelopes, wrong IDs and invalid results; confirm each is withheld. |
| Source | SEC 5.20 |
| Rationale | Conformance before inspection. |

#### SR-5.20-2 — Output schema validation

| Field | Value |
|---|---|
| ID | SR-5.20-2 |
| Parent ID | SEC-5.20 — Response conformance (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the manifest declares an `outputSchema`, the Response Inspection Pipeline (E-11) **SHALL** withhold a result whose `structuredContent` does not validate against it. |
| Allocation | Elements: E-11 Response Inspection Pipeline; Functions: F-26 |
| Verification Method | Test |
| Verification Statement | Return nonconforming structured content; confirm it is withheld. |
| Source | SEC 5.20; MCP:server/tools §Output Schema |
| Rationale | Structured results must match the curated schema. |

### SEC-6 Audit integrity and privacy

#### SR-6-1 — Research pseudonymization required

| Field | Value |
|---|---|
| ID | SR-6-1 |
| Parent ID | SEC-6 — Policy-linked audit integrity and privacy (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Research Dataset Service (E-32) **SHALL** export no principal, session or end-user identifier in clear form. |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-92; External interfaces: X-11 |
| Verification Method | Test |
| Verification Statement | Search an export for known identifiers; confirm absence. |
| Source | ARCH §4 E-32; SEC 6 |
| Rationale | Research data protection. |

#### SR-6-2 — S3 export grant

| Field | Value |
|---|---|
| ID | SR-6-2 |
| Parent ID | SEC-6 — Policy-linked audit integrity and privacy (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Research Dataset Service (E-32) **SHALL** include S3 raw-payload fields in an export only when the campaign carries an approved raw-export grant. |
| Allocation | Elements: E-32 Research Dataset Service; Functions: F-92, F-93 |
| Verification Method | Test |
| Verification Statement | Export with and without the grant; confirm S3 fields only with the grant. |
| Source | ARCH §19 OD-13 |
| Rationale | Raw content is the most sensitive data. |

#### SR-6-3 — Observation access control

| Field | Value |
|---|---|
| ID | SR-6-3 |
| Parent ID | SEC-6 — Policy-linked audit integrity and privacy (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Data Access Service (E-26) **SHALL** return observation data to console users only according to their Appendix C role and the data's sensitivity class. |
| Allocation | Elements: E-26 Data Access Service, E-24 Management Console & Control API; Functions: F-72, F-64 |
| Verification Method | Test |
| Verification Statement | Query S2 and S3 fields as each role; confirm the matrix is enforced. |
| Source | ARCH §10.2 |
| Rationale | Sensitivity-based access. |

#### SR-6.1-1 — Mandatory event floor

| Field | Value |
|---|---|
| ID | SR-6.1-1 |
| Parent ID | SEC-6.1 — Mandatory security metadata (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** record authentication failures, decisions, dispatches, outcomes, filter actions, approvals, secret uses, anomaly actions, drift events and administrative changes regardless of Audit Profile and Observation Policy settings. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-53; Internal interfaces: I-18 |
| Verification Method | Test |
| Verification Statement | Publish the most minimal policy; trigger each event class; confirm each is recorded. |
| Source | SEC 6.1 |
| Rationale | Non-disableable security evidence. |

#### SR-6.2-1 — Atomic intent commit

| Field | Value |
|---|---|
| ID | SR-6.2-1 |
| Parent ID | SEC-6.2 — Atomic decision and intent (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Enforcement Coordinator (E-12) **SHALL** append one journal record holding the decision, the invocation intent and the IDs of the exact rule, server revision, tool revision, filters, audit profile and observation profile to the Evidence Journal, and **SHALL** receive the completion of that record's flush to stable storage before issuing a launch capability. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-21 Audit & Evidence Service; Functions: F-29, F-55; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Kill the process at points before, during and after the append and the flush, using a fault-injecting file layer; confirm that no launch occurs whose intent record is absent from the journal after restart, and that `smcpctl journal verify` passes. |
| Source | SEC 6.2; OWNER (decision intent written and fsynced before the one-use launch capability is issued) |
| Rationale | Dispatch always has evidence. SEC 6.2 names a graph transaction; one flushed journal record gives the same atomicity on the evidence authority (A-9). |

#### SR-6.3-1 — Outcome before release

| Field | Value |
|---|---|
| ID | SR-6.3-1 |
| Parent ID | SEC-6.3 — Outcome before release (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Enforcement Coordinator (E-12) **SHALL** append the outcome and release disposition to the Evidence Journal and receive the completion of its flush before issuing a release authorization. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-21 Audit & Evidence Service; Functions: F-30, F-55; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Inject a flush failure after the backend responds; confirm the result is withheld with `-31003` and that no released content reaches the harness. |
| Source | SEC 6.3; OWNER (evidence authority is the journal) |
| Rationale | Release always has evidence. |

#### SR-6.4-1 — Exact links

| Field | Value |
|---|---|
| ID | SR-6.4-1 |
| Parent ID | SEC-6.4 — Exact historical links (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** link each evaluated-request event to its decision, policy revision, decisive rule revisions, target server and tool revisions and effective audit profile revision. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-54 |
| Verification Method | Inspection |
| Verification Statement | Traverse an event's links; confirm each target. |
| Source | SEC 6.4 |
| Rationale | Historical traceability. |

#### SR-6.5-1 — Origin attribution

| Field | Value |
|---|---|
| ID | SR-6.5-1 |
| Parent ID | SEC-6.5 — Event origin versus target (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** label each event's origin as `gateway`, `backend`, `broker` or `admin` and **SHALL** link a backend as observed only when the Gateway exchanged messages with it for that call. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-54 |
| Verification Method | Test |
| Verification Statement | Deny a call before dispatch; confirm no observed-backend link exists. |
| Source | SEC 6.5 |
| Rationale | No attribution of execution to uncalled servers. |

#### SR-6.7-1 — Secret scrubbing

| Field | Value |
|---|---|
| ID | SR-6.7-1 |
| Parent ID | SEC-6.7 — Secret removal (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) and the Observation Collector (E-29) **SHALL** replace registered secret fingerprints with `[REDACTED:<secretRef>]` in payloads, error texts, stderr captures and observation fields before persistence. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-29 Observation Collector; Functions: F-53, F-82 |
| Verification Method | Test |
| Verification Statement | Echo a delivered secret through every captured surface; confirm only redaction markers are persisted. |
| Source | SEC 6.7 |
| Rationale | No secrets at rest in evidence. |

#### SR-6.10-1 — Idempotent export

| Field | Value |
|---|---|
| ID | SR-6.10-1 |
| Parent ID | SEC-6.10 — Idempotent evidence export (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** feed journal events to the audit graph mirror (D-05) and to evidence export (X-09) exactly once per event ID, including after restart. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-26 Data Access Service; Functions: F-54, F-55; Internal interfaces: I-30; Data stores: D-05 |
| Verification Method | Test |
| Verification Statement | Crash the mirror feed and the exporter mid-batch; restart; confirm the mirror and the export each hold every journal event once, with no duplicates and no gaps. |
| Source | SEC 6.10; ARCH §2.2 A-9 |
| Rationale | Reliable evidence downstream of the journal. |

#### SR-6.11-1 — Export lag stop

| Field | Value |
|---|---|
| ID | SR-6.11-1 |
| Parent ID | SEC-6.11 — Export lag boundary (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the oldest journal event not yet in a signed segment is older than, or the count of such events exceeds, the CP-27 stop thresholds, the Enforcement Coordinator (E-12) **SHALL** refuse new launch authorizations. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-21 Audit & Evidence Service, E-23 Health & Safety Monitor; Functions: F-29, F-61 |
| Verification Method | Test |
| Verification Statement | Stall the exporter; confirm dispatch stops at the thresholds. |
| Source | SEC 6.11 |
| Rationale | Evidence must keep pace. |

#### SR-6.12-1 — Signing key custody

| Field | Value |
|---|---|
| ID | SR-6.12-1 |
| Parent ID | SEC-6.12 — Independent tamper evidence (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** sign journal segments with a key accessible only to the evidence-exporter identity and **SHALL** copy checkpoints to a directory writable only by that identity. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-22 Key & Trust Anchor Manager; Functions: F-55; Data stores: D-06 |
| Verification Method | Test |
| Verification Statement | Attempt to write checkpoints and read the key as other identities; confirm denial. |
| Source | SEC 6.12 |
| Rationale | Tamper evidence independent of the Data Server. |

#### SR-6.13-1 — Failure spool

| Field | Value |
|---|---|
| ID | SR-6.13-1 |
| Parent ID | SEC-6.13 — Failure evidence spool (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the graph mirror is unavailable, the Audit & Evidence Service (E-21) **SHALL** continue to record every event, including denials and failures, in the Evidence Journal, and **SHALL** backfill the mirror from the journal on recovery with each event's original policy status. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-53, F-54; Data stores: D-06, D-05 |
| Verification Method | Test |
| Verification Statement | Stop the graph database, generate permits, denials and failures, restart it; confirm every event is in the journal during the outage and in the mirror after recovery with its original `policy_status`. |
| Source | SEC 6.13; ARCH §2.2 A-9 |
| Rationale | The journal is the protected local record that SEC 6.13 asks for; the mirror catches up from it. |

#### SR-6.14-1 — Referenced version retention

| Field | Value |
|---|---|
| ID | SR-6.14-1 |
| Parent ID | SEC-6.14 — Historical retention (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Data Lifecycle & Memory Manager (E-28) **SHALL** retain every rule, route, server, tool, profile and baseline-snapshot version referenced by unexpired audit records. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-78 |
| Verification Method | Test |
| Verification Statement | Attempt to purge a referenced version; confirm refusal. |
| Source | SEC 6.14 |
| Rationale | Explanations remain possible. |

#### SR-6.15-1 — Purge receipt

| Field | Value |
|---|---|
| ID | SR-6.15-1 |
| Parent ID | SEC-6.15 — Controlled purge (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** record a retained deletion receipt for every authorized purge of payload or metadata. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-56 |
| Verification Method | Test |
| Verification Statement | Purge a payload; confirm the receipt. |
| Source | SEC 6.15 |
| Rationale | Accountable deletion. |

#### SR-6.16-1 — Audit authorization

| Field | Value |
|---|---|
| ID | SR-6.16-1 |
| Parent ID | SEC-6.16 — Audit access (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** authorize each audit query and export by the caller's Appendix C role. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-24 Management Console & Control API; Functions: F-57, F-64 |
| Verification Method | Test |
| Verification Statement | Query and export as each role; confirm the matrix. |
| Source | SEC 6.16 |
| Rationale | Audit confidentiality. |

#### SR-6.17-1 — Inert rendering

| Field | Value |
|---|---|
| ID | SR-6.17-1 |
| Parent ID | SEC-6.17 — Inert audit rendering (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Management Console & Control API (E-24) **SHALL** render audit and observation content as escaped text, **SHALL** prefix CSV cells beginning with `=`, `+`, `-` or `@` with an apostrophe in exports, and **SHALL** load no remote media. |
| Allocation | Elements: E-24 Management Console & Control API, E-32 Research Dataset Service; Functions: F-65, F-93 |
| Verification Method | Test |
| Verification Statement | Display and export fixtures with HTML, script and formula payloads; confirm inert output. |
| Source | SEC 6.17 |
| Rationale | Evidence cannot attack the viewer. |

#### SR-6.18-1 — Server-asserted label

| Field | Value |
|---|---|
| ID | SR-6.18-1 |
| Parent ID | SEC-6.18 — Server-asserted evidence (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** label stderr text, backend error messages and backend notifications as `server_asserted` evidence attributed to the instance. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-54 |
| Verification Method | Inspection |
| Verification Statement | Inspect stored backend-originated text events. |
| Source | SEC 6.18 |
| Rationale | Backend claims are not Gateway observations. |

#### SR-6.19-1 — Unevaluated status

| Field | Value |
|---|---|
| ID | SR-6.19-1 |
| Parent ID | SEC-6.19 — Unevaluated failure evidence (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | For events recorded without policy evaluation, the Audit & Evidence Service (E-21) **SHALL** record a stable system-control reason and `policy_status` of `not_evaluated` or `unavailable`. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-53 |
| Verification Method | Test |
| Verification Statement | Trigger an authentication failure and an outage denial; confirm the statuses. |
| Source | SEC 6.19 |
| Rationale | No invented decisions. |

#### SR-6.20-1 — Direct decision link

| Field | Value |
|---|---|
| ID | SR-6.20-1 |
| Parent ID | SEC-6.20 — Direct decision links (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** link every evaluated-request event to its decision with a `FOR_DECISION` relationship whether or not dispatch occurred. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-54 |
| Verification Method | Test |
| Verification Statement | Deny and permit calls; confirm the links. |
| Source | SEC 6.20 |
| Rationale | Denials are traceable. |

### SEC-7 Safe operation and recovery

#### SR-7-1 — Baseline integrity

| Field | Value |
|---|---|
| ID | SR-7-1 |
| Parent ID | SEC-7 — Safe operation and recovery (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Anomaly Scorer (E-31) **SHALL** refuse to load a baseline snapshot whose stored digest does not match its content. |
| Allocation | Elements: E-31 Anomaly Scorer, E-30 Behavior Baseline Engine; Functions: F-88; Internal interfaces: I-39 |
| Verification Method | Test |
| Verification Statement | Modify a stored snapshot; confirm the load is refused and an integrity event recorded. |
| Source | ARCH §17 item 1 (Data Server MUST); SEC 7 |
| Rationale | Baseline integrity. |

#### SR-7.1-1 — No side effects in retryable transactions

| Field | Value |
|---|---|
| ID | SR-7.1-1 |
| Parent ID | SEC-7.1 — Transaction retry safety (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Data Access Service (E-26) **SHALL** perform no dispatch, egress, file or export side effect inside a retryable database transaction function. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-72 |
| Verification Method | Inspection |
| Verification Statement | Inspect all transaction functions; confirm they contain only database work. |
| Source | SEC 7.1 |
| Rationale | Retries must not repeat side effects. |

#### SR-7.2-1 — Indeterminate outcomes

| Field | Value |
|---|---|
| ID | SR-7.2-1 |
| Parent ID | SEC-7.2 — Indeterminate mutation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a call to a tool of side-effect class `write`, `external` or `execute` loses its response or its instance fails after dispatch, the Tool Dispatcher (E-10) **SHALL** record the outcome as `indeterminate`, return Gateway error `-31009`, and **SHALL** not retry the call. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-24, F-25 |
| Verification Method | Test |
| Verification Statement | Kill a write-class fixture mid-call; confirm `indeterminate`, -31009 and no retry. |
| Source | SEC 7.2 |
| Rationale | No automatic replay of possibly executed mutations. |

#### SR-7.3-1 — Integrity validation

| Field | Value |
|---|---|
| ID | SR-7.3-1 |
| Parent ID | SEC-7.3 — Graph integrity validation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** validate the signature, schema, required fields, types, enumerations and cross-references of the active policy revision at publication and at startup, and the Health & Safety Monitor (E-23) **SHALL** enter `fail-closed` on failure. |
| Allocation | Elements: E-05 Policy Administration Service, E-23 Health & Safety Monitor; Functions: F-10, F-62; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Corrupt a stored rule, break a cross-reference and remove the signature, restarting after each; confirm `fail-closed` with the matching cause. |
| Source | SEC 7.3; ARCH §2.2 A-9 |
| Rationale | The policy authority is a file set; it is validated as a whole before it is trusted. |

#### SR-7.4-1 — Graph engine hardening

| Field | Value |
|---|---|
| ID | SR-7.4-1 |
| Parent ID | SEC-7.4 — Neo4j hardening (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Graph Database Engine (E-25) **SHALL** run with the HTTP and HTTPS connectors disabled, no plugins or unsafe procedures, file-URL CSV import disabled, `dbms.usage_report.enabled=false` and outbound network denied. |
| Allocation | Elements: E-25 Graph Database Engine; External interfaces: X-07 |
| Verification Method | Inspection |
| Verification Statement | Inspect the effective configuration and firewall rules. |
| Source | SEC 7.4 |
| Rationale | Minimal database attack surface. |

#### SR-7.5-1 — Secure bootstrap

| Field | Value |
|---|---|
| ID | SR-7.5-1 |
| Parent ID | SEC-7.5 — Secure bootstrap (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Management Console & Control API (E-24) **SHALL** create the first Administrator only with a one-use bootstrap credential generated by `smcpctl bootstrap`, stored with mode 0600 and valid for 24 hours. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-63 |
| Verification Method | Test |
| Verification Statement | Attempt creation without, with an expired and with a used credential; confirm only valid first use succeeds. |
| Source | SEC 7.5 |
| Rationale | Protected initial administration. |

#### SR-7.5-2 — No secrets on the command line

| Field | Value |
|---|---|
| ID | SR-7.5-2 |
| Parent ID | SEC-7.5 — Secure bootstrap (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The `smcpctl bootstrap`, `smcpctl install` and `smcpctl hash-password` commands **SHALL** read a password or bootstrap secret only from an interactive prompt or from a file with mode 0600 or stricter, and **SHALL** refuse one supplied as a command-line argument. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-63, F-97 |
| Verification Method | Test |
| Verification Statement | Run each command with a password argument, with a mode 0644 file, with a mode 0600 file and with the prompt; confirm refusal for the first two and success for the others. |
| Source | SEC 7.5; REVIEW (minor: bootstrap secret must not be passed on the command line) |
| Rationale | Command-line arguments are visible to other local processes and kept in shell history. |

#### SR-7.6-1 — Emergency stop serialization

| Field | Value |
|---|---|
| ID | SR-7.6-1 |
| Parent ID | SEC-7.6 — Emergency stop (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Enforcement Coordinator (E-12) **SHALL** process an emergency stop through its gate so that no launch authorization follows the stop. |
| Allocation | Elements: E-12 Enforcement Coordinator; Functions: F-31 |
| Verification Method | Test |
| Verification Statement | Race stop against launches; confirm the ordering. |
| Source | SEC 7.6 |
| Rationale | Reliable halt. |

#### SR-7.6-2 — Stop cancellation

| Field | Value |
|---|---|
| ID | SR-7.6-2 |
| Parent ID | SEC-7.6 — Emergency stop (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | On emergency stop, the Enforcement Coordinator (E-12) **SHALL** request cancellation of all in-flight calls and withdrawal of all secret grants. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-10 Tool Dispatcher, E-20 Secret Broker; Functions: F-31, F-52; Internal interfaces: I-20 |
| Verification Method | Test |
| Verification Statement | Stop with in-flight calls and active grants; confirm cancellation and withdrawal. |
| Source | SEC 7.6; ARCH §18.7 |
| Rationale | Stop limits ongoing activity. |

#### SR-7.7-1 — Offline backup procedure

| Field | Value |
|---|---|
| ID | SR-7.7-1 |
| Parent ID | SEC-7.7 — CE-compatible backup (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The `smcpctl backup` command **SHALL** stop dispatch, drain in-flight calls, seal the open journal segment, copy the Policy Store, Server Registry, configuration, encrypted vault, Evidence Journal, key material and trust anchors into the encrypted archive of FR-17.6, optionally add an Observation Store copy and a graph dump, and keep dispatch stopped until the archive is written and checksummed. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager, E-12 Enforcement Coordinator, E-21 Audit & Evidence Service; Functions: F-79; Data stores: D-15 |
| Verification Method | Test |
| Verification Statement | Run a backup under load; confirm the sequence from the journal, that dispatch remains stopped throughout and resumes after, and that the archive contains each listed component. |
| Source | SEC 7.7; ARCH §2.2 A-9 |
| Rationale | The authorities are files and are copied consistently while dispatch is stopped; the graph is optional because it can be rebuilt. |

#### SR-7.8-1 — Restore verification

| Field | Value |
|---|---|
| ID | SR-7.8-1 |
| Parent ID | SEC-7.8 — Verified restoration (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The `smcpctl restore` command **SHALL** restore into an isolated directory, verify the archive checksum, the journal chain and signatures and the policy revision signatures, re-apply every revocation recorded in the restored journal and in the current journal when present, and rebuild the graph mirror from the restored journal before enabling service. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-79 |
| Verification Method | Test |
| Verification Statement | Restore a backup taken before a revocation; confirm the revocation is re-applied from the journal before service starts. |
| Source | SEC 7.8 |
| Rationale | Restores must not resurrect revoked authority. |

#### SR-7.9-1 — Rollback preserves revocations

| Field | Value |
|---|---|
| ID | SR-7.9-1 |
| Parent ID | SEC-7.9 — Safe rollback (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** carry forward current credential revocations, principal suspensions and server suspensions when rolling back policy or application versions. |
| Allocation | Elements: E-05 Policy Administration Service, E-12 Enforcement Coordinator; Functions: F-12, F-32 |
| Verification Method | Test |
| Verification Statement | Revoke, then roll back policy; confirm the revocation remains effective. |
| Source | SEC 7.9 |
| Rationale | Rollback is not a revocation bypass. |

#### SR-7.10-1 — Audit capacity stop

| Field | Value |
|---|---|
| ID | SR-7.10-1 |
| Parent ID | SEC-7.10 — Audit capacity (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When free capacity for mandatory audit storage falls below a 256 MiB reserve, the Enforcement Coordinator (E-12) **SHALL** refuse new launch authorizations. |
| Allocation | Elements: E-12 Enforcement Coordinator, E-28 Data Lifecycle & Memory Manager, E-23 Health & Safety Monitor; Functions: F-29, F-78 |
| Verification Method | Test |
| Verification Statement | Fill storage to the reserve; confirm dispatch stops. |
| Source | SEC 7.10 |
| Rationale | Never dispatch without room for evidence. |

#### SR-7.11-1 — Pre-parse bounds

| Field | Value |
|---|---|
| ID | SR-7.11-1 |
| Parent ID | SEC-7.11 — Pre-routing bounds (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Harness Interface Endpoint (E-01) **SHALL** enforce the CP-06, CP-07 and CP-09 header, body, connection and unauthenticated-work limits before JSON parsing. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01 |
| Verification Method | Test |
| Verification Statement | Send oversize headers, oversize and slow bodies and connection floods; confirm rejection before parsing. |
| Source | SEC 7.11 |
| Rationale | Parser denial-of-service defense. |

#### SR-7.12-1 — Cancellation propagation

| Field | Value |
|---|---|
| ID | SR-7.12-1 |
| Parent ID | SEC-7.12 — Cancellation propagation (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When a northbound request is cancelled, the Tool Dispatcher (E-10) **SHALL** propagate cancellation southbound, and **SHALL** record a cancelled mutation as `indeterminate` rather than as undone. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-25 |
| Verification Method | Test |
| Verification Statement | Cancel a write-class call; confirm the southbound cancellation and `indeterminate`. |
| Source | SEC 7.12 |
| Rationale | Cancellation does not prove rollback. |

### SEC-8.9 GUI request protection

#### SR-8.9-1 — CSRF and preconditions

| Field | Value |
|---|---|
| ID | SR-8.9-1 |
| Parent ID | SEC-8.9 — GUI request protection (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Management Console & Control API (E-24) **SHALL** require a valid CSRF token and an `If-Match` revision precondition on every state-changing control API request from a browser session. |
| Allocation | Elements: E-24 Management Console & Control API; Functions: F-63 |
| Verification Method | Test |
| Verification Statement | Submit mutations without a token, with a wrong token and with a stale revision; confirm rejection. |
| Source | SEC 8.9 |
| Rationale | Browser mutation protection. |

## Appendix A — Controlled parameters (CP)

Values marked **SEC** are inherited from `MCP_Gateway_Security_SRS.md` Appendix A. Values marked **ARCH** come from `ArchitectureV2.md`. Changing a value requires a controlled revision of this SRS.

| ID | Parameter | Value | Origin |
|---|---|---|---|
| CP-01 | Northbound MCP endpoint path | `/mcp` | New |
| CP-02 | Harness listeners | TLS: `127.0.0.1:8443`; UDS (profile): `/run/smcp/harness.sock` | New |
| CP-03 | Admin listener | `127.0.0.1:8444` (TLS; `[admin_listener] address`) | New |
| CP-04 | Northbound supported protocol versions | `["2026-07-28", "2025-11-25"]`, both served in the baseline | SEC 5.1 |
| CP-05 | Southbound protocol eras | Modern `2026-07-28`; legacy `2025-11-25` | SEC 5.1 |
| CP-06 | Header limit / header deadline | 16 KiB / 5 s | SEC |
| CP-07 | Request body limit / body deadline | 1 MiB / 15 s | SEC |
| CP-08 | Expanded result size / JSON depth | 8 MiB / 32 | SEC |
| CP-09 | Connections / unauthenticated work / per-source rate | 128 / 32 concurrent / 10 req/s, burst 20 | SEC |
| CP-10 | Tool concurrency / queue | 4 per principal, 16 total / 32 | SEC |
| CP-11 | Default principal tool rate | 60 calls/min, burst 10 (at most 10 calls in any 10 s window; `[limits] principal_calls_per_minute`, `principal_call_burst`) | SEC |
| CP-12 | Decision deadline / candidate rules | 500 ms / 256 | SEC |
| CP-13 | Upstream execution / client deadline | 45 s / 60 s | SEC |
| CP-14 | Required filter deadline | 2 s per profile | SEC |
| CP-15 | Credential lifetime / rotation overlap | 30 days / ≤ 24 h | SEC |
| CP-16 | Revocation propagation | ≤ 2 s | SEC |
| CP-17 | Approval lifetime | ≤ 5 min, one use | SEC |
| CP-18 | Session max lifetime / idle timeout / concurrent sessions per principal | 8 h / 30 min / 8 | New |
| CP-19 | Catalog `ttlMs` / page size | 60,000 ms / 100 tools | New |
| CP-20 | Listen keep-alive / listen streams per session | 15 s / 2 | New |
| CP-21 | Progress relay rate | ≤ 10 notifications/s per request | New |
| CP-22 | Gateway error codes | Appendix B | New |
| CP-23 | Gateway metadata names | `_meta` prefix `local.smcpgw/`; session token in `Authorization: Bearer` (RFC 6750 header only) on the TLS listener; on the UDS listener the session is bound to the connection (first message `local.smcpgw/authenticate`, FR-2.15); egress header `Smcp-Egress-Auth`, whose one-use capabilities each call delivers in `_meta` `local.smcpgw/egress_auth` | New |
| CP-24 | Default instance budget | 512 MiB RAM, 1 CPU, 128 PIDs | SEC |
| CP-25 | Retention defaults | Metadata 90 d; payload 7 d; temporary full capture ≤ 24 h | SEC |
| CP-26 | Audit/evidence quota | 10 GiB; warn at 80% | SEC |
| CP-27 | Journal signing lag | Target 5 s; stop when the oldest unsigned event is older than 60 s or more than 1,000 events are unsigned | SEC |
| CP-28 | Argon2id | 64 MiB, t = 3, p = 1, salt ≥ 16 B | SEC |
| CP-29 | Admin session | 15 min idle, 8 h absolute | SEC |
| CP-30 | Anomaly defaults | Bands: normal \|z\| < 2, elevated < 3, abnormal < 4, critical ≥ 4; n_min = 30; σ_floor from catalog | ARCH §9.2 |
| CP-31 | Sampling defaults | Normal band 10%; elevated and above 100% | ARCH §9.5 |
| CP-32 | Performance targets | Decision p95 ≤ 10 ms (ceiling 100 ms); scoring p95 ≤ 2 ms; capture ≤ 1 ms; overhead p95 ≤ 50 ms (ceiling 250 ms); ingest ≥ 2,000 rec/s; snapshot ≤ 60 s / 10k contexts; GUI query p95 ≤ 2 s; idle RSS ≤ 4 GiB | ARCH §14; SEC |
| CP-33 | Default memory budget | Graph heap 1 GiB; graph page cache 1 GiB; DuckDB 512 MiB; baseline cache 128 MiB; capture queues 64 MiB; Gateway core 512 MiB | New |
| CP-34 | Revocation feed maximum staleness | 24 h | New |
| CP-35 | Artifact re-verification | At every instance launch | ARCH §4 E-13 |
| CP-36 | Schema validation bounds | Depth 32; 1,000 subschemas; 50 ms | New |
| CP-37 | stderr capture | 64 KiB per call; 1 MiB ring per instance | New |
| CP-38 | Instance idle teardown | 10 min | New |
| CP-39 | MRTR `requestState` lifetime | 5 min | New |
| CP-40 | Research pseudonym function | HMAC-SHA-256, per-dataset key | ARCH §4 E-32 |
| CP-41 | OAuth parameters | Authorization-code grant (Remote Access listener also: the RFC 8628 device authorization grant used by `smcp-connect`, device code lifetime 10 min, poll interval 5 s); PKCE `S256` only; resource URI `https://127.0.0.1:8443/mcp` (Remote Access listener: the configured public URL followed by `/mcp`); scope prefix `smcp:` with `template`, `purpose`, `project`, `user`; access-token lifetime = CP-18 idle timeout; refresh-token lifetime = CP-18 maximum lifetime; client-secret lifetime = CP-15; `iss` in authorization responses | New |
| CP-42 | Public tool names | `<alias>_<tool>`; alias `[a-z0-9]{1,16}`; tool part `[A-Za-z0-9_]`; whole name ≤ 64 characters | New |
| CP-43 | Adapter credential file | `$XDG_CONFIG_HOME/smcp/credentials.toml` (default `~/.config/smcp/`), mode 0600; refresh at 50% of access-token lifetime | New |
| CP-44 | Manifest classes | Risk class `low`, `moderate` or `high`; `high` = general SQL, code or shell execution, CAD scripting, browser automation, or process spawning beyond the declared argument vector (SEC 3.13). Side-effect class per tool: `read`, `write`, `external`, `execute`. `source_trust` per tool: `trusted` (content originates from the operator's own data) or `untrusted` (content from the Internet, third parties or other agents) | New |
| CP-45 | Approval hold | Hold bound 120 s (`[limits] approval_hold`, configurable 0 to 600 s; 0 disables hold); keep-alive interval 10 s (`[approvals] keepalive`); approval URL `https://<CP-03 admin listener>/approvals/<approvalId>`, or `[approvals] console_url` followed by `/approvals/<approvalId>` when set | New |
| CP-46 | Directories and service identities | **Enforced:** configuration `/etc/smcp` (root:smcp, 0750); state `/var/lib/smcp` with `policy/`, `registry/`, `artifacts/` (owner `smcp-core`, 0700), `journal/` (owner `smcp-evidence`, 0700), `keys/` (owner `smcp-keys`, 0700), `vault/` (owner `smcp-vault`, 0700), `exports/` (owner `smcp-core`, 0750); runtime `/run/smcp` (0750); logs `/var/log/smcp` (0750). Identities `smcp-core`, `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data`, `smcp-console`, and `smcp-srv` with a subordinate range of 65,536 UIDs and GIDs for rootless Podman. **Standalone macOS:** `~/Library/Application Support/smcp-gateway/` with `config/` and `state/`, logs `~/Library/Logs/smcp-gateway/`, all 0700. **Standalone Linux:** configuration `$XDG_CONFIG_HOME/smcp-gateway` (default `~/.config/smcp-gateway`), state `$XDG_STATE_HOME/smcp-gateway` (default `~/.local/state/smcp-gateway`) including `log/`, runtime `$XDG_RUNTIME_DIR/smcp-gateway`, all 0700 | New |
| CP-47 | Upgrade bounds | Health wait after start 60 s; migration time limit 120 s | New |
| CP-48 | Remote listener | The first of `127.0.0.1:8444` and `127.0.0.1:8445` that the CP-03 admin listener does not use (`127.0.0.1:8445` with the default admin listener; `[remote] address` overrides); TLS, Remote Access Profile only; public name set by the operator | New |
| CP-49 | Remote limits | Calls 30/min per client ID, burst 5; OAuth endpoints 10 req/s per source address, burst 20; lockout after 5 consecutive failed sign-ins or token requests, for 15 min; body 256 KiB; headers 8 KiB; concurrency 4 per client, 16 total; remote session maximum lifetime 2 h, idle timeout 15 min; pending dynamic registrations at most 32 in total and 4 per source address (IPv6: per /64), each kept 24 h | New |
| CP-50 | Diagnostic log and reload | Rotate at 10 MiB, keep 5 files. Reloadable keys: `log.level`, `limits.principal_calls_per_minute`, `limits.principal_call_burst`. Restart required: every other key, among them listener addresses, `state.dir`, `profile` and the other `limits.*` (read at startup by the components that hold them); servers are enabled and disabled at run time through G-10, and clients are managed in G-11 | New |
| CP-51 | Metrics endpoint | `127.0.0.1:9464`, path `/metrics`; disabled by default | New |
| CP-52 | Client ID Metadata Document allowlist | Empty by default; entries are added only by `[[client_metadata]]` configuration entries (`smcpctl clients setup` does not add them). Fetch only allowlisted HTTPS URLs; 5 s timeout; 64 KiB limit; cache 24 h; no redirects to other hosts | New |
| CP-53 | Local server CA | Validity 365 days; listener certificate validity 90 days, renewed when 30 days remain; CA name constraints are dNSName subtrees only, permitting `localhost` and the configured listener host names (no iPAddress subtrees, which BoringSSL-based TLS clients reject); listener certificate IP addresses are limited to loopback addresses and the configured listener IP literals; path length 0 | New |

## Appendix B — Gateway error codes and reason codes

Gateway-specific codes lie outside the JSON-RPC reserved range (`-32768` to `-32000`), as the MCP specification recommends. Every error carries `data.reasonCode`, `data.correlationId` and the plain-language `data.message` of Table B.2, plus `data.decisionId` when a decision exists (FR-1.20, FR-1.51).

### B.1 Error codes

| Code | Name | HTTP status (Streamable HTTP) | Meaning |
|---|---|---|---|
| `-31001` | PolicyDenied | 200 | The policy decision denied the request |
| `-31002` | ApprovalRequired | 200 | A human approval is pending; retry after approval (`data.approvalId`, `data.expiresAt`) |
| `-31003` | ResponseWithheld | 200 | The response was withheld by response inspection, scoring or release checks |
| `-31004` | GatewayFailClosed | 503 | Enforcement dependencies are unavailable or the Gateway is stopped |
| `-31005` | RateLimited | 429 | A rate, concurrency, queue or stream limit was reached |
| `-31006` | SessionInvalid | 401 | Missing, invalid, expired, suspended or misbound session |
| `-31007` | BackendError | 200 | The backend failed or returned a protocol error (`data.backendCode`) |
| `-31008` | Timeout | 200 | The client deadline expired |
| `-31009` | IndeterminateOutcome | 200 | A possibly executed mutation lost its outcome; it is not retried |
| `-31010` | InputRequiredUnsupported | 200 | The backend requested client input and the MRTR Relay Profile is disabled |

Standard codes used: `-32700`, `-32600`, `-32601`, `-32602`, `-32603`, `-32020` (HeaderMismatch), `-32022` (UnsupportedProtocolVersion).

### B.2 Reason codes and messages

`docs/troubleshooting.md` repeats this table with the operator's next action for each reason code (FR-18.7).

| Reason code | Code | Meaning | `data.message` |
|---|---|---|---|
| `NO_PERMIT` | `-31001` | No rule of the session's template permits the call | The Gateway's policy does not allow this tool in this session. Ask the Gateway operator to grant it. |
| `NO_TEMPLATE` | `-31001` | The session's template is not in the active policy | This session's policy template no longer exists. Sign in again to start a new session. |
| `TEMPLATE_NOT_PERMITTED` | `-31001` | A session create request named a template the principal's Framework Profile does not permit (FR-2.6) | The requested policy template is not permitted for this agent. Request a template its framework profile allows, or none for the default. |
| `PRINCIPAL_DISABLED` | `-31001` | The principal is disabled or suspended (SR-1.5-1) | This agent's access to the Gateway is suspended. Ask the Gateway operator. |
| `CREDENTIAL_INVALID` | `-31001` | The client credential is expired or revoked (SR-1.5-1) | This agent's Gateway credential is no longer valid. Ask the Gateway operator for a new one. |
| `REVISION_NOT_ENABLED` | `-31001` | The tool's server revision is not enabled (SR-1.5-1) | The tool's server is not enabled on the Gateway. Ask the Gateway operator. |
| `NO_ROUTE` | `-31001` | No route serves the tool's server and tool revision (SR-1.11-1) | The tool's server is not available right now. Try again later or ask the Gateway operator. |
| `AMBIGUOUS_ROUTE` | `-31001` | More than one route is eligible for the tool (SR-1.11-1) | The Gateway could not choose how to reach this tool and refused the call. Ask the Gateway operator. |
| `HIGH_RISK_UNFLAGGED` | `-31001` | The server is in a high-risk class the template or framework profile does not flag (SR-3.13-1) | This tool is in a high-risk class that this session's policy does not allow. |
| `DENY_RULE` | `-31001` | A deny rule of the session's template covers the tool (SR-1.4-1) | The Gateway's policy forbids this tool in this session. |
| `EVAL_BOUND` | `-31001` | The evaluation exceeded the CP-12 deadline or candidate-rule bound (SR-1.20-1) | The Gateway could not finish checking this call within its limits and refused it. Ask the operator to simplify the policy. |
| `APPROVAL_DENIED` | `-31001` | An approver denied the call | A person reviewing this call denied it. |
| `TAINT_DENIED` | `-31001` | The session is tainted and the template denies this side-effect class | This session has read untrusted content, so tools that write or send data are blocked. Start a new session to use them. |
| `ARGUMENTS_INVALID` | `-31001` | The arguments are not valid JSON (`size-limit` and argument filters) | The request arguments could not be read. |
| `ARGUMENTS_TOO_LARGE` | `-31001` | The arguments exceed the `size-limit` byte or string bound | The request is too large for this tool. Send less data in one call. |
| `ARGUMENTS_TOO_DEEP` | `-31001` | The arguments nest deeper than the `size-limit` depth bound | The request is nested too deeply. Simplify the arguments. |
| `UNICODE_CONTROL` | `-31001` | An argument contains bidirectional, invisible or tag characters (`unicode-control`) | The request contains hidden or direction-changing characters. Remove them and try again. |
| `SECRET_IN_ARGUMENTS` | `-31001` | An argument contains a known credential format or a registered secret (`secret-fingerprint`, SR-5.8-1) | The request appears to contain a password, key or token, so it was not sent. Remove the secret and try again. |
| `DATA_CLASS_IN_ARGUMENTS` | `-31001` | An argument matches a data-class rule whose request action is block (`pii-detect` named by the decision, SR-5.8-1) | The request contains personal or classified data that this tool may not receive, so it was not sent. Remove it and try again. |
| `PATH_INVALID` | `-31001` | A path argument uses an encoded separator, NUL, backslash traversal, home-relative or remote file form (`path-canonicalize`) | A file path in the request is not allowed in this form. Use a plain path. |
| `PATH_OUTSIDE_ROOTS` | `-31001` | A path argument resolves outside the granted roots (`path-canonicalize`, SR-1.8-4) | A file path in the request is outside the folders this tool may use. |
| `URL_INVALID` | `-31001` | A URL argument cannot be parsed or canonicalized (`url-canonicalize`) | A web address in the request is not valid. |
| `URL_NOT_ALLOWED` | `-31001` | A URL argument's scheme or host is not allowed, or it carries user information (`url-canonicalize`, SR-1.8-5) | A web address in the request is not allowed for this tool. |
| `URL_PRIVATE_ADDRESS` | `-31001` | A URL argument names a loopback, private, link-local or reserved destination (`url-canonicalize`) | A web address in the request points to a local or private network address, which this tool may not use. |
| `FILTER_UNAVAILABLE` | `-31001` | The decision's obligations name a filter that is not registered | The Gateway could not run a required check for this tool. Give the operator the correlation ID {correlationId}. |
| `FILTER_ERROR` | `-31001`, `-31003` | A required filter failed; the request is blocked or the result withheld (SR-5.10-1) | A Gateway safety check failed, so the call was stopped. Give the operator the correlation ID {correlationId}. |
| `FILTER_TIMEOUT` | `-31001`, `-31003` | A filter chain exceeded the CP-14 deadline (SR-5.10-1) | A Gateway safety check took too long, so the call was stopped. Try a smaller request. |
| `APPROVAL_REQUIRED` | `-31002` | The call is waiting for a person to approve it | This call needs approval. Open {approvalUrl} to approve it, then run the same request again. |
| `TAINT_APPROVAL` | `-31002` | Approval required because the session is tainted | This session has read untrusted content, so this tool needs approval. Open {approvalUrl} to approve it, then run the same request again. |
| `APPROVAL_EXPIRED` | `-31002` | The approval expired (CP-17) while the call was held | The approval for this call expired before it was used. Run the same request again to ask for a new approval. |
| `APPROVAL_CONSUMED` | `-31002` | An identical held call consumed the one-use approval first | The approval for this call was already used by an identical call. Run the same request again to ask for a new approval. |
| `APPROVAL_UNAVAILABLE` | `-31002` | The call needs approval and the Approval Service could not take the request | This call needs approval, but the Gateway's approval service is not available. Ask the Gateway operator to approve the call or check `smcpctl health`, then run the same request again. |
| `FILTER_BLOCKED` | `-31003` | A required response filter blocked the result | The tool's result was withheld by a Gateway content filter. The operator can see why in the audit record {correlationId}. |
| `SECRET_LEAK` | `-31003` | A registered secret fingerprint matched the result | The tool's result was withheld because it appeared to contain a protected secret. |
| `RESULT_TOO_LARGE` | `-31003` | The result exceeded the CP-08 bound | The tool's result was too large to inspect and was withheld. Narrow the request. |
| `RESULT_INVALID` | `-31003` | The backend response failed envelope, request-ID or `CallToolResult` validation, or carried an unrecognized `resultType` (SR-5.20-1, FR-5.23) | The tool's server returned a result the Gateway could not validate, so it was withheld. |
| `RELEASE_REFUSED` | `-31003` | The release recheck failed (session ended, policy changed or stop) | The result was withheld because the session or policy changed while the tool ran. Run the request again. |
| `OUTCOME_UNRECORDED` | `-31003` | The tool ran but its outcome could not be written to the Evidence Journal, so the result is withheld (SR-6.3-1) | The tool ran, but the Gateway could not record its outcome, so the result was withheld. It may have completed the action; check before trying again. The operator can see the cause with `smcpctl health`. |
| `ANOMALY_WITHHELD` | `-31003` | Synchronous scoring placed the call in the Anomaly Response Policy's withhold band (FR-4.15) | The tool's result was withheld because the call looked unusual for this agent. The operator can see why in the audit record {correlationId}. |
| `FAIL_CLOSED` | `-31004` | A critical dependency is unavailable | The Gateway is not accepting tool calls right now because a safety check failed. The operator can see the cause with `smcpctl health`. |
| `EMERGENCY_STOP` | `-31004` | An emergency stop is in effect | The Gateway operator has stopped all tool calls. |
| `NO_SNAPSHOT` | `-31004` | No verified policy revision is loaded | The Gateway has no valid policy loaded and is refusing all tool calls. |
| `JOURNAL_UNAVAILABLE` | `-31004` | The decision intent could not be written to the Evidence Journal | The Gateway could not record this call and did not run it. The operator can see the cause with `smcpctl health`. |
| `POLICY_REVISION_CHANGED` | `-31004` | The policy changed between decision and launch | The Gateway's policy changed while this call was being checked. Run the request again. |
| `CAPABILITY` | `-31004` | The one-use launch capability was missing or already used | The Gateway refused to run this call because an internal check failed. Run the request again; if it repeats, give the operator the correlation ID {correlationId}. |
| `RATE_LIMITED` | `-31005` | A rate limit was reached | Too many tool calls in a short time. Wait a minute and try again. |
| `QUOTA_EXHAUSTED` | `-31005` | The session used its per-session call quota | This session has used all the tool calls its policy allows. Start a new session. |
| `QUEUE_FULL` | `-31005` | The dispatch queue is full | The Gateway is busy. Try again shortly. |
| `SESSION_LIMIT` | `-31005` | A session create request would exceed the CP-18 concurrent-session limit of the principal (FR-2.10) | This agent already has the maximum number of open sessions. End one, then try again. |
| `LISTEN_LIMIT` | `-31005` | The session already holds the CP-20 number of open listen streams | This session already has the maximum number of open listen streams. Close one, then try again. |
| `SESSION_INVALID` | `-31006` | Missing, expired or unknown token | Your Gateway session is not valid. Sign in again. |
| `SESSION_STATE` | `-31006` | The session is suspended or terminated | Your Gateway session has ended. Sign in again. |
| `BACKEND_ERROR` | `-31007` | The backend returned a protocol error | The tool's server reported an error. |
| `DISPATCH_FAILED` | `-31007` | The backend could not be reached or started | The tool's server could not be started or reached. The operator can check it in the Servers view. |
| `BACKEND_OUTPUT_INVALID` | `-31007` | The instance wrote a stdout line that is not a single-line UTF-8 JSON-RPC message; the instance is replaced (FR-5.14) | The tool's server sent data that is not valid MCP, so the call was stopped and the server restarted. |
| `CLIENT_DEADLINE` | `-31008` | The CP-13 client deadline expired | The tool did not finish in time. |
| `UPSTREAM_TIMEOUT` | `-31009` | The backend did not answer within CP-13; it may have acted | The tool's server stopped responding. It may have completed the action; check before trying again. |
| `INSTANCE_FAILED` | `-31009` | The instance ended after a call to a tool of side-effect class `write`, `external` or `execute`, or an unclassified tool, was dispatched; it may have acted and is not retried (SR-7.2-1) | The tool's server stopped while running this call. It may have completed the action; check before trying again. |
| `CANCELLED` | `-31009` | The harness cancelled the call after dispatch; the backend may have acted | The call was cancelled before it finished. It may have completed the action; check before trying again. |
| `INPUT_REQUIRED_UNSUPPORTED` | `-31010` | The backend asked for client input without the MRTR profile | The tool asked for input that the Gateway does not relay. |
| `SCHEMA_INVALID` | `-32602` | Arguments do not match the tool's input schema | The arguments do not match what this tool accepts. |

### B.3 Reason codes no request reaches

The Gateway keeps these Table B.2 codes as defense in depth: an earlier check of the same call always answers first, so no request produces them. FR-1.51's verification confirms their message text through the error builder instead of the wire.

| Reason code | Why no request reaches it |
|---|---|
| `AMBIGUOUS_ROUTE` | Routes are server aliases, which are unique, and a public name resolves to one server, so the decision never sees two eligible routes |
| `NO_ROUTE` | The catalog presents a tool only while the registry resolves it to its server; when the route goes, the name leaves the catalog (an unknown tool, `-32602`) or the server is suspended (`REVISION_NOT_ENABLED`) |
| `DENY_RULE` | The catalog presents only granted tools that no deny rule covers (FR-1.26), so a call to a denied tool is an unknown tool (`-32602`) |
| `CREDENTIAL_INVALID` | Revoking a credential terminates its sessions under the Enforcement Coordinator's barrier (SR-1.16-1), so the session check answers first (`SESSION_INVALID`) |
| `PRINCIPAL_DISABLED` | Suspending a principal terminates its sessions under the same barrier, with the same effect |
| `CAPABILITY` | The launch capability is issued and consumed within one call; only a Gateway defect produces this code |
| `ARGUMENTS_INVALID` | `tools/call` arguments are decoded as a JSON object before the inspection chain runs; any other value is refused with `-32602` by the protocol layer |
| `CANCELLED` | MCP cancellation: the harness that cancelled the call gets no response to it; the code is recorded in the journal only |

## Appendix C — Application role matrix

| Operation | Administrator | Operator | Policy Author | Approver | Session Approver | Auditor | Researcher |
|---|---|---|---|---|---|---|---|
| Emergency stop / resume | Stop + resume | Stop | — | — | — | — | — |
| View health and status | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Edit, simulate policy drafts | ✓ | — | ✓ | — | — | — | Observation drafts and campaigns only |
| Publish / roll back policy | ✓ | — | ✓ | — | — | — | — |
| Approve research campaign | ✓ | — | ✓ | — | — | — | — |
| Decide tool-call approvals | ✓ | — | — | ✓ | — | — | — |
| Approve harness sign-in (OAuth authorization) | — | — | — | — | ✓ | — | — |
| Approve dynamic client registrations (Remote Access) | ✓ | — | — | — | ✓ | — | — |
| Enable / suspend / retire servers; aliases | ✓ | Suspend only | — | — | — | — | — |
| Enroll trust anchors | ✓ | — | — | — | — | — | — |
| Enable or disable the Remote Access Profile | ✓ | — | — | — | — | — | — |
| Principals, credentials, sessions | ✓ | Suspend/terminate sessions | — | — | — | — | — |
| Create Session Approver accounts | ✓ | — | — | — | — | — | — |
| Secret create / rotate / revoke | ✓ | — | — | — | — | — | — |
| Audit query and redacted export | ✓ | ✓ | ✓ | — | — | ✓ | — |
| Observation analytics (S0/S1) | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| Observation S2 fields | ✓ | — | ✓ | — | — | ✓ | Pseudonymized |
| Payload (S3) access | Separate grant | — | — | — | — | Separate grant | Campaign grant only |
| Baseline promotion / rollback | ✓ | — | ✓ | — | — | — | — |
| Memory budgets, backups, key rotation | ✓ | ✓ | — | — | — | — | — |
| Dataset export | ✓ | — | — | — | — | — | ✓ (approved campaigns) |
| Purge | ✓ | — | — | — | — | — | — |

One person may hold several roles; on a single-user installation the Administrator usually also holds Approver and Session Approver accounts. Each role is a separate account with its own password: the Administrator account itself cannot complete a harness sign-in (FR-2.19, FR-2.23), so the Administrator password is never typed into a harness sign-in page. Harness principals have no control-plane role (SR-2.5-1).

The rows name operations. Control API routes the rows do not name follow these rules (FR-8.2):

- Reads. Health, status and the API description are open to every role, and each role reads and ends its own sign-in session. Policy revisions, filters, servers and the tool catalog, decision explanations and the graph investigation queries are read with the audit journal, by the roles of the audit query row. Sessions, principals and their credentials, secret metadata, package revisions, server instances and egress are operational inventory, read by the Administrator, Operator and Auditor. Every other read route is open to the roles of the row it serves: keys and backups to that row, observation status, catalog, analytics, baselines and anomalies to the observation analytics row, client registrations to the Administrator and Session Approver (the Operator also reads the Remote Access Profile state), approvals to the Administrator and Approver, campaigns to the campaign roles and the Auditor, dataset exports to the Administrator and Researcher, Session Approver accounts to the Administrator.
- Restricting operations. Tightening a tool's classification (SR-3.11-1), killing a server instance and scanning the library (which imports and verifies revisions without enabling them) belong to the Operator's suspend permission. Rebuilding the graph mirror belongs to the memory budgets, backups and key rotation row. Verifying the journal belongs to the audit query row. Building a baseline snapshot and excluding a session from learning belong to the baseline row. Publishing an Audit Profile, Observation Policy or Anomaly Response Policy is publishing policy.
- Everything else is the Administrator's alone, including resuming a suspended session, acknowledging a latched integrity cause (FR-7.13), revoking an approved client registration, and reloading the configuration or the Secret Use Policy.
- Observation S2 fields reach the Operator's records removed (SR-6-3); the Researcher sees them only pseudonymized, in dataset exports (FR-10.33). Release 1.0 stores no payloads (SR-6.6-1), so the Payload (S3) row has no control API operation; S3 fields leave the Gateway only in an export of a campaign with a raw-export grant (SR-6-2).

## Appendix D — Graph data model (mirror)

The graph holds a **mirror** of policy, registry, session and audit records, fed from the Policy Store (D-01) and the Evidence Journal (D-06), and is the system of record only for the behavior model (`BaselineContext`, `FeatureStat`, `BaselineSnapshot`, `AbnormalEvent`) and the Parameter Catalog copy (A-9). Every label has a uniqueness constraint on `id` (FR-9.1). Required-property and cardinality checks are enforced by the Data Access Service, because Community Edition lacks Enterprise existence constraints. The evidence mirror derives `AuditEvent`, `Session`, `Principal`, `Invocation` (keyed by correlation ID), `Decision`, `PolicyRevision`, `PolicyControl`, `ServerRevision`, `ToolRevision` and `Approval` from journal events; `Checkpoint` records the mirror's journal position and the schema version (FR-9.2).

| Node label | Key properties | Owner |
|---|---|---|
| `Principal`, `CredentialRef` | id, frameworkType, enabled, profileId, certThumbprint, expiry, revocationEpoch | E-03, E-22 |
| `Session` | id, principalId, templateId, revisionId, observationPolicyId, contextKey, state, created, expires | E-04 |
| `Server`, `ServerRevision`, `ToolRevision` | id, alias, version, artifactDigest, manifestDigest, state, riskClass, sideEffectClass, era | E-14 |
| `ImportReceipt`, `TrustAnchor` | id, signer, results / fingerprint, scope, expiry | E-13, E-22 |
| `PolicyControl` | activeRevisionId, revocationEpoch, stopEpoch | E-12 |
| `PolicyRevision`, `PolicyObject`, `RuleRevision`, `RouteRevision` | id, parentId, digest, schemaVersion, type, effect, predicates | E-05 |
| `Approval` | id, sessionId, argsDigest, state, expiresAt, approver | E-07 |
| `Decision`, `Invocation` | id, outcome, reasonCode, revisionId, snapshotId, correlationId | E-06, E-12 |
| `AuditEvent`, `PayloadRef`, `OutboxRecord`, `Checkpoint` | id, class, phase, origin, policyStatus / digest, keyRef | E-21 |
| `SecretRef`, `SecretUse` | id, slot, mode, version (no value) | E-19, E-20 |
| `BaselineContext`, `FeatureStat`, `BaselineSnapshot`, `AbnormalEvent` | id, dims / feature, n, mean, m2 / digest, promoted | E-30, E-31 |
| `Parameter`, `CatalogVersion` | id, name, unit, sensitivity, cost | E-05 |
| `Campaign`, `Dataset` | id, state, scope, quota / checksum | E-32 |

| Relationship | From → To |
|---|---|
| `CONTAINS` | PolicyRevision → PolicyObject, RuleRevision, RouteRevision |
| `APPLIES_TO` | RuleRevision → ToolRevision |
| `BELONGS_TO` | ToolRevision → ServerRevision; ServerRevision → Server |
| `SELECTS_ROUTE` | RuleRevision → RouteRevision |
| `REQUIRES_AUDIT`, `REQUIRES_OBSERVATION` | RuleRevision → PolicyObject |
| `EVALUATED_UNDER`, `DECIDED_BY`, `CONSIDERED_RULE`, `APPLICABLE_RULE` | Decision → PolicyRevision / RuleRevision |
| `TARGETED`, `SELECTED_ROUTE` | Decision → ServerRevision / RouteRevision |
| `SCORED_AGAINST` | Decision → BaselineSnapshot |
| `AUTHORIZED_BY` | Invocation → Decision |
| `INVOKED` | Invocation → ToolRevision |
| `FOR_DECISION`, `FOR_INVOCATION`, `OBSERVED_FROM`, `RECORDED_UNDER`, `HAS_EXPORT` | AuditEvent → Decision / Invocation / ServerRevision / PolicyObject or PolicyRevision / OutboxRecord; `FOR_INVOCATION` also Approval → Invocation |
| `IN_SESSION`, `OF_PRINCIPAL` | Decision, Invocation, Approval, AuditEvent, Session → Session, Principal |
| `HAS_CONTEXT`, `HAS_STAT`, `INCLUDES`, `IN_CONTEXT`, `NEXT_TOOL` | Principal/ToolRevision → BaselineContext → FeatureStat; BaselineSnapshot → FeatureStat; AbnormalEvent → BaselineContext; ToolRevision → ToolRevision |
| `USES_SECRET` | SecretUse → SecretRef, Decision |
| `VERIFIED_BY`, `SIGNED_BY` | ServerRevision → ImportReceipt → TrustAnchor |

## Appendix E — Security-control coverage (SEC → SR)

Every requirement of `MCP_Gateway_Security_SRS.md` is listed. A MUST is covered when it has SR children here, is decomposed into child MUSTs in that document, or carries a recorded disposition. SHALL items of that document are covered as sources of FRs.

| SEC ID | Title | Imperative | Coverage | Children / citing requirements |
|---|---|---|---|---|
| 1 | Graph policy and routing authority | MUST | Realized by SR | SR-1-2, SR-1-3 |
| 1.1 | Authoritative graph | MUST | Realized by SR | SR-1.1-1, SR-1.1-2 |
| 1.2 | Graph outage | MUST | Realized by SR | SR-1.2-1, SR-1.2-2 |
| 1.3 | Default denial | MUST | Realized by SR | SR-1.3-1 |
| 1.4 | Deny precedence | MUST | Realized by SR | SR-1.4-1 |
| 1.5 | Admission prerequisites | MUST | Realized by SR | SR-1.5-1 |
| 1.6 | Exact scoped rules | MUST | Deferred | SR-1.6-1 (Appendix N) |
| 1.7 | Typed predicates | MUST | Realized by SR | SR-1.7-1, SR-1.7-2 |
| 1.8 | Argument scope | MUST | Realized by SR | SR-1.8-1, SR-1.8-2, SR-1.8-3, SR-1.8-4, SR-1.8-5 |
| 1.9 | Unambiguous permits | MUST | Realized by SR | SR-1.9-1 |
| 1.10 | Obligation combination | MUST | Realized by SR | SR-1.10-1 |
| 1.11 | Deterministic routing | MUST | Realized by SR | SR-1.11-1 |
| 1.12 | No semantic authorization | MUST | Realized by SR | SR-1.12-1, SR-1.12-2, SR-1.12-3 |
| 1.13 | Fixed query templates | MUST | Realized by SR | SR-1.13-1, SR-1.13-2 |
| 1.14 | Immutable revisions | MUST | Realized by SR | SR-1.14-1 |
| 1.15 | Atomic activation | MUST | Realized by SR | SR-1.15-1 |
| 1.16 | Publication ordering | MUST | Realized by SR | SR-1.16-1 |
| 1.17 | Pre-dispatch and release checks | MUST | Realized by SR | SR-1.17-1, SR-1.17-2 |
| 1.18 | Bound human approval | MUST | Realized by SR | SR-1.18-1, SR-1.18-2, SR-1.18-3 |
| 1.19 | Rule explanation | MUST | Realized by SR | SR-1.19-1 |
| 1.20 | Bounded graph work | MUST | Realized by SR | SR-1.20-1 |
| 2 | Identity and administration separation | MUST | Realized by SR | SR-2-1, SR-2-2 |
| 2.1 | Per-request authentication | MUST | Realized by SR | SR-2.1-1, SR-2.1-2, SR-2.1-3 |
| 2.2 | Distinct client credentials | MUST | Realized by SR | SR-2.2-1 |
| 2.3 | Client-key protection | MUST | Realized by SR | SR-2.3-1, SR-2.3-2 |
| 2.4 | Revocation deadline | MUST | Realized by SR | SR-2.4-1 |
| 2.5 | Admin identity | MUST | Realized by SR | SR-2.5-1 |
| 2.6 | Protected admin session | MUST | Realized by SR | SR-2.6-1 |
| 2.7 | Password verification | MUST | Realized by SR | SR-2.7-1 |
| 2.8 | Authenticated transport | MUST | Realized by SR | SR-2.8-1, SR-2.8-3, SR-2.8-4 |
| 2.9 | Origin and Host | MUST | Realized by SR | SR-2.9-1, SR-2.9-2, SR-2.9-3 |
| 2.10 | Credential separation | MUST | Realized by SR | SR-2.10-1 |
| 2.11 | OAuth boundary | MUST | Realized by SR | SR-2.11-1, SR-2.11-2, SR-2.11-4, SR-2.11-5 |
| 2.12 | State ownership | MUST | Deferred | SR-2.12-1 (Appendix N) |
| 2.13 | Encrypted secrets | MUST | Realized by SR | SR-2.13-1, SR-2.13-2, SR-2.13-3 |
| 2.14 | Minimal backend environment | MUST | Realized by SR | SR-2.14-1 |
| 3 | Source-inspectable server admission | MUST | Realized by SR | SR-3-1, SR-3-2, SR-3-3, SR-3-4, SR-3-5 |
| 3.1 | Source availability | MUST | Realized by SR | SR-3.1-1 |
| 3.2 | Source-to-artifact binding | MUST | Realized by SR | SR-3.2-1 |
| 3.3 | Safe source viewer | MUST | Realized by SR | SR-3.3-1 |
| 3.4 | Dependency inspection | MUST | Realized by SR | SR-3.4-1 |
| 3.5 | Quarantine execution | MUST | Realized by SR | SR-3.5-1 |
| 3.6 | No runtime bootstrap | MUST | Realized by SR | SR-3.6-1 |
| 3.7 | Manifest binding | MUST | Realized by SR | SR-3.7-1 |
| 3.8 | Drift suspension | MUST | Realized by SR | SR-3.8-1 |
| 3.9 | Explicit admission | MUST | Realized by SR | SR-3.9-1 |
| 3.10 | New tools denied | MUST | Realized by SR | SR-3.10-1 |
| 3.11 | Capability classification | MUST | Realized by SR | SR-3.11-1 |
| 3.12 | No administrative tool exposure | MUST | Realized by SR | SR-3.12-1 |
| 3.13 | High-risk candidates | MUST | Realized by SR | SR-3.13-1 |
| 3.14 | Stateful tool admission | MUST | Realized by SR | SR-3.14-1 |
| 4 | Contained local execution | MUST | Realized by SR | SR-4-1 |
| 4.1 | Separate OS identities | MUST | Realized by SR | SR-4.1-1, SR-4.1-2 |
| 4.2 | Private graph access | MUST | Realized by SR | SR-4.2-1, SR-4.2-2 |
| 4.3 | CE access boundary | MUST | Deferred | SR-4.3-1 (Appendix N) |
| 4.4 | Agent network allowlist | MUST | Disposition | Agent-sandbox network policy belongs to the harness deployment outside the SoI. The Security Limitations document (FR-18.2) states that an agent's native network and shell tools bypass the Gateway; the lockdown profiles (FR-15.1) cover MCP configuration only. |
| 4.5 | Backend egress | MUST | Realized by SR | SR-4.5-1, SR-4.5-2 |
| 4.6 | Filesystem authority | MUST | Realized by SR | SR-4.6-1 |
| 4.7 | Host-management exclusion | MUST | Realized by SR | SR-4.7-1, SR-4.7-2 |
| 4.8 | Safe process launch | MUST | Realized by SR | SR-4.8-1 |
| 4.9 | Hermes endpoint | MUST | Realized by SR | SR-4.9-1 |
| 4.10 | Runtime tool guard | MUST | Disposition | Client-side runtime tool guard belongs to the harness. The Gateway supports it with deterministic, manifest-derived catalogs (FR-1.25, FR-1.27) and the Claude Code lockdown profile limits MCP servers to the Gateway (FR-15.2). |
| 4.11 | Protected client configuration | MUST | Realized by SR | SR-4.11-1 |
| 4.12 | Local inference path | MUST | Disposition | Local inference routing belongs to the harness deployment outside the SoI; cloud-hosted models are expected for the supported clients and are stated in the Security Limitations document (FR-18.2). |
| 4.13 | Additional clients | MUST | Realized by SR | SR-4.13-1 |
| 4.14 | Overlay least privilege | MUST | Realized by SR | SR-4.14-1, SR-4.14-2 |
| 5 | Protocol and content boundary | MUST | Decomposed in SEC | SEC 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11, 5.12, 5.13, 5.14, 5.15, 5.16, 5.17, 5.18, 5.19, 5.20 |
| 5.1 | Explicit protocol profiles | MUST | Realized by SR | SR-5.1-1 |
| 5.2 | Header/body agreement | MUST | Realized by SR | SR-5.2-1, SR-5.2-2 |
| 5.3 | No unsafe downgrade | MUST | Realized by SR | SR-5.3-1 |
| 5.4 | Authorized discovery | MUST | Realized by SR | SR-5.4-1 |
| 5.5 | Independent invocation check | MUST | Realized by SR | SR-5.5-1 |
| 5.6 | Unqualified capabilities | MUST | Realized by SR | SR-5.6-1, SR-5.6-2 |
| 5.7 | Private caches | MUST | Realized by SR | SR-5.7-1, SR-5.7-2, SR-5.7-3 |
| 5.8 | Outgoing filtering | MUST | Realized by SR | SR-5.8-1, SR-5.8-2 |
| 5.9 | Incoming filtering | MUST | Realized by SR | SR-5.9-1, SR-5.9-2 |
| 5.10 | Filter failure | MUST | Realized by SR | SR-5.10-1 |
| 5.11 | Buffered release | MUST | Realized by SR | SR-5.11-1 |
| 5.12 | Safe transformation | MUST | Realized by SR | SR-5.12-1 |
| 5.13 | Untrusted content treatment | MUST | Realized by SR | SR-5.13-1, SR-5.13-2 |
| 5.14 | Context-sensitive text checks | MUST | Realized by SR | SR-5.14-1 |
| 5.15 | Connection-time destination checks | MUST | Realized by SR | SR-5.15-1, SR-5.15-2 |
| 5.16 | One-use web authorization | MUST | Realized by SR | SR-5.16-1 |
| 5.17 | Web content execution | MUST | Realized by SR | SR-5.17-1 |
| 5.18 | Uninspected binary content | MUST | Realized by SR | SR-5.18-1, SR-5.18-2 |
| 5.19 | Public-fetch method profile | MUST | Realized by SR | SR-5.19-1 |
| 5.20 | Response conformance | MUST | Realized by SR | SR-5.20-1, SR-5.20-2 |
| 6 | Policy-linked audit integrity and privacy | MUST | Realized by SR | SR-6-1, SR-6-2, SR-6-3 |
| 6.1 | Mandatory security metadata | MUST | Realized by SR | SR-6.1-1 |
| 6.2 | Atomic decision and intent | MUST | Realized by SR | SR-6.2-1 |
| 6.3 | Outcome before release | MUST | Realized by SR | SR-6.3-1 |
| 6.4 | Exact historical links | MUST | Realized by SR | SR-6.4-1 |
| 6.5 | Event origin versus target | MUST | Realized by SR | SR-6.5-1 |
| 6.6 | Policy-directed payload storage | MUST | Deferred | SR-6.6-1 (Appendix N) |
| 6.7 | Secret removal | MUST | Realized by SR | SR-6.7-1 |
| 6.8 | Payload encryption | MUST | Deferred | SR-6.8-1 (Appendix N) |
| 6.9 | Retention conflict | MUST | Deferred | SR-6.9-1 (Appendix N) |
| 6.10 | Idempotent evidence export | MUST | Realized by SR | SR-6.10-1 |
| 6.11 | Export lag boundary | MUST | Realized by SR | SR-6.11-1 |
| 6.12 | Independent tamper evidence | MUST | Realized by SR | SR-6.12-1 |
| 6.13 | Failure evidence spool | MUST | Realized by SR | SR-6.13-1 |
| 6.14 | Historical retention | MUST | Realized by SR | SR-6.14-1 |
| 6.15 | Controlled purge | MUST | Realized by SR | SR-6.15-1 |
| 6.16 | Audit access | MUST | Realized by SR | SR-6.16-1 |
| 6.17 | Inert audit rendering | MUST | Realized by SR | SR-6.17-1 |
| 6.18 | Server-asserted evidence | MUST | Realized by SR | SR-6.18-1 |
| 6.19 | Unevaluated failure evidence | MUST | Realized by SR | SR-6.19-1 |
| 6.20 | Direct decision links | MUST | Realized by SR | SR-6.20-1 |
| 7 | Safe operation and recovery | MUST | Realized by SR | SR-7-1 |
| 7.1 | Transaction retry safety | MUST | Realized by SR | SR-7.1-1 |
| 7.2 | Indeterminate mutation | MUST | Realized by SR | SR-7.2-1 |
| 7.3 | Graph integrity validation | MUST | Realized by SR | SR-7.3-1 |
| 7.4 | Neo4j hardening | MUST | Realized by SR | SR-7.4-1 |
| 7.5 | Secure bootstrap | MUST | Realized by SR | SR-7.5-1, SR-7.5-2 |
| 7.6 | Emergency stop | MUST | Realized by SR | SR-7.6-1, SR-7.6-2 |
| 7.7 | CE-compatible backup | MUST | Realized by SR | SR-7.7-1 |
| 7.8 | Verified restoration | MUST | Realized by SR | SR-7.8-1 |
| 7.9 | Safe rollback | MUST | Realized by SR | SR-7.9-1 |
| 7.10 | Audit capacity | MUST | Realized by SR | SR-7.10-1 |
| 7.11 | Pre-routing bounds | MUST | Realized by SR | SR-7.11-1 |
| 7.12 | Cancellation propagation | MUST | Realized by SR | SR-7.12-1 |
| 8 | Local operator product | SHALL | Source of FR | FR-8 |
| 8.1 | Server lifecycle GUI | SHALL | Disposition | The draft, quarantine and test states are realized before import by the packaging command: `smcpctl package build` is the quarantine probe (SR-3.5-1) and its manifest is the reviewed draft (FR-14.3). Approve is the import with signature verification (SR-3-1), and enable, suspend and retire are the registry states shown and changed in G-10 (FR-5.7, FR-8.18). |
| 8.2 | Policy GUI | SHALL | Source of FR | FR-8.4 |
| 8.3 | Policy graph explanation | SHALL | Source of FR | FR-8.22 |
| 8.4 | Operator graph search | SHALL | Source of FR | FR-7.3 |
| 8.5 | Credential management | SHALL | Source of FR | FR-6.2, FR-6.12, FR-8.20 |
| 8.6 | Filter workbench | SHALL | Source of FR | FR-8.27 |
| 8.7 | Enforcement status | SHALL | Source of FR | FR-8.3 |
| 8.8 | Local UI assets | SHALL | Source of FR | FR-8.25, FR-8.26 |
| 8.9 | GUI request protection | MUST | Realized by SR | SR-8.9-1 |
| 8.10 | Application roles | SHALL | Source of FR | FR-8.2 |
| 9 | Open-source local engineering capabilities | SHALL | Source of FR | FR-12, FR-12.2 |
| 9.1 | Open-source inventory | SHALL | Source of FR | FR-12.1 |
| 9.2 | Community Edition | SHALL | Source of FR | FR-12.11 |
| 9.3 | Local execution | SHALL | Source of FR | FR-12.2 |
| 9.4 | Curated engineering catalog | SHALL | Disposition | The V1 engineering server catalog is replaced by the four reference packages (FR-14.9) and the packaging guide (FR-18.6); further servers are operator-packaged. |
| 9.5 | Initial functions | SHALL | Disposition | Scoped file reading and local repository inspection are provided by the reference filesystem and git packages (FR-14.9). Local document search and tabular analysis are left to operator-packaged servers in v1. |
| 9.6 | Public web exception | SHALL | Source of FR | SR-5.19-1 |
| 9.7 | Conditional client scope | SHALL | Disposition | Realized by the client matrix labels (SR-4.13-1) and the cloud agent records (FR-15.9). |
| 10 | Qualification and versioned baselines | SHALL | Decomposed in SEC | SEC 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9 |
| 10.1 | SRS baseline identity | SHALL | Disposition | Satisfied by the V1 security SRS baseline itself; this SRS carries its own baseline identity in its header. |
| 10.2 | Local version control | SHALL | Disposition | Satisfied by the existing Git tag `mcp-gateway-srs-v1`; this SRS will be tagged on approval. |
| 10.3 | Requirement records | SHALL | Source of FR | FR-12.10 |
| 10.4 | Document authority | SHALL | Disposition | Satisfied by Section 1.4 of this SRS (document authority). |
| 10.5 | Performance qualification | SHALL | Source of FR | FR-11 |
| 10.6 | Acceptance evidence | SHALL | Source of FR | FR-8.34, FR-12.9, FR-12.10, FR-19, FR-19.3, FR-19.4 |
| 10.7 | Release provenance | SHALL | Source of FR | FR-12.8, FR-13.1, FR-13.2 |
| 10.8 | Local security review | SHALL | Disposition | Source review of packaged servers is the operator's decision at packaging (FR-14.3, FR-14.5); Gateway release scanning is covered by FR-12.8. |
| 10.9 | Operator procedures | SHALL | Source of FR | FR-12.7, FR-18, FR-18.4, FR-18.8 |

## Appendix F — Allocation matrix (element → requirements)

Use this matrix to code element by element. A requirement allocated to several elements appears under each.

| Element | Name | Functional (FR) | Security (SR) |
|---|---|---|---|
| E-01 | Harness Interface Endpoint | FR-1, FR-1.1, FR-1.2, FR-1.3, FR-1.41, FR-1.47, FR-1.48, FR-9.17, FR-11, FR-11.5, FR-12, FR-12.1, FR-12.2, FR-12.6, FR-12.8, FR-12.10, FR-15, FR-15.8, FR-15.9, FR-16, FR-16.1, FR-16.2, FR-16.3, FR-16.4, FR-16.6, FR-16.7, FR-16.8, FR-16.11 | SR-2.8-1, SR-2.8-3, SR-2.9-1, SR-2.9-2, SR-2.9-3, SR-4.14-1, SR-4.14-2, SR-7.11-1 |
| E-02 | Protocol Mediator | FR-1, FR-1.4, FR-1.5, FR-1.6, FR-1.7, FR-1.8, FR-1.9, FR-1.10, FR-1.11, FR-1.12, FR-1.13, FR-1.14, FR-1.15, FR-1.16, FR-1.17, FR-1.18, FR-1.19, FR-1.20, FR-1.21, FR-1.22, FR-1.28, FR-1.31, FR-1.32, FR-1.33, FR-1.34, FR-1.35, FR-1.36, FR-1.37, FR-1.38, FR-1.39, FR-1.42, FR-1.43, FR-1.44, FR-1.45, FR-1.46, FR-1.47, FR-1.48, FR-1.51, FR-3.14, FR-3.19, FR-3.21, FR-3.22, FR-3.25, FR-4.1, FR-4.2, FR-5.24, FR-11.5, FR-12.9, FR-18.7, FR-18.9 | SR-2-1, SR-5.1-1, SR-5.2-1, SR-5.2-2, SR-5.3-1, SR-5.6-1, SR-5.11-1 |
| E-03 | Identity & Authentication Service | FR-2, FR-2.1, FR-2.5, FR-2.6, FR-2.15, FR-2.17, FR-2.18, FR-2.23, FR-16, FR-16.3, FR-16.5, FR-16.6 | SR-2.1-1, SR-2.1-2, SR-2.1-3, SR-2.11-1, SR-2.11-2, SR-2.11-5, SR-4.14-2 |
| E-04 | Session Manager | FR-1.48, FR-2, FR-2.2, FR-2.3, FR-2.4, FR-2.6, FR-2.7, FR-2.8, FR-2.9, FR-2.10, FR-2.11, FR-2.12, FR-2.13, FR-2.19, FR-2.20, FR-2.21, FR-2.22, FR-16.12 | SR-2.1-2, SR-2.3-1, SR-2.11-4, SR-5.13-2 |
| E-05 | Policy Administration Service | FR-3, FR-3.1, FR-3.2, FR-3.4, FR-3.5, FR-3.6, FR-3.8, FR-3.9, FR-6.5, FR-6.9, FR-9.17, FR-10.37, FR-18.5 | SR-1-3, SR-1.1-1, SR-1.1-2, SR-1.9-1, SR-1.14-1, SR-1.15-1, SR-3.13-1, SR-7.3-1, SR-7.9-1 |
| E-06 | Policy Decision Service | FR-3, FR-3.10, FR-3.11, FR-3.12, FR-3.13, FR-11, FR-11.2 | SR-1-2, SR-1.1-1, SR-1.1-2, SR-1.2-1, SR-1.3-1, SR-1.4-1, SR-1.5-1, SR-1.7-1, SR-1.7-2, SR-1.10-1, SR-1.11-1, SR-1.12-1, SR-1.12-2, SR-1.12-3, SR-1.15-1, SR-1.18-1, SR-1.19-1, SR-1.20-1, SR-3.10-1, SR-5.12-1, SR-5.13-2 |
| E-07 | Approval Service | FR-3, FR-3.14, FR-3.15, FR-3.16, FR-3.17, FR-3.18, FR-3.19, FR-3.20, FR-3.21, FR-3.22, FR-3.23, FR-3.24, FR-3.25 | SR-1.18-2, SR-1.18-3 |
| E-08 | Access Enforcement Point | FR-1.23, FR-1.24, FR-1.25, FR-1.26, FR-1.27, FR-1.28, FR-1.29, FR-1.30, FR-1.35, FR-1.50, FR-1.52, FR-4, FR-4.1, FR-4.3, FR-11.5 | SR-1.2-1, SR-3.12-1, SR-5.4-1, SR-5.5-1, SR-5.7-1, SR-5.7-2, SR-5.18-2 |
| E-09 | Request Inspection Pipeline | FR-4, FR-4.3, FR-4.4, FR-4.5, FR-4.7, FR-4.15, FR-4.16, FR-4.17, FR-8.27, FR-11.5, FR-19, FR-19.1, FR-19.5 | SR-1.8-1, SR-1.8-2, SR-1.8-3, SR-1.8-4, SR-1.8-5, SR-1.18-3, SR-5.8-1, SR-5.10-1, SR-5.12-1, SR-5.14-1 |
| E-10 | Tool Dispatcher | FR-1.32, FR-1.39, FR-1.40, FR-1.41, FR-1.43, FR-4, FR-4.3, FR-4.8, FR-4.9, FR-4.10, FR-4.13, FR-5, FR-5.13, FR-5.14, FR-5.19, FR-5.20, FR-5.21, FR-5.23, FR-5.24, FR-5.26, FR-5.32, FR-5.40, FR-11.5, FR-12.9 | SR-2.10-1, SR-5.6-2, SR-5.7-3, SR-7.2-1, SR-7.6-2, SR-7.12-1 |
| E-11 | Response Inspection Pipeline | FR-4, FR-4.3, FR-4.4, FR-4.6, FR-4.7, FR-4.11, FR-4.12, FR-4.15, FR-4.16, FR-4.17, FR-4.18, FR-8.27, FR-11.5, FR-19, FR-19.1, FR-19.5 | SR-2-1, SR-5.7-3, SR-5.9-1, SR-5.10-1, SR-5.13-1, SR-5.14-1, SR-5.18-1, SR-5.20-1, SR-5.20-2 |
| E-12 | Enforcement Coordinator | FR-3.20, FR-4, FR-4.3, FR-4.13, FR-4.14, FR-11.5, FR-11.10, FR-18.8 | SR-1.2-2, SR-1.16-1, SR-1.17-1, SR-1.17-2, SR-2.4-1, SR-4.1-1, SR-5.11-1, SR-5.16-1, SR-6.2-1, SR-6.3-1, SR-6.11-1, SR-7.6-1, SR-7.6-2, SR-7.7-1, SR-7.9-1, SR-7.10-1 |
| E-13 | Library Trust Verifier | FR-5, FR-5.1, FR-5.2, FR-5.3, FR-5.4, FR-14, FR-14.1, FR-14.2, FR-14.3, FR-14.4, FR-14.5, FR-14.6, FR-14.7, FR-14.9, FR-14.11, FR-14.12, FR-18.6 | SR-3-1, SR-3-2, SR-3-3, SR-3-4, SR-3-5, SR-3.1-1, SR-3.2-1, SR-3.5-1, SR-5.9-2 |
| E-14 | Local Server Registry | FR-1.26, FR-1.27, FR-1.49, FR-4.16, FR-5, FR-5.5, FR-5.6, FR-5.7, FR-5.8, FR-5.21, FR-5.22, FR-5.39, FR-5.40, FR-14, FR-14.9, FR-19.1, FR-19.5 | SR-3-3, SR-3.4-1, SR-3.7-1, SR-3.8-1, SR-3.9-1, SR-3.11-1, SR-3.14-1, SR-4-1, SR-5.9-2 |
| E-15 | Server Runtime Manager | FR-5, FR-5.9, FR-5.12, FR-5.14, FR-5.15, FR-5.27, FR-5.37, FR-12.3, FR-14.10, FR-19.1 | SR-2.14-1, SR-3-2, SR-3.6-1, SR-3.8-1, SR-4.8-1 |
| E-16 | Execution Sandbox | FR-5, FR-12.3, FR-13.5, FR-19.1 | SR-4.1-2, SR-4.5-1, SR-4.6-1, SR-4.7-1, SR-4.7-2 |
| E-17 | Runtime Monitor | FR-5, FR-5.33, FR-5.34, FR-5.35 | — |
| E-18 | Egress Broker | FR-5, FR-5.36, FR-5.37, FR-5.38, FR-6.6, FR-12.2, FR-19.1 | SR-4.5-1, SR-4.5-2, SR-5.8-2, SR-5.15-1, SR-5.15-2, SR-5.16-1, SR-5.17-1, SR-5.19-1 |
| E-19 | Secret Vault | FR-6, FR-6.1, FR-6.2, FR-6.3, FR-6.4, FR-6.12 | SR-2.13-1, SR-2.13-3, SR-4.1-1 |
| E-20 | Secret Broker | FR-3.1, FR-6, FR-6.6, FR-6.7, FR-6.8, FR-6.9, FR-6.10, FR-6.11 | SR-2-1, SR-2.13-2, SR-2.13-3, SR-7.6-2 |
| E-21 | Audit & Evidence Service | FR-7, FR-7.1, FR-7.2, FR-7.3, FR-7.4, FR-7.5, FR-7.14, FR-9.17, FR-12.7, FR-13.8, FR-16.8, FR-17.7, FR-17.8 | SR-1.2-2, SR-4.1-1, SR-6.1-1, SR-6.2-1, SR-6.3-1, SR-6.4-1, SR-6.5-1, SR-6.7-1, SR-6.10-1, SR-6.11-1, SR-6.12-1, SR-6.13-1, SR-6.15-1, SR-6.16-1, SR-6.18-1, SR-6.19-1, SR-6.20-1, SR-7.7-1 |
| E-22 | Key & Trust Anchor Manager | FR-2.18, FR-7, FR-7.7, FR-7.8, FR-7.10, FR-13, FR-14, FR-14.8, FR-17, FR-17.7 | SR-1.1-2, SR-2.2-1, SR-2.3-1, SR-2.8-4, SR-2.13-1, SR-3-1, SR-6.12-1 |
| E-23 | Health & Safety Monitor | FR-7, FR-7.11, FR-7.12, FR-7.13, FR-12.3, FR-13, FR-13.7, FR-13.9, FR-13.10, FR-13.13, FR-17, FR-17.1, FR-17.2, FR-17.3, FR-17.4, FR-17.5, FR-17.9, FR-19.3 | SR-4-1, SR-6.11-1, SR-7.3-1, SR-7.10-1 |
| E-24 | Management Console & Control API | FR-2.19, FR-2.23, FR-3.1, FR-3.23, FR-3.24, FR-3.25, FR-8, FR-8.1, FR-8.2, FR-8.3, FR-8.4, FR-8.5, FR-8.6, FR-8.7, FR-8.8, FR-8.9, FR-8.10, FR-8.11, FR-8.12, FR-8.13, FR-8.14, FR-8.15, FR-8.16, FR-8.17, FR-8.18, FR-8.19, FR-8.20, FR-8.21, FR-8.22, FR-8.23, FR-8.24, FR-8.25, FR-8.26, FR-8.27, FR-8.28, FR-8.29, FR-8.30, FR-8.31, FR-8.32, FR-8.33, FR-8.34, FR-8.35, FR-11, FR-11.8, FR-12, FR-12.1, FR-12.2, FR-12.4, FR-12.7, FR-12.8, FR-12.10, FR-13, FR-13.1, FR-13.2, FR-13.3, FR-13.4, FR-13.5, FR-13.6, FR-13.7, FR-13.8, FR-13.10, FR-13.11, FR-13.12, FR-13.13, FR-14.10, FR-16.5, FR-16.11, FR-17.9, FR-18, FR-18.1, FR-18.2, FR-18.4, FR-18.8, FR-18.9, FR-19, FR-19.2, FR-19.3, FR-19.4 | SR-1.19-1, SR-2-2, SR-2.5-1, SR-2.6-1, SR-2.7-1, SR-2.8-1, SR-2.9-2, SR-2.9-3, SR-3.3-1, SR-3.4-1, SR-3.9-1, SR-4.1-1, SR-4.14-1, SR-6-3, SR-6.16-1, SR-6.17-1, SR-7.5-1, SR-7.5-2, SR-8.9-1 |
| E-25 | Graph Database Engine | FR-9, FR-9.1, FR-9.18, FR-11.1, FR-12, FR-12.1, FR-12.2, FR-12.8, FR-12.11 | SR-4.1-1, SR-4.2-1, SR-7.4-1 |
| E-26 | Data Access Service | FR-9, FR-9.2, FR-9.3, FR-9.5, FR-9.6, FR-11.1, FR-11.6, FR-11.8 | SR-1.13-1, SR-1.13-2, SR-4.2-1, SR-6-3, SR-6.10-1, SR-7.1-1 |
| E-27 | Observation Store | FR-9, FR-9.7, FR-9.8, FR-9.9, FR-11, FR-11.1, FR-11.6, FR-12, FR-12.1, FR-12.11 | SR-4.2-2 |
| E-28 | Data Lifecycle & Memory Manager | FR-9, FR-9.10, FR-9.11, FR-9.12, FR-9.14, FR-9.15, FR-9.16, FR-11, FR-11.9, FR-12, FR-12.4, FR-12.6, FR-12.7, FR-13, FR-13.7, FR-13.8, FR-17, FR-17.6, FR-18.8 | SR-6.14-1, SR-7.7-1, SR-7.8-1, SR-7.10-1 |
| E-29 | Observation Collector | FR-1.44, FR-1.45, FR-10, FR-10.1, FR-10.2, FR-10.3, FR-10.4, FR-10.5, FR-10.6, FR-10.7, FR-10.8, FR-10.9, FR-10.10, FR-10.11, FR-10.37, FR-11, FR-11.4 | SR-6.7-1 |
| E-30 | Behavior Baseline Engine | FR-10, FR-10.12, FR-10.13, FR-10.14, FR-10.15, FR-10.16, FR-10.17, FR-10.18, FR-10.19, FR-10.20, FR-10.21, FR-11.7 | SR-7-1 |
| E-31 | Anomaly Scorer | FR-4.15, FR-10, FR-10.22, FR-10.23, FR-10.24, FR-10.25, FR-10.26, FR-10.27, FR-10.28, FR-10.29, FR-11, FR-11.3 | SR-1.12-2, SR-7-1 |
| E-32 | Research Dataset Service | FR-3.1, FR-10, FR-10.30, FR-10.31, FR-10.32, FR-10.33, FR-10.34, FR-10.35, FR-10.36, FR-12.4 | SR-6-1, SR-6-2, SR-6.17-1 |
| E-33 | Harness Adapter Kit | FR-1.48, FR-12.12, FR-12.13, FR-15, FR-15.1, FR-15.2, FR-15.3, FR-15.4, FR-15.5, FR-15.6, FR-15.7, FR-15.8, FR-15.9, FR-15.10, FR-16, FR-16.2, FR-16.9, FR-16.10, FR-18, FR-18.2, FR-18.3 | SR-2.3-2, SR-4.9-1, SR-4.11-1, SR-4.13-1 |

## Appendix G — Architecture coverage

### G.1 Functions

| ID | Name | Requirements |
|---|---|---|
| F-01 | Terminate harness transport | FR-1, FR-1.1, FR-1.2, FR-1.3, FR-1.41, FR-1.47, FR-9.17, FR-16, FR-16.1, FR-16.2, FR-16.3, FR-16.4, FR-16.6, FR-16.7, SR-2.8-1, SR-2.8-3, SR-2.9-1, SR-2.9-2, SR-2.9-3, SR-4.14-2, SR-7.11-1, SR-2.8-2 (deferred) |
| F-02 | Validate and normalize MCP messages | FR-1, FR-1.4, FR-1.5, FR-1.8, FR-1.10, FR-1.11, FR-1.16, FR-1.21, FR-1.22, FR-1.28, FR-1.33, FR-1.38, FR-1.44, FR-1.45, FR-1.47, FR-4.1, FR-4.2, FR-18.9, SR-5.2-1, SR-5.2-2, SR-5.6-1 |
| F-03 | Negotiate protocol profile | FR-1, FR-1.9, FR-1.12, FR-1.17, FR-1.46, SR-5.1-1, SR-5.3-1, SR-5.6-1 |
| F-04 | Authenticate framework instance | FR-2, FR-2.1, FR-2.15, FR-2.17, FR-2.18, FR-16.3, FR-16.6, SR-2.1-1, SR-2.1-3, SR-2.11-1, SR-2.11-5, SR-4.14-2, SR-2.11-3 (deferred) |
| F-05 | Verify session proof | FR-2, FR-2.5, SR-2.1-2, SR-2.1-3 |
| F-06 | Establish session | FR-2, FR-2.2, FR-2.3, FR-2.4, FR-2.10, FR-2.19, FR-2.20, FR-16.12, SR-2.3-1 |
| F-07 | Bind Allow policy to session | FR-2, FR-2.4, FR-2.6, FR-2.7, FR-2.12, FR-2.13, FR-2.20, FR-2.21, FR-16.12 |
| F-08 | Maintain session state and expiry | FR-2, FR-2.2, FR-2.8, FR-2.9, FR-2.22, FR-2.16 (deferred) |
| F-09 | Terminate or revoke session | FR-2, FR-2.2, FR-2.11, SR-2.11-4, FR-2.16 (deferred) |
| F-10 | Validate policy revision | FR-3, FR-3.1, FR-3.2, FR-3.8, FR-6.5, FR-6.9, FR-8.4, FR-18.5, SR-1-3, SR-1.9-1, SR-3.13-1, SR-7.3-1, FR-3.26 (deferred), FR-3.3 (deferred), SR-1-1 (deferred), SR-6.9-1 (deferred) |
| F-11 | Simulate policy | FR-3, FR-3.5, FR-3.6, FR-8.4 |
| F-12 | Publish/activate policy revision | FR-3, FR-3.4, FR-3.9, FR-8.4, SR-1.1-2, SR-1.14-1, SR-1.15-1, SR-7.9-1 |
| F-13 | Evaluate access decision | FR-3, FR-3.10, FR-3.11, FR-11.2, SR-1-2, SR-1.1-1, SR-1.1-2, SR-1.2-1, SR-1.3-1, SR-1.4-1, SR-1.5-1, SR-1.7-1, SR-1.7-2, SR-1.11-1, SR-1.12-1, SR-1.12-3, SR-1.15-1, SR-1.20-1, SR-3.10-1, SR-1.6-1 (deferred) |
| F-14 | Compute effective obligations | FR-3, FR-3.11, FR-3.12, FR-3.13, SR-1.10-1, SR-1.11-1, SR-1.12-2, SR-1.18-1, SR-5.13-2 |
| F-15 | Evaluate secret-use decision | FR-3 |
| F-16 | Explain decision | FR-3, SR-1.12-3, SR-1.19-1 |
| F-17 | Request approval | FR-3, FR-3.14, FR-3.18, FR-3.19, FR-3.20, FR-3.22, FR-3.23, FR-3.25, SR-1.18-3 |
| F-18 | Record and consume approval | FR-3, FR-3.15, FR-3.16, FR-3.17, FR-3.20, FR-3.21, FR-3.24, FR-3.25, FR-8.21, SR-1.18-2 |
| F-19 | Present session-scoped catalog | FR-1.23, FR-1.24, FR-1.25, FR-1.26, FR-1.27, FR-1.28, FR-1.35, FR-1.50, FR-1.52, SR-3.12-1, SR-5.4-1, SR-5.7-1, SR-5.7-2, SR-5.18-2 |
| F-20 | Enforce access decision | FR-1.29, FR-1.30, FR-4.3, SR-1.2-1, SR-5.5-1, SR-2.12-1 (deferred) |
| F-21 | Inspect and transform request | FR-4.3, FR-4.4, FR-4.5, FR-4.7, FR-4.15, FR-4.16, FR-4.17, FR-8.27, FR-19, FR-19.1, FR-19.5, SR-1.8-1, SR-1.8-2, SR-1.8-3, SR-1.8-4, SR-1.8-5, SR-1.18-3, SR-5.8-1, SR-5.10-1, SR-5.12-1, SR-5.14-1 |
| F-22 | Serialize released response | FR-1, FR-1.6, FR-1.7, FR-1.13, FR-1.14, FR-1.15, FR-1.18, FR-1.19, FR-1.20, FR-1.31, FR-1.32, FR-1.34, FR-1.35, FR-1.36, FR-1.37, FR-1.39, FR-1.42, FR-1.43, FR-1.51, FR-5.24, FR-18.7, SR-5.11-1, FR-5.25 (deferred) |
| F-23 | Dispatch tool call | FR-4.8, FR-4.13, FR-5.13, FR-5.19, FR-5.32, FR-5.40, SR-2.10-1, SR-5.6-2, FR-5.16 (deferred), FR-5.17 (deferred), FR-5.18 (deferred), FR-5.28 (deferred), FR-5.29 (deferred), SR-5.1-2 (deferred), SR-5.3-2 (deferred) |
| F-24 | Correlate and collect response | FR-1.32, FR-1.39, FR-1.40, FR-4.10, FR-5.13, FR-5.14, FR-5.20, FR-5.21, FR-5.23, FR-5.24, SR-7.2-1, FR-5.25 (deferred), FR-5.28 (deferred), FR-5.30 (deferred), FR-5.31 (deferred) |
| F-25 | Cancel in-flight call | FR-1.41, FR-1.43, FR-4.9, FR-5.26, SR-7.2-1, SR-7.12-1 |
| F-26 | Validate response conformance | SR-5.20-1, SR-5.20-2 |
| F-27 | Inspect and transform response | FR-4.4, FR-4.6, FR-4.7, FR-4.11, FR-4.15, FR-4.16, FR-4.17, FR-4.18, FR-8.27, FR-19, FR-19.1, FR-19.5, SR-5.9-1, SR-5.10-1, SR-5.14-1, SR-5.18-1, SR-2.12-1 (deferred) |
| F-28 | Label provenance | FR-4.12, FR-4.17, FR-4.18, SR-5.13-1 |
| F-29 | Authorize launch under barrier | FR-4.3, FR-4.13, SR-1.2-2, SR-1.16-1, SR-1.17-1, SR-6.2-1, SR-6.11-1, SR-7.10-1 |
| F-30 | Authorize release under barrier | FR-4.3, SR-1.16-1, SR-1.17-2, SR-5.11-1, SR-6.3-1 |
| F-31 | Execute emergency stop | FR-4.14, FR-8.3, FR-11.10, FR-18.8, SR-1.16-1, SR-7.6-1, SR-7.6-2 |
| F-32 | Apply revocation | SR-1.16-1, SR-2.4-1, SR-7.9-1 |
| F-33 | Verify package signature and integrity | FR-5.1, FR-5.2, FR-5.3, FR-5.4, FR-14.7, SR-3-1, SR-3-2, SR-3-5, SR-3.2-1 |
| F-34 | Validate server manifest | FR-1.52, FR-4.16, FR-5.2, FR-14.3, FR-14.4, FR-14.11, FR-19.5, SR-3.1-1, SR-3.2-1, SR-5.9-2 |
| F-35 | Process revocation feed | FR-5.3, FR-14.12, SR-3-3, SR-3-4 |
| F-36 | Maintain verified server inventory | FR-1.49, FR-5.5, FR-5.6, FR-5.7, FR-5.39, FR-14.9, SR-3.7-1, SR-3.9-1, SR-3.11-1, SR-3.14-1, SR-4-1, SR-5.9-2 |
| F-37 | Detect drift and expiry | FR-5.8, FR-5.21, FR-5.22, FR-19.1, SR-3.8-1, FR-5.17 (deferred), FR-5.31 (deferred) |
| F-38 | Instantiate server instance | FR-5.9, FR-5.37, FR-14.10, SR-2.14-1, SR-3-2, SR-3.6-1, SR-4.8-1, FR-5.10 (deferred) |
| F-39 | Supervise lifecycle | FR-5.12, FR-5.15, FR-5.11 (deferred) |
| F-40 | Tear down and sanitize | FR-5.14, FR-5.27, SR-3.8-1, FR-5.11 (deferred) |
| F-41 | Contain server execution | FR-19.1, SR-4.1-2, SR-4.5-1, SR-4.6-1, SR-4.7-1, SR-4.7-2 |
| F-42 | Observe runtime behavior | FR-5.33 |
| F-43 | Detect declared-behavior deviation | FR-5.34 |
| F-44 | Trigger containment response | FR-5.35 |
| F-45 | Authorize and mediate egress | FR-5.36, FR-5.38, FR-19.1, SR-4.5-2, SR-5.8-2, SR-5.15-1, SR-5.15-2, SR-5.16-1, SR-5.17-1, SR-5.19-1 |
| F-46 | Inject credential at egress | FR-6.6, SR-5.8-2 |
| F-47 | Store and protect secrets | FR-6, FR-6.1, FR-6.2, FR-6.12, SR-2.13-1 |
| F-48 | Rotate and retire secrets | FR-6, FR-6.3, FR-6.4 |
| F-49 | Authorize secret use | FR-6, FR-6.11 |
| F-50 | Deliver secret | FR-6, FR-6.6, FR-6.7, FR-6.8, FR-6.9, FR-6.11, SR-2.13-2 |
| F-51 | Register leak fingerprints | FR-6, FR-6.10 |
| F-52 | Revoke secret delivery | FR-6, FR-6.7, FR-6.8, SR-7.6-2 |
| F-53 | Record security event | FR-7.1, FR-7.2, FR-16.8, SR-6.1-1, SR-6.7-1, SR-6.13-1, SR-6.19-1, FR-7.6 (deferred), SR-6.6-1 (deferred), SR-6.8-1 (deferred) |
| F-54 | Link evidence | SR-6.4-1, SR-6.5-1, SR-6.10-1, SR-6.13-1, SR-6.18-1, SR-6.20-1 |
| F-55 | Produce tamper-evident journal | FR-7.4, FR-7.5, FR-7.14, FR-17.7, FR-17.8, SR-1.2-2, SR-6.2-1, SR-6.3-1, SR-6.10-1, SR-6.12-1 |
| F-56 | Enforce retention and purge | SR-6.15-1 |
| F-57 | Serve audit queries | FR-7.3, FR-8.22, FR-11.8, SR-6.16-1 |
| F-58 | Manage trust anchors | FR-7.10, FR-14.8 |
| F-59 | Issue and revoke framework credentials | FR-2.18, FR-7.7, FR-16, FR-16.5, SR-2.2-1, SR-2.3-1, SR-2.11-2, FR-2.14 (deferred), FR-7.15 (deferred) |
| F-60 | Protect Gateway keys | FR-7.7, FR-7.8, FR-17, FR-17.7, SR-2.8-4, SR-2.13-1, FR-7.15 (deferred), FR-7.9 (deferred) |
| F-61 | Monitor enforcement health | FR-7.11, FR-7.12, FR-13.9, FR-13.10, FR-17, FR-17.1, FR-17.2, FR-17.3, FR-17.4, FR-17.5, FR-17.9, FR-19.3, SR-4-1, SR-6.11-1 |
| F-62 | Drive fail-closed state | FR-7.12, FR-7.13, FR-9.17, FR-13.9, FR-13.13, SR-7.3-1 |
| F-63 | Authenticate administrative user | FR-2.19, FR-2.23, FR-8, SR-2.5-1, SR-2.6-1, SR-2.7-1, SR-7.5-1, SR-7.5-2, SR-8.9-1 |
| F-64 | Enforce administrative roles | FR-2.23, FR-8, FR-8.2, SR-2-2, SR-6-3, SR-6.16-1 |
| F-65 | Present management views | FR-8, FR-8.1, FR-8.3, FR-8.4, FR-8.5, FR-8.14, FR-8.17, FR-8.18, FR-8.19, FR-8.20, FR-8.21, FR-8.22, FR-8.23, FR-8.25, FR-8.26, FR-8.27, FR-8.28, FR-8.29, FR-8.30, FR-8.31, FR-8.32, FR-8.33, FR-8.34, FR-8.35, FR-13.10, FR-18, FR-18.4, FR-19.2, FR-19.4, SR-3.3-1, SR-3.4-1, SR-6.17-1 |
| F-66 | Estimate observation cost | FR-8.11, FR-3.7 (deferred) |
| F-67 | Provide parameter-selection workbench | FR-8, FR-8.6, FR-8.7, FR-8.8, FR-8.9, FR-8.10, FR-8.11, FR-8.12, FR-8.24, FR-8.25 |
| F-68 | Present behavior analytics | FR-8, FR-8.13 |
| F-69 | Present performance and resource views | FR-8, FR-8.15, FR-8.16 |
| F-70 | Persist and index graph data | FR-9.1, FR-9.18 |
| F-71 | Execute bounded graph queries and transactions | FR-9.18 |
| F-72 | Authorize and execute typed data operations | FR-9.2, FR-9.3, SR-1.13-1, SR-1.13-2, SR-6-3, SR-7.1-1, SR-4.3-1 (deferred) |
| F-73 | Batch and route writes | FR-9.5, FR-11.6, FR-9.4 (deferred) |
| F-74 | Apply backpressure | FR-9.6 |
| F-75 | Store observation and meta-metric records | FR-9.7, FR-9.8, FR-11.6 |
| F-76 | Serve aggregate queries | FR-9.9, FR-11.8 |
| F-77 | Allocate and enforce memory budgets | FR-9.10, FR-9.11, FR-9.12, FR-11.9 |
| F-78 | Manage storage tiers, retention and quotas | FR-9.14, FR-9.15, SR-6.14-1, SR-7.10-1, FR-9.13 (deferred) |
| F-79 | Schedule and verify backups | FR-9.16, FR-13.7, FR-13.8, FR-17, FR-17.6, FR-18.8, SR-7.7-1, SR-7.8-1 |
| F-80 | Collect raw observables | FR-1.44, FR-1.45, FR-10.1, FR-10.3, FR-11.4 |
| F-81 | Extract features | FR-10.3, FR-10.5 |
| F-82 | Apply sampling, sensitivity and escalation rules | FR-10.4, FR-10.6, FR-10.7, FR-10.8, SR-6.7-1, SR-6.6-1 (deferred) |
| F-83 | Collect meta-metrics | FR-10.2, FR-10.8, FR-10.9, FR-10.10, FR-10.11 |
| F-84 | Update baseline statistics | FR-10.12, FR-10.13, FR-10.14, FR-10.15, FR-10.16, FR-10.17 |
| F-85 | Build baseline snapshot | FR-10.18, FR-11.7 |
| F-86 | Promote or roll back baseline snapshot | FR-8.13, FR-10.20, FR-10.21 |
| F-87 | Detect baseline drift | FR-10.19 |
| F-88 | Score request features | FR-4.15, FR-10.22, FR-10.23, FR-10.24, FR-11.3, SR-7-1 |
| F-89 | Score response features | FR-4.15, FR-10.23, FR-10.24, FR-11.3 |
| F-90 | Classify and emit anomaly obligation | FR-10.25, FR-10.26, FR-10.27, FR-10.28, FR-10.29, SR-1.12-2 |
| F-91 | Manage research capture campaigns | FR-8.17, FR-10.30, FR-10.31 |
| F-92 | Extract and pseudonymize datasets | FR-10.32, FR-10.33, SR-6-1, SR-6-2 |
| F-93 | Export datasets with data dictionary | FR-8.17, FR-10.34, FR-10.35, FR-10.36, SR-6-2, SR-6.17-1 |
| F-94 | Obtain and refresh harness session | FR-12.12, FR-15, FR-15.8, FR-18.3, SR-2.3-2 |
| F-95 | Bridge stdio to the harness interface | FR-12.13, FR-15, FR-15.8, FR-15.9, FR-16, FR-16.9, FR-18.3 |
| F-96 | Build, sign and verify server package | FR-14, FR-14.1, FR-14.2, FR-14.3, FR-14.5, FR-14.6, FR-14.7, FR-14.9, FR-14.10, FR-14.12, FR-18.6, SR-3.5-1 |
| F-97 | Install, upgrade and remove the Gateway | FR-12.4, FR-12.7, FR-13, FR-13.1, FR-13.2, FR-13.3, FR-13.4, FR-13.5, FR-13.6, FR-13.7, FR-13.8, FR-13.11, FR-13.12, FR-13.13, FR-16.11, FR-17.9, FR-18.1, SR-4.14-1, SR-7.5-2, FR-12.5 (deferred) |
| F-98 | Diagnose and lock down harness configuration | FR-15, FR-15.1, FR-15.2, FR-15.3, FR-15.4, FR-15.5, FR-15.6, FR-15.7, FR-15.10, FR-16.10, FR-18, FR-18.2, FR-18.3, SR-4.9-1, SR-4.11-1, SR-4.13-1 |
| F-99 | Track session taint | SR-5.13-2 |

### G.2 External interfaces

| ID | Requirements |
|---|---|
| X-01 | FR-1, FR-1.1, FR-1.2, FR-1.3, FR-1.4, FR-1.5, FR-1.6, FR-1.7, FR-1.8, FR-1.9, FR-1.10, FR-1.11, FR-1.12, FR-1.13, FR-1.14, FR-1.15, FR-1.16, FR-1.17, FR-1.18, FR-1.19, FR-1.20, FR-1.21, FR-1.22, FR-1.23, FR-1.24, FR-1.25, FR-1.26, FR-1.27, FR-1.28, FR-1.29, FR-1.30, FR-1.31, FR-1.32, FR-1.33, FR-1.34, FR-1.35, FR-1.36, FR-1.37, FR-1.38, FR-1.39, FR-1.40, FR-1.41, FR-1.42, FR-1.43, FR-1.44, FR-1.46, FR-1.47, FR-1.48, FR-1.50, FR-1.51, FR-1.52, FR-2.2, FR-2.3, FR-2.4, FR-2.5, FR-2.15, FR-2.17, FR-2.18, FR-2.19, FR-2.20, FR-2.21, FR-2.22, FR-2.23, FR-3.14, FR-3.16, FR-3.19, FR-3.21, FR-3.22, FR-3.25, FR-4.12, FR-12.9, FR-12.12, FR-12.13, FR-15, FR-15.8, SR-2-1, SR-2.1-2, SR-2.8-1, SR-2.9-1, SR-2.9-2, SR-2.11-1, SR-2.11-4, SR-2.11-5, SR-5.2-1, SR-5.2-2, FR-5.25 (deferred), SR-2.8-2 (deferred), SR-2.11-3 (deferred) |
| X-02 | FR-14, FR-14.3, FR-14.5, FR-14.6, FR-14.9, FR-14.12 |
| X-03 | FR-5.1, FR-5.2, FR-5.3, FR-14, FR-14.4, FR-14.11 |
| X-04 | FR-2.19, FR-2.23, FR-8, FR-8.1, FR-8.2, FR-8.3, FR-8.4, FR-8.5, FR-8.6, FR-8.9, FR-8.10, FR-8.11, FR-8.12, FR-8.13, FR-8.14, FR-8.15, FR-8.16, FR-8.17, FR-8.18, FR-8.19, FR-8.20, FR-8.22, FR-8.23, FR-8.24, FR-8.26, FR-8.27, FR-8.28, FR-8.29, FR-8.30, FR-8.31, FR-8.32, FR-8.33, FR-8.34, FR-8.35, FR-16.5, SR-2.5-1, SR-2.8-1, SR-2.9-2 |
| X-05 | FR-3.17, FR-3.18, FR-3.23, FR-3.24, FR-3.25, FR-8.21 |
| X-06 | FR-5.36, FR-5.38, SR-4.5-2, SR-5.15-1 |
| X-07 | FR-12.3, FR-12.4, FR-12.11, FR-13, FR-13.4, FR-13.5, FR-13.6, FR-13.9, FR-13.11, FR-13.12, FR-15.4, SR-4.1-1, SR-4.1-2, SR-4.2-1, SR-4.14-1, SR-7.4-1, FR-7.9 (deferred), FR-12.5 (deferred) |
| X-08 | FR-6.2 |
| X-09 | FR-7.14 |
| X-10 | FR-10.2 |
| X-11 | FR-10.34, FR-10.35, FR-10.36, SR-6-1 |
| X-12 | FR-1.48, FR-12.12, FR-12.13, FR-15, FR-15.1, FR-15.2, FR-15.3, FR-15.6, FR-15.7, FR-15.8, FR-15.10, FR-16.9, FR-18.3, SR-2.3-2, SR-4.9-1, SR-4.11-1, SR-4.13-1 |
| X-13 | FR-15.9, FR-16, FR-16.1, FR-16.2, FR-16.3, FR-16.4, FR-16.5, FR-16.6, FR-16.7, FR-16.8, FR-16.9, FR-16.10, FR-16.11, FR-16.12, FR-18.3, SR-2.11-2, SR-4.14-1, SR-4.14-2 |
| X-14 | FR-3.23 |
| X-15 | FR-17.4, FR-17.5 |
| X-16 | FR-13, FR-13.1, FR-13.2, FR-13.3, FR-13.7 |
| X-17 | FR-14, FR-14.1, FR-14.2, SR-3.5-1 |

### G.3 Internal interfaces

| ID | Requirements |
|---|---|
| I-01 | FR-1.1, FR-1.4 |
| I-02 | FR-2.5, SR-2.1-1, SR-2.1-2 |
| I-03 | FR-1.11, FR-1.23, FR-4.1 |
| I-04 | FR-2.6, SR-2.1-2 |
| I-05 | FR-2.6, FR-2.7, FR-2.12, FR-2.13, SR-1-2, SR-1.5-1 |
| I-06 | FR-2.18, FR-3.1, FR-3.5, FR-3.6, FR-3.8, FR-3.9, FR-4.14, FR-5.6, FR-6.2, FR-6.12, FR-7.3, FR-7.10, FR-7.12, FR-8.1, FR-9.3, FR-10.19, FR-14.8, SR-1.19-1, FR-2.14 (deferred), FR-3.26 (deferred), FR-3.3 (deferred), FR-3.7 (deferred), FR-7.6 (deferred), SR-4.3-1 (deferred) |
| I-07 | FR-1.27, FR-2.1, FR-3.1, FR-3.2, FR-3.10, FR-9.3, SR-1-1 (deferred), SR-4.3-1 (deferred) |
| I-08 | FR-1.29, FR-1.50, FR-3.11, FR-3.12, FR-3.13, SR-1-2 |
| I-09 | SR-5.12-1 |
| I-10 | FR-3.14, FR-3.15, FR-3.20 |
| I-11 | FR-3.20, FR-4.13 |
| I-12 | FR-5.10 (deferred) |
| I-13 | FR-1.39, FR-4.9, FR-4.10, FR-5.13, FR-5.14, FR-5.19, FR-5.20, FR-5.21, FR-5.23, FR-5.24, FR-5.26, FR-5.32, FR-5.40, FR-12.9, SR-2.10-1, FR-5.16 (deferred), FR-5.18 (deferred), FR-5.25 (deferred), FR-5.28 (deferred), FR-5.29 (deferred), FR-5.30 (deferred), FR-5.31 (deferred) |
| I-14 | FR-6.10 |
| I-15 | FR-4.11 |
| I-16 | FR-1.31 |
| I-17 | SR-3-1 |
| I-18 | FR-3.17, FR-4.2, FR-5.34, FR-6.4, FR-6.11, FR-7.1, FR-10.29, SR-5.9-2, SR-6.1-1 |
| I-19 | FR-5.12, FR-5.35, FR-7.13 |
| I-20 | FR-2.11, SR-2.4-1, SR-7.6-2 |
| I-21 | FR-5.4, FR-5.5, FR-5.39, SR-5.9-2 |
| I-22 | FR-5.9, FR-5.37 |
| I-23 | FR-5.9, FR-5.27 |
| I-24 | FR-5.33 |
| I-25 | FR-5.36, SR-4.5-1, SR-5.16-1 |
| I-26 | FR-6.6 |
| I-27 | SR-2.13-3 |
| I-28 | FR-6.7, FR-6.8 |
| I-29 | FR-1.44, FR-1.45, FR-4.2, FR-4.7, FR-5.15, FR-10.1, FR-10.2, FR-10.29 |
| I-30 | FR-7.3, FR-9.3, SR-6.10-1, SR-4.3-1 (deferred) |
| I-31 | FR-4.15, FR-10.7, FR-10.28, SR-1.12-2 |
| I-32 | FR-7.11, FR-9.11, FR-9.12, FR-9.15 |
| I-33 | FR-9.3, FR-9.6, FR-9.4 (deferred), SR-4.3-1 (deferred) |
| I-34 | FR-9.3, FR-10.12, SR-4.3-1 (deferred) |
| I-35 | FR-9.3, FR-10.32, FR-10.33, SR-4.3-1 (deferred) |
| I-36 | FR-9.2, SR-1.13-1, SR-4.2-1 |
| I-37 | FR-9.5, FR-9.9, SR-1.13-1, SR-4.2-2 |
| I-38 | FR-9.6, FR-9.10, FR-9.11, FR-9.12 |
| I-39 | FR-10.20, FR-10.21, FR-10.22, SR-7-1 |

### G.4 Data stores

| ID | Requirements |
|---|---|
| D-01 | FR-2.1, FR-2.18, FR-3.1, FR-3.4, FR-6.5, FR-9.1, FR-9.16, FR-10.30, SR-1.1-1, SR-1.1-2, SR-1.14-1, SR-1.15-1, SR-7.3-1, FR-3.26 (deferred) |
| D-02 | FR-1.49, FR-5.4, FR-5.5, FR-5.7, FR-5.8, FR-9.1, FR-9.16 |
| D-03 | FR-5.39, FR-14.1, SR-3-2 |
| D-04 | FR-6.1, FR-9.16 |
| D-05 | FR-9.1, SR-6.10-1, SR-6.13-1 |
| D-06 | FR-7.4, FR-7.5, FR-7.14, FR-9.16, FR-13.11, FR-13.12, FR-17.8, SR-1.2-2, SR-6.2-1, SR-6.3-1, SR-6.12-1, SR-6.13-1 |
| D-07 | FR-2.8, FR-2.13, FR-2.20, FR-9.1, FR-2.16 (deferred) |
| D-08 | FR-7.7, FR-7.8, FR-9.16, FR-17.7, SR-1.1-2, SR-2.8-4, FR-7.15 (deferred), FR-7.9 (deferred) |
| D-09 | FR-9.7, FR-9.8, FR-9.14, FR-9.13 (deferred) |
| D-10 | FR-9.1, FR-10.13, FR-10.15, FR-10.16, FR-10.18 |
| D-11 | FR-8.6, FR-8.7, FR-8.8, FR-9.1, FR-10.5, FR-10.37 |
| D-12 | FR-9.14, FR-10.35, FR-10.36 |
| D-13 | FR-9.7, FR-10.9, FR-10.11, FR-9.13 (deferred) |
| D-14 | FR-17.1, FR-17.2, FR-17.3 |
| D-15 | FR-9.16, FR-13.11, FR-17.6, SR-7.7-1 |

### G.5 GUI view modules

| ID | Requirements naming the module |
|---|---|
| G-01 | FR-8.3, FR-8.28, FR-8.29, FR-8.31, FR-8.34 |
| G-02 | FR-8.4, FR-8.27 |
| G-03 | FR-8.4, FR-8.5 |
| G-04 | FR-8.4, FR-8.6, FR-8.7, FR-8.8, FR-8.9, FR-8.10, FR-8.11, FR-8.12, FR-8.24 |
| G-05 | FR-8.13 |
| G-06 | FR-8.4, FR-8.14 |
| G-07 | FR-8.15 |
| G-08 | FR-8.16 |
| G-09 | FR-8.4, FR-8.17, FR-10.36 |
| G-10 | FR-8.18, SR-3.3-1, SR-3.4-1 |
| G-11 | FR-2.18, FR-8.19, FR-16.5 |
| G-12 | FR-8.20 |
| G-13 | FR-3.23, FR-3.25, FR-8.21 |
| G-14 | FR-8.22, FR-8.28, FR-8.29, FR-8.34 |

## Appendix H — Requirement index

| ID | Parent | Method | Elements | Title |
|---|---|---|---|---|
| FR-1 | — | Analysis | E-01, E-02 | Northbound MCP server |
| FR-1.1 | FR-1 | Test | E-01 | Harness listeners |
| FR-1.2 | FR-1 | Test | E-01 | Single MCP endpoint |
| FR-1.3 | FR-1 | Test | E-01 | GET and DELETE rejection |
| FR-1.4 | FR-1 | Test | E-02 | Single message per POST |
| FR-1.5 | FR-1 | Test | E-02 | Notification acceptance |
| FR-1.6 | FR-1 | Test | E-02 | Response content type selection |
| FR-1.7 | FR-1 | Test | E-02 | SSE stream conduct |
| FR-1.8 | FR-1 | Test | E-02 | Required request metadata |
| FR-1.9 | FR-1 | Test | E-02 | Unsupported protocol version |
| FR-1.10 | FR-1 | Test | E-02 | Unknown method |
| FR-1.11 | FR-1 | Test | E-02 | Baseline northbound method set |
| FR-1.12 | FR-1 | Test | E-02 | server/discover result |
| FR-1.13 | FR-1 | Test | E-02 | Cacheable result hints |
| FR-1.14 | FR-1 | Test | E-02 | resultType on results |
| FR-1.15 | FR-1 | Inspection | E-02 | Result serverInfo |
| FR-1.16 | FR-1 | Test | E-02 | Legacy session headers ignored |
| FR-1.17 | FR-1 | Test | E-02 | initialize version negotiation |
| FR-1.18 | FR-1 | Test | E-02 | JSON-RPC response conformance |
| FR-1.19 | FR-1 | Inspection | E-02 | Reserved error codes |
| FR-1.20 | FR-1 | Test | E-02 | Gateway error data |
| FR-1.21 | FR-1 | Test | E-02 | Duplicate in-flight request ID |
| FR-1.22 | FR-1 | Test | E-02 | UTF-8 and JSON parsing |
| FR-1.23 | FR-1 | Test | E-08 | tools/list pagination |
| FR-1.24 | FR-1 | Test | E-08 | Invalid cursor |
| FR-1.25 | FR-1 | Test | E-08 | Deterministic tool order |
| FR-1.26 | FR-1 | Test | E-08, E-14 | Public tool names |
| FR-1.27 | FR-1 | Test | E-08, E-14 | Tool definition source |
| FR-1.28 | FR-1 | Test | E-08, E-02 | x-mcp-header removal |
| FR-1.29 | FR-1 | Test | E-08 | tools/call routing |
| FR-1.30 | FR-1 | Test | E-08 | Unknown public tool |
| FR-1.31 | FR-1 | Test | E-02 | Tool result relay |
| FR-1.32 | FR-1 | Test | E-02, E-10 | Backend protocol error mapping |
| FR-1.33 | FR-1 | Test | E-02 | subscriptions/listen support |
| FR-1.34 | FR-1 | Test | E-02 | Subscription acknowledgment ordering |
| FR-1.35 | FR-1 | Test | E-02, E-08 | Tool list change notification |
| FR-1.36 | FR-1 | Test | E-02 | Listen keep-alive |
| FR-1.37 | FR-1 | Test | E-02 | Graceful listen closure |
| FR-1.38 | FR-1 | Test | E-02 | Listen stream limit |
| FR-1.39 | FR-1 | Test | E-10, E-02 | Progress relay |
| FR-1.40 | FR-1 | Test | E-10 | Progress rate bound |
| FR-1.41 | FR-1 | Test | E-01, E-10 | Northbound cancellation detection |
| FR-1.42 | FR-1 | Test | E-02 | No log notifications northbound |
| FR-1.43 | FR-1 | Test | E-10, E-02 | Client deadline |
| FR-1.44 | FR-1 | Test | E-02, E-29 | Trace context handling |
| FR-1.45 | FR-1 | Inspection | E-02, E-29 | Self-asserted clientInfo |
| FR-1.46 | FR-1 | Test | E-02 | Legacy era service |
| FR-1.47 | FR-1 | Test | E-01, E-02 | Unix-domain-socket harness transport |
| FR-1.48 | FR-1 | Inspection | E-01, E-02, E-04, E-33 | Harness interface specification |
| FR-1.49 | FR-1 | Test | E-14 | Public name collisions |
| FR-1.50 | FR-1 | Test | E-08 | Approval hint on presented tools |
| FR-1.51 | FR-1 | Test | E-02 | Plain-language error message |
| FR-1.52 | FR-1 | Test | E-08 | Tool metadata presentation scan |
| FR-2 | — | Analysis | E-03, E-04 | Identity and sessions |
| FR-2.1 | FR-2 | Inspection | E-03 | Principal registry |
| FR-2.2 | FR-2 | Test | E-04 | Session API |
| FR-2.3 | FR-2 | Test | E-04 | Session create request |
| FR-2.4 | FR-2 | Test | E-04 | Session create response |
| FR-2.5 | FR-2 | Test | E-03 | Session token presentation |
| FR-2.6 | FR-2 | Test | E-04, E-03 | Template selection |
| FR-2.7 | FR-2 | Test | E-04 | Claim narrowing |
| FR-2.8 | FR-2 | Test | E-04 | Session state model |
| FR-2.9 | FR-2 | Test | E-04 | Session lifetime |
| FR-2.10 | FR-2 | Test | E-04 | Concurrent session limit |
| FR-2.11 | FR-2 | Test | E-04 | Session termination effects |
| FR-2.12 | FR-2 | Test | E-04 | Revision change handling |
| FR-2.13 | FR-2 | Test | E-04 | Baseline context key |
| FR-2.15 | FR-2 | Test | E-03 | UDS peer mapping |
| FR-2.17 | FR-2 | Test | E-03 | Authorization metadata |
| FR-2.18 | FR-2 | Test | E-03, E-22 | Client registration |
| FR-2.19 | FR-2 | Test | E-04, E-24 | Authorization endpoint |
| FR-2.20 | FR-2 | Test | E-04 | Token endpoint as session creation |
| FR-2.21 | FR-2 | Test | E-04 | Scope mapping |
| FR-2.22 | FR-2 | Test | E-04 | Token refresh |
| FR-2.23 | FR-2 | Test | E-24, E-03 | Session Approver sign-in account |
| FR-3 | — | Analysis | E-05, E-06, E-07 | Policy capability |
| FR-3.1 | FR-3 | Test | E-05, E-20, E-24, E-32 | Policy object types |
| FR-3.2 | FR-3 | Test | E-05 | Policy schema |
| FR-3.4 | FR-3 | Inspection | E-05 | Revision record |
| FR-3.5 | FR-3 | Test | E-05 | Policy simulation |
| FR-3.6 | FR-3 | Test | E-05 | Effective permission report |
| FR-3.8 | FR-3 | Test | E-05 | Policy export and import |
| FR-3.9 | FR-3 | Test | E-05 | Policy rollback |
| FR-3.10 | FR-3 | Test | E-06 | Compiled decision snapshot |
| FR-3.11 | FR-3 | Test | E-06 | Decision record |
| FR-3.12 | FR-3 | Test | E-06 | Obligation types |
| FR-3.13 | FR-3 | Test | E-06 | Rate limit counters |
| FR-3.14 | FR-3 | Test | E-07, E-02 | Approval request creation |
| FR-3.15 | FR-3 | Test | E-07 | Approval consumption on retry |
| FR-3.16 | FR-3 | Test | E-07 | Approval status query |
| FR-3.17 | FR-3 | Test | E-07 | Approver decision |
| FR-3.18 | FR-3 | Inspection | E-07 | Approval evidence display |
| FR-3.19 | FR-3 | Test | E-07, E-02 | Approval hold mode |
| FR-3.20 | FR-3 | Test | E-07, E-12 | Approval during hold |
| FR-3.21 | FR-3 | Test | E-07, E-02 | Denial during hold |
| FR-3.22 | FR-3 | Test | E-07, E-02 | Hold bound fallback |
| FR-3.23 | FR-3 | Test | E-07, E-24 | Approver notification |
| FR-3.24 | FR-3 | Test | E-24, E-07 | Approval CLI |
| FR-3.25 | FR-3 | Demonstration | E-07, E-02, E-24 | Real-harness approval acceptance |
| FR-4 | — | Analysis | E-08, E-09, E-10, E-11, E-12 | Enforcement pipeline |
| FR-4.1 | FR-4 | Test | E-02, E-08 | Canonical request object |
| FR-4.2 | FR-4 | Test | E-02 | Correlation ID |
| FR-4.3 | FR-4 | Test | E-08, E-09, E-10, E-11, E-12 | Stage order |
| FR-4.4 | FR-4 | Inspection | E-09, E-11 | Filter interface |
| FR-4.5 | FR-4 | Test | E-09 | Built-in request filters |
| FR-4.6 | FR-4 | Test | E-11 | Built-in response filters |
| FR-4.7 | FR-4 | Test | E-09, E-11 | Filter findings |
| FR-4.8 | FR-4 | Test | E-10 | Dispatch queue |
| FR-4.9 | FR-4 | Test | E-10 | Upstream execution timeout |
| FR-4.10 | FR-4 | Test | E-10 | Response buffering |
| FR-4.11 | FR-4 | Test | E-11 | Release disposition |
| FR-4.12 | FR-4 | Test | E-11 | Provenance metadata |
| FR-4.13 | FR-4 | Test | E-12, E-10 | Launch capability |
| FR-4.14 | FR-4 | Test | E-12 | Emergency stop control |
| FR-4.15 | FR-4 | Test | E-09, E-11, E-31 | Synchronous scoring integration |
| FR-4.16 | FR-4 | Test | E-09, E-11, E-14 | Versioned detection rule sets |
| FR-4.17 | FR-4 | Test | E-09, E-11 | Injection findings as tags |
| FR-4.18 | FR-4 | Test | E-11 | Untrusted-content delimiting |
| FR-5 | — | Analysis | E-10, E-13, E-14, E-15, E-16, E-17, E-18 | Server trust and execution |
| FR-5.1 | FR-5 | Test | E-13 | Library sources |
| FR-5.2 | FR-5 | Test | E-13 | Package contents |
| FR-5.3 | FR-5 | Test | E-13 | Library polling |
| FR-5.4 | FR-5 | Inspection | E-13 | Import receipt |
| FR-5.5 | FR-5 | Inspection | E-14 | Manifest registration |
| FR-5.6 | FR-5 | Test | E-14 | Server alias |
| FR-5.7 | FR-5 | Test | E-14 | Enablement state |
| FR-5.8 | FR-5 | Test | E-14 | Expiry suspension |
| FR-5.9 | FR-5 | Inspection | E-15 | Launch specification |
| FR-5.12 | FR-5 | Test | E-15 | Crash handling |
| FR-5.13 | FR-5 | Test | E-10 | stdio framing |
| FR-5.14 | FR-5 | Test | E-10, E-15 | Invalid stdout |
| FR-5.15 | FR-5 | Test | E-15 | stderr capture |
| FR-5.19 | FR-5 | Test | E-10 | Legacy southbound handshake |
| FR-5.20 | FR-5 | Test | E-10 | Legacy server-initiated requests |
| FR-5.21 | FR-5 | Test | E-10, E-14 | Startup tool list |
| FR-5.22 | FR-5 | Test | E-14 | Backend tool definition validity |
| FR-5.23 | FR-5 | Test | E-10 | Result type handling |
| FR-5.24 | FR-5 | Test | E-10, E-02 | InputRequiredResult without MRTR profile |
| FR-5.26 | FR-5 | Test | E-10 | Southbound cancellation |
| FR-5.27 | FR-5 | Test | E-15 | Instance shutdown |
| FR-5.32 | FR-5 | Test | E-10 | Southbound progress token |
| FR-5.33 | FR-5 | Test | E-17 | Runtime observables |
| FR-5.34 | FR-5 | Test | E-17 | Declared-behavior rules |
| FR-5.35 | FR-5 | Test | E-17 | Containment actions |
| FR-5.36 | FR-5 | Test | E-18 | Egress endpoints |
| FR-5.37 | FR-5 | Inspection | E-15, E-18 | Egress configuration injection |
| FR-5.38 | FR-5 | Test | E-18 | Egress limits |
| FR-5.39 | FR-5 | Test | E-14 | Artifact cache |
| FR-5.40 | FR-5 | Test | E-10, E-14 | Era agreement with the manifest |
| FR-6 | — | Analysis | E-19, E-20 | Secret management |
| FR-6.1 | FR-6 | Inspection | E-19 | Secret record |
| FR-6.2 | FR-6 | Test | E-19 | Write-only values |
| FR-6.3 | FR-6 | Test | E-19 | Rotation |
| FR-6.4 | FR-6 | Test | E-19 | Retirement zeroization |
| FR-6.5 | FR-6 | Test | E-05 | Secret slot binding |
| FR-6.6 | FR-6 | Test | E-20, E-18 | Delivery mode S1 |
| FR-6.7 | FR-6 | Test | E-20 | Delivery mode S2 |
| FR-6.8 | FR-6 | Test | E-20 | Delivery mode S3 |
| FR-6.9 | FR-6 | Test | E-20, E-05 | Delivery mode S4 |
| FR-6.10 | FR-6 | Test | E-20 | Leak fingerprints |
| FR-6.11 | FR-6 | Test | E-20 | Secret use event |
| FR-6.12 | FR-6 | Test | E-19 | Reference impact preview |
| FR-7 | — | Analysis | E-21, E-22, E-23 | Assurance services |
| FR-7.1 | FR-7 | Inspection | E-21 | Event schema |
| FR-7.2 | FR-7 | Test | E-21 | Event phases |
| FR-7.3 | FR-7 | Test | E-21 | Audit query API |
| FR-7.4 | FR-7 | Inspection | E-21 | Journal segment format |
| FR-7.5 | FR-7 | Test | E-21 | Journal verification |
| FR-7.7 | FR-7 | Inspection | E-22 | Local certificate authorities |
| FR-7.8 | FR-7 | Inspection | E-22 | Key purposes |
| FR-7.10 | FR-7 | Demonstration | E-22 | Trust anchor enrollment |
| FR-7.11 | FR-7 | Test | E-23 | Health checks |
| FR-7.12 | FR-7 | Test | E-23 | Health states |
| FR-7.13 | FR-7 | Test | E-23 | Fail-closed recovery |
| FR-7.14 | FR-7 | Test | E-21 | Evidence export |
| FR-8 | — | Analysis | E-24 | Management product |
| FR-8.1 | FR-8 | Inspection | E-24 | Control API |
| FR-8.2 | FR-8 | Test | E-24 | Application roles |
| FR-8.3 | FR-8 | Demonstration | E-24 | G-01 Gateway Control |
| FR-8.4 | FR-8 | Demonstration | E-24 | G-02 Policy Studio |
| FR-8.5 | FR-8 | Demonstration | E-24 | G-03 Audit Profile Tuning |
| FR-8.6 | FR-8 | Demonstration | E-24 | G-04 Observation & Parameter Workbench |
| FR-8.7 | FR-8 | Test | E-24 | Catalog-driven GUI |
| FR-8.8 | FR-8 | Demonstration | E-24 | Observation presets |
| FR-8.9 | FR-8 | Demonstration | E-24 | Scope builder |
| FR-8.10 | FR-8 | Demonstration | E-24 | Sampling and baseline controls |
| FR-8.11 | FR-8 | Demonstration | E-24 | Cost preview display |
| FR-8.12 | FR-8 | Demonstration | E-24 | Live record preview |
| FR-8.13 | FR-8 | Demonstration | E-24 | G-05 Behavior Analytics |
| FR-8.14 | FR-8 | Demonstration | E-24 | G-06 Anomaly Response Policy |
| FR-8.15 | FR-8 | Demonstration | E-24 | G-07 Performance & Meta-metrics |
| FR-8.16 | FR-8 | Demonstration | E-24 | G-08 Data Server & Memory |
| FR-8.17 | FR-8 | Demonstration | E-24 | G-09 Research Campaigns & Export |
| FR-8.18 | FR-8 | Demonstration | E-24 | G-10 Servers & Library |
| FR-8.19 | FR-8 | Demonstration | E-24 | G-11 Sessions & Principals |
| FR-8.20 | FR-8 | Demonstration | E-24 | G-12 Secrets |
| FR-8.21 | FR-8 | Demonstration | E-24 | G-13 Approvals |
| FR-8.22 | FR-8 | Demonstration | E-24 | G-14 Audit Investigation |
| FR-8.23 | FR-8 | Test | E-24 | Live updates |
| FR-8.24 | FR-8 | Demonstration | E-24 | Usability |
| FR-8.25 | FR-8 | Inspection | E-24 | Inline help |
| FR-8.26 | FR-8 | Test | E-24 | Local assets |
| FR-8.27 | FR-8 | Demonstration | E-24, E-09, E-11 | Filter test workbench |
| FR-8.28 | FR-8 | Test | E-24 | Navigation and deep links |
| FR-8.29 | FR-8 | Test | E-24 | Empty, error and loading states |
| FR-8.30 | FR-8 | Test | E-24 | Supported browsers |
| FR-8.31 | FR-8 | Test | E-24 | First-run checklist |
| FR-8.32 | FR-8 | Test | E-24 | Accessibility conformance |
| FR-8.33 | FR-8 | Test | E-24 | Keyboard operation |
| FR-8.34 | FR-8 | Inspection | E-24 | Per-view acceptance tests |
| FR-8.35 | FR-8 | Inspection | E-24 | Visual rules |
| FR-9 | — | Analysis | E-25, E-26, E-27, E-28 | Data Server |
| FR-9.1 | FR-9 | Inspection | E-25 | Graph data model |
| FR-9.2 | FR-9 | Test | E-26 | Schema migrations |
| FR-9.3 | FR-9 | Inspection | E-26 | Typed operation catalog |
| FR-9.5 | FR-9 | Test | E-26 | Observation batching |
| FR-9.6 | FR-9 | Test | E-26 | Backpressure |
| FR-9.7 | FR-9 | Inspection | E-27 | Observation tables |
| FR-9.8 | FR-9 | Test | E-27 | Schema evolution |
| FR-9.9 | FR-9 | Test | E-27 | Aggregate queries |
| FR-9.10 | FR-9 | Test | E-28 | Memory budget application |
| FR-9.11 | FR-9 | Test | E-28 | Memory accounting |
| FR-9.12 | FR-9 | Test | E-28 | Degradation order |
| FR-9.14 | FR-9 | Test | E-28 | Retention execution |
| FR-9.15 | FR-9 | Test | E-28 | Quota thresholds |
| FR-9.16 | FR-9 | Test | E-28 | Backup scheduling |
| FR-9.17 | FR-9 | Test | E-01, E-05, E-21 | Startup gating |
| FR-9.18 | FR-9 | Inspection | E-25 | Decision and event indexes |
| FR-10 | — | Analysis | E-29, E-30, E-31, E-32 | Observation and analytics |
| FR-10.1 | FR-10 | Test | E-29 | Observable emission |
| FR-10.2 | FR-10 | Test | E-29 | Timing spans |
| FR-10.3 | FR-10 | Test | E-29 | Record assembly |
| FR-10.4 | FR-10 | Test | E-29 | Parameter selection |
| FR-10.5 | FR-10 | Test | E-29 | Feature extraction |
| FR-10.6 | FR-10 | Test | E-29 | Deterministic sampling |
| FR-10.7 | FR-10 | Test | E-29 | Capture escalation |
| FR-10.8 | FR-10 | Test | E-29 | Drop accounting |
| FR-10.9 | FR-10 | Test | E-29 | System meta-metrics |
| FR-10.10 | FR-10 | Test | E-29 | Gateway-added overhead |
| FR-10.11 | FR-10 | Test | E-29 | Policy cost attribution |
| FR-10.12 | FR-10 | Test | E-30 | Context key computation |
| FR-10.13 | FR-10 | Test | E-30 | Streaming statistics |
| FR-10.14 | FR-10 | Test | E-30 | Feature transforms |
| FR-10.15 | FR-10 | Test | E-30 | Robust statistics option |
| FR-10.16 | FR-10 | Test | E-30 | Categorical and sequence features |
| FR-10.17 | FR-10 | Test | E-30 | Learning exclusions |
| FR-10.18 | FR-10 | Test | E-30 | Snapshot build |
| FR-10.19 | FR-10 | Test | E-30 | Drift report |
| FR-10.20 | FR-10 | Test | E-30 | Promotion |
| FR-10.21 | FR-10 | Test | E-30 | Rollback |
| FR-10.22 | FR-10 | Test | E-31 | Snapshot loading |
| FR-10.23 | FR-10 | Test | E-31 | z-score computation |
| FR-10.24 | FR-10 | Test | E-31 | Robust score |
| FR-10.25 | FR-10 | Test | E-31 | Score combination |
| FR-10.26 | FR-10 | Test | E-31 | Band classification |
| FR-10.27 | FR-10 | Test | E-31 | Uncharacterized context |
| FR-10.28 | FR-10 | Test | E-31 | Asynchronous scoring |
| FR-10.29 | FR-10 | Inspection | E-31 | Scoring record |
| FR-10.30 | FR-10 | Test | E-32 | Campaign record |
| FR-10.31 | FR-10 | Test | E-32 | Campaign activation |
| FR-10.32 | FR-10 | Test | E-32 | Dataset extraction |
| FR-10.33 | FR-10 | Test | E-32 | Pseudonymization |
| FR-10.34 | FR-10 | Test | E-32 | Export formats |
| FR-10.35 | FR-10 | Inspection | E-32 | Dataset manifest |
| FR-10.36 | FR-10 | Test | E-32 | Export destination |
| FR-10.37 | FR-10 | Inspection | E-29, E-05 | Parameter Catalog content |
| FR-11 | — | Analysis | E-01, E-06, E-29, E-31, E-27, E-24, E-28 | Performance |
| FR-11.1 | FR-11 | Inspection | E-25, E-26, E-27 | Reference workload |
| FR-11.2 | FR-11 | Test | E-06 | Decision latency |
| FR-11.3 | FR-11 | Test | E-31 | Scoring latency |
| FR-11.4 | FR-11 | Test | E-29 | Capture overhead |
| FR-11.5 | FR-11 | Test | E-01, E-02, E-08, E-09, E-10, E-11, E-12 | Total overhead |
| FR-11.6 | FR-11 | Test | E-27, E-26 | Observation ingest |
| FR-11.7 | FR-11 | Test | E-30 | Snapshot build time |
| FR-11.8 | FR-11 | Test | E-24, E-26 | GUI query latency |
| FR-11.9 | FR-11 | Test | E-28 | Idle footprint |
| FR-11.10 | FR-11 | Test | E-12 | Stop latency |
| FR-12 | — | Analysis | E-01, E-24, E-25, E-27, E-28 | Implementation constraints |
| FR-12.1 | FR-12 | Inspection | E-01, E-24, E-25, E-27 | Open-source components |
| FR-12.2 | FR-12 | Test | E-01, E-18, E-24, E-25 | No external service dependency |
| FR-12.3 | FR-12 | Demonstration | E-15, E-16, E-23 | Host platform |
| FR-12.4 | FR-12 | Inspection | E-28, E-32, E-24 | Filesystem layout |
| FR-12.6 | FR-12 | Test | E-01, E-28 | Configuration file |
| FR-12.7 | FR-12 | Demonstration | E-24, E-28, E-21 | Administrative CLI |
| FR-12.8 | FR-12 | Inspection | E-01, E-24, E-25 | Release provenance |
| FR-12.9 | FR-12 | Inspection | E-02, E-10 | MCP conformance suite |
| FR-12.10 | FR-12 | Inspection | E-01, E-24 | Requirement-tagged tests |
| FR-12.11 | FR-12 | Inspection | E-25, E-27 | No paid database features |
| FR-12.12 | FR-12 | Demonstration | E-33 | Session helper adapter |
| FR-12.13 | FR-12 | Test | E-33 | Stdio bridge adapter |
| FR-13 | — | Analysis | E-24, E-22, E-23, E-28 | Installation lifecycle |
| FR-13.1 | FR-13 | Inspection | E-24 | Release archives |
| FR-13.2 | FR-13 | Test | E-24 | Installer verification |
| FR-13.3 | FR-13 | Test | E-24 | Homebrew formula |
| FR-13.4 | FR-13 | Test | E-24 | Idempotent install |
| FR-13.5 | FR-13 | Test | E-24, E-16 | Enforced profile installation |
| FR-13.6 | FR-13 | Test | E-24 | Standalone profile installation |
| FR-13.7 | FR-13 | Test | E-24, E-28, E-23 | Upgrade procedure |
| FR-13.8 | FR-13 | Test | E-24, E-28, E-21 | Upgrade rollback |
| FR-13.9 | FR-13 | Test | E-23 | No silent profile downgrade |
| FR-13.10 | FR-13 | Test | E-23, E-24 | Standalone labelling |
| FR-13.11 | FR-13 | Test | E-24 | Uninstall |
| FR-13.12 | FR-13 | Test | E-24 | Purge |
| FR-13.13 | FR-13 | Test | E-23, E-24 | Configuration schema version |
| FR-14 | — | Analysis | E-13, E-14, E-22 | Operator self-curation |
| FR-14.1 | FR-14 | Test | E-13 | Package build |
| FR-14.2 | FR-14 | Test | E-13 | Pinned references only |
| FR-14.3 | FR-14 | Test | E-13 | Manifest from live tool list |
| FR-14.4 | FR-14 | Test | E-13 | Local servers only |
| FR-14.5 | FR-14 | Inspection | E-13 | Provenance statement |
| FR-14.6 | FR-14 | Test | E-13 | Package signing |
| FR-14.7 | FR-14 | Test | E-13 | Offline package verification |
| FR-14.8 | FR-14 | Test | E-22 | Operator key as a scoped trust anchor |
| FR-14.9 | FR-14 | Test | E-13, E-14 | Reference packages |
| FR-14.10 | FR-14 | Inspection | E-24, E-15 | Bootstrap uses a packaged server |
| FR-14.11 | FR-14 | Test | E-13 | Manifest schema |
| FR-14.12 | FR-14 | Test | E-13 | Revocation entries |
| FR-15 | — | Analysis | E-33, E-01 | Harness integration |
| FR-15.1 | FR-15 | Test | E-33 | Lockdown profiles |
| FR-15.2 | FR-15 | Test | E-33 | Claude Code lockdown profile |
| FR-15.3 | FR-15 | Test | E-33 | Doctor: MCP server inventory |
| FR-15.4 | FR-15 | Test | E-33 | Doctor: readable paths |
| FR-15.5 | FR-15 | Test | E-33 | Doctor output |
| FR-15.6 | FR-15 | Test | E-33 | Reversible lockdown |
| FR-15.7 | FR-15 | Test | E-33 | Per-client CA trust setup |
| FR-15.8 | FR-15 | Test | E-33, E-01 | Client matrix regression |
| FR-15.9 | FR-15 | Inspection | E-33, E-01 | Cloud agent matrix record |
| FR-15.10 | FR-15 | Inspection | E-33 | Pinned client matrix file |
| FR-16 | — | Analysis | E-01, E-03, E-33 | Remote Access Profile |
| FR-16.1 | FR-16 | Test | E-01 | Remote listener |
| FR-16.2 | FR-16 | Demonstration | E-01, E-33 | Tunnel providers |
| FR-16.3 | FR-16 | Test | E-01, E-03 | Public name binding |
| FR-16.4 | FR-16 | Test | E-01 | Remote endpoint set |
| FR-16.5 | FR-16 | Test | E-03, E-24 | Operator-approved dynamic registration |
| FR-16.6 | FR-16 | Test | E-01, E-03 | Remote rate limits and lockout |
| FR-16.7 | FR-16 | Test | E-01 | Remote request bounds |
| FR-16.8 | FR-16 | Test | E-21, E-01 | Remote origin evidence |
| FR-16.9 | FR-16 | Test | E-33 | smcp-connect relay |
| FR-16.10 | FR-16 | Inspection | E-33 | Vendor allowlist guidance |
| FR-16.11 | FR-16 | Test | E-24, E-01 | Disabled by default |
| FR-16.12 | FR-16 | Test | E-04 | Remote session limits |
| FR-17 | — | Analysis | E-23, E-22, E-28 | Operations |
| FR-17.1 | FR-17 | Test | E-23 | Diagnostic log |
| FR-17.2 | FR-17 | Test | E-23 | Diagnostic log rotation |
| FR-17.3 | FR-17 | Test | E-23 | Diagnostic log content limits |
| FR-17.4 | FR-17 | Test | E-23 | Metrics endpoint |
| FR-17.5 | FR-17 | Inspection | E-23 | Metric set and labels |
| FR-17.6 | FR-17 | Test | E-28 | Encrypted backups |
| FR-17.7 | FR-17 | Test | E-22, E-21 | Key rotation |
| FR-17.8 | FR-17 | Test | E-21 | Verification across key transitions |
| FR-17.9 | FR-17 | Test | E-23, E-24 | Configuration reload |
| FR-18 | — | Analysis | E-24, E-33 | Documentation set |
| FR-18.1 | FR-18 | Inspection | E-24 | Install guide |
| FR-18.2 | FR-18 | Inspection | E-24, E-33 | Security Limitations |
| FR-18.3 | FR-18 | Inspection | E-33 | Per-client quick starts |
| FR-18.4 | FR-18 | Inspection | E-24 | Operator guide |
| FR-18.5 | FR-18 | Test | E-05 | Policy reference |
| FR-18.6 | FR-18 | Inspection | E-13 | Packaging guide |
| FR-18.7 | FR-18 | Test | E-02 | Troubleshooting and reason codes |
| FR-18.8 | FR-18 | Inspection | E-24, E-28, E-12 | Tested runbooks |
| FR-18.9 | FR-18 | Inspection | E-24, E-02 | Scope statement |
| FR-19 | — | Analysis | E-24, E-11, E-09 | Verification evidence |
| FR-19.1 | FR-19 | Test | E-11, E-09, E-14, E-15, E-16, E-18 | Hostile backend fixture suite |
| FR-19.2 | FR-19 | Inspection | E-24 | Hostile suite results |
| FR-19.3 | FR-19 | Inspection | E-24, E-23 | Enforced label gating |
| FR-19.4 | FR-19 | Inspection | E-24 | Acceptance scenario records |
| FR-19.5 | FR-19 | Test | E-09, E-11, E-14 | Labelled detection corpora |
| SR-1-2 | SEC-1 | Test | E-06 | Layer intersection |
| SR-1-3 | SEC-1 | Test | E-05 | Template within profile |
| SR-1.1-1 | SEC-1.1 | Inspection | E-06, E-05 | Single policy source |
| SR-1.1-2 | SEC-1.1 | Test | E-05, E-06, E-22 | Signed policy revisions |
| SR-1.2-1 | SEC-1.2 | Test | E-06, E-08 | Snapshot unavailability denial |
| SR-1.2-2 | SEC-1.2 | Test | E-12, E-21 | Data Server outage |
| SR-1.3-1 | SEC-1.3 | Test | E-06 | Default deny |
| SR-1.4-1 | SEC-1.4 | Test | E-06 | Deny precedence |
| SR-1.5-1 | SEC-1.5 | Test | E-06 | Prerequisite checks |
| SR-1.7-1 | SEC-1.7 | Test | E-06 | Predicate operator set |
| SR-1.7-2 | SEC-1.7 | Test | E-06 | Missing attribute denial |
| SR-1.8-1 | SEC-1.8 | Test | E-09 | Argument schema validation |
| SR-1.8-2 | SEC-1.8 | Test | E-09 | Schema dialect handling |
| SR-1.8-3 | SEC-1.8 | Test | E-09 | Schema resource bounds |
| SR-1.8-4 | SEC-1.8 | Test | E-09 | Path canonicalization |
| SR-1.8-5 | SEC-1.8 | Test | E-09 | URL canonicalization |
| SR-1.9-1 | SEC-1.9 | Test | E-05 | Overlap rejection |
| SR-1.10-1 | SEC-1.10 | Test | E-06 | Obligation precedence |
| SR-1.11-1 | SEC-1.11 | Test | E-06 | Single route |
| SR-1.12-1 | SEC-1.12 | Inspection | E-06 | No semantic authorization |
| SR-1.12-2 | SEC-1.12 | Test | E-06, E-31 | Restrict-only anomaly effect |
| SR-1.12-3 | SEC-1.12 | Inspection | E-06 | Snapshot recording |
| SR-1.13-1 | SEC-1.13 | Test | E-26 | Fixed query templates |
| SR-1.13-2 | SEC-1.13 | Test | E-26 | Template integrity |
| SR-1.14-1 | SEC-1.14 | Test | E-05 | Immutable revisions |
| SR-1.15-1 | SEC-1.15 | Test | E-05, E-06 | Atomic activation |
| SR-1.16-1 | SEC-1.16 | Test | E-12 | Coordinator serialization |
| SR-1.17-1 | SEC-1.17 | Test | E-12 | Pre-launch recheck |
| SR-1.17-2 | SEC-1.17 | Test | E-12 | Pre-release recheck |
| SR-1.18-1 | SEC-1.18 | Test | E-06 | Approval floor |
| SR-1.18-2 | SEC-1.18 | Test | E-07 | Approval binding |
| SR-1.18-3 | SEC-1.18 | Test | E-07, E-09 | Approval after transformation |
| SR-1.19-1 | SEC-1.19 | Test | E-06, E-24 | Decision explanation API |
| SR-1.20-1 | SEC-1.20 | Test | E-06 | Evaluation bounds |
| SR-2-1 | SEC-2 | Test | E-02, E-11, E-20 | Secrets never northbound |
| SR-2-2 | SEC-2 | Test | E-24 | Researcher role limits |
| SR-2.1-1 | SEC-2.1 | Test | E-03 | Verified principal derivation |
| SR-2.1-2 | SEC-2.1 | Test | E-03, E-04 | Session token binding |
| SR-2.1-3 | SEC-2.1 | Test | E-03 | Per-request authentication |
| SR-2.2-1 | SEC-2.2 | Test | E-22 | Independent credentials |
| SR-2.3-1 | SEC-2.3 | Inspection | E-22, E-04 | Bearer key generation |
| SR-2.3-2 | SEC-2.3 | Test | E-33 | Adapter credential storage |
| SR-2.4-1 | SEC-2.4 | Test | E-12 | Revocation latency |
| SR-2.5-1 | SEC-2.5 | Test | E-24 | Admin endpoint separation |
| SR-2.6-1 | SEC-2.6 | Test | E-24 | Admin session profile |
| SR-2.7-1 | SEC-2.7 | Inspection | E-24 | Password hashing |
| SR-2.8-1 | SEC-2.8 | Test | E-01, E-24 | TLS profile |
| SR-2.8-3 | SEC-2.8 | Inspection | E-01 | UDS permissions |
| SR-2.9-1 | SEC-2.9 | Test | E-01 | Origin validation |
| SR-2.9-2 | SEC-2.9 | Test | E-01, E-24 | Host validation |
| SR-2.9-3 | SEC-2.9 | Inspection | E-01, E-24 | Loopback binding |
| SR-2.8-4 | SEC-2.8 | Test | E-22 | Local CA constraints |
| SR-2.10-1 | SEC-2.10 | Test | E-10 | Credential separation |
| SR-2.11-1 | SEC-2.11 | Test | E-03 | OAuth token validation |
| SR-2.11-2 | SEC-2.11 | Test | E-03 | Dynamic registration approval |
| SR-2.11-4 | SEC-2.11 | Test | E-04 | Refresh token reuse |
| SR-2.11-5 | SEC-2.11 | Test | E-03 | Truthful authorization metadata |
| SR-2.13-1 | SEC-2.13 | Inspection | E-19, E-22 | Vault encryption |
| SR-2.13-2 | SEC-2.13 | Inspection | E-20 | Plaintext lifetime |
| SR-2.13-3 | SEC-2.13 | Test | E-19, E-20 | Vault isolation |
| SR-2.14-1 | SEC-2.14 | Inspection | E-15 | Backend environment allowlist |
| SR-3-1 | SEC-3 | Test | E-13, E-22 | Signature verification |
| SR-3-2 | SEC-3 | Test | E-13, E-15 | Artifact digest verification |
| SR-3-3 | SEC-3 | Test | E-13, E-14 | Revocation processing |
| SR-3-4 | SEC-3 | Test | E-13 | Revocation feed staleness |
| SR-3-5 | SEC-3 | Test | E-13 | Rollback protection |
| SR-3.1-1 | SEC-3.1 | Test | E-13 | Source evidence presence |
| SR-3.2-1 | SEC-3.2 | Test | E-13 | Provenance binding |
| SR-3.3-1 | SEC-3.3 | Test | E-24 | Inert evidence display |
| SR-3.4-1 | SEC-3.4 | Demonstration | E-24, E-14 | Dependency visibility |
| SR-3.5-1 | SEC-3.5 | Test | E-13 | Packaging probe isolation |
| SR-3.6-1 | SEC-3.6 | Test | E-15 | No runtime bootstrap |
| SR-3.7-1 | SEC-3.7 | Inspection | E-14 | Manifest digest binding |
| SR-3.8-1 | SEC-3.8 | Test | E-14, E-15 | Runtime drift suspension |
| SR-3.9-1 | SEC-3.9 | Test | E-14, E-24 | Explicit enablement |
| SR-3.10-1 | SEC-3.10 | Test | E-06 | New tools denied |
| SR-3.11-1 | SEC-3.11 | Test | E-14 | Classification retention |
| SR-3.12-1 | SEC-3.12 | Test | E-08 | No administrative tools |
| SR-3.13-1 | SEC-3.13 | Test | E-05 | High-risk grants |
| SR-3.14-1 | SEC-3.14 | Test | E-14 | Stateful tool contract |
| SR-4.1-1 | SEC-4.1 | Inspection | E-12, E-25, E-19, E-21, E-24 | Service identities |
| SR-4-1 | SEC-4 | Test | E-14, E-23 | Standalone profile restrictions |
| SR-4.1-2 | SEC-4.1 | Inspection | E-16 | Instance identities |
| SR-4.2-1 | SEC-4.2 | Test | E-25, E-26 | Private database listeners |
| SR-4.2-2 | SEC-4.2 | Inspection | E-27 | Observation file protection |
| SR-4.9-1 | SEC-4.9 | Test | E-33 | Single MCP endpoint per locked-down client |
| SR-4.11-1 | SEC-4.11 | Test | E-33 | Protected client configuration |
| SR-4.13-1 | SEC-4.13 | Inspection | E-33 | Exclusive-gateway label |
| SR-4.5-1 | SEC-4.5 | Test | E-16, E-18 | Sandbox network isolation |
| SR-4.5-2 | SEC-4.5 | Test | E-18 | Per-call egress grant |
| SR-4.6-1 | SEC-4.6 | Test | E-16 | Mount restriction |
| SR-4.7-1 | SEC-4.7 | Inspection | E-16 | Host exclusion |
| SR-4.7-2 | SEC-4.7 | Test | E-16 | Resource limits |
| SR-4.8-1 | SEC-4.8 | Inspection | E-15 | No shell launch |
| SR-4.14-1 | SEC-4.14 | Test | E-01, E-24 | Remote Access host rules |
| SR-4.14-2 | SEC-4.14 | Test | E-01, E-03 | Remote authentication |
| SR-5.1-1 | SEC-5.1 | Inspection | E-02 | Profile separation |
| SR-5.2-1 | SEC-5.2 | Test | E-02 | Header/body agreement |
| SR-5.2-2 | SEC-5.2 | Test | E-02 | Required headers |
| SR-5.3-1 | SEC-5.3 | Test | E-02 | No northbound downgrade |
| SR-5.4-1 | SEC-5.4 | Test | E-08 | Authorized discovery |
| SR-5.5-1 | SEC-5.5 | Test | E-08 | Independent call authorization |
| SR-5.6-1 | SEC-5.6 | Test | E-02 | Unqualified features rejected |
| SR-5.6-2 | SEC-5.6 | Inspection | E-10 | No southbound client capabilities |
| SR-5.7-1 | SEC-5.7 | Test | E-08 | Private caches |
| SR-5.7-2 | SEC-5.7 | Test | E-08 | Cursor integrity |
| SR-5.7-3 | SEC-5.7 | Inspection | E-10, E-11 | No result caching |
| SR-5.8-1 | SEC-5.8 | Test | E-09 | Outbound argument filtering |
| SR-5.8-2 | SEC-5.8 | Test | E-18 | Egress content filtering |
| SR-5.9-1 | SEC-5.9 | Test | E-11 | Response surfaces |
| SR-5.9-2 | SEC-5.9 | Test | E-13, E-14 | Tool metadata scanning |
| SR-5.10-1 | SEC-5.10 | Test | E-09, E-11 | Filter failure |
| SR-5.11-1 | SEC-5.11 | Test | E-02, E-12 | No partial release |
| SR-5.12-1 | SEC-5.12 | Test | E-09, E-06 | Re-authorization after transformation |
| SR-5.13-1 | SEC-5.13 | Inspection | E-11 | Untrusted labeling |
| SR-5.13-2 | SEC-5.13 | Test | E-04, E-06 | Session taint |
| SR-5.14-1 | SEC-5.14 | Test | E-09, E-11 | Unicode corpus |
| SR-5.15-1 | SEC-5.15 | Test | E-18 | Connection-time resolution |
| SR-5.15-2 | SEC-5.15 | Test | E-18 | Reserved address denial |
| SR-5.16-1 | SEC-5.16 | Test | E-18, E-12 | One-use egress capability |
| SR-5.17-1 | SEC-5.17 | Test | E-18 | No ambient cookies |
| SR-5.18-1 | SEC-5.18 | Test | E-11 | Binary content gate |
| SR-5.18-2 | SEC-5.18 | Test | E-08 | Icon handling |
| SR-5.19-1 | SEC-5.19 | Test | E-18 | Public-fetch method profile |
| SR-5.20-1 | SEC-5.20 | Test | E-11 | Response envelope validation |
| SR-5.20-2 | SEC-5.20 | Test | E-11 | Output schema validation |
| SR-6-1 | SEC-6 | Test | E-32 | Research pseudonymization required |
| SR-6-2 | SEC-6 | Test | E-32 | S3 export grant |
| SR-6-3 | SEC-6 | Test | E-26, E-24 | Observation access control |
| SR-6.1-1 | SEC-6.1 | Test | E-21 | Mandatory event floor |
| SR-6.2-1 | SEC-6.2 | Test | E-12, E-21 | Atomic intent commit |
| SR-6.3-1 | SEC-6.3 | Test | E-12, E-21 | Outcome before release |
| SR-6.4-1 | SEC-6.4 | Inspection | E-21 | Exact links |
| SR-6.5-1 | SEC-6.5 | Test | E-21 | Origin attribution |
| SR-6.7-1 | SEC-6.7 | Test | E-21, E-29 | Secret scrubbing |
| SR-6.10-1 | SEC-6.10 | Test | E-21, E-26 | Idempotent export |
| SR-6.11-1 | SEC-6.11 | Test | E-12, E-21, E-23 | Export lag stop |
| SR-6.12-1 | SEC-6.12 | Test | E-21, E-22 | Signing key custody |
| SR-6.13-1 | SEC-6.13 | Test | E-21 | Failure spool |
| SR-6.14-1 | SEC-6.14 | Test | E-28 | Referenced version retention |
| SR-6.15-1 | SEC-6.15 | Test | E-21 | Purge receipt |
| SR-6.16-1 | SEC-6.16 | Test | E-21, E-24 | Audit authorization |
| SR-6.17-1 | SEC-6.17 | Test | E-24, E-32 | Inert rendering |
| SR-6.18-1 | SEC-6.18 | Inspection | E-21 | Server-asserted label |
| SR-6.19-1 | SEC-6.19 | Test | E-21 | Unevaluated status |
| SR-6.20-1 | SEC-6.20 | Test | E-21 | Direct decision link |
| SR-7-1 | SEC-7 | Test | E-31, E-30 | Baseline integrity |
| SR-7.1-1 | SEC-7.1 | Inspection | E-26 | No side effects in retryable transactions |
| SR-7.2-1 | SEC-7.2 | Test | E-10 | Indeterminate outcomes |
| SR-7.3-1 | SEC-7.3 | Test | E-05, E-23 | Integrity validation |
| SR-7.4-1 | SEC-7.4 | Inspection | E-25 | Graph engine hardening |
| SR-7.5-1 | SEC-7.5 | Test | E-24 | Secure bootstrap |
| SR-7.5-2 | SEC-7.5 | Test | E-24 | No secrets on the command line |
| SR-7.6-1 | SEC-7.6 | Test | E-12 | Emergency stop serialization |
| SR-7.6-2 | SEC-7.6 | Test | E-12, E-10, E-20 | Stop cancellation |
| SR-7.7-1 | SEC-7.7 | Test | E-28, E-12, E-21 | Offline backup procedure |
| SR-7.8-1 | SEC-7.8 | Test | E-28 | Restore verification |
| SR-7.9-1 | SEC-7.9 | Test | E-05, E-12 | Rollback preserves revocations |
| SR-7.10-1 | SEC-7.10 | Test | E-12, E-28, E-23 | Audit capacity stop |
| SR-7.11-1 | SEC-7.11 | Test | E-01 | Pre-parse bounds |
| SR-7.12-1 | SEC-7.12 | Test | E-10 | Cancellation propagation |
| SR-8.9-1 | SEC-8.9 | Test | E-24 | CSRF and preconditions |

## Appendix I — Requirement-set checks

Generated by the SRS build script from the requirement records, `ArchitectureV2.md` and `MCP_Gateway_Security_SRS.md`.

| Check | Result |
|---|---|
| Requirements | 529 total: 367 FR (19 roots), 162 SR |
| Deferred from release 1.0 (Appendix N) | 32: FR-2.14, FR-2.16, FR-3.26, FR-3.3, FR-3.7, FR-5.10, FR-5.11, FR-5.16, FR-5.17, FR-5.18, FR-5.25, FR-5.28, FR-5.29, FR-5.30, FR-5.31, FR-7.6, FR-7.15, FR-7.9, FR-9.4, FR-9.13, FR-12.5, SR-1-1, SR-1.6-1, SR-2.8-2, SR-2.11-3, SR-2.12-1, SR-4.3-1, SR-5.1-2, SR-5.3-2, SR-6.6-1, SR-6.8-1, SR-6.9-1 |
| Verification methods | Analysis 19, Demonstration 28, Inspection 77, Test 405 |
| Unique IDs; required fields; SHALL present; no MUST imperative | Pass |
| Orphans (non-root without a valid parent) | None |
| Every SR parent is a MUST in the security SRS | Pass |
| Security MUSTs (122) covered (SR, SEC decomposition or disposition) | Pass |
| SEC requirements with dispositions (realized outside the Gateway or by process) | SEC 4.4, SEC 4.10, SEC 4.12, SEC 8.1, SEC 9.4, SEC 9.5, SEC 9.7, SEC 10.1, SEC 10.2, SEC 10.4, SEC 10.8 |
| Security SHALL items without citing FR | None |
| Barren functional roots (no children) | None |
| Parameter Catalog (`docs/parameters.json`) | 93 parameters; all 92 ARCH §10.3 IDs present |
| Implementation status (`docs/status/elements.json`) | implemented 8, partial 25 |
| Elements without an allocated requirement | None |
| Functions without an allocated requirement | None |
| External interfaces without an allocated requirement | None |
| Internal interfaces without an allocated requirement | None |
| Data stores without an allocated requirement | None |
| GUI modules without an allocated requirement | None |
| Allocation IDs resolve in `ArchitectureV2.md` | Pass |
| Cross-references to FR/SR/CP IDs resolve | Pass |

### I.1 Items for owner review

The owner delegated specification decisions to the project team on 2026-10-16. The items below record the decisions taken under that delegation; each is explained in `CHANGELOG.md`.

1. **SEC wording versus V2.** Several parent MUSTs name V1 components (Neo4j "graph service", "admission worker", Hermes). The SR children realize them on V2 elements; the parent text is unchanged in the security SRS. In particular, SEC 1.1, 6.2 and 6.3 name the graph as the authority; their SR children realize them on the Policy Store and the Evidence Journal (A-9).
2. **Dispositions.** The SEC requirements listed above are realized outside the Gateway (harness deployment or process). V1.2 replaced the curation-system dispositions with packaging requirements (FR-14) and the harness dispositions for SEC 4.9, 4.11 and 4.13 with lockdown requirements.
3. **Owner-set values.** CP values marked *New* in Appendix A are engineering values set under the delegation; they are revised by controlled change.
4. **Usability measure.** FR-8.24 turns "user friendly" into a timed task.

## Appendix J — Server package manifest schema

The normative schema is `docs/schemas/manifest.schema.json` (JSON Schema 2020-12, `manifest_version` 1). The Library Trust Verifier validates every manifest against it (FR-14.11). This appendix summarizes the package layout and the schema; when the two disagree, the schema file governs.

### J.1 Package layout

A package is a directory in the library (OD-7), written by `smcpctl package build` and `smcpctl package sign` (FR-14.1 to FR-14.6):

```
<library>/<server-id>/<revision>/
  index.json            package index: digests of the files below, package ID, created time
  index.json.minisig    minisign signature over index.json (SR-3-1)
  manifest.json         validated against docs/schemas/manifest.schema.json
  provenance.json       source reference, licenses and artifact digest (FR-14.5, SR-3.2-1)
  artifact/<sha256>     the pinned artifact, stored by SHA-256 (FR-14.1, D-03)
<library>/revocations/<server-id>-<revision>.json(.minisig)   revocation entries (FR-14.12)
```

`index.json` has the members `package_format` (integer, 1), `server_id`, `revision`, `created_at`, and `files`, an object mapping each relative path above to its lowercase hex SHA-256. The signature covers the exact bytes of `index.json`.

### J.2 Manifest field groups

| Member | Required | Content | Checked by |
|---|---|---|---|
| `manifest_version` | Yes | Constant `1` | FR-14.11 |
| `server` | Yes | `id`, `revision`, `alias` (CP-42), `publisher`, optional `description` and `homepage` | FR-5.5, SR-3-5 |
| `artifact` | Yes | `type` (`npm`, `pypi`, `oci`, `binary`), `reference`, exact `version`, `sha256`, optional `registry_integrity` and `size_bytes` | FR-14.1, FR-14.2, SR-3-2 |
| `launch` | Yes | `runtime` (`node`, `python`, `oci`, `native`), `argv` (no shell, no installer as the first element), `env_allowlist`, `env_fixed` | SR-3.6-1, SR-4.8-1, SR-2.14-1 |
| `era` | Yes | `2026-07-28` or `2025-11-25` as observed at packaging | FR-5.17 |
| `risk_class` | Yes | `low`, `moderate`, `high` (CP-44) | SR-3-1, SR-4-1, FR-14.8 |
| `instance_scope` | Yes | Supported scopes | FR-5.10 |
| `stateful` | No | Whether a handle contract applies | SR-3.14-1 |
| `tools` | Yes | Per tool: `name`, `title`, `description`, `description_sha256`, `input_schema`, `output_schema`, `annotations`, `side_effect` and `source_trust` (CP-44), optional `risk_class` and `class` (`standard` or `gateway-admin`) | FR-5.5, SR-3.7-1, SR-5.13-2, SR-3.12-1 |
| `tools_list_sha256` | No | Digest of the canonical `tools/list` read at packaging | SR-3.8-1 |
| `capabilities` | Yes | `filesystem` slots with mode, `egress` destinations with ports, methods and optional request size, response size and duration limits, `spawns_processes`, `resources` | SR-1-1, SR-4.6-1, SR-4.5-2, FR-5.38 |
| `secrets` | No | Slots with purpose, destination and delivery modes | FR-6.5 |
| `behavior_hints` | No | Declared-behavior rules and expected ranges | FR-5.34 |
| `provenance` | Yes | Source kind, URI and digest, SPDX licenses, provenance statement digest | SR-3.1-1, SR-3.2-1 |
| `packaging` | Yes | Tool name and version, build time, operator note | FR-14.3 |
| `attestations` | No | Review status, advisory check time, re-curation date | FR-5.8 |
| `expires` | No | Date after which the revision is suspended | FR-5.8 |

The schema has no member that names a network endpoint for the server; a remote backend cannot be expressed and is rejected (FR-14.4).

## Appendix K — Client matrix

The machine-readable matrix is `docs/clients/matrix.json` (FR-15.10). Pinned versions are set there, not here. "Lockdown mechanism" names the client's own control that the lockdown profile uses (FR-15.1); where a client offers none, `smcpctl doctor` reports the gap (FR-15.3, FR-15.4) and the client is labelled `gateway-available` rather than `exclusive-gateway` (SR-4.13-1). Mechanisms marked *to confirm at pinning* are not yet verified against the pinned version and are recorded with their result when the matrix job first runs (FR-15.8).

### K.1 Local clients

| Client | Connection mode | Session mechanism | Lockdown mechanism | CA trust | Notes |
|---|---|---|---|---|---|
| Claude Code (Anthropic) | Streamable HTTP to `/mcp`; `smcp-stdio` as fallback | OAuth 2.1 sign-in (pre-registered client ID or allowlisted metadata document); `headersHelper` with `smcp-session` | Managed settings: `allowedMcpServers`, managed-only allowlist where supported, `permissions.deny` on Gateway paths (FR-15.2) | `NODE_EXTRA_CA_CERTS` | Honors `anthropic/requiresUserInteraction` (FR-1.50). Primary client for the approval acceptance test (FR-3.25). |
| Codex CLI (OpenAI) | Streamable HTTP; `smcp-stdio` | OAuth (`codex mcp login`) or `http_headers_helper` with `smcp-session` | Administrator requirements file with an MCP server allowlist matched by name and transport, where the pinned version supports it | *To confirm at pinning* | Treat as 2025-11-25 era until confirmed (CCB §2). |
| Hermes Agent (Nous Research) | Streamable HTTP; `smcp-stdio` | OAuth with PKCE, or a static header from `smcp-session` | None documented; file permissions and doctor report | `ssl_verify` with a CA bundle path | Supports per-server mTLS (mTLS Harness Profile). |
| OpenCode | Remote MCP over HTTP; local stdio with `smcp-stdio` | OAuth or headers from `smcp-session` | Global configuration `mcp` and `permission` settings; *to confirm at pinning* whether a non-user-writable scope exists | `NODE_EXTRA_CA_CERTS` *to confirm at pinning* | |
| Gemini CLI (Google) | Streamable HTTP (`httpUrl`); `smcp-stdio` | OAuth or headers | System settings file defining `mcpServers` and the server allowlist; enterprise admin controls where available. The vendor states that name-based allowlists are not a security boundary. | `NODE_EXTRA_CA_CERTS` | Labelled `gateway-available` until bypass tests pass. |
| Goose (Block) | stdio extension running `smcp-stdio`; Streamable HTTP | Headers from `smcp-session`; OAuth *to confirm at pinning* | `GOOSE_ALLOWLIST` environment variable naming a YAML allowlist matched on the extension command | *To confirm at pinning* | Allowlist is checked at extension installation. |
| Grok Build (xAI, local CLI) | *To confirm at pinning*; `smcp-stdio` expected to work wherever a stdio command is accepted | *To confirm at pinning* | *To confirm at pinning* | *To confirm at pinning* | |

### K.2 Cloud agents (Remote Access Profile)

Cloud agents run on the vendor's computer. They reach the Gateway only through the Remote Access Profile (FR-16), and their built-in browser, terminal and connector tools are outside the Gateway's control (FR-18.2). Each entry records a dated manual run or, while none has been made, a `not-run` entry with its review date and reason (FR-15.9); live cloud-agent runs are descoped from release 1.x.

| Agent | Connection mode | Registration | Vendor allowlist | Notes |
|---|---|---|---|---|
| Grok Bot (xAI) | Remote MCP URL through the tunnel, or `smcp-connect` where the agent accepts only a command | Dynamic Client Registration with operator approval (FR-16.5), or a pre-registered client | *To confirm*: vendor admin MCP allowlist | |
| ChatGPT agent "dots" (OpenAI) | Remote MCP URL through Cloudflare Tunnel, Tailscale Funnel or the vendor's MCP tunnel where offered | Dynamic Client Registration with operator approval, or pre-registered | *To confirm*: workspace admin connector and MCP controls | The vendor tunnel, where used, is the forwarding path of FR-16.2. |
| Meta Muse (Meta) | Remote MCP URL through the tunnel, or `smcp-connect` | *To confirm* | *To confirm* | |

## Appendix L — Hostile backend fixture suite

The hostile fixture is an MCP server built into the test binary that behaves as each row describes (FR-19.1). "Both" means the row is asserted in the Enforced and Standalone profiles; "Enforced" rows depend on E-16 to E-18 and are listed as limitations for the Standalone profile in the Security Limitations document. Results are published per row (FR-19.2).

| ID | Attack | Fixture behavior | Expected outcome | Profiles | Requirements |
|---|---|---|---|---|---|
| HF-01 | Poisoned tool description | A description containing instructions to the model to call another tool or reveal data | Blocking metadata rule matches; the tool is suspended at import, not presented, and `metadata_blocked` is recorded | Both | SR-5.9-2, FR-1.52 |
| HF-02 | Poisoned schema property description | The same text inside a nested `properties.*.description` | As HF-01 | Both | SR-5.9-2 |
| HF-03 | Rug pull through `list_changed` | After enablement, sends `notifications/tools/list_changed` and returns a changed description and an added tool | The server revision is suspended for drift; the changed and added tools never appear in a catalog | Both | SR-3.8-1, SR-3.10-1, FR-5.31 |
| HF-04 | Prompt injection in text content | Result text with injection phrases | Released with an injection-marker tag; P-143 recorded; the session is tainted if the tool's `source_trust` is `untrusted` | Both | FR-4.17, SR-5.13-2 |
| HF-05 | Prompt injection in structured content | The same phrases inside `structuredContent` string fields | As HF-04 | Both | SR-5.9-1, FR-4.17 |
| HF-06 | Prompt injection in an error result | `isError` result whose text carries the phrases | As HF-04; the error is filtered before release | Both | SR-5.9-1 |
| HF-07 | Prompt injection in progress messages | `notifications/progress` messages carrying the phrases | Progress messages are filtered and tagged before relay | Both | SR-5.9-1, FR-1.39 |
| HF-08 | Secret exfiltration in a result | Echoes a value registered as a secret fingerprint | Result withheld with `-31003` `SECRET_LEAK`; secret grant suspended | Both | FR-6.10, SR-5.11-1 |
| HF-09 | Secret exfiltration in arguments | The agent passes a registered secret value as an argument | Request blocked before dispatch by the outbound argument filter | Both | SR-5.8-1 |
| HF-10 | Schema smuggling: remote `$ref` | `inputSchema` with `$ref` to an external URL | Tool definition refused at import; no network request | Both | SR-1.8-2, SR-1.8-3 |
| HF-11 | Schema smuggling: deep nesting | Schema nested beyond the CP-36 depth | Tool definition refused at import | Both | SR-1.8-3 |
| HF-12 | Schema smuggling: huge enum | Enum with more subschemas or members than CP-36 allows | Tool definition refused at import | Both | SR-1.8-3 |
| HF-13 | Schema smuggling: `additionalProperties` games | Runtime schema loosens `additionalProperties` or adds `patternProperties` compared with the manifest | Drift suspension; arguments are validated against the packaged schema only | Both | SR-3.7-1, SR-3.8-1, SR-1.8-1 |
| HF-14 | Public-name collision | Two tools of one server whose names map to the same public name under FR-1.26 (for example `a.b` and `a_b`) | The revision is not enabled; the reason names both backend tool names | Both | FR-1.49 |
| HF-15 | Cross-server shadowing | Descriptions that reference another server's public tool names or redefine their behavior | Blocking metadata rule matches; tool suspended | Both | SR-5.9-2 |
| HF-16 | Oversized result | A result larger than CP-08 | Withheld with `-31003` `RESULT_TOO_LARGE`; nothing partial released | Both | SR-5.11-1, FR-4.10 |
| HF-17 | Slow-drip response | Writes one byte per second | Call ends at the CP-13 deadline with `-31009` `UPSTREAM_TIMEOUT`; instance restarted | Both | FR-4.9, SR-7.2-1 |
| HF-18 | Invalid stdout | Non-JSON lines on standard output | Instance terminated; call fails with `-31007`; event recorded | Both | FR-5.14 |
| HF-19 | Never responding | Accepts the call and never answers | As HF-17 | Both | FR-4.9 |
| HF-20 | Fork bomb | Spawns processes without limit | PID limit stops growth; instance killed; host unaffected | Enforced | SR-4.7-2, FR-5.35 |
| HF-21 | Memory blow-up | Allocates without limit | cgroup memory limit kills the instance; Gateway unaffected | Enforced | SR-4.7-2 |
| HF-22 | Symlink and path escape | Arguments with `../` and a symlink created to `/etc` inside its mount | Path arguments outside the grant are denied before dispatch; reads through the symlink fail inside the sandbox | Both (argument check); Enforced (mount) | SR-1.8-4, SR-4.6-1 |
| HF-23 | Direct network escape | Opens TCP connections to the Internet, the LAN and loopback services | Every connection fails; only broker endpoints are reachable | Enforced | SR-4.5-1 |
| HF-24 | DNS escape and rebinding | Resolves attacker names directly and through the broker with a rebinding answer | Direct resolution fails; the broker refuses the rebound private address | Enforced | SR-5.15-1, SR-5.15-2 |
| HF-25 | Unsolicited client-input request | Returns `InputRequiredResult` asking for elicitation | `-31010` without the MRTR profile | Both | FR-5.24 |
| HF-26 | Legacy server-initiated request | Sends `roots/list` or `sampling/createMessage` to the Gateway | Rejected; nothing relayed northbound | Both | FR-5.20, SR-5.6-2 |
| HF-27 | Unicode control and bidirectional text | Result text with bidi overrides and zero-width characters | `unicode-control` filter finding per the versioned corpus | Both | SR-5.14-1 |

## Appendix M — Acceptance scenarios and the enforced label

The acceptance scenarios of `MCP_Gateway_Security_SRS.md` Appendix B are mapped below to V1.2 requirements. A release is labelled "enforced" only when every row has a passing automated or recorded result for the release commit in the Enforced profile (FR-19.3); records follow FR-19.4.

| Scenario | V1.2 realization | Requirements | Evidence |
|---|---|---|---|
| AT-01 Identity and local HTTP | OAuth tokens, TLS, Host and Origin, header and body checks before dispatch | SR-2.1-1, SR-2.1-3, SR-2.8-1, SR-2.9-1, SR-2.9-2, SR-5.2-1, SR-7.11-1 | Automated |
| AT-02 Exact authorization | Default deny, deny precedence, argument bounds, hidden-tool calls | SR-1.3-1, SR-1.4-1, SR-1.8-1, SR-5.5-1 | Automated |
| AT-03 Policy authority and outage | Signed Policy Store as sole source; journal failure refuses dispatch; graph outage does not | SR-1.1-1, SR-1.1-2, SR-1.2-1, SR-1.2-2, SR-6.13-1, FR-9.17 | Automated |
| AT-04 Routing and overlap | Single route; overlap rejected at publication | SR-1.9-1, SR-1.11-1 | Automated |
| AT-05 Publication and revocation race | Serialized activation and launches; revocation bound | SR-1.15-1, SR-1.16-1, SR-2.4-1 | Automated |
| AT-06 Source and build evidence | Packaging provenance, signature and digest checks; drift suspension | FR-14.5, SR-3-1, SR-3-2, SR-3.1-1, SR-3.2-1, SR-3.8-1 | Automated |
| AT-07 Safe evidence display | Manifests, licenses and SBOMs rendered inert and bounded | SR-3.3-1, SR-6.17-1 | Automated (Playwright) |
| AT-08 Worker containment | Path, symlink, host socket, privilege, network and DNS escapes fail | SR-4.5-1, SR-4.6-1, SR-4.7-1, SR-4.7-2; Appendix L HF-20 to HF-24 | Automated (Enforced) |
| AT-09 Request and response filters | Secret, injection, malformed, binary and oversized content | SR-5.8-1, SR-5.9-1, SR-5.10-1, SR-5.11-1, SR-5.18-1; Appendix L HF-04 to HF-09, HF-16 | Automated |
| AT-10 Web broker | Grant scope, reserved addresses, rebinding, redirects | SR-4.5-2, SR-5.15-1, SR-5.15-2, SR-5.19-1 | Automated (Enforced) |
| AT-11 Audit linkage | Exact links survive rename, update and removal; denied targets not shown as executing | SR-6.4-1, SR-6.5-1, SR-6.20-1 | Automated |
| AT-12 Audit consistency | Journal flush faults, mirror replay and duplicate IDs | SR-6.2-1, SR-6.3-1, SR-6.10-1, SR-6.11-1 | Automated |
| AT-13 Integrity, privacy, retention | Journal tamper detection, no raw secrets, retention conflicts, purge receipts | FR-7.5, SR-6.7-1, SR-6.9-1, SR-6.15-1 | Automated |
| AT-14 Retry and crash | No replay of possibly executed mutations | SR-7.1-1, SR-7.2-1 | Automated |
| AT-15 Console authority | Harness credentials, Auditor mutations, CSRF, stale edits and approval replays denied | SR-2.5-1, SR-8.9-1, SR-1.18-2 | Automated (Playwright) |
| AT-16 Harness lockdown | Single MCP endpoint, protected client configuration and doctor findings for every local client (generalizes the V1 Hermes cutover) | FR-15.1, FR-15.3, SR-4.9-1, SR-4.11-1 | Automated (client matrix) |
| AT-17 Offline engineering workflow | Reference filesystem and git packages work with outbound access blocked | FR-12.2, FR-14.9 | Automated |
| AT-18 Remote access | Remote listener only through the tunnel; pending registrations refused; no listener on a non-loopback address | FR-16.1, FR-16.5, SR-2.9-3, SR-4.14-1, SR-4.14-2 | Recorded (tunnel provider) and automated (local tunnel stand-in) |
| AT-19 Backup, restore and rollback | Dispatch stopped during backup; restore verifies signatures and re-applies revocations; upgrade rollback | SR-7.7-1, SR-7.8-1, SR-7.9-1, FR-13.8 | Automated |
| AT-20 Limits and load | Pre-routing bounds, latency targets, disk exhaustion, restart | SR-7.10-1, SR-7.11-1, FR-11.2, FR-11.5 | Automated (load job) |
| AT-21 Version baseline | Requirement report complete; SRS regenerates without change; release tag resolves the matching documents | FR-12.10, FR-19.3 | Automated (CI) |

## Appendix N — Requirements deferred from release 1.0

These records keep their IDs and text so that a later release can restore them unchanged. They are not part of the requirement set of release 1.0 (Section 2.7): Appendices E to I and the requirement report leave them out, and no test or record needs to verify them. Each states why it is deferred and what release 1.0 does instead.

#### FR-2.14 — Credential issuance (deferred)

| Field | Value |
|---|---|
| ID | FR-2.14 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | When the mTLS Harness Profile is enabled, the Key & Trust Anchor Manager (E-22) **SHALL** issue framework-instance client certificates by signing a submitted certificate signing request with the Gateway's local client CA. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-59; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Enable the profile; submit a CSR through G-11; confirm the issued certificate chains to the client CA and names the principal ID. |
| Source | ARCH §4 E-22; ARCH §19 OD-2; Client-Compatibility-Brief §4.2 |
| Rationale | Only Hermes can present a per-server client certificate. mTLS is a hardening option, not the baseline credential. |
| Deferral | Release 1.0 ships without the mTLS Harness Profile. Harness requests are authenticated by bearer access tokens over TLS on a loopback listener, and per-instance credentials are OAuth clients managed in G-11. Client-certificate issuance and the client CA are deferred with the profile. |

#### FR-2.16 — Restart invalidation (deferred)

| Field | Value |
|---|---|
| ID | FR-2.16 |
| Parent ID | FR-2 — Identity and sessions |
| Statement | When the Gateway restarts, the Session Manager (E-04) **SHALL** reject every access token issued before the restart and **SHALL** keep each unexpired session resumable only through its current refresh token (FR-2.22), until the session's CP-18 maximum lifetime. |
| Allocation | Elements: E-04 Session Manager; Functions: F-08, F-09; Data stores: D-07 |
| Verification Method | Test |
| Verification Statement | Restart the Gateway with active sessions; confirm the old access tokens receive -31006, a refresh with the current refresh token resumes the same session ID, and a refresh after the maximum lifetime fails. |
| Source | ARCH §13 D-07; OWNER (sessions may survive restart via refresh tokens) |
| Rationale | Requiring a new browser sign-in after every restart or upgrade makes the product unusable; a rotated refresh token keeps the resume bound to the one client that holds it. |
| Deferral | Release 1.0 ends every session when the Gateway restarts: sessions, their session-taint marks and their quota counters are held in memory, and resuming a session with a refresh token issued before the restart would reset its taint and quota. Every access and refresh token issued before a restart is refused, and the harness signs in again. Resumable sessions with persisted taint and quota state are deferred. |

#### FR-3.26 — Response Policy and Runtime Profile objects (deferred)

| Field | Value |
|---|---|
| ID | FR-3.26 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** support Response Policy and Runtime Profile objects as published, versioned policy objects. |
| Allocation | Elements: E-05 Policy Administration Service, E-11 Response Inspection Pipeline, E-15 Server Runtime Manager; Functions: F-10; Internal interfaces: I-06; Data stores: D-01 |
| Verification Method | Test |
| Verification Statement | Create, validate and publish one Response Policy and one Runtime Profile; confirm each is stored and evaluated by E-11 and E-15. |
| Source | ARCH §7.2 |
| Rationale | Separately published response and runtime objects let a policy author change response handling and instance limits without editing configuration. |
| Deferral | Release 1.0 sets response handling with the `filters` obligations of permit rules and the `[filters]` configuration (where a requirement names the Response Policy, release 1.0 reads that configuration), and runtime limits with the verified manifest and the `[runtime]` configuration. Instance scopes that would need a Runtime Profile are already deferred (FR-5.10). Separate Response Policy and Runtime Profile objects need a publication path, schema and simulation support that release 1.0 does not have. |

#### FR-3.3 — Draft workspace (deferred)

| Field | Value |
|---|---|
| ID | FR-3.3 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** hold edits in a named draft derived from a stated parent revision until the draft is published or discarded. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10; Internal interfaces: I-06 |
| Verification Method | Demonstration |
| Verification Statement | Create a draft, edit it in two sessions of G-02, discard one and publish the other; confirm the active revision changes only on publish. |
| Source | ARCH §4 E-05 |
| Rationale | Authors iterate on policy without affecting enforcement. |
| Deferral | Release 1.0 has no server-side named drafts. A document is validated and simulated through the control API without being stored, and published with a stated parent revision that must still be active (a stale parent is refused, so two editors cannot overwrite each other); the G-02 editor keeps the unpublished text in the browser. Named drafts shared between sessions are deferred. |

#### FR-3.7 — Observation cost estimate (deferred)

| Field | Value |
|---|---|
| ID | FR-3.7 |
| Parent ID | FR-3 — Policy capability |
| Statement | The Policy Administration Service (E-05) **SHALL** estimate records per day, storage per day and added p95 latency for a draft Observation Policy or Research Campaign from the trailing 7 days of call rates. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-66; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Estimate a policy over a replayed 7-day fixture traffic set; confirm estimates are within ±25% of the measured values after one replayed day. |
| Source | ARCH §11 item 6; ARCH §5 F-66 |
| Rationale | Researchers must know the cost of a capture choice before publishing it. |
| Deferral | Release 1.0 reports the measured cost of observation instead of an estimate: GET /api/v1/observations/cost ranks the time spent per stage, policy revision and Observation Policy from recorded spans, and the meta-metrics give records and store growth per interval. A forecast for a draft Observation Policy or Research Campaign from seven days of call rates is deferred until those object types have drafts (FR-3.3). |

#### FR-5.10 — Instance scope (deferred)

| Field | Value |
|---|---|
| ID | FR-5.10 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Server Runtime Manager (E-15) **SHALL** create instances per call, per session or shared, as selected by the Runtime Profile from the scopes the manifest allows, defaulting to per session. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-38; Internal interfaces: I-12 |
| Verification Method | Test |
| Verification Statement | Configure each scope; confirm instance counts after calls from two sessions. |
| Source | ARCH §4 E-15; ARCH §19 OD-3 |
| Rationale | Isolation versus cold-start cost is a policy choice. |
| Deferral | Release 1.0 runs one shared instance per enabled server revision, started with the Gateway and replaced after an upstream timeout or failure. Per-session and per-call instances need per-instance secret delivery (the Secret Broker delivers S2 and S3 secrets per server alias) and per-instance sandbox resources that release 1.0 does not have; they are deferred to the release that adds the Runtime Profile object. |

#### FR-5.11 — Instance reuse and idle teardown (deferred)

| Field | Value |
|---|---|
| ID | FR-5.11 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Server Runtime Manager (E-15) **SHALL** reuse a live instance of the matching scope and **SHALL** tear down an instance idle for the CP-38 interval. |
| Allocation | Elements: E-15 Server Runtime Manager; Functions: F-39, F-40 |
| Verification Method | Test |
| Verification Statement | Make two calls in one session and then wait past CP-38; confirm one instance is reused and then torn down. |
| Source | ARCH §4 E-15 |
| Rationale | Bounds resource use on a single PC. |
| Deferral | Deferred with per-session and per-call instance scopes (FR-5.10): with one shared instance per revision there is nothing to reuse by scope or to tear down when idle. The instance runs until the Gateway stops, its revision is suspended, or it is replaced after a failure. |

#### FR-5.16 — Era probe (deferred)

| Field | Value |
|---|---|
| ID | FR-5.16 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When an instance starts, the Tool Dispatcher (E-10) **SHALL** send `server/discover` with protocol version 2026-07-28 and classify the server as modern on a `DiscoverResult` or recognized modern error, and as legacy on any other error or no response within 5 seconds. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Start modern and legacy fixture servers; confirm each classification. |
| Source | MCP:basic/transports/stdio §Backward Compatibility |
| Rationale | Curated servers may implement either era. |
| Deferral | Release 1.0 speaks the 2025-11-25 era southbound only, through the `initialize` handshake of FR-5.19; the reference packages and the servers `smcpctl package build` probes are 2025-11-25 servers. The `server/discover` probe and modern southbound requests are deferred to the release that adds the modern southbound client. A revision whose manifest era differs from the era its instance negotiates is not used (FR-5.40). |

#### FR-5.17 — Era consistency with manifest (deferred)

| Field | Value |
|---|---|
| ID | FR-5.17 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When the probed era differs from the protocol era declared in the manifest, the Tool Dispatcher (E-10) **SHALL** refuse to use the instance and the Local Server Registry (E-14) **SHALL** suspend the server revision. |
| Allocation | Elements: E-10 Tool Dispatcher, E-14 Local Server Registry; Functions: F-23, F-37 |
| Verification Method | Test |
| Verification Statement | Launch a legacy fixture whose manifest declares modern; confirm refusal and suspension. |
| Source | SEC 3.8; ARCH §6.3 |
| Rationale | The runtime must match the curated declaration. |
| Deferral | Deferred with the era probe (FR-5.16). Release 1.0 compares the manifest era with the negotiated era instead (FR-5.40). |

#### FR-5.18 — Modern southbound requests (deferred)

| Field | Value |
|---|---|
| ID | FR-5.18 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Tool Dispatcher (E-10) **SHALL** send each modern southbound request with `_meta.io.modelcontextprotocol/protocolVersion`, an empty `clientCapabilities` object in the baseline profile, Gateway `clientInfo`, and a request ID unique among its in-flight requests to that instance. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Capture southbound requests; confirm the metadata and ID uniqueness. |
| Source | MCP:basic/index §Per-request protocol fields |
| Rationale | Modern server requirement. |
| Deferral | Deferred with the era probe (FR-5.16): release 1.0 sends no modern southbound requests. |

#### FR-5.25 — MRTR Relay Profile (deferred)

| Field | Value |
|---|---|
| ID | FR-5.25 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | When the MRTR Relay Profile is enabled, the Tool Dispatcher (E-10) **SHALL** relay a backend `InputRequiredResult` northbound with the backend `requestState` wrapped in a Gateway `requestState` that is integrity-protected and bound to session, correlation ID, backend tool revision and the CP-39 expiry. |
| Allocation | Elements: E-10 Tool Dispatcher, E-02 Protocol Mediator; Functions: F-24, F-22; External interfaces: X-01; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Enable the profile; complete an elicitation round trip; confirm that tampered, expired and cross-session states are rejected. |
| Source | MCP:basic/patterns/mrtr §Server Requirements; SEC 5.6 |
| Rationale | Lets elicitation be qualified later without trusting harness-carried state. |
| Deferral | Release 1.0 ships without the MRTR Relay Profile. Relaying elicitation, sampling and roots needs a signed request-state protocol and a harness that answers it; none of the Appendix K clients needs it to use the reference packages. A backend InputRequiredResult ends the call with -31010 (FR-5.24) and server-initiated requests get -32601 (FR-5.20). |

#### FR-5.28 — Southbound Streamable HTTP client (deferred)

| Field | Value |
|---|---|
| ID | FR-5.28 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | For an instance using Streamable HTTP, the Tool Dispatcher (E-10) **SHALL** send each request as a POST carrying `Accept: application/json, text/event-stream`, `MCP-Protocol-Version`, `Mcp-Method` and, where applicable, `Mcp-Name`, and **SHALL** accept both JSON and SSE responses. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23, F-24; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Run the southbound HTTP conformance fixtures; confirm the headers and both response types. |
| Source | MCP:basic/transports/streamable-http §Sending Messages; §Standard Request Headers |
| Rationale | Some curated servers use the HTTP binding inside their sandbox. |
| Deferral | Release 1.0 runs every server instance over stdio, which is the only transport of the reference packages (FR-14.9) and of servers packaged with `smcpctl package build`. A southbound Streamable HTTP client needs its own conformance fixtures and egress handling; it is deferred to the release that admits HTTP instances. |

#### FR-5.29 — Southbound header encoding (deferred)

| Field | Value |
|---|---|
| ID | FR-5.29 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Tool Dispatcher (E-10) **SHALL** mirror `x-mcp-header` parameters into `Mcp-Param-{name}` headers and **SHALL** apply the `=?base64?…?=` encoding rules to `Mcp-Name` and `Mcp-Param-*` values. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Call fixture tools with non-ASCII, padded and sentinel-like values; confirm the encodings. |
| Source | MCP:basic/transports/streamable-http §Value Encoding |
| Rationale | Clients must support `x-mcp-header`. |
| Deferral | Deferred with the southbound Streamable HTTP client (FR-5.28): header mirroring exists only on that transport. |

#### FR-5.30 — Southbound SSE comments (deferred)

| Field | Value |
|---|---|
| ID | FR-5.30 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | The Tool Dispatcher (E-10) **SHALL** ignore SSE comment lines received from Streamable HTTP instances. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-24; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Inject comment lines into a fixture stream; confirm no error. |
| Source | MCP:basic/transports/streamable-http §Receiving Messages |
| Rationale | Keep-alive comments are valid. |
| Deferral | Deferred with the southbound Streamable HTTP client (FR-5.28): SSE exists only on that transport. |

#### FR-5.31 — Southbound list-change watch (deferred)

| Field | Value |
|---|---|
| ID | FR-5.31 |
| Parent ID | FR-5 — Server trust and execution |
| Statement | For a shared or session-scoped modern instance whose server declares `tools.listChanged`, the Tool Dispatcher (E-10) **SHALL** hold a `subscriptions/listen` stream with `toolsListChanged: true` and **SHALL** trigger a tool-list comparison on each change notification. |
| Allocation | Elements: E-10 Tool Dispatcher, E-14 Local Server Registry; Functions: F-24, F-37; Internal interfaces: I-13 |
| Verification Method | Test |
| Verification Statement | Make a fixture add a tool at runtime; confirm the comparison and the resulting suspension. |
| Source | MCP:basic/patterns/subscriptions; SEC 3.8 |
| Rationale | Detects runtime tool drift. |
| Deferral | Deferred with the southbound Streamable HTTP client and modern-era instances (FR-5.28, FR-5.16). Release 1.0 acts on `notifications/tools/list_changed` from stdio instances by re-reading the tool list and comparing it with the manifest (SR-3.8-1). |

#### FR-7.6 — Alerts (deferred)

| Field | Value |
|---|---|
| ID | FR-7.6 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Audit & Evidence Service (E-21) **SHALL** raise an alert in the management console for each event matching an alert rule of the effective Audit Profile. |
| Allocation | Elements: E-21 Audit & Evidence Service; Functions: F-53; Internal interfaces: I-06 |
| Verification Method | Test |
| Verification Statement | Configure an alert on `withheld`; trigger it; confirm the console alert. |
| Source | ARCH §7.2 Audit Profile |
| Rationale | Operators need notification of significant events. |
| Deferral | The release 1.0 Audit Profile sets retention and escalation parameters only; it has no alert rules. The console raises alerts for anomaly bands (G-06) and health causes, and the evidence stream with filters (FR-8.23) follows any event class live. Alert rules in the Audit Profile are deferred. |

#### FR-7.15 — Client certificate authority (deferred)

| Field | Value |
|---|---|
| ID | FR-7.15 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Key & Trust Anchor Manager (E-22) **SHALL** operate a local certificate authority for harness client certificates separate from the server certificate authority. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-59, F-60; Data stores: D-08 |
| Verification Method | Inspection |
| Verification Statement | Inspect both CA certificates and an issued certificate of each kind; confirm separate roots. |
| Source | ARCH §4 E-22 |
| Rationale | Separates client identity from server identity. |
| Deferral | Deferred with the mTLS Harness Profile (FR-2.14): release 1.0 authenticates harnesses with bearer access tokens and issues no client certificates, so a client CA would have nothing to sign. |

#### FR-7.9 — Key protection at rest (deferred)

| Field | Value |
|---|---|
| ID | FR-7.9 |
| Parent ID | FR-7 — Assurance services |
| Statement | The Key & Trust Anchor Manager (E-22) **SHALL** seal private keys to the host TPM 2.0 when present, store them in the user's login Keychain on macOS, and otherwise store them in files owned by the key-holding service identity with mode 0600, encrypted under an operator passphrase when the configuration sets `keys.passphrase = true`. |
| Allocation | Elements: E-22 Key & Trust Anchor Manager; Functions: F-60; External interfaces: X-07; Data stores: D-08 |
| Verification Method | Test |
| Verification Statement | Start on a TPM host, on macOS and on a non-TPM Linux host with and without the passphrase option; confirm the protection method in each case and that key files copied to another host are unusable where sealing or encryption applies. |
| Source | ARCH §15 E-19/E-22; OWNER (platform profiles) |
| Rationale | Keys must not sit in plaintext on disk where the platform offers protection. An unattended service cannot wait for a passphrase at every start, so the passphrase is an option rather than the default. |
| Deferral | Release 1.0 stores private keys in files with mode 0600 under the state directory, owned by the key-holding identity in the Enforced profile (SR-6.12-1); the vault master key can be held in the macOS Keychain. TPM sealing, Keychain storage of every private key and passphrase encryption are deferred: they need reference hardware and an unattended-start design that release 1.0 does not have. |

#### FR-9.4 — Write priority classes (deferred)

| Field | Value |
|---|---|
| ID | FR-9.4 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Access Service (E-26) **SHALL** order queued writes by the priority classes P0 policy and control, P1 mandatory audit, P2 observation and P3 research. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-73; Internal interfaces: I-33 |
| Verification Method | Test |
| Verification Statement | Saturate the queue with P2 writes and submit a P1 write; confirm the P1 write commits first. |
| Source | ARCH §4 E-26 |
| Rationale | Mandatory writes must not wait behind optional data. |
| Deferral | In release 1.0 the Data Access Service writes only the evidence mirror, from one ordered stream: the journal (P0 and P1 records are committed to the journal before the call proceeds, independent of the graph), and observation data is written to the Observation Store, not through the Data Access Service. With one write class in the queue there is nothing to order; priority classes are deferred until a second writer shares the queue. |

#### FR-9.13 — Storage tiering (deferred)

| Field | Value |
|---|---|
| ID | FR-9.13 |
| Parent ID | FR-9 — Data Server |
| Statement | The Data Lifecycle & Memory Manager (E-28) **SHALL** keep observation partitions younger than 30 days in the hot tier and **SHALL** move older partitions to compressed warm storage until their retention ends. |
| Allocation | Elements: E-28 Data Lifecycle & Memory Manager; Functions: F-78; Data stores: D-09, D-13 |
| Verification Method | Test |
| Verification Statement | Age fixture partitions; confirm tier moves and query continuity. |
| Source | ARCH §4 E-28 |
| Rationale | Bounded fast storage with retained history. |
| Deferral | Release 1.0 writes observation partitions as compressed columnar files (Parquet through DuckDB) or JSON Lines from the start and deletes them at the end of their retention; there is one tier. A separate hot tier is deferred until measurements on reference hardware show that queries over 30 days need one. |

#### FR-12.5 — Service management (deferred)

| Field | Value |
|---|---|
| ID | FR-12.5 |
| Parent ID | FR-12 — Implementation constraints |
| Statement | The Gateway **SHALL** install as systemd system services in the Enforced profile, and as a launchd user agent on macOS or a systemd user unit on Linux in the Standalone profile, with declared start ordering Key & Trust Anchor Manager, Gateway core, console, then the optional Data Server. |
| Allocation | Elements: E-25 Graph Database Engine, E-22 Key & Trust Anchor Manager, E-24 Management Console & Control API; Functions: F-97; External interfaces: X-07 |
| Verification Method | Test |
| Verification Statement | Reboot an Enforced host and log in on a Standalone host; confirm the start order from the service manager log and that the Gateway serves harness requests while the Data Server is still starting. |
| Source | ARCH §15; ARCH §2.2 A-9 |
| Rationale | Startup gating depends on the keys and the core only; the graph mirror starts last because enforcement does not wait for it. |
| Deferral | Release 1.0 runs the Key & Trust Anchor Manager, the Gateway core, the console and the graph mirror in one process, smcpd, which `smcpctl install` installs as one systemd system service in the Enforced profile and as one launchd user agent (macOS) or systemd user unit (Linux) in the Standalone profile. There are no separate element services whose start order could be declared: smcpd loads its keys and trust anchors before it opens a listener, serves the console from the same process, and starts the graph mirror without waiting for it, so harness requests are served while the mirror is still connecting (FR-9.17). Separate per-element services with declared start ordering are deferred with a multi-process split of the Gateway. |

#### SR-1-1 — Capability ceiling (deferred)

| Field | Value |
|---|---|
| ID | SR-1-1 |
| Parent ID | SEC-1 — Graph policy and routing authority (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** reject publication of any grant whose tools, paths, egress destinations or secret slots exceed the capability ceiling of the referenced server revision's manifest. |
| Allocation | Elements: E-05 Policy Administration Service, E-14 Local Server Registry; Functions: F-10; Internal interfaces: I-07 |
| Verification Method | Test |
| Verification Statement | Publish grants exceeding each ceiling dimension; confirm each is rejected with the exceeded dimension named. |
| Source | ARCH §7.3; ARCH §7.1 layer 1 |
| Rationale | The signed manifest bounds all authority. |
| Deferral | Release 1.0 policy grants name a server alias and tools only; they carry no paths, egress destinations or secret slots, so a grant cannot exceed those dimensions of a manifest. A granted tool that the enabled server revision does not serve has no public name and is never presented or dispatched. Filesystem slots, egress grants and secret slots are bound in the configuration, not in the policy document. Publication-time checks of grants against the manifest ceiling are deferred with grants that carry those dimensions. |

#### SR-1.6-1 — Exact match scope (deferred)

| Field | Value |
|---|---|
| ID | SR-1.6-1 |
| Parent ID | SEC-1.6 — Exact scoped rules (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Decision Service (E-06) **SHALL** match permits on principal or Framework Profile, session template, exact server revision ID, exact tool revision ID and MCP method. |
| Allocation | Elements: E-06 Policy Decision Service; Functions: F-13 |
| Verification Method | Test |
| Verification Statement | Change each dimension of a permitted request in turn; confirm each change results in deny. |
| Source | SEC 1.6 |
| Rationale | No implicit widening. |
| Deferral | Release 1.0 permit rules match the Framework Profile, the session template, the server alias, the tool name and the `tools/call` method (no other method reaches the decision). The exact revisions are fixed outside the rule: a server revision that is not enabled is never dispatched to, a relaunch with a different revision suspends the server, and every decision record carries the exact server and tool revision IDs. Rules that name revision IDs, which would need a policy publication for every server upgrade, are deferred. |

#### SR-2.8-2 — Mutual TLS (deferred)

| Field | Value |
|---|---|
| ID | SR-2.8-2 |
| Parent ID | SEC-2.8 — Authenticated transport (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | When the mTLS Harness Profile is enabled, the Harness Interface Endpoint (E-01) **SHALL** require a client certificate chaining to the Gateway client CA on the TLS harness listener. |
| Allocation | Elements: E-01 Harness Interface Endpoint; Functions: F-01; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Enable the profile; connect without a certificate and with a foreign certificate; confirm rejection during the handshake. |
| Source | SEC 2.8; ARCH §19 OD-2 |
| Rationale | Optional transport-level framework authentication for harnesses that can present a client certificate. |
| Deferral | Deferred with the mTLS Harness Profile (FR-2.14); release 1.0 authenticates harness requests with bearer access tokens. |

#### SR-2.11-3 — No open metadata fetch (deferred)

| Field | Value |
|---|---|
| ID | SR-2.11-3 |
| Parent ID | SEC-2.11 — OAuth boundary (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Identity & Authentication Service (E-03) **SHALL** fetch a Client ID Metadata Document only from a URL that is pre-registered or matches the CP-52 allowlist, within the CP-52 limits, and **SHALL** refuse every other metadata URL without a network request. |
| Allocation | Elements: E-03 Identity & Authentication Service; Functions: F-04; External interfaces: X-01 |
| Verification Method | Test |
| Verification Statement | Present an allowlisted metadata URL, a non-allowlisted URL pointing at a capture server and an allowlisted URL that redirects to another host; confirm success, refusal with no request reaching the capture server, and refusal of the redirect. |
| Source | SEC 2.11; REVIEW (I4: CIMD URL allowlist or pre-registration, no open outbound fetch) |
| Rationale | An open fetch lets an unauthenticated caller make the Gateway send requests to arbitrary hosts. |
| Deferral | Release 1.0 never fetches Client ID Metadata Documents: a metadata-URL client ID is accepted only when it is pre-registered in the configuration or approved through the Remote Access registration flow, and every other URL is refused without a network request. Fetching documents from an allowlist (CP-52) is deferred; no open fetch exists in the meantime. |

#### SR-2.12-1 — Handle ownership (deferred)

| Field | Value |
|---|---|
| ID | SR-2.12-1 |
| Parent ID | SEC-2.12 — State ownership (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | For a tool with a manifest handle contract, the Access Enforcement Point (E-08) **SHALL** record handles created by results with their owning session and principal, and **SHALL** deny calls presenting a handle owned by another session or principal or past its expiry. |
| Allocation | Elements: E-08 Access Enforcement Point, E-11 Response Inspection Pipeline; Functions: F-20, F-27 |
| Verification Method | Test |
| Verification Statement | Create a handle in session A and use it from session B and after expiry; confirm denial. |
| Source | SEC 2.12; MCP:server/tools §Stateful Tools |
| Rationale | Handles are names, not capabilities. |
| Deferral | The release 1.0 manifest schema (Appendix J) has no handle contract, and none of the reference packages returns handles that a later call presents. Handle tracking is deferred until the manifest schema defines handle contracts. |

#### SR-4.3-1 — Caller allowlist (deferred)

| Field | Value |
|---|---|
| ID | SR-4.3-1 |
| Parent ID | SEC-4.3 — CE access boundary (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Data Access Service (E-26) **SHALL** authenticate each calling element by Unix-socket peer credentials and **SHALL** permit only the operations allowlisted for that element. |
| Allocation | Elements: E-26 Data Access Service; Functions: F-72; Internal interfaces: I-07, I-30, I-33, I-34, I-35, I-06 |
| Verification Method | Test |
| Verification Statement | Invoke a policy-write operation from the Observation Collector identity; confirm denial. |
| Source | SEC 4.3 |
| Rationale | Application-level separation without Enterprise database roles. |
| Deferral | In release 1.0 the Data Access Service is a library inside the `smcpd` process, called only by the graph mirror and the console routes of that process; no element reaches it across a process or socket boundary, so there is no peer to authenticate by socket credentials. Its operations are fixed by the reviewed template catalog and the control API role matrix (Appendix C). Peer authentication is deferred to a release that splits elements into separate processes. |

#### SR-5.1-2 — Southbound era by manifest (deferred)

| Field | Value |
|---|---|
| ID | SR-5.1-2 |
| Parent ID | SEC-5.1 — Explicit protocol profiles (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Tool Dispatcher (E-10) **SHALL** use legacy 2025-11-25 behavior toward an instance only when the manifest declares that era. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23 |
| Verification Method | Test |
| Verification Statement | Probe a modern server whose manifest declares legacy; confirm suspension rather than legacy use. |
| Source | SEC 5.1; FR-5.17 |
| Rationale | Curated protocol era. |
| Deferral | Deferred with the era probe (FR-5.16). Release 1.0 uses legacy behavior toward every instance and refuses a revision whose manifest declares another era (FR-5.40), so legacy behavior is never used toward a revision whose manifest declares the modern era. |

#### SR-5.3-2 — No southbound downgrade (deferred)

| Field | Value |
|---|---|
| ID | SR-5.3-2 |
| Parent ID | SEC-5.3 — No unsafe downgrade (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Tool Dispatcher (E-10) **SHALL** treat a recognized modern error from an era probe as modern and **SHALL** never fall back to legacy because of it. |
| Allocation | Elements: E-10 Tool Dispatcher; Functions: F-23 |
| Verification Method | Test |
| Verification Statement | Return `-32022` to a probe; confirm modern handling. |
| Source | SEC 5.3; MCP:basic/transports/stdio §Backward Compatibility |
| Rationale | Specification fallback rule. |
| Deferral | Deferred with the era probe (FR-5.16): release 1.0 sends no era probe, so there is no probe error to classify. |

#### SR-6.6-1 — Policy-directed payload capture (deferred)

| Field | Value |
|---|---|
| ID | SR-6.6-1 |
| Parent ID | SEC-6.6 — Policy-directed payload storage (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** capture optional payloads only as directed by the evaluated Audit Profile, Observation Policy or Research Campaign, into the storage class it names. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-29 Observation Collector; Functions: F-53, F-82 |
| Verification Method | Test |
| Verification Statement | Toggle capture in the profile; confirm payload presence follows it. |
| Source | SEC 6.6 |
| Rationale | Policy-directed capture. |
| Deferral | Release 1.0 captures no payloads: observation records hold derived parameters only, and the S3 parameters (raw arguments and raw responses) are never stored. With no optional payload capture there is nothing for an Audit Profile, Observation Policy or Research Campaign to direct; directed payload capture is deferred with its encrypted storage (SR-6.8-1). |

#### SR-6.8-1 — Payload encryption (deferred)

| Field | Value |
|---|---|
| ID | SR-6.8-1 |
| Parent ID | SEC-6.8 — Payload encryption (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Audit & Evidence Service (E-21) **SHALL** store captured payloads as age-encrypted blobs referenced in the graph by ciphertext digest and key reference. |
| Allocation | Elements: E-21 Audit & Evidence Service, E-22 Key & Trust Anchor Manager; Functions: F-53 |
| Verification Method | Inspection |
| Verification Statement | Inspect a payload blob and its graph reference. |
| Source | SEC 6.8 |
| Rationale | Encrypted payloads. |
| Deferral | Deferred with payload capture (SR-6.6-1): release 1.0 stores no payloads, so there are no payload blobs to encrypt or reference from the graph. |

#### SR-6.9-1 — Retention validation (deferred)

| Field | Value |
|---|---|
| ID | SR-6.9-1 |
| Parent ID | SEC-6.9 — Retention conflict (MUST, `MCP_Gateway_Security_SRS.md`) |
| Statement | The Policy Administration Service (E-05) **SHALL** reject publication of retention settings whose greatest minimum exceeds the smallest maximum, or whose capture requirement contradicts a no-capture classification. |
| Allocation | Elements: E-05 Policy Administration Service; Functions: F-10 |
| Verification Method | Test |
| Verification Statement | Publish conflicting retention and capture settings; confirm rejection. |
| Source | SEC 6.9 |
| Rationale | Consistent retention. |
| Deferral | Release 1.0 has one retention setting per store (the Audit Profile's `retention` and the `[evidence]` and `[observation]` settings) and no no-capture data classifications, because payload capture is deferred (SR-6.6-1). There are no competing minimum and maximum retentions or capture requirements to conflict. Retention validation is deferred with policy-directed capture. |

