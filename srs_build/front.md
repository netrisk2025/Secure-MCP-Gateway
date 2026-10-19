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
