# Secure MCP Gateway — Software Requirements Specification

| Field | Value |
|---|---|
| File | `Secure_MCP_Gateway_SRS.md` |
| Baseline | V1.1 draft (implementation SRS; harness authentication, protocol eras, adapters and tool naming revised) |
| Date | 2026-10-16 (America/New_York) |
| Owner | netrisk |
| System of Interest | Secure MCP Gateway (local, single PC) |
| Architecture | `ArchitectureV2.md` V2.2 draft — elements E-01…E-33, functions F-01…F-95, interfaces X-01…X-12 and I-01…I-39, GUI modules G-01…G-14, data stores D-01…D-13 |
| Security control root | `MCP_Gateway_Security_SRS.md` (V1 security-control baseline; cited as `SEC`) |
| Protocol baseline | MCP specification and schema 2026-07-28 (`mcp-spec/2026-07-28/`; cited as `MCP:` and `SCHEMA:`) |
| Skill | `Skills.md` (INCOSE GtWR + project rules) |
| Status | Draft for owner review. Requirements are not yet implemented or verified. |

## Contents

1. Purpose, scope and intended use
2. Conventions and traceability rules
3. Recommended technology stack (open source only)
4. Functional requirements (FR-1 … FR-12)
5. Security requirements (SR, parented to `SEC` MUSTs)
6. Appendix A — Controlled parameters (CP)
7. Appendix B — Gateway error codes
8. Appendix C — Application role matrix
9. Appendix D — Graph data model
10. Appendix E — Security-control coverage (SEC → SR)
11. Appendix F — Allocation matrix (element → requirements)
12. Appendix G — Architecture coverage (functions, interfaces, data stores, GUI modules)
13. Appendix H — Requirement index
14. Appendix I — Requirement-set checks

## 1. Purpose, scope and intended use

### 1.1 Purpose

This SRS is the **implementation baseline** for coding the Secure MCP Gateway. It states what each architectural element must do (functional requirements, **FR**) and which concrete security controls each element must enforce (security requirements, **SR**). Every requirement is allocated to an element, a function and, where one is crossed, an interface in `ArchitectureV2.md`, and every SR traces to a parent **MUST** in `MCP_Gateway_Security_SRS.md`.

### 1.2 Intended use of the Gateway

Per the owner, the Gateway is a local secure MCP gateway on a single PC whose **primary purpose is research**. It is a vehicle for developing effective security policies, new run-time policies and longer-term trend-analysis techniques. That is why this SRS gives first-class functional weight to the policy studio and simulation, observation capture, behavior baselines, meta-metrics and dataset export, alongside enforcement.

### 1.3 Scope

**In scope:** all elements E-01…E-33 of `ArchitectureV2.md` and their interfaces.
**Outside the SoI (interfaces only):** the MCP Curation System and Trusted MCP Server Library (X-02/X-03), agentic frameworks (X-12), offline analytics tools (X-11), and the host platform (X-07). The reference harness adapters (E-33) are inside the SoI and are delivered with the release.

### 1.4 Relationship to other documents

| Document | Role |
|---|---|
| `MCP_Gateway_Security_SRS.md` | **Root of security controls.** Its MUSTs parent the SRs in Section 5. Its SHALL roots 8, 9 and 10 are cited as sources of FRs. Its Appendices A and F supply controlled values and frozen semantics reused here. |
| `ArchitectureV2.md` | Element, function and interface definitions used for allocation. |
| `architecture.md` rev 2.0 | Problem-space analysis (cited as `A2`). |
| `mcp-spec/2026-07-28/` | Normative protocol text and schema. When this SRS and the MCP specification disagree on protocol behavior, the specification governs unless an SR intentionally restricts it. |

### 1.5 Conditional profiles

Some requirements apply only when a profile is enabled. Profiles are disabled in the baseline configuration and are enabled only after their requirements pass verification.

| Profile | Enables | Requirements |
|---|---|---|
| UDS Harness Profile | Unix-domain-socket harness transport | FR-1.47, FR-2.15, SR-2.8-3 |
| MRTR Relay Profile | Relaying backend `InputRequiredResult` (elicitation, sampling, roots) | FR-5.25, SR-5.6-2 |
| mTLS Harness Profile | Client-certificate authentication on the TLS harness listener, in addition to the bearer token | FR-2.14, SR-2.8-2 |
| Overlay Profile | Non-loopback listeners for owned remote devices | SR-2.9-3, SR-4.14-1 |

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
| `MCP:<page>` | `mcp-spec/2026-07-28/specification/<page>.mdx` |
| `SCHEMA:<type>` | `mcp-spec/2026-07-28/schema/schema.ts` type |
| `CP-nn` | Appendix A controlled parameter |
| `OWNER` | Owner direction in the tasking for this SRS |

### 2.5 Subjects

Each statement names its allocated element as the subject, for example *"The Session Manager (E-04) SHALL …"*. Requirements on the release, rather than on run-time behavior, name *"The Gateway release"* or the delivered command.

## 3. Recommended technology stack (open source only)

All selections carry OSI-approved licenses. Exact versions, digests and transitive licenses are frozen at qualification (FR-12.1, FR-12.8). License statements here describe the upstream projects and must be re-verified at the pinned version.

### 3.1 Selections

| Layer | Recommendation | License | Elements | Why |
|---|---|---|---|---|
| Host OS | Linux, kernel ≥ 6.8 (e.g., Ubuntu 24.04 LTS or Debian 13) with cgroup v2 and unprivileged user namespaces | GPL-2.0 | All, X-07 | Isolation primitives the design relies on |
| Service management | systemd | LGPL-2.1+ | All | Ordering, restart, sandboxing directives |
| Implementation language | **Go** (current stable release) | BSD-3-Clause | E-01…E-23, E-25 integration, E-26…E-32 | One memory-safe language for the core; strong concurrency, static binaries |
| MCP protocol | Official MCP Go SDK (`modelcontextprotocol/go-sdk`), only if its pinned release implements 2026-07-28; otherwise a project protocol layer generated from `schema.json` | Apache-2.0 (with retained MIT notices) | E-02, E-10 | Conformance with the stateless 2026-07-28 revision; see risk note 3.3 |
| JSON Schema validation | `santhosh-tekuri/jsonschema` v6 | Apache-2.0 | E-05, E-09, E-11, E-14 | Supports 2020-12 and draft-07; no remote `$ref` by default |
| HTTP | Go `net/http` + `go-chi/chi` router | BSD-3 / MIT | E-01, E-04, E-07, E-18, E-24 | Mature HTTP/1.1 and HTTP/2 with TLS 1.3 |
| Cryptography | Go `crypto/*` (TLS 1.3, Ed25519, HMAC-SHA-256), `golang.org/x/crypto/argon2` | BSD-3 | E-03, E-21, E-22, E-24 | Standard library primitives |
| Secret and payload encryption | `filippo.io/age` | BSD-3 | E-19, E-21 | Simple, audited file encryption |
| TPM sealing | `google/go-tpm` | Apache-2.0 | E-22 | Hardware-backed key sealing where available |
| Package signature verification | `sigstore/sigstore-go` (cosign bundles, offline trust root) **or** minisign verification (`aead.dev/minisign`) — per ARCH OD-1 | Apache-2.0 / MIT | E-13 | Offline verification of curation signatures |
| Graph database | **Neo4j Community Edition** (pinned release) on an OpenJDK 21 build | GPL-3.0 (Neo4j CE); GPL-2.0 + Classpath Exception (OpenJDK) | E-25 | Owner-selected graph DB; mature Cypher, ACID, local |
| Graph driver | Neo4j Go driver | Apache-2.0 | E-26 | Parameterized queries, managed transactions |
| Columnar Observation Store | **DuckDB** with Parquet files, via the official DuckDB Go driver | MIT | E-27 | Embedded, fast aggregation, native Parquet export |
| Statistics | `gonum` (stats), `influxdata/tdigest` (quantile sketches) | BSD-3 / Apache-2.0 | E-30, E-31 | Welford, transforms, robust statistics in Go |
| Internal tracing | OpenTelemetry Go SDK with an in-process exporter to E-29 (no network exporter) | Apache-2.0 | E-29, all instrumented | Standard span model; matches MCP `_meta` trace keys |
| Sandbox | **Podman** (rootless) with `crun`, `conmon`, `netavark`; default seccomp; AppArmor or SELinux | Apache-2.0; GPL-2.0+ / LGPL-2.1+; GPL-2.0 | E-15, E-16 | Rootless OCI isolation without a privileged daemon socket |
| Network enforcement | nftables (via `google/nftables` Go library) | GPL-2.0 (nftables); Apache-2.0 (library) | E-16, E-18, E-25 | Per-identity and per-namespace rules |
| Configuration | TOML (`pelletier/go-toml` v2) validated by JSON Schema | MIT | All | Readable, schema-validated configuration |
| IDs | UUIDv7 (`google/uuid`) | BSD-3 | All | Time-ordered unique IDs |
| GUI | **React** + **TypeScript** + **Vite**; Mantine UI components; TanStack Query | MIT; Apache-2.0; MIT; MIT; MIT | E-24 | Mainstream, local-bundled SPA |
| Graph visualization | Cytoscape.js | MIT | E-24 (G-05, G-14) | Bounded graph rendering |
| Charts | Apache ECharts | Apache-2.0 | E-24 (G-05, G-07, G-08) | Distributions, timelines, heatmaps |
| API contract | OpenAPI 3.1; `oapi-codegen` (Go), `openapi-typescript` (TS) | Apache-2.0 / MIT | E-24 | Generated, consistent client and server |
| Testing | Go `testing`; Playwright (GUI end-to-end); `vegeta` (load) | BSD-3; Apache-2.0; MIT | All | Requirement-tagged automated verification (FR-12.10) |
| Supply chain | Syft (SBOM), Grype and `govulncheck` (vulnerabilities), cosign (release signing) | Apache-2.0; Apache-2.0; BSD-3; Apache-2.0 | Release | FR-12.8 provenance |

### 3.2 Explicitly excluded

| Excluded | Reason |
|---|---|
| Neo4j Enterprise, Aura, APOC/GDS plugins | Paid, cloud or unnecessary attack surface (SEC 9.2, SR-7.4-1) |
| Memgraph, FalkorDB | Licenses are source-available rather than OSI-approved (verify at evaluation; ARCH OD-4) |
| HashiCorp Vault | Business Source License (not OSI-approved); OpenBao (MPL-2.0) remains a future option |
| Docker Desktop | Proprietary distribution terms; privileged daemon socket model |
| External telemetry, SaaS logging or hosted identity | Violates local, offline baseline (FR-12.2) |

### 3.3 Stack risks to retire in the first prototype phase

1. **MCP SDK revision support.** *Retired 2026-10-16.* The 2026-07-28 revision removed `initialize`, sessions and the GET stream. The spike in `spikes/go-sdk-dual-era/` shows that `modelcontextprotocol/go-sdk` v1.8.0 serves both eras on one `StreamableHTTPHandler` when `Stateless` is set: 2026-07-28 `server/discover`, `tools/list`, `tools/call` and `subscriptions/listen` (with `notifications/tools/list_changed` delivered on the listen stream) and 2025-11-25 `initialize`, `notifications/initialized`, `tools/list` and `tools/call`, with an `initialize` naming an older version answered with `2025-11-25` as FR-1.17 requires. In the default stateful mode the handler rejects every 2026-07-28 request, so the Gateway uses stateless mode. Legacy clients receive no `Mcp-Session-Id`, which revision 2025-11-25 permits; FR-1.46 is worded accordingly. The SDK's default `cacheScope`, `ttlMs` and `logging` capability must be overridden to meet FR-1.12, FR-1.13 and FR-1.42.
2. **Neo4j CE write throughput.** Measure the decision-intent and outcome transactions (SR-6.2-1, SR-6.3-1) at the FR-11 reference load. If they miss, keep CE as the system of record and batch non-mandatory graph writes.
3. **Rootless Podman start latency.** Measure per-session instance cold start. If it is excessive, prefer the `shared` scope for stateless, read-only servers (ARCH OD-3).
