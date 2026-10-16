# MCP Servers — FloorPlan

Updated: 2026-10-15 (site and client brief added)

Scope: this repository (`Secure-MCP-Gateway`). This map covers every top-level path. Paths are relative to the repository root.

| Path | Contents | Access / purpose |
|---|---|---|
| `architecture.md` | Architecture revision 2.0: Neo4j CE design, data flows, licenses, engineering server catalog, GUI and Hermes/client integration procedures | Current design; implementation remains pending |
| `ArchitectureV2.md` | Architecture V2.2 draft (2026-10-16): logical decomposition into 10 subsystems / 33 elements (E-xx) incl. graph Data Server, Observation & Analytics and the Harness Adapter Kit, 95 functions (F-xx), 12 external (X-xx) and 39 internal (I-xx) interfaces, 13 data stores, 14 GUI view modules (G-xx), session Allow-policy model, secrets design, sigma-based behavior baselines/anomaly scoring, Parameter Catalog and meta-metrics, research capture/export, V1→V2 traceability. Assumes external curation system + signed Trusted MCP Server Library; reference harness adapters are in scope (E-33) | Allocation baseline for SRS V2; proposed, not implemented |
| `MCP_Gateway_Security_SRS.md` | Security-control SRS, V1 (renamed from `MCP_Gateway_SRS.md`); 150 hierarchical controls; root of security MUSTs | Parent of all SR requirements in the implementation SRS |
| `Secure_MCP_Gateway_SRS.md` | Implementation SRS V1.1 draft (2026-10-16): open-source tech stack; 287 functional (FR) and 158 security (SR) requirements allocated to ArchitectureV2 elements/functions/interfaces; SR parented to security-SRS MUSTs; coverage, allocation and index appendices. **Generated — edit `srs_build/`** | Coding baseline (draft, pending owner review) |
| `srs_build/` | Requirement source records (`req*.txt`), front matter, appendices and `gen.py` validator/generator for `Secure_MCP_Gateway_SRS.md` | Edit sources here and rebuild; see `srs_build/README.md` |
| `Skills.md` | Requirement-development skill (INCOSE GtWR + project MUST/SHALL rules) | Use when creating or refining requirements |
| `mcp-spec/` | Unmodified local reference copy of the official MCP specification, latest released version 2026-07-28 (spec MDX, `schema.ts`/`schema.json`, examples, upstream LICENSE); `README.md` records source, commit and checksum | Read-only external reference; replace by adding a new version subdirectory |
| `versions/` | Immutable `MCP_Gateway_SRS_V1.md` snapshot and `MCP_Gateway_SRS_V1.validation.json` document-check evidence | Preserve released snapshots; add a new version for later baselines |
| `CHANGELOG.md` | Baseline history and future versioning procedure | Update with each approved document revision |
| `Client-Compatibility-Brief.md` | Client compatibility brief (2026-10-15): what Claude Code, Codex CLI and Hermes expect from an MCP server today, protocol-era support, authentication hooks, and the SRS changes needed to meet them (OAuth 2.1 as primary session mechanism, legacy era in baseline, tool-name limits) | Input to the next SRS revision; sources cited |
| `README.md` | Entry point for the public repository: what the project is, where to start reading, how to rebuild the SRS and the site | Keep in step with FloorPlan |
| `site/` | Static Next.js website that renders the specification: home, architecture, elements, interfaces, requirements explorer, security controls, client brief, full documents. Parses `ArchitectureV2.md`, `srs_build/req*.txt` and `MCP_Gateway_Security_SRS.md` at build time | Rebuild or redeploy after any document change; `npm ci && npm run build` in `site/` |
| `vercel.json`, `.vercelignore` | Vercel deployment configuration for the site (build from `site/`, output `site/out`) | Deployment only; no runtime component |
| `Secure-MCP-Gateway-Research-Brief.md` | Original September 21, 2026 research and recommendations | Preserved unchanged; historical claims require current validation |
| `archive/` | Original `Secure-MCP-Gateway-Architecture.md` and pre-split `architecture-pre-srs-v1-2026-10-04.md` | Historical reference, preserved byte-for-byte; do not edit |
| `work/` | Ignored drafts, candidate/numbered requirement records, generation and validation scripts, prior validation evidence | Intermediate documentation work; not production configuration or runtime test evidence |
| `.git/` | Git history and annotated version tags (`mcp-gateway-srs-v1` marks the SRS V1 baseline) | Remote `origin` = https://github.com/ethan03805/Secure-MCP-Gateway (public) |
| `.gitignore` | Exclusions for work material, secrets, graph data, audit payloads, model weights and source caches | Keep sensitive/runtime artifacts out of documentation history |
| `go.mod`, `go.sum` | Go module `github.com/ethan03805/secure-mcp-gateway` for the Gateway implementation | Build with `go build ./...`; test with `go test ./...` |
| `cmd/` | `smcpd` (the Gateway daemon) and `smcpctl` (bootstrap, config validate, journal verify, health, hash-password) | First vertical slice; see README |
| `internal/` | Gateway packages by element: `edge` (E-01, E-02, E-08, E-12), `session` (E-03, E-04, OAuth 2.1), `policy` (E-05, E-06), `backend` (E-10, E-14, E-15), `audit` (E-21), `keys` (E-22), `config` (FR-12.6 with `config.schema.json`), `reqtest` (requirement tagging), `e2e` (end-to-end tests with an in-binary backend server) | Implementation of the first slice; each test declares the requirement IDs it verifies (FR-12.10) |
| `tools/reqreport/` | Reads `go test -json` output and writes the requirement-to-test report that CI publishes | FR-12.10 |
| `spikes/` | Throwaway experiments that retire SRS §3.3 stack risks; each has its own `go.mod` and a `README.md` recording the result (`go-sdk-dual-era`: MCP Go SDK serves both protocol eras on one handler in stateless mode) | Evidence for design decisions; not part of the Gateway build |
| `.github/workflows/` | Continuous integration: SRS regeneration check, site build, Go build and tests | Runs on every push and pull request |

Future source/deployment directories shown in the architecture are planned only. No production application, Neo4j database, MCP server, overlay or client configuration was installed or altered by this documentation task.
