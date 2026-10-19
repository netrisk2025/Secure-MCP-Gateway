# MCP Servers — FloorPlan

Updated: 2026-10-18 (phases 3 to 9: every element wired into `smcpd`, the hostile fixture suite, the console with every Appendix C role and the OpenAPI description, the acceptance, conformance and performance suites with Enforced results for every scenario, the release pipeline with the Homebrew tap, its verification workflows, release provenance files and the SBOM license check, the Enforced profile installer, runbook execution records, site chapters for status, install and agents; release v1.0.0 published)

Scope: this repository (`Secure-MCP-Gateway`). This map covers every top-level path and the main subdirectories. Paths are relative to the repository root.

## Top level

| Path | Contents | Access / purpose |
|---|---|---|
| `README.md` | Entry point: what the product is, status, v1 scope, profiles, install, quick start, where the documentation is, how to verify | Keep in step with this file; the site takes its opening paragraph |
| `LICENSE` | Apache License 2.0, full text | Project license |
| `SECURITY.md` | How to report a vulnerability, supported versions, scope, release signing key | Public security policy |
| `CHANGELOG.md` | Baseline and implementation history with the reason for each change; revision procedure | Update with each change, under the top in-progress heading |
| `ArchitectureV2.md` | Architecture V2.3: subsystems, elements E-01 to E-33, functions, external and internal interfaces, data stores, GUI view modules G-01 to G-14; session Allow-policy model, secrets design, behavior baselines and anomaly scoring, Parameter Catalog, platform profiles, policy and evidence authority, Remote Access profile | Allocation baseline for the SRS; implementation state per element is in `docs/status/elements.json` |
| `Secure_MCP_Gateway_SRS.md` | Implementation SRS V1.2: technology stack, platform and conditional profiles, requirements (FR and SR) allocated to the architecture, appendices A to M (controlled parameters, error and reason codes, roles, graph mirror model, coverage, allocation, index, set checks, manifest schema, client matrix, hostile fixtures, acceptance mapping). **Generated — edit `srs_build/`** | Coding baseline |
| `srs_build/` | Requirement source records (`req*.txt`), front matter, appendices (`appendix.md`, `appendix2.md`) and `gen.py`, the validator and generator for `Secure_MCP_Gateway_SRS.md` | Edit sources here and run `make srs`; see `srs_build/README.md` |
| `MCP_Gateway_Security_SRS.md` | Security-control SRS V1: hierarchical controls; root of every SR; Appendix B acceptance scenarios AT-01 to AT-21 | Parent of all SR requirements |
| `Client-Compatibility-Brief.md` | What each supported client expects from an MCP server: protocol eras, authentication hooks, lockdown mechanisms, and the cloud agents | Evidence for the client matrix (SRS Appendix K) |
| `architecture.md` | Architecture revision 2.0: problem-space analysis, Neo4j CE design, data flows, licenses, engineering server catalog | Background and rationale; superseded as an allocation baseline by `ArchitectureV2.md` |
| `Skills.md` | Requirement-development skill (INCOSE GtWR plus project MUST/SHALL rules) | Use when creating or refining requirements |
| `Secure-MCP-Gateway-Research-Brief.md` | Original September 21, 2026 research and recommendations | Preserved unchanged; historical claims need current validation |
| `go.mod`, `go.sum` | Go module `github.com/ethan03805/secure-mcp-gateway` | `go build ./...`, `go test ./...` |
| `Makefile` | `make check` (what the required CI jobs check, including the site unit tests), `make status` (requirement report), `make integration`, `make hostile`, `make conformance`, `make openapi`, `make vuln`, `make srs`, `make site` (build plus page and link check), `make console`, `make console-e2e`, `make release-snapshot` | Developer and CI entry points |
| `install.sh` | Release installer: detects OS and architecture, downloads the archive and checksum file, verifies the checksum file's minisign signature (and its Sigstore bundle when cosign is installed) and the archive's SHA-256, installs the binaries | Users; see `docs/install.md` |
| `.goreleaser.yaml` | Release archives for linux and darwin, amd64 and arm64, with all seven binaries, an SBOM per archive, the build recipe, lockfiles, `PROVENANCE.md` and `THIRD_PARTY_NOTICES.txt` in each archive, the minisign-signed checksum file and the Homebrew formula | Run by `release.yml` and `make release-snapshot` |
| `.golangci.yml` | golangci-lint v2 configuration; every exclusion states why it exists | Read by the `lint` CI job |
| `vercel.json`, `.vercelignore` | Vercel deployment configuration for the site | Deployment only |
| `.gitignore`, `.gitattributes` | Exclusions for local work, secrets, runtime state, build output and agent worktrees; generated-file marks, `CHANGELOG.md` union merge, LF endings for shell scripts | Repository hygiene |
| `.git/` | Git history and tags (`mcp-gateway-srs-v1` marks the SRS V1 baseline) | Remote `origin` = https://github.com/ethan03805/Secure-MCP-Gateway |

## Code

| Path | Contents | Access / purpose |
|---|---|---|
| `cmd/smcpd/` | The Gateway daemon: builds every component from the configuration and wires the optional elements (approvals, secrets, egress, sandbox, packages, console, graph, analytics, remote access, operations) | Binary |
| `cmd/smcpctl/` | Command-line tool. Offline: bootstrap, config validate and migrate, journal verify and export, hash-password, package, trust, filters, restore, upgrade, uninstall, version. Control API: health, reload, keys, backup, stop, resume, policy, approvals, graph, observe, admin redeem, egress, runtime, secrets, remote, clients, lockdown, doctor | Binary; `smcpctl --help` lists every command |
| `cmd/smcp-refserver/` | Read-only reference MCP server packaged by `smcpctl bootstrap` as the example backend | Binary |
| `cmd/smcp-session/`, `cmd/smcp-stdio/`, `cmd/smcp-connect/` | Harness adapters (E-33): header helper, local stdio relay, remote relay with device sign-in | Binaries; see `docs/adapters.md` |
| `cmd/smcp-workload/` | FR-11 reference workload: generates the reference dataset and measures decision latency, P-213 overhead, observation overhead, console query latency and idle memory against real `smcpd` instances | Shipped in the release archives; run by the CI job `perf`; see `docs/acceptance.md` |
| `cmd/smcp-hostile/` | Hostile backend MCP server that serves any SRS Appendix L fixture | Test binary for the hostile suite; never package it for real use; see `docs/hostile-fixtures.md` |
| `internal/` | Gateway packages, one or more per element. `internal/README.md` maps each package to its elements, names the extension points and lists residual gaps | Implementation; each test declares the requirements it verifies, fully or partly (FR-12.10) |
| `internal/edge`, `pipeline`, `backend`, `app`, `config`, `profile`, `channel` | Harness listener and call pipeline (E-01, E-02, E-08, E-12), seams, dispatch (E-10, E-14 part), wiring, configuration schema, profile decision, request origin | Core |
| `internal/session`, `authguard`, `remote` | OAuth 2.1 sessions (E-03, E-04), sign-in rate limits and lockout, Remote Access listener (FR-16) | Identity |
| `internal/policy`, `policystore`, `policyadmin` | Decisions, taint, rates and quotas (E-06); signed Policy Store and publication (E-05) | Policy |
| `internal/approval` | Approval Service (E-07) | Approvals |
| `internal/filters` | Request and response filters, rule sets, corpora, metadata scan (E-09, E-11) | Inspection |
| `internal/packaging`, `library` | Package formats, build, signing, trust anchors (E-13); library, registry, verified manifests (E-13, E-14) | Server admission |
| `internal/sandbox`, `egress` | Rootless Podman launcher and Runtime Monitor (E-15 to E-17); Egress Broker (E-18) | Containment |
| `internal/secrets` | Secret Vault and Secret Broker (E-19, E-20) | Secrets |
| `internal/audit`, `keys`, `health`, `metrics`, `backup`, `ops`, `diag` | Evidence journal (E-21), keys and certificates (E-22), health monitor and metrics (E-23), backup, operations routes, diagnostic log | Evidence and operations |
| `internal/adminapi`, `consoleapi`, `consoleauth`, `openapi`, `filterapi`, `principals`, `obspolicy` | Control API base, the Appendix C role matrix, cookie sessions and per-object `If-Match` revisions; console backend routes; console accounts and sign-in; `GET /api/v1/openapi.json`; filter workbench routes; principal directory and OAuth client credentials (G-11); published observation objects (G-03, G-04, G-06, G-08) (E-24) | Control plane |
| `internal/graph` | Neo4j graph mirror (E-25, E-26, E-28 graph part) | Data Server |
| `internal/observe`, `obsstore`, `baseline`, `anomaly`, `research`, `analytics` | Observation Collector (E-29), Observation Store (E-27), baselines (E-30), anomaly scoring (E-31), research exports (E-32), SS-10 wiring | Observation and analytics |
| `internal/adapter`, `harness`, `tunnel` | Adapter credential file and relays; client setup, lockdown and doctor; tunnel drivers (E-33) | Harness integration |
| `internal/ids`, `reqtest`, `gwtest`, `testport`, `e2e`, `posixacl` | Identifiers and secrets; requirement and acceptance-scenario claims in tests; a full Gateway for tests; loopback ports reserved across test processes; end-to-end tests over TLS; POSIX ACL entries for per-instance secret files (Linux) | Shared and tests |
| `internal/acceptance` | Acceptance scenarios of SRS Appendix M as tests of the real binaries; `SMCP_ACCEPTANCE_PROFILE=enforced` runs them in the Enforced profile | FR-19.3, FR-19.4; the `go`, `graph`, `acceptance-enforced` and `offline` CI jobs; see `docs/acceptance.md` |
| `internal/conformance` | MCP conformance suite (tests only): a complete Gateway over a scripted backend, driven with the message examples of `mcp-spec/2026-07-28/schema/examples` and validated against `schema.json` | FR-12.9; `make conformance` |
| `internal/perf` | Reference dataset and workload behind `cmd/smcp-workload` | FR-11; CI job `perf` |
| `internal/hostile` | Hostile fixture catalog and server, and the suite (build tag `hostile`) that runs the Gateway against every Appendix L row and writes `build/hostile.{md,json}` | FR-19.1, FR-19.2; `make hostile` and the CI job `hostile` |
| `console/` | Management console (E-24): React, TypeScript and Vite from hand-built components (`src/`), Playwright acceptance tests (`e2e/`), committed build `dist/` embedded into `smcpd` by `embed.go` | `make console` rebuilds `dist/`; `make console-e2e` runs Playwright |
| `tools/reqreport/` | Reads `go test -json` output and the coverage profile and writes `build/reqreport.{json,md}` and `build/status.json` | FR-12.10; run by `make status` and CI |
| `tools/sbomcheck/` | Checks that every entry of a release SBOM has a license that is OSI-approved, public domain or reviewed per package in `packaging/sbom-review.json` | FR-12.1; run by the release workflow over the archives' SBOMs |
| `tools/provenance/` | Writes `PROVENANCE.md` (source commit, Go toolchain, build run, recipe digests) and `THIRD_PARTY_NOTICES.txt` (license files of every linked Go module, the Go standard library and the bundled console npm packages) into each release archive | FR-12.8; run before the GoReleaser build |
| `tools/installsh/` | Tests of `install.sh` through a local HTTPS server with test keys (intact release, modified archive or checksum file, other key, missing signature) | FR-13.2 |
| `tools/openapi/` | Writes `site/data/openapi.json`, the control API's OpenAPI document with the roles of each route, from `internal/openapi` and the route registrations in the Go sources; its test fails when the committed file is stale | FR-8.1; `make openapi`, and the regenerate workflow on pull requests |
| `spikes/` | Experiments that retire SRS §3.3 stack risks; each has its own `go.mod` and a `README.md` recording the result | Evidence for design decisions; not part of the Gateway build |

## Packaging and scripts

| Path | Contents | Access / purpose |
|---|---|---|
| `packaging/homebrew/` | Homebrew formula template, rendered by hand with `scripts/render-brew-formula.sh`; the release workflow writes the formula to the tap `ethan03805/homebrew-tap` with GoReleaser | Release only; the `tap` workflow installs from the tap and compares the binaries with the release archive |
| `packaging/sbom-review.json` | Reviewed license exceptions for the SBOM check, one entry per package with the reason | Read by `tools/sbomcheck` |
| `packaging/linux/` | `install-enforced.sh` (prepares a Linux host for the Enforced profile: identities including `smcp-srv`, subordinate IDs, directories, nftables, AppArmor, systemd), `systemd/` units, `nftables/smcp.nft`, the AppArmor profiles; embedded in `smcpctl` for `smcpctl install --profile enforced` | Run as root on the Gateway host; see `docs/enforced-profile.md` and `docs/sandbox.md` |
| `packaging/npm/smcp-connect/` | npm package of `smcp-connect` with no dependencies, and its tests | Published for cloud-agent machines (`npx smcp-connect`) |
| `packaging/reference/` | Recipes and lock files for the reference servers (filesystem, memory, git, fetch) | Input to `smcpctl package build` and `scripts/build-reference-packages.sh` |
| `scripts/` | CI and maintenance scripts: end-to-end integration run (`ci-integration.sh`) and its MCP test client (`itest-client/`), the hostile sandbox probe server (`sandbox-probe/`), egress namespace test, Enforced install under real systemd (`ci-systemd.sh`), Standalone install with launchd or a systemd user manager (`ci-install-standalone.sh`), the offline acceptance run (`ci-offline.sh`), the release SBOM (`release-sbom.sh`), reference package build, npm audit gate, status publishing, site redeploy trigger, merge queue, PR auto-update, Homebrew formula rendering | Run by CI and maintainers; see `scripts/README.md` |
| `scripts/agents/` | Real-agent conformance suite: bootstraps a Gateway, signs real agent CLIs in, drives one prompt per scenario and judges each from the journal; `install-clis.sh` and `publish.sh` for the workflow | `go test ./scripts/agents`; the "Real agents" workflow; see `docs/agents-conformance.md` |
| `.github/` | Workflows: `ci.yml` (required jobs srs, go, lint, site, security, linux-integration, console; also install-standalone, console-enforced, graph, hostile, perf, acceptance-enforced, offline and the status publisher), `agents.yml` (Real agents), `reference-packages.yml`, `release.yml` (archives, signatures, SBOMs, release label), `tap.yml` (Homebrew tap install check), `regenerate.yml`, `auto-update.yml`; PR template, CODEOWNERS, Dependabot configuration, reviewed npm audit allowlist | Runs on every push and pull request |

## Documentation

| Path | Contents | Access / purpose |
|---|---|---|
| `docs/README.md` | Index of the documentation set | Start here |
| `docs/install.md`, `quickstart.md`, `operator-guide.md` | Install, upgrade, rollback and removal; first run; day-2 operation | FR-18.1, FR-18.4 |
| `docs/policy-reference.md`, `packaging-guide.md`, `troubleshooting.md`, `security-limitations.md` | Policy document and store; server packaging; error and reason codes; what is not protected | FR-18.5, FR-18.6, FR-18.7, FR-18.2 |
| `docs/release-checklist.md`, `acceptance.md`, `security-review-2026-10.md` | Release procedure; acceptance scenarios, release label and performance measurements; the pre-release security review | FR-13, FR-19.3, FR-19.4, FR-11 |
| `docs/icd/` | Interface control documents X-01 (harness interface) and X-12 (adapter hooks) | FR-1.48 |
| `docs/approvals.md`, `filters.md`, `secrets.md`, `sandbox.md`, `enforced-profile.md`, `egress.md`, `console.md`, `console-style.md`, `graph.md`, `observation.md`, `remote-access.md`, `adapters.md`, `harness.md`, `agents-conformance.md`, `hostile-fixtures.md` | Reference for each element group | Operators and developers |
| `docs/api/` | Control API routes per element | Integrators |
| `docs/clients/` | One quick start per client of SRS Appendix K, cloud agents, and `matrix.json` (pinned versions and results) | FR-18.3, FR-15.10 |
| `docs/operations/` | Health, logs, metrics, reload, keys, backup, upgrade and uninstall | Operations part of the operator guide |
| `docs/runbooks/` | Emergency stop, revocation, policy rollback, key compromise, backup and restore, key rotation, upgrade rollback | FR-18.8 |
| `docs/flows/` | Mermaid sequence diagrams of eleven flows (tool call, sign-in, approval hold, packaging, enforced sandbox launch, secret delivery, egress, remote access, cloud agent, emergency stop, journal verification), each with the current implementation's differences | Rendered by the site's Flows chapter |
| `docs/verification/` | Verification record format, inspection, demonstration and supporting records counted by `tools/reqreport`, runbook execution records (`runbooks/`), and the gap list | FR-19.4, FR-18.8 |
| `docs/schemas/manifest.schema.json`, `docs/parameters.json` (with `parameters.go`), `docs/status/elements.json` | Manifest schema, Parameter Catalog (embedded in the binaries), element implementation state | Data files checked by `gen.py` |

## Site and reference material

| Path | Contents | Access / purpose |
|---|---|---|
| `site/` | Static Next.js website (https://secure-mcp-gateway-pearl.vercel.app): specification, element and requirement status, console browser results, flows, interfaces, real-agent results with per-agent notes (`docs/clients/matrix.json`), the control API reference (`site/data/openapi.json`), releases and their verification, and every document. Parses `ArchitectureV2.md`, `srs_build/req*.txt`, `MCP_Gateway_Security_SRS.md`, `docs/flows/`, every Markdown file under `docs/` (ordered by `docs/README.md`) and the root documents listed in `site/src/lib/content.ts` at build time; reads `status.json` and `history.json` from the `site-data` branch (falling back to `site/data/*.sample.json`) the release list from the GitHub API and the tap and reference-packages results from `site-data/workflows.json`. `test/` holds unit tests, `scripts/check-out.mjs` the page and link check of the export | `make site`; redeployed after document changes |
| `mcp-spec/` | Unmodified copy of the MCP specification release 2026-07-28 (MDX, `schema.ts`/`schema.json`, examples, upstream license); `README.md` records source, commit and checksum | Read-only reference; add a new version subdirectory to update |
| `versions/` | Immutable `MCP_Gateway_SRS_V1.md` snapshot and its validation evidence | Released snapshots only |
| `archive/` | Original `Secure-MCP-Gateway-Architecture.md` and pre-split `architecture-pre-srs-v1-2026-10-04.md` | Historical reference, preserved byte for byte |
