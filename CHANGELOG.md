# MCP Gateway documentation changelog

## Unreleased — SRS V1.1 draft, architecture V2.2 draft — 2026-10-16

Harness interface revised to match what shipping clients can do (`Client-Compatibility-Brief.md`). No snapshot or tag yet; this is a draft for owner review.

- OAuth 2.1 is the baseline framework credential and session mechanism. The access token is the session. New FR-2.17 to FR-2.22; FR-2.2, FR-2.5, SR-2.1-1, SR-2.1-2, SR-2.3-1 and SR-2.11-1 revised; CP-23 and CP-41.
- mTLS becomes the optional mTLS Harness Profile (FR-2.14, SR-2.8-2). The OAuth Profile and Legacy Northbound Profile rows are removed because both are now baseline.
- Both protocol eras are served in the baseline (CP-04, FR-1.16, FR-1.17, FR-1.46, SR-5.1-1, SR-5.3-1).
- Reference adapters enter the system of interest: E-33 Harness Adapter Kit, F-94, F-95, X-12 in the architecture; FR-12.12 `smcp-session`, FR-12.13 `smcp-stdio`, SR-2.3-2 and CP-43 in the SRS; FR-1.48 now requires an X-12 ICD.
- Public tool names limited to 64 characters with `_` as separator (FR-1.26, FR-1.49, CP-42).
- Architecture document-control row V2.2; OD-2 decided; A-2 and X-01 revised; the Section 8.3 sequence-diagram note fixed so it parses.
- Client-facing hints from the brief §4.5: new FR-1.50 sets `anthropic/requiresUserInteraction` on approval-obligated tools; FR-5.22 extended with the property-name drift rule.
- SRS §3.3 risk 1 (Go SDK dual-era service) retired by `spikes/go-sdk-dual-era/`; FR-1.46 reworded to match (no `Mcp-Session-Id` required for 2025-11-25 clients).

## Implementation — first vertical slice — 2026-10-16

First Gateway code: Go module with `smcpd` and `smcpctl`. OAuth 2.1 sessions, policy decisions, session-scoped catalogs, stdio dispatch and a signed evidence journal, on both protocol eras through the MCP Go SDK. 70 requirements are claimed by passing tests; the README lists what the slice leaves out. Implementation changes are recorded here from now on alongside document baselines.

## SRS V1 / architecture 2.0 — 2026-10-04

First separate system requirements specification: `MCP_Gateway_SRS.md`, with an immutable byte-identical snapshot at `versions/MCP_Gateway_SRS_V1.md`. The local annotated Git tag `mcp-gateway-srs-v1` identifies this baseline and its matching architecture.

- Split the former combined document into design/integration procedures and a normative SRS.
- Defined 150 hierarchical requirements, including 122 MUST control statements, source traceability, one verification method per requirement, and 21 acceptance scenarios.
- Selected Neo4j Community Edition for authoritative policy, routing and audit metadata, replacing the prior Casbin/SQLite authorities. Documented CE limits, deterministic graph evaluation, denial semantics, immutable version links, dispatch/revocation ordering and independently protected audit evidence.
- Specified GUI inspection of server source, licenses, build provenance, tool manifests, policy explanations and linked audits.
- Curated 11 local engineering server candidates or explicitly proposed adapters, with primary source/license references, containment restrictions and admission gates. None is represented as installed or admitted.
- Retained detailed Hermes gateway-only procedures and the qualified scope for Headscale, Codex CLI and Grok Bot feasibility.
- Preserved the previous combined architecture without byte changes at `archive/architecture-pre-srs-v1-2026-10-04.md`. The September architecture and research brief remain unchanged.
- Initialized local Git history with the pre-split baseline followed by this revision. No remote repository or push is required or configured by this task.

Validation evidence is in `versions/MCP_Gateway_SRS_V1.validation.json`. Document checks and research reviews do not establish runtime security or implementation compliance.

## Combined architecture 1.0 — 2026-10-04

Accepted and expanded the earlier research into a combined architecture/specification with Hermes integration, OSS licensing, GUI administration, security controls and acceptance procedures. This document is retained in the archive and in the initial local Git commit.

## Historical inputs — 2026-09-21

The original `Secure-MCP-Gateway-Architecture.md` is preserved in `archive/`. The original `Secure-MCP-Gateway-Research-Brief.md` remains at the project root.

## Future revision procedure

1. Edit the active SRS and architecture with impact/source/verification updates; preserve IDs for unchanged requirements and record retirements or replacements.
2. Assign the next SRS version, update the architecture revision and cross-references, and create a new immutable SRS snapshot under `versions/`.
3. Validate requirement structure, source traceability, example syntax and snapshot identity; retain the validation record.
4. Commit the complete matching baseline locally and add its version tag, such as `mcp-gateway-srs-v2`.
5. Leave V1's snapshot and tag unchanged. Keep secrets, database dumps, audit payloads and live runtime data out of Git.
