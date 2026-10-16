# Secure MCP Gateway

A local reference monitor and research instrument for agentic frameworks that use the Model Context Protocol. The Gateway decides what a tool call may do before any server code runs, contains and watches the server while it runs, and inspects what comes back before the agent sees it. It records enough about every call to learn what normal looks like, so the same system doubles as an instrument for studying how agents use tools.

**Status:** specified; first vertical slice implemented. The repository holds the architecture, the security-control baseline, a generated implementation SRS, and a Go implementation of the first slice: OAuth 2.1 sessions, policy decisions, dispatch to stdio MCP servers and a signed evidence journal. See [Running the first slice](#running-the-first-slice) for what it does and does not yet do.

**Website:** the specification is rendered at the project site (see `site/`). Every count, element page and requirement on the site is read from the documents in this repository at build time.

## Start here

| Read | For |
|---|---|
| `ArchitectureV2.md` | The logical decomposition: 10 subsystems, 32 elements, 93 functions, 50 interfaces, 13 data stores, the session Allow-policy model, secrets design and the anomaly method |
| `Secure_MCP_Gateway_SRS.md` | The implementation baseline: 434 SHALL requirements allocated to the architecture. Generated from `srs_build/`; edit the sources, not the output |
| `MCP_Gateway_Security_SRS.md` | The 150 security controls that parent every security requirement |
| `Client-Compatibility-Brief.md` | What Claude Code, Codex CLI and Hermes expect today, and where the specification must change to meet them |
| `architecture.md` | The problem-space analysis behind the design: threats, Neo4j Community Edition limits, protocol pitfalls, race control |
| `FloorPlan.md` | What every file in the repository is for |
| `CHANGELOG.md` | Baseline history and the revision procedure |

## Running the first slice

The slice is the path a tool call takes from a harness to a backend server and back, with the controls the SRS puts on that path. It runs on macOS and Linux; the sandbox, egress broker and systemd packaging (FR-12.3 to FR-12.5) are not yet implemented, so backend servers run as plain subprocesses.

```
go build -o build/ ./cmd/...
./build/smcpctl bootstrap --dir ~/smcp --admin-password '<at least 12 characters>'
./build/smcpd --config ~/smcp/smcp.toml
```

`bootstrap` writes `smcp.toml` (listener, administrator, principals, OAuth clients, backend servers), `policy.json` (framework profiles and session allow templates) and `state/` (a local CA and listener certificate, the Ed25519 evidence key, the journal). The example configuration launches the reference filesystem MCP server over `npx` on a sandbox directory and grants a read-only template by default.

To connect Claude Code:

```
export NODE_EXTRA_CA_CERTS=~/smcp/state/tls/ca.crt
claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
```

Claude Code discovers the Gateway's OAuth metadata, opens a browser, and the Gateway's sign-in page asks for the administrator password. The token it receives is the Gateway session (FR-2.20); the tools it lists are exactly those the session's template permits (SR-5.4-1), named `<alias>_<tool>` (FR-1.26).

Other commands: `smcpctl config validate`, `smcpctl health`, `smcpctl journal verify` (checks the hash chain and signatures of the evidence journal, FR-7.5) and `smcpctl hash-password` (for confidential client secrets used by the session API, FR-2.2).

### What the slice implements

| Area | Elements | Implemented |
|---|---|---|
| Harness listener | E-01 | TLS 1.3 loopback listener, POST-only MCP endpoint, body and header bounds, Host and Origin checks |
| Protocol | E-02 | Both protocol eras on one endpoint through the MCP Go SDK (stateless mode), method allowlist, cache hints, Gateway error codes with `reasonCode`, `correlationId`, `decisionId` |
| Identity and sessions | E-03, E-04 | OAuth 2.1 authorization server (metadata, PKCE, `resource`, `iss`, administrator sign-in, refresh), session API, bearer authentication on every request, lifetimes and per-principal limits, scope-to-template mapping |
| Policy | E-05, E-06 | Schema-validated policy file with framework profiles and allow templates, compiled snapshot, default deny, decision records, sliding-window rate limits |
| Enforcement | E-08, E-09, E-12 | Session-scoped catalog, approval hint on tools, schema-validate request filter, one-use launch capability, pre-launch and pre-release rechecks, emergency stop, provenance metadata |
| Dispatch | E-10, E-14, E-15 | stdio backend launch with an environment allowlist, live tool list as the server revision, public-name derivation and collision refusal, concurrency and queue bounds, upstream timeout, result size bound, backend error mapping, bounded stderr capture |
| Assurance | E-21, E-22 | Mandatory event floor to a signed, hash-chained JSON Lines journal; local CA, listener certificate and evidence key; Argon2id password hashing |
| Build | FR-12.6, FR-12.10 | TOML configuration validated against a published JSON Schema; every test declares the requirement IDs it verifies and CI publishes the requirement report |

### What it deliberately does not do yet

- No signed packages or manifests (E-13): tools come from the live backend. No sandbox (E-16), runtime monitor (E-17) or egress broker (E-18): backends are ordinary subprocesses with an allowlisted environment.
- No Approval Service (E-07): a call whose template requires approval is refused with `-31002`.
- No Data Server (SS-9), observation, baselines or research export (SS-10), management console (E-24), secrets (SS-6) or health monitor beyond `/healthz`.
- Backend instances are shared across sessions (FR-5.10 defaults to per session). Progress relay (FR-1.39) and the UDS listener (FR-1.47) are not implemented.
- Keys are files with mode 0600; TPM sealing and passphrase encryption (FR-7.9) are not implemented.
- `smcpctl` lacks emergency stop, backup and restore, which need the admin listener.

The requirement report (`build/reqreport.md` after `go test -json ./... | go run ./tools/reqreport -out build/reqreport`) lists every requirement a test claims to verify and its result.

## Rebuilding the SRS

```
python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md
```

The build fails on any traceability error and warns on coverage gaps against the architecture and the security SRS.

## Building the website

```
cd site
npm ci
npm run build      # static export to site/out
npm run dev        # local preview
```

The site is a static Next.js export. It parses `ArchitectureV2.md`, `srs_build/req*.txt` and `MCP_Gateway_Security_SRS.md` directly, so a change to any of them changes the site on the next build. Deployment is configured by `vercel.json` at the repository root.

## Reference material

`mcp-spec/` is an unmodified copy of the MCP specification release 2026-07-28, kept for citation. `versions/` holds immutable snapshots of released baselines. `archive/` holds superseded documents, preserved byte for byte.
