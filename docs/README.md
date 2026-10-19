# Documentation

User and operator documentation for the Secure MCP Gateway, and the data files that the SRS references. The documentation set is specified by SRS FR-18.

## Scope of v1

- The Gateway relays MCP **tools** only. Resources and prompts are not supported; sampling, elicitation and roots requests from servers are refused (`-32601`, or `-31010` for an `InputRequiredResult`); the MRTR Relay Profile that would relay them is not implemented.
- Backends are **local** MCP servers that the Gateway launches from signed packages. Remote (hosted) MCP servers cannot be used as backends in v1.
- macOS runs the Standalone (unconfined) profile, labelled "not enforced". Server containment requires the Enforced profile on Linux.

## Start here

| Document | For |
|---|---|
| [Install guide](install.md) | install.sh, Homebrew, building from source, the Linux enforced host, upgrade, rollback, uninstall (FR-18.1) |
| [Release checklist](release-checklist.md) | Publishing a release: signing key, secrets, snapshot, tag, post-release verification (FR-13.1 to FR-13.3) |
| [Quick start](quickstart.md) | Bootstrap, start, connect Claude Code or Codex, make a call, approve a held call, verify the journal |
| [Operator guide](operator-guide.md) | Day-2 operation: accounts and roles, approvals, sessions, policy publication, packages, secrets, emergency stop, backups, keys, reload, logs and metrics, upgrade, remote access (FR-18.4) |
| [Security Limitations](security-limitations.md) | What the Gateway does not protect against (FR-18.2) |
| [Security review, October 2026](security-review-2026-10.md) | Findings of the pre-release adversarial review, their fixes and the residual risks |
| [Troubleshooting and reason codes](troubleshooting.md) | Every Appendix B error code and reason code with the next action (FR-18.7) |

## Reference

| Document | Requirement | Contents |
|---|---|---|
| [Policy reference](policy-reference.md) | FR-18.5 | Policy document, evaluation, taint, rates and quotas, the Policy Store, `smcpctl policy` |
| [Packaging guide](packaging-guide.md) | FR-18.6 | Recipes, build, sign, verify, trust anchors, import, enable, revoke; worked example with the reference servers |
| [Tool-call approvals](approvals.md) | FR-3.14 to FR-3.24 | Hold mode, who can decide, `smcpctl approvals`, notifications |
| [Request and response filters](filters.md) | FR-4.4 to FR-4.18, FR-1.52 | Every filter, rule sets and measured rates, `smcpctl filters` |
| [Secrets: vault and broker](secrets.md) | FR-6 | Vault, Secret Use Policy, delivery modes S1 to S4, leak detection |
| [Enforced profile on Linux](enforced-profile.md) | FR-13.5, SR-4.5-1, CP-46 | Installing packaging/linux, smcpd.service under systemd, AppArmor profile, egress for sandboxed servers |
| [Server sandbox](sandbox.md) | FR-12.3, FR-13.5, SR-4.5-1 to SR-4.7-2 | Enforced-profile prerequisites, Linux installer, `[runtime]`, sandbox profile, Runtime Monitor, `smcpctl runtime` |
| [Egress Broker](egress.md) | E-18 | Grants, DNS and address checks, limits, evidence, `smcpctl egress` |
| [Management console](console.md), [console visual rules](console-style.md) | FR-8 | Views, sign-in, roles |
| [Graph mirror](graph.md) | FR-9.1 to FR-9.3, FR-9.18 | Neo4j mirror, catch-up and rebuild, canned queries, `smcpctl graph` |
| [Observation and analytics](observation.md) | FR-10, FR-11 | Collector, store, baselines, anomaly scoring, research exports, `smcpctl observe` |
| [Operations](operations/README.md) | FR-7.11 to FR-7.14, FR-13.7 to FR-13.13, FR-17 | Health, logs, metrics, reload, keys, backup, upgrade, uninstall |
| [Remote Access Profile](remote-access.md) | FR-16 | Tunnel, remote listener, registrations, device sign-in, limits |
| [Harness adapters](adapters.md) | FR-12.12, FR-12.13, FR-16.9 | `smcp-session`, `smcp-stdio`, `smcp-connect`, the credential file |
| [X-01 harness interface ICD](icd/x-01-harness-interface.md) | FR-1.48, FR-12.9 | Listeners (TLS and UDS), both protocol eras, OAuth endpoints and scopes, session API, required headers, error codes, conformance fixtures and the conformance suite (`make conformance`) |
| [X-12 adapter hooks ICD](icd/x-12-adapter-hooks.md) | FR-1.48 | Adapter hooks, credential file and lockdown per supported framework |
| [Client setup, lockdown and doctor](harness.md) | FR-15.1 to FR-15.7 | `smcpctl clients setup`, `lockdown`, `doctor` |
| [Real-agent conformance suite](agents-conformance.md) | FR-15.8, FR-15.10 | `scripts/agents`, the "Real agents" workflow, the broken-build check, known client findings |
| [Hostile backend fixtures](hostile-fixtures.md) | FR-19.1, FR-19.2, Appendix L | `internal/hostile`, `cmd/smcp-hostile`, the CI job "hostile" |
| [Acceptance scenarios, release label and performance](acceptance.md) | FR-19.3, FR-19.4, FR-11, FR-10.2, FR-10.11 | AT-01 to AT-21 and where they run, the release label, `smcp-workload` and the CI job "perf", stage timing spans |
| [Verification records](verification/README.md) | FR-19.4, FR-18.8 | Record format, inspection records ([inspections.md](verification/inspections.md)), runbook execution records and the [gap list](verification/gap-list.md) of unverified requirements |

## Client quick starts (FR-18.3)

[clients/README.md](clients/README.md) is the index. One page per client of SRS Appendix K: [Claude Code](clients/claude-code.md), [Codex CLI](clients/codex.md), [Hermes](clients/hermes.md), [OpenCode](clients/opencode.md), [Gemini CLI](clients/gemini-cli.md), [Goose](clients/goose.md), [Grok Build](clients/grok-build.md), and [cloud agents](clients/cloud-agents.md) through the Remote Access Profile. Each covers connection, sign-in, CA trust, lockdown and `smcpctl doctor`. Results at pinned versions are in [clients/matrix.json](clients/matrix.json).

## Runbooks (FR-18.8)

| Runbook | Use when |
|---|---|
| [Emergency stop](runbooks/emergency-stop.md) | Tool execution must stop now |
| [Package revocation](runbooks/revocation.md) | A server revision or its signing key must be withdrawn |
| [Policy rollback](runbooks/policy-rollback.md) | A published policy is wrong, or the Gateway starts fail-closed with `policy_signature` |
| [Key compromise](runbooks/key-compromise.md) | A key, token, password or secret may be exposed |
| [Backup and restore](runbooks/backup-restore.md) | Taking a backup or restoring one |
| [Key rotation](runbooks/key-rotation.md) | Scheduled rotation of the listener certificate, CA or evidence key |
| [Upgrade rollback](runbooks/upgrade-rollback.md) | Upgrading, or an upgrade rolled back |

FR-18.8 asks for a recorded execution of each runbook against the release commit. Each runbook was executed against a real `smcpd` on 2026-10-17; the records are in [verification/runbooks/](verification/runbooks/FR-18.8.md). `scripts/ci-integration.sh` also runs the backup, restore, rotation and upgrade steps on every pull request.

## Control API

Routes are on the loopback admin listener (default `https://127.0.0.1:8444`), authenticated with the operator token or a sign-in token.

| Document | Routes |
|---|---|
| [api/approvals.md](api/approvals.md) | `/api/v1/approvals*` |
| [api/policy.md](api/policy.md) | `/api/v1/policy*` |
| [api/packages.md](api/packages.md) | `/api/v1/packages*` |
| [api/secrets.md](api/secrets.md) | `/api/v1/secrets*`, `/api/v1/secret-use-policy*` |
| [api/runtime.md](api/runtime.md) | `/api/v1/runtime*` |
| [api/egress.md](api/egress.md) | `/api/v1/egress*` |
| [api/console.md](api/console.md) | `/api/v1/sessions*`, `/api/v1/servers*`, `/api/v1/catalog`, `/api/v1/audit/*` |
| [api/ops.md](api/ops.md) | `/api/v1/health/*`, `/api/v1/keys*`, `/api/v1/backup*`, `/api/v1/config/reload` |
| [api/graph.md](api/graph.md) | `/api/v1/graph*` |
| [api/observation.md](api/observation.md) | `/api/v1/observations*`, `/api/v1/baselines*`, `/api/v1/anomalies*`, `/api/v1/research*` |
| [api/remote.md](api/remote.md) | `/api/v1/remote*`, `/api/v1/clients*` |

## Flows

**[System map](flows/system-map.md)**: the whole product in one flowchart, from installation and start-up through a tool call to its evidence and day-2 operations, with element IDs on every box. On the project site it has pan and zoom, a stage index and an SVG download (`/flows/system-map/`).

Sequence diagrams of the main flows, each with the differences of the current implementation.

| Flow | File |
|---|---|
| System map (whole product, one flowchart) | [flows/system-map.md](flows/system-map.md) |
| Tool call | [flows/tool-call.md](flows/tool-call.md) |
| OAuth sign-in | [flows/oauth-sign-in.md](flows/oauth-sign-in.md) |
| Approval in hold mode | [flows/approval-hold.md](flows/approval-hold.md) |
| Server packaging and admission | [flows/server-packaging.md](flows/server-packaging.md) |
| Enforced sandbox launch | [flows/enforced-sandbox-launch.md](flows/enforced-sandbox-launch.md) |
| Secret delivery | [flows/secrets-delivery.md](flows/secrets-delivery.md) |
| Egress through the broker | [flows/egress.md](flows/egress.md) |
| Remote access: enable and device sign-in | [flows/remote-access.md](flows/remote-access.md) |
| Cloud agent through a tunnel | [flows/cloud-agent-tunnel.md](flows/cloud-agent-tunnel.md) |
| Emergency stop | [flows/emergency-stop.md](flows/emergency-stop.md) |
| Evidence journal verification | [flows/journal-verification.md](flows/journal-verification.md) |

## Data files

| File | Contents | Used by |
|---|---|---|
| [schemas/manifest.schema.json](schemas/manifest.schema.json) | JSON Schema of the server package manifest (SRS Appendix J) | E-13 import, `smcpctl package` |
| [parameters.json](parameters.json) | Parameter Catalog: every observation parameter of ARCH §10.3 with its attributes (FR-10.37); embedded in the binaries by `parameters.go` | E-29, E-27, E-32, G-04 |
| [status/elements.json](status/elements.json) | Implementation state of each element E-01 to E-33: `implemented`, `partial` or `not-started`, with the packages and main gaps | CI status data, project site |
| [clients/matrix.json](clients/matrix.json) | Client matrix with pinned versions and latest results (FR-15.10) | Real agents workflow, quick starts |

The SRS build (`srs_build/gen.py`) checks `parameters.json`, `schemas/manifest.schema.json` and `status/elements.json`. Update `status/elements.json` in the same pull request that changes an element's implementation state.
