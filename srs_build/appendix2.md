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
