# Security Limitations

This document states what the Secure MCP Gateway does not protect against, so that you can decide how far to rely on it. It is required by SRS FR-18.2 and is updated with each release. Where a limitation has a partial mitigation, the mitigation is named; none of them removes the limitation.

## What the Gateway controls

The Gateway mediates MCP tool calls from an agent harness to MCP servers that it launches itself. For those calls it authenticates the harness, decides each call against signed policy, inspects arguments and results, asks a person for approval where policy says so, contains the server (Enforced profile only) and records signed evidence. Everything else an agent can do is outside its control.

## Limitations

### 1. The Standalone profile contains nothing

On macOS, and on Linux without rootless Podman, nftables, cgroup v2 and systemd, the Gateway runs in the Standalone (unconfined) profile. Backend servers run as ordinary child processes with your user's permissions. A malicious or compromised server can read and write any file you can, open network connections, start processes and use as much memory and CPU as the operating system allows.

- **Consequence:** sandbox, egress and resource controls (SR-4.5-1, SR-4.6-1, SR-4.7-1, SR-4.7-2, the Egress Broker) do not apply. Appendix L rows HF-20 to HF-24 are not defended.
- **Mitigation:** servers classified `high` risk are refused in this profile (SR-4-1); health always reports `degraded` with cause `unconfined`; every release built for this profile is labelled "not enforced" (FR-13.10).

### 2. The agent runs as the Gateway's own user in the Standalone profile

In the Standalone profile the agent harness and the Gateway run under the same operating-system account. The agent's own file and shell tools can read the Gateway's keys, policy, journal and the harness credential file, and can stop or reconfigure the Gateway.

- **Mitigation:** the per-client lockdown profiles deny the client's own file tools access to the Gateway paths where the client supports such rules (FR-15.1, FR-15.2), and `smcpctl doctor` reports the paths that remain readable (FR-15.4). These rules are enforced by the client, not by the operating system.

### 3. Non-MCP tools bypass the Gateway

An agent's built-in tools (shell or terminal, file editing, web browsing, web fetch, code execution, and vendor connectors) do not go through MCP and never reach the Gateway. This is true of every client in the matrix, and it is the main way an agent can act outside the Gateway's policy.

- **Mitigation:** the lockdown profiles restrict which MCP servers a client loads; they do not disable built-in tools. Use each client's own permission settings to restrict or disable built-in tools.

### 4. Lockdown is only as strong as each client's settings enforcement

Lockdown profiles use each client's own configuration controls (Appendix K of the SRS). Some clients have no administrator-level MCP allowlist, and some vendors state that their allowlists match server names and are not a security boundary. A user, or an agent with shell access, may be able to edit the client's configuration.

- **Mitigation:** clients are labelled `exclusive-gateway` only after passing the bypass tests at their pinned version (SR-4.13-1); all others are labelled `gateway-available`.

### 5. Cloud agents: the tunnel provider sees your traffic

In the Remote Access profile the tunnel provider (Cloudflare, Tailscale, or the agent vendor's tunnel) terminates the public TLS connection. It can read and modify requests and results between the cloud agent and your computer. The client address it forwards is recorded as a claim of the provider, not a verified fact (FR-16.8).

- **Mitigation:** OAuth tokens bound to approved clients, strict rate limits, lockout and request bounds apply to every remote request (FR-16.5 to FR-16.7, SR-4.14-2). Choose a provider you are willing to trust with the content of your tool calls.

### 6. Cloud agents: the vendor's machine is not under your control

A cloud agent runs on the vendor's computer. Installing the Gateway inside that computer is not a control, because the agent controls it. The vendor's administrative MCP allowlist, where one exists, is the only thing that keeps the agent from using other MCP servers; the cloud agent's own browser, terminal and connectors do not pass through the Gateway.

### 7. Detection filters are heuristics

The secret-fingerprint, injection, PII, Unicode-control and metadata filters match versioned rule sets. Each rule set has measured false-positive and false-negative rates on its labelled corpus (FR-19.5); rates on real traffic will differ. The current rates are in [filters.md](filters.md#labelled-corpora-and-measured-rates-fr-195). A determined attacker can phrase content to avoid any fixed rule set.

### 8. Prompt-injection findings are tags only

In v1, `injection-detect` and `injection-marker` findings are recorded as tags and observation values and do not block or withhold anything (FR-4.17). The deterministic controls that act on untrusted content are session taint (SR-5.13-2), which requires approval for or denies writing and external tools after a session has read untrusted content, and the optional delimiting obligation (FR-4.18).

### 9. Approval depends on the person approving

An approval is only as good as the decision behind it. The approval view shows the exact tool, server revision, arguments and decisive rules (FR-3.18), but it cannot tell whether an action is wise. Desktop notifications deliberately omit arguments (FR-3.23); open the console or `smcpctl approvals show` to see them.

### 10. Signed does not mean safe

A package signature shows who packaged a server and that it has not changed since. It does not show that the server's code is benign. The operator's packaging run reads the server's tool list; it does not review its source.

### 11. Scope limits

- Remote (hosted) MCP servers cannot be used as backends in v1 (FR-14.4).
- Only MCP tools are relayed. Resources and prompts are refused (SR-5.6-1); sampling, elicitation and roots requests from servers are refused (`-32601`, or `-31010` for an `InputRequiredResult`); the MRTR Relay Profile that would relay them is not implemented.
- Windows is not supported.

### 12. Known gaps in release 1.0

These are requirements release 1.0, and the main branch after it, do not meet in full; [verification/gap-list.md](verification/gap-list.md) tracks them.

- **Remote Access host rules on macOS (SR-4.14-1):** in the Enforced profile `smcpctl remote enable` installs nftables rules that drop non-loopback connections to the Gateway ports. macOS runs only the Standalone profile and has no nftables; the Gateway still binds loopback only, and [remote-access.md](remote-access.md#host-rules) gives a pf anchor that you load yourself.
- **Secret copies in memory (SR-2.13-2, RR-11):** the Secret Broker overwrites its byte buffers after each delivery, but Go strings cannot be overwritten: the S4 environment value (and the `NAME=value` entry built for the child process), the header the Egress Broker sets on each S1 request and the age library's decryption buffers stay in the Gateway's memory until it is reused. Prefer S1 to S3 over S4.
- **Command-configured servers (SR-3.6-1, RR-12):** the content address recorded at the first launch covers the command file and file arguments named by absolute path, not modules an interpreter loads from its search path or files the server reads later. Package the server to have its whole tree verified before each launch.
- **Egress capabilities in the Standalone profile (security review RR-09):** one-use egress capabilities are in the server's memory, so another process of the same user can use them while the call runs; a server configured with `[egress] require_capability = false` is authorized by instance and grant only.
- **Unpackaged servers (RR-10):** egress grants are checked against a manifest only for packaged servers; set `[packages] require_signed = true` to refuse unpackaged ones.
- **Session state:** sessions, taint, rate windows and quotas are kept in memory; a restart ends every session (FR-2.16), so harnesses sign in again.
- **Performance:** the FR-11 budgets have been measured on CI runners only, not on recorded reference hardware.
- **No SELinux module:** the Enforced profile ships AppArmor profiles for `smcpd` and for image-less servers (`smcp-server`). Servers that run from an image have only the container runtime's default confinement, and on a host with SELinux instead of AppArmor no host policy module confines `smcpd`; `[[runtime.server]] selinux_type` only passes a type to Podman.
- **Graph engine firewall (SR-4.2-1, SR-7.4-1):** the optional Neo4j engine is reached on loopback only, but no nftables rule limits the engine port to the Data Server or denies the engine outbound connections.
- **One identity for the Secret Vault and the Secret Broker (SR-2.13-3):** both run inside `smcpd` under one service identity (`smcp-core` in the Enforced profile). Every other CP-46 identity is denied read access to the vault, which the linux-integration job checks; a compromise of `smcpd` itself exposes the vault.
- **One identity for the Gateway's components (SR-4.1-1):** the Data Access Service, the vault and Secret Broker, the evidence exporter, the key manager and the console are packages of the one `smcpd` process and run as `smcp-core`. `smcpctl install` creates `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data` and `smcp-console`, but no process runs as them yet. The separation release 1.x enforces is between `smcpd` (`smcp-core`) and the servers (`smcp-srv` and its subordinate UIDs).
- **Cloud agents not exercised:** live cloud-agent runs are descoped from release 1.x (FR-15.9, FR-16.10). No cloud agent (Grok Bot, ChatGPT agent, Meta Muse) has a dated run through the Remote Access Profile, and the quick starts name a vendor allowlist setting only where the vendor's public documentation names one (`docs/clients/cloud-agents.md`, reviewed 2026-10-18). The Remote Access Profile itself is tested with a local tunnel stand-in, a recorded tunnel provider run (AT-18) and the conformance suite relayed through `smcp-connect` and a test tunnel (FR-16.9).
- **Release archives without cgo:** the archives are built with `CGO_ENABLED=0`, so the Observation Store uses JSON Lines and research exports cannot be written as Parquet. Build from source with cgo for DuckDB and Parquet.

### 13. Trusted computing base

The host operating system, its administrator, the Gateway binaries and the trust-anchor store are trusted (ARCH A-4). A person with administrator access to the host can change or disable every control and can delete evidence that has not been exported.

## Reporting a limitation that is not listed

See `SECURITY.md` at the repository root.
