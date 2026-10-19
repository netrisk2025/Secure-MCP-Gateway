# System map

The whole Gateway in one flowchart: installation and bootstrap, `smcpd` start-up, server onboarding, client connection, tool listing, one `tools/call` from the harness to the backend and back, the evidence and data that every call leaves behind, and day-2 operations. Each box names the element of `ArchitectureV2.md` that does the work (E-01 to E-33); edge labels carry the data or the decision that passes. Boxes with a dashed border are refusals and error branches; the reason codes are those of `internal/edge` and [the troubleshooting guide](../troubleshooting.md). Cylinders are stores; rounded boxes are people and agents.

The chart describes the code on `main`. Where the code differs from the SRS or the architecture document, the chart follows the code; the differences are listed under [Notes](#notes). The detailed flows linked from each stage carry the step-by-step sequence diagrams.

```mermaid
flowchart TB
  classDef deny stroke-dasharray:5 3
  classDef actor stroke-width:2px

  subgraph S1["1 Install and bootstrap"]
    direction TB
    subgraph S1a["1a Install"]
      direction LR
      I1(["Operator"]):::actor
      I2["install.sh: minisign-signed<br/>checksums, cosign bundle if<br/>cosign is installed, archive<br/>SHA-256; Homebrew: SHA-256"]
      I3["Binaries: smcpd, smcpctl,<br/>smcp-stdio, smcp-session,<br/>smcp-connect, smcp-refserver"]
      I4["Linux Enforced host only:<br/>install-enforced.sh, CP-46<br/>users incl. smcp-srv,<br/>AppArmor, nftables, systemd<br/>E-16"]
      I1 --> I2 -->|verified| I3
      I3 -.->|Linux| I4
    end
    subgraph S1b["1b smcpctl bootstrap"]
      direction LR
      I5["smcpctl bootstrap (install<br/>adds a launchd or systemd<br/>unit): Administrator and<br/>Session Approver passwords,<br/>Argon2id · E-24, E-03"]
      I7["keys.Ensure: CP-53 server CA,<br/>90-day listener certificate,<br/>Ed25519 evidence key,<br/>operator token, install ID<br/>E-22"]
      I8["smcp-refserver packaged,<br/>signed with a one-time key,<br/>anchor scoped to low,<br/>imported and enabled<br/>E-13, E-14"]
      I9["smcp.toml (0600), ports<br/>8443 and 8444; policy.json<br/>written and compiled<br/>E-05"]
      I5 --> I7 --> I8 --> I9
    end
    S1a --> S1b
  end

  subgraph S2["2 smcpd start-up"]
    direction TB
    subgraph S2a["2a Configuration, listeners, keys"]
      direction LR
      B1["smcpd --config smcp.toml<br/>JSON schema checked,<br/>unknown keys refused"]
      B2["Interrupted key rotations<br/>finished; loopback ports<br/>8443, 8444, metrics bound<br/>E-22, E-01, E-24, E-23"]
      B3["Health, Podman runtime,<br/>approvals, library, graph,<br/>analytics, secrets built<br/>E-23, E-15, E-07, E-14,<br/>E-25, E-27, E-19, E-20"]
      B4["Key file modes, evidence<br/>key, listener certificate<br/>renewed at 30 days · E-22"]
      B1 --> B2 --> B3 --> B4
    end
    subgraph S2b["2b Policy, journal, egress"]
      direction LR
      B5{{"Policy Store: first start<br/>imports policy.json; active<br/>revision signature<br/>verifies? · E-05"}}
      B5X["Bad signature: fail-closed,<br/>every call -31004<br/>NO_SNAPSHOT; policy.json<br/>not compiling: no start"]:::deny
      B7["Journal opened; crash<br/>recovery seals an<br/>unclosed segment · E-21"]
      B8["Egress Broker when<br/>[egress] enabled · E-18"]
      B5 -->|no| B5X
      B5 -->|yes| B7 --> B8
    end
    subgraph S2c["2c Profile and servers"]
      direction LR
      B9{{"profile.Resolve<br/>E-23, E-16"}}
      B9E["Enforced: Linux, rootless<br/>Podman, cgroup v2, nftables,<br/>systemd, confining launcher;<br/>label enforced"]
      B9S["Standalone: configured, or<br/>auto with a prerequisite<br/>missing (always on macOS);<br/>label not enforced;<br/>high risk refused"]
      B9X["mode = enforced and a<br/>prerequisite fails:<br/>smcpd refuses to start"]:::deny
      B10["backend.Start launches<br/>servers by 8c and 8d,<br/>without the call gate<br/>E-10"]
      B9 --> B9E & B9S & B9X
      B9E & B9S --> B10
    end
    subgraph S2d["2d Services and readiness"]
      direction LR
      B11["Decider, Policy service,<br/>sessions, OAuth, edge,<br/>control API · E-06, E-05,<br/>E-04, E-03, E-01, E-24"]
      B12["started event with<br/>release_label committed<br/>E-23, E-21"]
      B13["Console, principals,<br/>remote access, UDS socket<br/>E-24, E-01, E-33"]
      B14["smcpd listening; smcpctl<br/>health: healthy, degraded<br/>or fail-closed · E-23"]
      B11 --> B12 --> B13 --> B14
    end
    S2a -->|keys and listeners ready| S2b
    S2b --> S2c
    S2c --> S2d
  end

  subgraph S3["3 Server onboarding"]
    direction TB
    subgraph S3a["3a Package and sign"]
      direction LR
      P2["Operator: smcpctl package<br/>build --recipe: exact<br/>version, digest, risk<br/>class · E-13"]
      P3["Fetch from the registry,<br/>verify digest, store<br/>under SHA-256"]
      P4["Probe once: empty dir, no<br/>secrets; no network only<br/>with --sandbox podman"]
      P5["manifest.json, provenance;<br/>smcpctl package sign with<br/>a minisign key"]
      P2 -->|ranges refused| P3 --> P4 -->|tools/list| P5
    end
    subgraph S3b["3b Trust, import, enable"]
      direction LR
      P8["Library scan: anchor from<br/>smcpctl trust add scoped to<br/>the risk class, signature,<br/>digests, schema, provenance,<br/>revocations · E-13, E-22"]
      P10["Immutable revision,<br/>verified-disabled; import<br/>receipt · E-14, E-21"]
      P11{{"Enable: CLI or G-10,<br/>Administrator · E-14"}}
      P11X["ALIAS_CONFLICT,<br/>PUBLIC_NAME_COLLISION,<br/>expired, or high risk in<br/>Standalone: refused"]:::deny
      P8 --> P10 --> P11
      P11 -->|refused| P11X
    end
    subgraph S3c["3c Run and drift"]
      direction LR
      P12["[[server]] package = id,<br/>optional package_sha256;<br/>public name alias_tool<br/>E-10"]
      P13["Each launch re-verifies<br/>artifact SHA-256 and<br/>tree digest · E-13"]
      P9{{"Metadata rule-set scan<br/>of the loaded tools<br/>(SR-5.9-2) · E-14"}}
      P9X["Tool with a blocking<br/>finding left out,<br/>metadata_blocked"]:::deny
      P14["Drift at start or on<br/>list_changed: MANIFEST_DRIFT,<br/>revision suspended,<br/>instance torn down"]:::deny
      P12 --> P13 --> P9
      P9 -->|blocking| P9X
      P9 -.->|run time| P14
    end
    S3a -->|signed library entry| S3b
    S3b -->|enabled| S3c
  end

  subgraph S4["4 Client connection"]
    direction TB
    subgraph S4a["4a Client setup and transport"]
      direction LR
      C1(["Person with a harness:<br/>Claude Code, Codex,<br/>Gemini CLI, ..."]):::actor
      C2["smcpctl clients setup:<br/>MCP entry, CA trust,<br/>lockdown, backups<br/>E-33"]
      C3{{"Transport"}}
      C3H["HTTPS to<br/>127.0.0.1:8443/mcp,<br/>smcp-session helper"]
      C3S["smcp-stdio relay with<br/>the CP-43 credential<br/>file · E-33"]
      C3U["UDS profile: peer UID<br/>and Argon2id bearer key<br/>E-01; else -31006"]
      C1 --> C2 --> C3
      C3 --> C3H & C3S & C3U
    end
    subgraph S4b["4b OAuth 2.1 authorization"]
      direction LR
      C4["No token: 401 with<br/>resource_metadata;<br/>discovery, S256 only<br/>E-01, E-03"]
      C6["Client ID: pre-registered,<br/>or metadata document from<br/>the CP-52 allowlist · E-03"]
      C7["Browser: /oauth/authorize,<br/>PKCE S256, resource,<br/>smcp:template:name"]
      C8(["Session Approver signs in<br/>and approves; Administrator<br/>refused; lockout · E-03"]):::actor
      C4 --> C6 --> C7 --> C8
    end
    subgraph S4c["4c Token and session"]
      direction LR
      C9["/oauth/token with code<br/>and code_verifier · E-03"]
      C10{{"Principal enabled,<br/>template permitted,<br/>session cap?"}}
      C10X["invalid_scope -31001<br/>TEMPLATE_NOT_PERMITTED;<br/>429 -31005 SESSION_LIMIT;<br/>invalid_grant"]:::deny
      C11["Session: principal,<br/>template, claims; records<br/>the active policy<br/>revision · E-04"]
      C12["Access token is the<br/>session; refresh rotates,<br/>reuse ends it · E-04"]
      C9 --> C10
      C10 -->|no| C10X
      C10 -->|yes| C11 --> C12
    end
    subgraph S4d["4d Remote access through a tunnel"]
      direction LR
      R1["smcpctl remote enable:<br/>nftables smcp_remote,<br/>loopback remote listener,<br/>Tailscale Funnel or<br/>Cloudflare · E-33"]
      R3["Cloud agent or<br/>smcp-connect registers<br/>(RFC 7591); pending until<br/>G-11 or CLI approval"]
      R4["Auth code with PKCE or<br/>device grant; template in<br/>remote.templates · E-03"]
      R5["Session as in 4c;<br/>events carry the<br/>remote origin · E-04"]
      R1 -->|public URL| R3 --> R4 --> R5
    end
    S4a -->|http or stdio| S4b
    S4b -->|code, state, iss| S4c
    S4c ~~~ S4d
  end

  subgraph S5["5 Tool listing"]
    direction LR
    L1["tools/list on<br/>the session · E-02"]
    L2["Session catalog for the<br/>active revision: enabled,<br/>unsuspended tools · E-08"]
    L3["Presentation screen when<br/>the catalog is built:<br/>metadata rule sets<br/>E-08, E-13"]
    L4["HMAC pagination cursor,<br/>approval hint, cache<br/>ttlMs · E-02, E-08"]
    L5["Policy activation or a<br/>suspension: catalog updated,<br/>tools/list_changed on<br/>listen streams · E-08"]
    L1 --> L2 --> L3 --> L4
    L5 -.->|refresh| L2
  end

  subgraph S6["6 Tool call: edge, session and decision"]
    direction TB
    subgraph S6a["6a Edge, authentication, mediation"]
      direction LR
      T2{{"Edge: Host, Origin,<br/>CP-09 limits, CP-07<br/>body bound · E-01"}}
      T2X["421 or 403, or -31005<br/>QUEUE_FULL before<br/>the body is read"]:::deny
      T3{{"Fail-closed gate, then<br/>token to session<br/>E-23, E-12, E-03"}}
      T3X["-31004 FAIL_CLOSED,<br/>EMERGENCY_STOP,<br/>NO_SNAPSHOT; 401 -31006"]:::deny
      T4{{"Mediation: JSON, no<br/>batch, era, method<br/>allowlist, tool in the<br/>session catalog<br/>E-02, E-08"}}
      T4X["-32700, -32600, -32601;<br/>-32602 unknown tool;<br/>notification 202"]:::deny
      T2 -->|refused| T2X
      T2 -->|ok| T3
      T3 -->|refused| T3X
      T3 -->|ok| T4
      T4 -->|invalid| T4X
    end
    subgraph S6b["6b Call record, session, decision"]
      direction LR
      T7["requested event first:<br/>argument digest, receipt<br/>time · E-21"]
      T5{{"Session still active,<br/>gate again<br/>E-04, E-12"}}
      T5X["-31006 SESSION_STATE,<br/>-31004 fail-closed"]:::deny
      T6{{"Decision on the snapshot:<br/>default deny, deny first,<br/>predicates, taint, rates,<br/>quotas · E-06"}}
      T6X["-31001 DENY_RULE,<br/>NO_PERMIT, TAINT_DENIED;<br/>-31005 RATE_LIMITED,<br/>QUOTA_EXHAUSTED"]:::deny
      T7 --> T5
      T5 -->|refused| T5X
      T5 -->|ok| T6
      T6 -->|deny| T6X
    end
    subgraph S6c["6c Request inspection"]
      direction LR
      T8{{"Request filters, CP-14<br/>deadline: schema, size,<br/>unicode, secrets, paths,<br/>URLs, injection · E-09"}}
      T8X["-31001 FILTER_BLOCKED,<br/>SECRET_IN_ARGUMENTS;<br/>-32602 SCHEMA_INVALID"]:::deny
      T9["observe-request probe<br/>E-29, E-31; S2 secret<br/>file filter last · E-20"]
      T10{{"Arguments changed:<br/>second decision,<br/>launch bound to it<br/>E-06"}}
      T10X["-31001 when the<br/>second decision<br/>denies"]:::deny
      T11{{"Approval<br/>obligation?"}}
      T8 -->|block| T8X
      T8 -->|pass| T9 --> T10
      T10 -->|deny| T10X
      T10 -->|permit or unchanged| T11
    end
    S6a -->|session, principal, template| S6b
    S6b -->|permit: filters, approval, route| S6c
  end

  subgraph S7["7 Approval hold"]
    direction TB
    subgraph S7a["7a Hold and notify"]
      direction LR
      A1["Pending approval bound to<br/>session, principal, tool<br/>revision, argument digest,<br/>policy revision · E-07"]
      A2["Within 2 s: OS notification<br/>without arguments, G-13,<br/>approvals watch<br/>E-07, E-24"]
      A3["Held as an event stream:<br/>keep-alive every 10 s,<br/>bound 120 s (CP-45) or<br/>CP-17 expiry · E-02"]
      A1 --> A2 --> A3
    end
    subgraph S7b["7b Decision"]
      direction LR
      A5{{"Approver decides<br/>in G-13 or smcpctl<br/>approvals"}}
      A5D["-31001<br/>APPROVAL_DENIED"]:::deny
      A5T["-31002 APPROVAL_REQUIRED:<br/>approvalId, expiresAt,<br/>approvalUrl; pending until<br/>CP-17 expiry"]:::deny
      A6["One-use approval<br/>consumed; the call<br/>continues · E-07"]
      A5 -->|deny| A5D
      A5 -->|bound reached| A5T
      A5 -->|approve| A6
      A5T -.->|approve, same request again| A6
    end
    S7a -->|keep-alives until a decision| S7b
  end

  subgraph S8["8 Tool call: launch gate, dispatch, egress; instance launch"]
    direction TB
    subgraph S8a["8a Launch authorization"]
      direction LR
      D1{{"Gate: stop, policy and<br/>server revision, session,<br/>principal, credential,<br/>journal, health · E-12"}}
      D1X["-31004 EMERGENCY_STOP,<br/>POLICY_REVISION_CHANGED;<br/>-31006; -31001 principal,<br/>credential, revision"]:::deny
      D2{{"authorized event<br/>committed, fsync<br/>E-21"}}
      D2X["-31004<br/>JOURNAL_UNAVAILABLE,<br/>endpoint fails closed"]:::deny
      D3["One-use launch capability:<br/>correlation, decision,<br/>revision, tool · E-12"]
      D1 -->|refused| D1X
      D1 -->|ok| D2
      D2 -->|failed| D2X
      D2 -->|flushed| D3
    end
    subgraph S8b["8b Dispatch and egress"]
      direction LR
      D11["dispatched recorded;<br/>capability consumed,<br/>FIFO slot (CP-10) · E-10"]
      D4{{"Instance ready? A call<br/>waits for a relaunch<br/>under way (8c) · E-10"}}
      D4X["-31007 DISPATCH_FAILED<br/>(server suspended)"]:::deny
      D14{{"One-use egress caps in<br/>_meta (E-18); tools/call<br/>over stdio, timeout<br/>(CP-13), bounded read<br/>E-10"}}
      D11X["-31007 BACKEND_ERROR,<br/>-31009 UPSTREAM_TIMEOUT,<br/>-31005 QUEUE_FULL"]:::deny
      D12["Server egress: grant and<br/>capability, recorded first,<br/>S1 header, pinned DNS,<br/>reserved IPs refused · E-18"]
      D13["Progress relayed with<br/>the northbound token,<br/>10 per second · E-02"]
      D11 --> D4
      D4 -->|no| D4X
      D4 -->|yes| D14
      D14 -->|error| D11X
      D14 -.->|server calls out| D12
      D14 -.->|progress| D13
    end
    subgraph S8c["8c Instance launch: at start-up and relaunch after exit or timeout, never per call"]
      direction LR
      D6a["Command servers: content<br/>address checked · E-10"]
      D5["Secret Broker: S3 file 0600,<br/>S4 env with waiver, S1 header<br/>grant; secret_use committed;<br/>fingerprints · E-20, E-19"]
      D6["Packaged servers: artifact<br/>re-verified; failure<br/>suspends the revision<br/>E-13"]
      D6a --> D5 --> D6
    end
    subgraph S8d["8d Launcher"]
      direction LR
      D7{{"Launcher for<br/>the profile · E-15"}}
      D7S["Standalone: unconfined<br/>subprocess, proxy<br/>variables advisory"]
      D7E["Enforced: rootless Podman<br/>(as smcp-srv with run_as);<br/>read-only root, cap-drop<br/>all, seccomp, userns, CP-24<br/>cgroups, network none or<br/>egress · E-16"]
      D8["Runtime Monitor: cgroups,<br/>inotify, podman events;<br/>deviation, limit_breach<br/>E-17"]
      D9["initialize, tools/list<br/>against the signed<br/>manifest · E-10, E-13"]
      D7 --> D7S & D7E
      D7E --> D8
      D7S --> D9
      D8 --> D9
    end
    S8a -->|launch capability| S8b
    S8b ~~~ S8c
    S8c --> S8d
  end

  subgraph S9["9 Tool call: response, release and result"]
    direction TB
    subgraph S9a["9a Response inspection"]
      direction LR
      F1{{"Response chain: size,<br/>schema, content type,<br/>secrets, vault leak, PII,<br/>injection, delimit · E-11"}}
      F1X["-31003 SECRET_LEAK<br/>withheld, secret<br/>suspended; RESULT_*"]:::deny
      F2["Provenance labels;<br/>observe-response last<br/>E-11, E-29"]
      F1 -->|withhold| F1X
      F1 -->|pass| F2
    end
    subgraph S9b["9b Release"]
      direction LR
      F3{{"Release authorization<br/>under the gate: stop,<br/>session · E-12"}}
      F3X["-31003 RELEASE_REFUSED<br/>result withheld"]:::deny
      F4{{"delivered event<br/>committed, fsync<br/>E-21"}}
      F4X["-31003<br/>OUTCOME_UNRECORDED"]:::deny
      F5(["Result to the agent, _meta<br/>provenance marked<br/>untrusted; session taint<br/>applied · E-02, E-06"]):::actor
      F3 -->|refused| F3X
      F3 -->|ok| F4
      F4 -->|failed| F4X
      F4 -->|committed| F5
    end
    S9a --> S9b
  end

  subgraph S10["10 Evidence and data"]
    direction TB
    subgraph S10a["10a Journal and graph mirror"]
      direction LR
      J1[("Evidence journal: hash-<br/>chained JSON Lines, group<br/>fsync, Ed25519 footer per<br/>segment · E-21")]
      J2["Signed anchor at each<br/>segment close; export_dir<br/>off the machine · E-21"]
      J3["smcpctl journal verify:<br/>chain, footers, key<br/>transitions · E-21"]
      J4["Observer fanout: bounded<br/>queues, drops counted,<br/>never blocks · E-21"]
      J5[("Neo4j graph mirror,<br/>optional: MERGE, catch-up<br/>every 60 s, rebuild<br/>E-25, E-26")]
      J1 --> J2 --> J3
      J1 --> J4 --> J5
    end
    subgraph S10b["10b Observation and anomaly scoring"]
      direction LR
      J6["Observation Collector:<br/>one record per call from<br/>its events and probes<br/>E-29"]
      J7[("Observation Store: day<br/>partitions, DuckDB and<br/>Parquet or JSON Lines<br/>E-27")]
      J8["Baselines: sealed<br/>snapshots, drift,<br/>promotion · E-30"]
      J9["Anomaly Scorer: z, robust<br/>z, CP-30 bands; alerts,<br/>optional obligations · E-31"]
      J6 --> J7 --> J8 --> J9
    end
    subgraph S10c["10c Exports, lifecycle, backup"]
      direction LR
      J11["Research campaigns:<br/>pseudonymized exports,<br/>dictionary, manifest<br/>E-32"]
      J12["Retention: observations<br/>90 days (CP-25), graph<br/>30 days; memory stages<br/>E-28"]
      J13["smcpctl backup: drain,<br/>age-encrypted archive;<br/>restore verifies in an<br/>isolated directory · E-28"]
      J11 ~~~ J12 ~~~ J13
    end
    S10a -->|events after commit| S10b
    S10b --> S10c
  end

  subgraph S11["11 Operations"]
    direction TB
    subgraph S11a["11a Access"]
      direction LR
      O1(["Administrator, Operator,<br/>Policy Author, Auditor,<br/>Researcher, Approver,<br/>Session Approver"]):::actor
      O2["Console 127.0.0.1:8444,<br/>G-01 to G-14; cookie,<br/>CSRF, If-Match · E-24"]
      O3["CLI with the operator<br/>token: the smcpctl<br/>commands (Administrator)"]
      O4{{"Control API role<br/>matrix, Appendix C<br/>E-24"}}
      O1 --> O2 & O3 --> O4
    end
    subgraph S11b["11b Actions"]
      direction LR
      O5["Policy: validate, diff,<br/>simulate, publish with<br/>parent check, signed,<br/>atomic activation · E-05"]
      O6["Emergency stop: cancels<br/>calls in flight, withdraws<br/>S1 and S2; resume by<br/>Administrator · E-12"]
      O7["keys rotate tls, ca<br/>(7-day overlap) or<br/>evidence · E-22"]
      O9["smcpctl upgrade: minisign,<br/>backup, swap, health in<br/>60 s, rollback · E-24"]
      O5 ~~~ O6 ~~~ O7 ~~~ O9
    end
    subgraph S11c["11c Health and diagnostics"]
      direction LR
      O11["Health monitor: 1 s checks,<br/>critical causes latch<br/>fail-closed, 10 s recovery<br/>E-23"]
      O10["smcpctl health, loopback<br/>metrics, diagnostic log<br/>(not evidence) · E-23;<br/>smcpctl doctor · E-33"]
      O8["Packages, anchors, secrets,<br/>egress grants, principals,<br/>remote clients · E-14,<br/>E-18, E-19, E-22, E-33"]
      O11 --> O10
      O10 ~~~ O8
    end
    S11a -->|role permits| S11b
    S11b --> S11c
  end

  S1 ==>|config, keys, signed reference package| S2
  S2 ==>|listeners up, policy active| S3
  S3 ==>|enabled revisions| S4
  S4 ==>|access token| S5
  S5 ==>|tools/call, POST /mcp with Bearer| S6
  S6 ==>|approval obligation; without one the call goes to 8| S7
  S7 ==>|approved, or no obligation| S8
  S8 ==>|result| S9
  S9 ==>|journal events| S10
  S10 ==>|evidence, analytics, health| S11
```

## Stages

The system map page lists these stages beside the chart; selecting one zooms to it.

| No. | Stage | Subgraph | What it shows | Detailed flows |
|---|---|---|---|---|
| 1 | Install and bootstrap | `S1` | Verified installation, the Enforced host installer, `smcpctl bootstrap`: accounts, keys, the signed reference package, configuration and policy. | [Install guide](../install.md), [Quick start](../quickstart.md), [Enforced profile](../enforced-profile.md) |
| 2 | smcpd start-up | `S2` | Configuration, listeners, policy verification, journal recovery, profile detection, release label, health. | [Enforced sandbox launch](enforced-sandbox-launch.md), [Operations](../operations/README.md) |
| 3 | Server onboarding | `S3` | Package build, probe and signing, trust anchors, library import, enablement, public names, pinning, the metadata scan at server start, drift. | [Server packaging](server-packaging.md), [Packaging guide](../packaging-guide.md) |
| 4 | Client connection | `S4` | `smcpctl clients setup`, OAuth 2.1 with PKCE and Session Approver sign-in, sessions, the UDS profile, remote access through a tunnel. | [OAuth sign-in](oauth-sign-in.md), [Remote access](remote-access.md), [Cloud agent](cloud-agent-tunnel.md) |
| 5 | Tool listing | `S5` | The session catalog, the presentation screen and `list_changed`. | [Tool call](tool-call.md) |
| 6 | Tool call: edge, session and decision | `S6` | Edge bounds, protocol mediation, session, access enforcement, the policy decision and request inspection. | [Tool call](tool-call.md), [Filters](../filters.md) |
| 7 | Approval hold | `S7` | Pending approval, notification, keep-alives, decision, timeout and retry. | [Approval hold](approval-hold.md), [Approvals](../approvals.md) |
| 8 | Tool call: launch gate, dispatch, egress; instance launch | `S8` | Launch authorization, dispatch, egress capabilities, and how instances are launched at start-up and relaunched: secret delivery, artifact check, standalone and enforced launchers, the Runtime Monitor. | [Secret delivery](secrets-delivery.md), [Enforced sandbox launch](enforced-sandbox-launch.md), [Egress](egress.md) |
| 9 | Tool call: response, release and result | `S9` | Response inspection, provenance, release authorization, the `delivered` commit and the result. | [Tool call](tool-call.md) |
| 10 | Evidence and data | `S10` | Journal, anchor, verification, graph mirror, observation, baselines, anomaly scoring, research exports, retention, backup. | [Journal verification](journal-verification.md), [Graph mirror](../graph.md), [Observation](../observation.md) |
| 11 | Operations | `S11` | Console views, control API roles, policy publication, emergency stop, key rotation, upgrade, diagnostics, health. | [Emergency stop](emergency-stop.md), [Console](../console.md), [Operator guide](../operator-guide.md) |

## Notes

- Sessions record the policy revision that was active at sign-in, but decisions always use the active snapshot. A policy activation brings every session catalog to the new revision and sends `list_changed`; a call whose revision changes between decision and dispatch is refused with `POLICY_REVISION_CHANGED`.
- Backend instances are shared across sessions. A call never launches a server: instances are launched at start-up (`backend.Start`) and relaunched in the background after an exit or a timeout, and a call that finds no instance waits for a relaunch under way or fails with `DISPATCH_FAILED`. Per-session and per-call instances are deferred from release 1.0.
- The `requested` event is the first thing the tool-call handler records, after authentication and mediation and before the session check and the decision. The tool name is checked against the session catalog during mediation (`-32602` for an unknown tool).
- The metadata rule sets are applied when an enabled server's tools are loaded (SR-5.9-2) and again when a session catalog is built (FR-1.52); a library import does not scan them.
- The S2 file is written during request inspection, so it exists while a held call waits for approval. It is deleted when the call ends, whatever the outcome.
- The Observation Collector makes one record per call from the call's journal events and the `observe-request` and `observe-response` probes. Scoring is asynchronous by default; the approval and withhold obligations of the Anomaly Response Policy need synchronous scoring and are off by default.
- The graph mirror and the observation pipeline are evidence observers. They are fed after the journal accepts an event and never block or fail a call; only the optional synchronous anomaly obligations above can hold or withhold one.
- Emergency stop does not tear down server instances or end sessions; see [Emergency stop](emergency-stop.md).
- The Remote Access Profile, Dynamic Client Registration and the device grant exist only on the remote listener.
- The static SVG copy of this chart, for download, is `site/public/system-map.svg`, regenerated with `npm run render-system-map` in `site/`.
