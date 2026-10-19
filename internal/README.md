# internal: architecture map

This directory holds the Gateway's Go packages, one or more per architecture
element of `ArchitectureV2.md`. This file maps packages to elements, names the
extension points (seams) that elements still to be built plug into, and lists
the known residual gaps of what exists.

Rule for parallel work: an element is added by implementing a seam below and
registering it through `app.Options` (or `adminapi.Server.Handle` for control
API routes). It should not need edits to `edge`, `backend` or `session`.
When a seam is missing, add it to `internal/pipeline` with a default that
keeps today's behavior, and test the default.

## Packages

| Package | Elements | What it holds |
|---|---|---|
| `app` | wiring | Builds every component from a validated config; used by `cmd/smcpd` and the end-to-end tests. Seams are passed in `app.Options`. |
| `edge` | E-01, E-02, E-08, E-12 | Harness listener, MCP protocol (Go SDK, stateless), per-session catalogs, the FR-4.3 call pipeline, launch and release authorization under the barrier, emergency stop, policy activation, health. |
| `pipeline` | seams for E-07, E-09, E-11, E-12, E-13, E-15, E-16, E-20 | Interfaces and defaults (see below). Depends only on `policy` and the MCP SDK. |
| `backend` | E-10, E-14, E-15 (part) | Server registry, public names, FIFO concurrency queue, upstream timeout, bounded result reading, capability check before dispatch, suspended tools of a revision (SR-5.9-2), content address of command-configured servers checked before each relaunch (SR-3.6-1, `pipeline.ContentAddress`). |
| `session` | E-03, E-04 | OAuth 2.1 authorization server (Session Approver sign-in), session API, session table with refresh-token rotation and reuse detection, janitor. |
| `authguard` | E-03, E-24 | Per-source rate limit, lockout with backoff, bounded Argon2id, unknown-account dummy verification. |
| `filters` | E-09, E-11, E-14 (metadata scan) | Built-in request and response filters, versioned rule sets with digests (`filters/rules/`), labelled corpora (`filters/testdata/corpus/`), registered secret fingerprints, the import-time metadata scan (a `ManifestSource` decorator) and the presentation screen (`ToolScreen`). Wired by `app/inspection.go`; documented in `docs/filters.md`. |
| `policy` | E-05 (part), E-06 | Schema-validated policy document and canonical form, compiled snapshot, decisions with deny precedence, rate and burst windows, session quotas, evaluation bounds, restrict-only session taint, filter obligations, `Diff`, `Simulate`, `Replace` for hot swap. |
| `policystore` | E-05 (D-01) | Signed Policy Store: Ed25519 policy-signing key, immutable revision files named by digest, signed policy-control record with atomic activation. |
| `policyadmin` | E-05 | Load at start (import or verify, fail-closed on `policy_signature`), publish, rollback, simulate from the journal, the `/api/v1/policy*` control API routes, and the `adminapi.Controller` wrapper that sends `policy/reload` through the store. |
| `audit` | E-21 | Signed hash-chained journal with group-committed fsync, crash recovery, external anchor, verifier; evidence-key transition records (`RotateKey`), `Seal`, unsigned-event measurement, evidence export (`Exporter`); `Fanout` with non-blocking observers; `Memory` for tests; `Options.OpenSegment`, the segment-file seam the crash-consistency test (`internal/edge/crash_test.go`) fills with a fault-injecting layer. |
| `secrets` | E-19, E-20 | Age-encrypted vault, Secret Use Policy, broker (S1 to S4 delivery, leak fingerprints, leak and S2 filters, emergency-stop withdrawal), `/api/v1/secrets` routes. |
| `keys` | E-22 (part) | CP-53 name-constrained local server CA, listener certificate and renewal, CA rotation with overlap, evidence key and pending-key rotation, `CertReloader` for listeners, key inventory, operator token, installation ID, Argon2id. |
| `health` | E-23 | Health & Safety Monitor: checks, states, fail-closed latch with 10 s recovery and acknowledgment, `Gate` for the edge. |
| `metrics` | E-23 | Loopback Prometheus exposition fed by an evidence observer and the journal's fsync timing. |
| `backup` | E-28 (part) | age-encrypted backup archive with manifest; restore into an isolated directory with verification. |
| `ops` | E-21, E-22, E-23 | Daemon operations runtime: attaches monitor, metrics, export, key maintenance, online backup and reload to a started `app.App`; `/api/v1/health/*`, `/api/v1/keys*`, `/api/v1/backup*`, `/api/v1/config/reload`. |
| `packaging` | E-13, E-22 (part) | Package formats (manifest, index, provenance, recipe), `smcpctl package build` (fetch by digest, probe, manifest), minisign signing and offline verification, trust anchors, revocation entries. `pkgtest` builds signed fixture packages. |
| `library` | E-13, E-14 | Library scan and import with receipts, content-addressed artifact store, immutable revisions and registry states, enablement, the verified `ManifestSource` with drift detection and artifact re-verification, `/api/v1/packages` routes. |
| `adminapi` | E-24 (base) | Control API on the loopback admin listener: login, bootstrap redemption, health, stop, resume, policy reload; browser cookie sessions with CSRF token and `If-Match` preconditions on per-object revisions (`browser.go`, `revision.go`; login routes registered with `HandlePublic` get them, authenticators may implement `TokenRevoker`); role seam (`AddAuthenticator`, `HandleRoles`, `HandlePublic`, `ActorOf`, `RoleOf`); the Appendix C role matrix per route pattern (`rolematrix.go`) and the registered route table (`Routes`). |
| `consoleauth` | E-24 | Sign-in of Operator, Policy Author, Auditor and Researcher accounts (`[[console.account]]`) and of Session Approvers for the console; `/api/v1/console/*`. |
| `openapi` | E-24 (FR-8.1) | `GET /api/v1/openapi.json` from the hand-maintained operation table and the live route roles; the test that every route is described. |
| `principals` | E-24 (G-11), E-03 | Principal directory: principals and OAuth client credentials created from the control API, suspension of file principals (`<state>/principals.json`), attached with `config.SetDirectory` so `FindPrincipal` and `FindClient` see them; `/api/v1/principals*`, `/api/v1/credentials/*`. |
| `obspolicy` | E-24 (G-03, G-04, G-06, G-08) | Published observation objects (Audit Profile, Observation Policy, Anomaly Response Policy, memory budget) as numbered revisions, validated with `analytics.Resolve`; applied to the analytics configuration copy at start; `/api/v1/observations/objects`, `/audit-profile`, `/observation-policy`, `/anomaly-response`, `/memory-budget`. |
| `filterapi` | E-09, E-11 (FR-8.27) | Filter test workbench routes `/api/v1/filters*` over `filters.Scan`. |
| `graph` | E-25, E-26, E-28 (graph part) | Neo4j graph mirror as an evidence observer: digest-verified template catalog, Data Access Service, migrations, journal catch-up and rebuild, retention, engine configuration and heap check, `/api/v1/graph*`. Wired in `cmd/smcpd`; disabled unless `[graph] enabled`. |
| `approval` | E-07 | Approval Service: persisted one-use approvals bound per SR-1.18-2, hold mode, CP-17 expiry, `/api/v1/approvals*`, Approver accounts, watch stream, desktop notifier, harness status route. Wired in `cmd/smcpd`. |
| `consoleapi` | E-24 | Console backend: serves the embedded console (`console/`, `go:embed`) under a strict CSP, `/api/v1/sessions*`, `/api/v1/servers*`, `/api/v1/catalog`, `/api/v1/audit/*` (journal browser, export, verification, evidence stream). Attached in `cmd/smcpd` with `consoleapi.Attach`. |
| `profile` | E-23 (part), E-16 | Standalone versus enforced profile decision. |
| `config` | all | TOML configuration validated against `config.schema.json`; Appendix A defaults by key presence. |
| `diag` | all | Diagnostic logger (slog); daemon logger with rotating JSON Lines file and redaction of sensitive attribute names. Not evidence; never logs secrets, tokens or arguments. |
| `ids` | all | UUIDv7 identifiers and 256-bit secrets. |
| `reqtest` | FR-12.10, FR-19.4 | `Verifies` and `Partial` requirement claims and `Scenario` acceptance-scenario claims in tests. |
| `remote` | E-01, E-03 (FR-16) | Remote Access Profile: loopback remote listener with CP-49 bounds and limits, public-name host check, RFC 7591 registration with operator approval, authorization-code and device grants, `/api/v1/remote*` and `/api/v1/clients*`. Wired in `cmd/smcpd`. |
| `adapter` | E-33 | CP-43 credential file, session acquisition and refresh, stdio relay; `smcp-session`, `smcp-stdio`, `smcp-connect` (`cmd/`). npm twin in `packaging/npm/smcp-connect`. |
| `harness` | E-33 | Client setup, lockdown profiles and doctor checks for the Appendix K clients (`smcpctl clients setup`, `lockdown`, `doctor`). |
| `tunnel` | E-33, E-01 | Tailscale Funnel and Cloudflare quick tunnel drivers, the public-name check and the SR-4.14-1 nftables host rules (`smcpctl remote`). |
| `channel` | FR-16.8 | Request origin (local or remote) carried in the context and applied to evidence events. |
| `gwtest` | tests | Starts a full Gateway with an in-process backend and a fake tunnel for tests. |
| `testport` | tests, `scripts/agents` | Loopback ports below the ephemeral range for listener addresses written into test configurations, reserved across concurrent test processes. |
| `e2e` | all | End-to-end tests over TLS with the test binary as a stdio backend. |
| `acceptance` | FR-19.4, AT-01 to AT-21 | Acceptance scenarios as tests of the real binaries (bootstrap, CLI, control API, OAuth MCP client); `SMCP_ACCEPTANCE_PROFILE=enforced` runs them in the Enforced profile. See `docs/acceptance.md`. |
| `conformance` | FR-12.9 | MCP conformance suite (tests only): a complete Gateway over a scripted stdio backend, driven with the `mcp-spec/2026-07-28/schema/examples` messages and validated against `schema.json`; `make conformance`. |
| `perf` | FR-11 | Reference dataset and workload, FR-11 measurements against real smcpd (`cmd/smcp-workload`, CI job `perf`). |
| `hostile` | FR-19.1, FR-19.2 | Hostile backend fixture server for every SRS Appendix L row (also `cmd/smcp-hostile`) and the suite (build tag `hostile`) that runs the Gateway against each fixture and writes `build/hostile.json`. See `docs/hostile-fixtures.md`. |
| `egress` | E-18 | Egress Broker: per-instance forward proxy and destination endpoints, grants, pinned DNS, reserved-address refusal, limits, evidence, nftables confinement of sandbox namespaces, `/api/v1/egress` routes. See `docs/egress.md`. |
| `sandbox` | E-15, E-16, E-17 | Rootless Podman launcher (`sandbox.Launcher`, `Confined() == true`), launch specification, Runtime Monitor (cgroup sampling, inotify, `podman events`), FR-5.27 shutdown, `sandbox.Doctor` prerequisite checks, `/api/v1/runtime*`. Selected by `[runtime] sandbox = "podman"`; with `run_as`, Podman runs as the CP-46 server identity through sudo (`runner.go`); secret files for other UIDs get ACL entries (`secretacl.go`). See `docs/sandbox.md`. |
| `posixacl` | E-16, E-20 (support) | Reads and adds named-user entries of POSIX access ACLs (`system.posix_acl_access`) without external tools; Linux only. Used to let one instance UID read its secret files. |
| `observe` | E-29 | Observation Collector: an audit observer plus the mandatory `observe-request` and `observe-response` probes; one record per call with the computed Parameter Catalog parameters, sampling, capture escalation, drop counts, meta-metrics. |
| `obsstore` | E-27 | Observation Store: day-partitioned write-once tables; DuckDB with Parquet (cgo) or JSON Lines (no cgo); aggregate queries; retention. |
| `baseline` | E-30 | Behavior Baseline Engine: Welford and t-digest statistics, transforms, sealed snapshots, drift, promotion and rollback. |
| `anomaly` | E-31 | Anomaly Scorer: snapshot load, z and robust z, CP-30 bands, asynchronous alerts and optional synchronous obligations. |
| `research` | E-32 | Research Dataset Service: campaigns, pseudonymized exports (Parquet, CSV, JSON Lines, GraphML) with dictionary, manifest and checksums. |
| `analytics` | E-27, E-29 to E-32 (wiring) | Builds SS-10 from `[observation]`, registers the probes and observer, and serves `/api/v1/observations*`, `/api/v1/baselines*`, `/api/v1/anomalies*`, `/api/v1/research*`; see `docs/observation.md`. |

## Call pipeline (FR-4.3)

`edge/pipeline.go` runs, in order: authenticate (`mcpChain`), session check,
fail-closed check, decision (`policy.Decider`), request inspection
(`pipeline.Filters.RunRequest`), approval (`pipeline.Approver`), launch
authorization, dispatch (`backend.Registry.Call`), response inspection
(`pipeline.Filters.RunResponse`), provenance, release authorization.
Request scoring and response scoring (E-31) are the `observe-request` and
`observe-response` probes, which run after every other filter of their
chain; response validation (size bound, output schema) opens the response
chain (`e2e.TestStageOrder`).

Evidence ordering: `requested`, `dispatched` and `completed` are appended;
`authorized` (the decision intent) is committed with fsync before the
launch capability is issued; `delivered` is committed before the result is
released; every refusal commits its terminal event. If an append or commit
fails the call is refused with `-31004` and reason `JOURNAL_UNAVAILABLE`
(a failed `delivered` commit withholds the result with `-31003` and the
same reason), and the journal's sticky error fails the whole endpoint
closed.

Message mediation (`edge/mediate.go`): `mcpChain` reads each POST body
before the SDK sees it. Invalid UTF-8 JSON gets 400 and `-32700`; a batch,
response object or scalar gets 400 and `-32600`; a notification gets 202
and is discarded; `Last-Event-ID` is dropped from 2026-07-28 requests; a
duplicate in-flight request ID gets `-32600`; a listen request beyond
`listen_streams_per_session` gets `-31005` (`LISTEN_LIMIT`). Plain-text SDK
errors are rewritten as JSON-RPC errors that echo the request ID. A
request with a progress token is answered as an event stream; listen
streams get comment keep-alives every 15 s when idle and end with an empty
`resultType: "complete"` response when the Gateway ends them.

Barrier: launch and release authorization hold `Gateway.gate` for reading;
`Stop`, `Resume`, `ActivatePolicy` and `Serialize` hold it for writing.
`Serialize` runs revocations under the gate (SR-1.16-1): credential
revocation and principal suspension (`principals.Service.Gate`) and the
library's suspension or revocation of a running revision (`app.Start`).
Launch authorization rechecks the policy revision, session, principal,
credential (`config.CredentialRevoked`) and server revision under the gate
(SR-1.17-1).

## Seams and who fills them

| Seam | Interface | Default | Element and future work |
|---|---|---|---|
| Approval | `pipeline.Approver` (`Request(ctx, ApprovalRequest) (ApprovalResult, error)`), `adminapi.Approvals` | `RefuseApprover`: immediate `-31002` with retry text and console link | Filled by `internal/approval` in `cmd/smcpd`. Anomaly (E-31) and taint obligations still need to reach it; the console (G-13) reads `/api/v1/approvals`. |
| Harness routes | `edge.Gateway.HandleSession(pattern, SessionHandler)` | none | Routes on the harness listener for an authenticated session (E-07 uses `/smcp/v1/approvals/{id}`). |
| Control API roles | `adminapi.Authenticator`, `Server.HandleRoles(pattern, h, roles...)`, `adminapi/rolematrix.go` | `Handle` routes admit the Administrator and the roles the matrix lists for the pattern | An element that owns accounts of another Appendix C role registers an Authenticator. A new route that another role may use gets a row in the matrix (and in `internal/openapi/routes.go`, which a test enforces). |
| Request filters | `pipeline.RequestFilter`, registered with `Filters.RegisterRequest(f, Registration{Order, Mandatory})`; optional `Versioned`; findings in `RequestVerdict.Findings` | `NewFilters`: `schema-validate`; `app` adds the `internal/filters` built-ins | Non-mandatory filters run when a policy rule names them in `filters`. IDs are unique per chain. Each chain run is bounded by `SetDeadline` (CP-14) and reported to `Filters.Observe` observers and `Call.Inspection`. |
| Response filters | `pipeline.ResponseFilter`, `Filters.RegisterResponse` | `app` adds the `internal/filters` built-ins | A filter error, panic, timeout or an unknown obligation ID refuses the call. `Inspection.Tags()` and `Disposition()` feed provenance. |
| Catalog screen | `pipeline.ToolScreen` (`Present(ctx, server, revision, tool) error`), `edge.Deps.Screen` | nil (present all) | `filters.Inspector` re-applies the metadata rule sets before presentation (FR-1.52). |
| Launch | `pipeline.Launcher` (`Launch(ctx, ServerSpec) (Process, error)`, `Confined()`) | `SubprocessLauncher` (unconfined); `InProcessLauncher` for tests | `internal/sandbox.Launcher` (E-15, E-16, E-17): rootless Podman, selected by `[runtime] sandbox = "podman"` in `cmd/smcpd`; see docs/sandbox.md. |
| Manifests | `pipeline.ManifestSource` (`Tools(ctx, spec, live) (ToolSet, error)`), optional `pipeline.ManifestWatcher` (`ListChanged`) | `LiveManifest`: live `tools/list`, `Verified: false` | `library.Runtime` through `app.Options.Packages`: `[[server]] package = "<id>"` entries run the enabled signed revision; drift at start or on `list_changed` returns `pipeline.ErrServerSuspended` and the registry tears the instance down (`Registry.Suspend`). `command` entries keep the unverified live list unless `[packages] require_signed`. |
| Secrets | `pipeline.SecretBroker` (`Resolve(ctx, SecretRequest)`), `pipeline.SecretFingerprints`, `pipeline.SecretHeaderInjector` | `NoSecrets`: a server with `secret_env` does not start | `internal/secrets` (E-19, E-20), enabled by `[secrets]` through `secrets.Configure` in `cmd/smcpd`; see `docs/secrets.md`. `app.Start` registers delivered values with the E-09/E-11 inspector (`ShareFingerprints`) and, with `[egress] enabled`, gives the broker the Egress Broker as its S1 `SecretHeaderInjector` (`SetInjector`). E-29 scans with `Broker.Fingerprints()`. |
| Evidence observers | `audit.Observer`, registered through `app.Options.Observers` | none | E-29 collector, E-26 graph mirror, E-27 store. Observers get events after the journal accepted them, on their own goroutine with a bounded queue; a full queue drops and counts (`Fanout.Dropped`). They can never block or fail a call. |
| Control API routes | `adminapi.Server.Handle(pattern, handler)` | health, stop, resume, policy reload, approvals placeholder, login, bootstrap | E-24 agent: console backend routes; the same bearer authentication, origin and JSON content-type rules apply. Handlers read the authenticated actor with `adminapi.ActorOf(r)`. E-05 registers `/api/v1/policy*` from `policyadmin`. |
| Launch capability | `pipeline.Capabilities` (issue) and `pipeline.CapabilityChecker` (consume) | one-use ledger shared by edge and backend | Bound to correlation ID, decision ID, policy revision and public tool name (FR-4.13). |
| Health gate | `app.Options.HealthGate func() []string` (edge `Deps.HealthGate`) | none | Filled by `internal/health.Monitor.Gate` in `cmd/smcpd`; non-empty refuses MCP requests and launch authorizations with `FAIL_CLOSED`. |
| Health checks | `health.Monitor.Register(name, health.Check)` | the checks `internal/ops` registers | E-19 (vault), E-25 to E-28 (graph mirror, Observation Store, memory stage) register their own; a critical cause gates the edge. |
| Profile | `profile.Resolve(mode, launcher, confined, host)` | standalone on macOS or without a confining launcher | E-16 agent supplies the confining launcher; `[profile] mode = "enforced"` refuses to start without one. |
| Egress | `pipeline.EgressAttacher` (`Attach(ctx, EgressRequest) (*EgressAttachment, error)`), `pipeline.EgressAware` (`SetEgress`) | `NoEgress`; with `[egress] enabled` the broker wraps unconfined launchers (advisory proxy variables) | `sandbox.Launcher` implements `EgressAware`: for `network = "egress"` it calls `Attach` with `EgressNetwork{ListenAddr: 127.0.0.1, GuestAddr: 10.0.2.2, LauncherConfines: true}`, creates the container on slirp4netns, installs nftables rules allowing only `EgressAttachment.Allow` in the container's namespace (`podman unshare nsenter ... nft`), then starts it; any failure removes the container and closes the attachment. |
| Elements report | `ops.Options.Elements`, `ops.Options.PendingApprovals` | none | `cmd/smcpd/elements.go` lists every wired element as `info.elements` of `/api/v1/health/status`; `PendingApprovals` feeds `smcp_pending_approvals`. |

## Element status

Every element E-01 to E-33 has code. E-07, E-09, E-12, E-17, E-18, E-23, E-30 and E-31 are recorded as implemented (every allocated requirement verified, none deferred from release 1.0, no other known gap); the others are partial. `docs/status/elements.json` records each element's state and its main gaps, and the requirement report (`make status`, `build/reqreport.md`) lists which requirements tests verify, partly verify or leave unverified. The Data Server (E-25 to E-28) and SS-10 (E-29 to E-32) attach as evidence observers and must not gate enforcement. `cmd/smcpd` wires every element; `smcpctl health` lists each with its runtime state (`info.elements`).

## Residual gaps in what exists

- Result size: lines from a backend are bounded while read (CP-08 plus 64 KiB
  of envelope). When the request ID of an oversized response is not within
  the retained prefix, the response is dropped and the call ends at the
  upstream timeout as indeterminate. Nesting depth is not bounded.
- Held calls: a `tools/call` is served by an event-stream SDK handler
  behind a buffering writer (`edge/stream.go`) and re-encoded as JSON when
  it is never held. A tools/call response that carries more than one event
  without being held (for example backend notifications) is sent as an
  event stream.
- Anchor rollback: replacing the anchor with an older signed copy together
  with deleting later segments is not detectable locally; set
  `[evidence] export_dir` to storage off the machine (FR-7.14).
- Configuration reload applies `log.level`,
  `limits.principal_calls_per_minute` and `limits.principal_call_burst`
  live (CP-50); every other key is reported as `restart_required`.
- Server CA rotation: during the overlap the listener presents the outgoing
  CA's certificate, so clients must import the bundle, not the new CA alone.
- Under the Remote Access profile the per-source limits key on the client
  address the tunnel forwards, which is the provider's claim (FR-16.8);
  call rates are per client ID, and lockout applies to both the client ID
  and the source address (FR-16.6).
- The SDK client caches `tools/list` for `ttlMs`. Policy activation updates
  every cached session catalog in place and sends
  `notifications/tools/list_changed` on that session's open
  `subscriptions/listen` streams; a client without a listen stream sees
  the new catalog when its cache expires.
- Session taint state, rate windows and quotas are in memory and end with
  the session or a restart, like sessions themselves.
- Unknown methods (FR-1.10) answer HTTP 404 with `-32601` in the
  2026-07-28 era; a legacy-era session gets HTTP 200 with `-32601`,
  because a legacy client reads 404 as an expired session.
