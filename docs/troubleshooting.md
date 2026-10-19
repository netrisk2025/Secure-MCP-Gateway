# Troubleshooting and reason codes

Every Gateway error returned to a harness carries a JSON-RPC `code`, `data.reasonCode` and `data.correlationId`, plus `data.decisionId` when a policy decision was made. Search the evidence journal or the console's Audit Investigation view (G-14) for the correlation ID to see every event of the call. This guide is required by SRS FR-18.7; Appendix B of the SRS is the normative table, including the plain-language `data.message` text.

## Quick checks

| Symptom | Check |
|---|---|
| The harness shows no Gateway tools | `smcpctl health`; then confirm the session's template grants tools (`policy.json`) and that the server started (diagnostic log) |
| Every call fails with `-31004` | `smcpctl health` lists the causes; see `FAIL_CLOSED` below |
| TLS or certificate errors in the harness | The harness does not trust the Gateway CA; see the client quick start (`docs/clients/README.md`) |
| The browser sign-in page does not open | The harness must support MCP OAuth; otherwise use `smcp-session` or `smcp-stdio` |
| `smcpctl journal verify` fails | Do not edit or delete journal files; keep a copy of the directory and report the message |

## Reason codes returned to the harness

| Reason code | Code | Meaning | What to do |
|---|---|---|---|
| `NO_PERMIT` | `-31001` | No rule of the session's template permits this tool | Grant the tool in the template, publish the policy, and start a new session |
| `NO_TEMPLATE` | `-31001` | The session's template is not in the active policy | Sign in again; the session was created under a template that no longer exists |
| `TEMPLATE_NOT_PERMITTED` | `-31001` | A session create request (token endpoint or session API) named a template the principal's Framework Profile does not permit; carried in `smcp_error` of the OAuth error | Request a permitted template (or none for the profile default), or add the template to the Framework Profile |
| `PRINCIPAL_DISABLED` | `-31001` | The principal is disabled or suspended (SR-1.5-1) | Re-enable the principal in G-11 (`POST /api/v1/principals/{id}/enable`) if the suspension is over |
| `CREDENTIAL_INVALID` | `-31001` | The client credential is expired or revoked (SR-1.5-1) | Issue a new credential in G-11 and sign the harness in again |
| `REVISION_NOT_ENABLED` | `-31001` | The tool's server revision is not enabled (SR-1.5-1) | Check the server's revision in G-10 (`GET /api/v1/packages`); enable it or restore it from suspension |
| `NO_ROUTE` | `-31001` | No route serves the tool's server and tool revision (SR-1.11-1) | Check that the server is running (`smcpctl health`, G-10) |
| `AMBIGUOUS_ROUTE` | `-31001` | More than one route is eligible for the tool (SR-1.11-1) | Report it: release 1.0 has one route per server alias |
| `HIGH_RISK_UNFLAGGED` | `-31001` | The server is in a high-risk class the template or framework profile does not flag (SR-3.13-1) | Add the class to `high_risk` on the template and its framework profile, if the grant is intended |
| `DENY_RULE` | `-31001` | A deny rule of the session's template covers the tool | Remove or narrow the deny rule and publish; `data.decisiveRules` names it |
| `EVAL_BOUND` | `-31001` | The decision exceeded CP-12 (more than 256 candidate rules for the server, or 500 ms) | Split the template's rules for that server |
| `APPROVAL_DENIED` | `-31001` | An approver denied the call | None; the decision is recorded with the approver's identity |
| `TAINT_DENIED` | `-31001` | The session has read untrusted content and the template denies writing or external tools | Start a new session, or change the template's `taint_action` to `approve` |
| `ARGUMENTS_INVALID` | `-31001` | The arguments are not valid JSON | Fix the client; the harness sent malformed arguments |
| `ARGUMENTS_TOO_LARGE` | `-31001` | The arguments exceed the size-limit filter's bound | Send less data per call, or raise `[filters.size]` `argument_bytes` or `string_bytes` |
| `ARGUMENTS_TOO_DEEP` | `-31001` | The arguments nest deeper than the size-limit filter allows | Raise `[filters.size]` `argument_depth` if the nesting is legitimate |
| `UNICODE_CONTROL` | `-31001` | An argument contains bidirectional, zero-width or tag characters | `data.findings` names the rule; see [filters.md](filters.md) for the permitted contexts |
| `SECRET_IN_ARGUMENTS` | `-31001` | An argument contains a known credential format or a registered secret | The agent tried to send a credential to a tool; check the session's earlier results for how it obtained it |
| `DATA_CLASS_IN_ARGUMENTS` | `-31001` | An argument matches a data-class rule (`pii` rule set) whose request action is `block`; the built-in rules only tag | `data.findings` names the rule; change the rule-set version pinned in `[filters] rule_versions` if the rule is wrong for this tool |
| `PATH_INVALID` | `-31001` | A path argument uses an encoded separator, NUL, backslash traversal or `~` | Use a plain absolute or root-relative path |
| `PATH_OUTSIDE_ROOTS` | `-31001` | A path argument resolves outside the granted roots | Add the directory to `[filters.paths]` `roots` or `server_roots` if access is intended |
| `URL_INVALID` | `-31001` | A URL argument cannot be parsed or canonicalized | Check the URL; it must be absolute with a host |
| `URL_NOT_ALLOWED` | `-31001` | The URL's scheme or host is not allowed, or it carries user information | Adjust `[filters.urls]` `schemes`, `hosts` or `deny_hosts` |
| `URL_PRIVATE_ADDRESS` | `-31001` | The URL names a loopback, private, link-local or reserved destination | Set `[filters.urls]` `allow_private = true` only if the tool must reach local services |
| `FILTER_UNAVAILABLE` | `-31001` | A policy rule names a filter ID that is not registered | Correct the rule's `filters` list; `smcpctl filters rules` and [filters.md](filters.md) list the IDs |
| `FILTER_ERROR` | `-31001`, `-31003` | A required filter failed (fail closed) | Look up the correlation ID in the journal; the `filter` event names the filter |
| `FILTER_TIMEOUT` | `-31001`, `-31003` | A filter chain exceeded the CP-14 deadline (default 2 s) | Narrow the request, or raise `[filters]` `deadline` |
| `APPROVAL_REQUIRED` | `-31002` | The call needs a person's approval | Open `data.approvalUrl` or run `smcpctl approvals list`, approve, then repeat the same request |
| `TAINT_APPROVAL` | `-31002` | Approval required because the session has read untrusted content | As `APPROVAL_REQUIRED` |
| `APPROVAL_EXPIRED` | `-31002` | The approval expired (CP-17) while the call was held | Repeat the request to ask for a new approval; decide within `approvals.lifetime` |
| `APPROVAL_CONSUMED` | `-31002` | An identical concurrent call used the one-use approval first | Repeat the request |
| `APPROVAL_UNAVAILABLE` | `-31002` | The approval service could not take the request (for example, the journal could not record it) | `smcpctl health`; check the journal directory and the diagnostic log |
| `FILTER_BLOCKED` | `-31003` | A required response filter blocked the result (including a filter that names no reason of its own) | Look up the correlation ID; the `filter` event names the filter, the rule and the rule-set version |
| `SECRET_LEAK` | `-31003` | The result appeared to contain a registered secret | Review the server; the secret grant is suspended until you re-enable it |
| `RESULT_TOO_LARGE` | `-31003` | The result exceeded the size bound (CP-08) | Narrow the request, or raise the bound if the result is legitimate |
| `RELEASE_REFUSED` | `-31003` | The release recheck failed: the session was suspended or ended, or an emergency stop is in effect (the journal's `withheld` event names the cause) | Repeat the request |
| `OUTCOME_UNRECORDED` | `-31003` | The tool ran, but its outcome could not be recorded in the evidence journal, so the result was withheld (SR-6.3-1) | Check disk space and permissions of the journal directory; check whether the action happened before repeating it |
| `FAIL_CLOSED` | `-31004` | A critical health check failed | Run `smcpctl health`; fix the listed cause (policy snapshot, journal, vault, clock, trust anchors, audit capacity) |
| `EMERGENCY_STOP` | `-31004` | An emergency stop is in effect | An Administrator resumes with `smcpctl resume` or from G-01 |
| `NO_SNAPSHOT` | `-31004` | No verified policy revision is loaded | If health lists `policy_signature`, a file under `state/policy/` was altered: restore it from a backup and restart, or publish a valid revision with `smcpctl policy publish`. If it lists `policy_invalid`, the signed document fails the current schema or cross-reference checks: publish a corrected revision |
| `JOURNAL_UNAVAILABLE` | `-31004` | The decision could not be recorded in the evidence journal; the call did not run. At start, when the journal cannot be opened for writing, smcpd answers every harness request this way (and `/healthz` with `fail-closed`) until the journal directory is writable, then starts (FR-9.17) | Check disk space and permissions of the journal directory (`<state>/journal`) |
| `POLICY_REVISION_CHANGED` | `-31004` | The policy changed between decision and launch | Repeat the request |
| `CAPABILITY` | `-31004` | The one-use launch capability was missing, expired or already used (FR-4.13) | Repeat the request; if it repeats, report the correlation ID; a correct Gateway never produces it |
| `RATE_LIMITED` | `-31005` | A rate or burst limit was reached (principal, session or session-tool window) | Wait; `data.callsPerMinute` and `data.burst` show the limits |
| `QUOTA_EXHAUSTED` | `-31005` | The session used its `calls_per_session` quota | Start a new session, or raise the quota in the template or rule |
| `QUEUE_FULL` | `-31005` | The dispatch queue is full, or (before authentication) the CP-09 unauthenticated-work limit of the harness listener is in use | Wait, or raise the concurrency limits (CP-10) |
| `SESSION_LIMIT` | `-31005` | A session create request would exceed `sessions_per_principal` (CP-18); carried in `smcp_error` of the OAuth error | End an open session of the principal, or raise `sessions_per_principal` |
| `LISTEN_LIMIT` | `-31005` | The session already holds `listen_streams_per_session` (CP-20) open `subscriptions/listen` streams | Close a listen stream, or raise the limit |
| `SESSION_INVALID` | `-31006` | Missing, expired or unknown token | Sign in again; the harness normally does this itself after a 401 |
| `SESSION_STATE` | `-31006` | The session is suspended or terminated, also while a call was running (that call's outcome is `indeterminate`) | Sign in again; check the effect of a call that was running before retrying it |
| `BACKEND_ERROR` | `-31007` | The server returned a protocol error | `data.backendCode` is the server's code; check the server's stderr in the diagnostic log |
| `BACKEND_OUTPUT_INVALID` | `-31007` | The server wrote a stdout line that is not one UTF-8 JSON-RPC message; the instance was replaced | Check the server's stderr in the diagnostic log; the server is misbehaving or prints logs to stdout |
| `DISPATCH_FAILED` | `-31007` | The server could not be started or reached | Check the Servers view (G-10) and the diagnostic log |
| `RESULT_INVALID` | `-31003` | The server's response was not a valid result (malformed `CallToolResult` or unknown `resultType`) and was withheld | Check the server version; the result never reached the harness |
| `CLIENT_DEADLINE` | `-31008` | The call did not finish within the client deadline (CP-13) | Repeat with a smaller request, or raise the deadline |
| `UPSTREAM_TIMEOUT` | `-31009` | The server stopped responding; it may have acted | Check whether the action happened before repeating it |
| `INSTANCE_FAILED` | `-31009` | The server process ended while a write, external, execute or unclassified tool was running; it may have acted | Check whether the action happened before repeating it; the server was restarted |
| `INPUT_REQUIRED_UNSUPPORTED` | `-31010` | The server returned an `InputRequiredResult` (elicitation, sampling or roots); the Gateway does not relay such requests | The MRTR Relay Profile is not implemented; use a tool that does not ask the client for input |
| `CANCELLED` | `-31009` | The harness cancelled the call after it was sent to the server; the action may have happened | Check the tool's effect before retrying; the journal records the call as `indeterminate` |
| `ANOMALY_WITHHELD` | `-31003` | The Anomaly Response Policy withholds results in this call's sigma band | Review the score in G-06; if the call is normal, promote a new baseline or raise `withhold_band` |
| `SCHEMA_INVALID` | `-32602` | Arguments do not match the tool's input schema | `data.findings` lists the violations |

The Gateway never returns `AMBIGUOUS_ROUTE`, `NO_ROUTE`, `DENY_RULE`, `CREDENTIAL_INVALID`, `PRINCIPAL_DISABLED`, `CAPABILITY` or `ARGUMENTS_INVALID` for a request in release 1.0, and a harness never sees `CANCELLED`: an earlier check answers first (SRS Appendix B, Table B.3 gives the reason for each). A call to a denied or ungranted tool is an unknown tool (`-32602`), and a call after a credential revocation or principal suspension gets `SESSION_INVALID`.

## Reason codes seen by operators only

These appear in the evidence journal, the diagnostic log or command output, not in harness errors.

| Reason code | Where | Meaning | What to do |
|---|---|---|---|
| `PERMIT` | Journal `decision` events | The decision permitted the call | None |
| `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`, `APPROVAL_EXPIRED`, `APPROVAL_CONSUMED` | Journal `approval` events (E-07) | Lifecycle of a tool-call approval; see `docs/approvals.md` | Decide pending approvals in G-07; an expired approval means the harness must call again |
| `APPROVER_SIGNIN`, `APPROVER_SIGNIN_FAILED` | Journal events | Approver account sign-in on the control API | Repeated failures: check who is signing in; the account locks at the failure limit |
| `ADMIN_SIGNIN`, `ADMIN_SIGNIN_FAILED` | Journal `admin` and `auth_failure` events | Administrator sign-in on the control API succeeded or failed | Repeated failures: check who is signing in; reset the password with `smcpctl hash-password` if it is lost |
| `ADMIN_AUTH_FAILED` | Journal `auth_failure` events | A control API request carried a missing, expired or invalid bearer token | Sign in again; for scripts, use the operator token in the state directory |
| `CONSOLE_SIGNIN`, `CONSOLE_SIGNIN_FAILED` | Journal `admin` and `auth_failure` events | Console account sign-in succeeded or failed | Repeated failures: check who is signing in; console accounts are `[[console.account]]` entries |
| `BROWSER_SESSION_STARTED` | Journal `admin` events | A console browser session was created after sign-in | None |
| `CSRF_TOKEN_INVALID` | Journal `auth_failure` events, control API 403 | A console request carried a missing or wrong CSRF token | Reload the console; repeated events from a page you did not open suggest a cross-site request attempt |
| `BOOTSTRAP_REDEEMED`, `BOOTSTRAP_TOKEN_INVALID` | Journal `admin` and `auth_failure` events | The one-use bootstrap credential set the Administrator password, or an expired, used or wrong bootstrap credential was presented | Run `smcpctl bootstrap` again for a new credential if the first one expired |
| `ADMIN_ROLE_REFUSED` | Journal `auth_failure` events | An authenticated account's role does not permit the control API route (control API 403 `role_refused`) | Use an account with the role the route needs (Appendix C) |
| `role_refused`, `not_pending`, `signin_failed`, `audit_unavailable` | Control API error codes | See `docs/api/approvals.md` | Follow the error's `message`; `audit_unavailable` means the journal refused the event (`smcpctl health`) |
| `POLICY_PUBLISHED`, `POLICY_ROLLED_BACK`, `POLICY_IMPORTED`, `POLICY_ACTIVATED` | Journal admin events | A policy revision was stored or activated; see `docs/policy-reference.md` | None |
| `POLICY_INVALID`, `POLICY_CONFLICT`, `POLICY_ACTIVATION_FAILED` | Journal admin events, control API | A publication was refused | Fix the document as the error's findings describe; `POLICY_CONFLICT` means another revision became active first, so start from it |
| `POLICY_SIGNATURE` | Journal admin event, health cause `policy_signature` or `policy_invalid` (detail `cause`) | The active policy revision did not verify at start, or verified but failed the schema or cross-reference checks; the Gateway is fail-closed | Roll back to a good revision (`smcpctl policy rollback`) and keep the state directory for investigation |
| `POLICY_SIMULATED` | Journal admin events | A policy simulation ran | None |
| `SECRET_USE_POLICY_ACTIVATED`, `SECRET_USE_POLICY_INVALID` | Journal `admin` events | A Secret Use Policy revision was activated, or refused as invalid | Fix the policy as the control API error describes |
| `OBSERVATION_OBJECT_PUBLISHED` | Journal `admin` events | An Audit Profile, Observation Policy, Anomaly Response Policy or memory budget revision was published | None |
| `SESSION_END` | Journal session events | A session ended (expiry, termination or revocation) | None; the harness signs in again |
| `SESSION_API` | Journal `session` events | A session was created or terminated through the session API (`smcp-session`, `smcp-stdio`) rather than the browser flow | None |
| `REFRESH` | Journal `session` events | A session's tokens were refreshed | None |
| `refresh_token_reuse` | Journal event | A rotated refresh token was presented again; the session was ended (SR-2.11-4) | Find which copy of the harness holds the old token; a reused token may mean it was copied |
| `CLIENT_AUTH_FAILED` | Journal `auth_failure` events | An OAuth client failed authentication (wrong secret or unknown client) | Check the client's registration (`[[client]]` or G-11) and its secret |
| `AUTH_CODE_REUSE` | Journal `auth_failure` events | An authorization code was redeemed a second time; the session it created was ended | Find the duplicate redemption; a reused code may mean it was intercepted |
| `UDS_PEER` | Journal `session` events | A session was created on the UDS harness socket for a registered peer UID with its key (FR-2.15) | None |
| `UDS_AUTH_REQUIRED`, `UDS_PEER_UNREGISTERED`, `UDS_KEY_INVALID` | Journal `auth_failure` events | A UDS socket connection was refused: its first message was not `local.smcpgw/authenticate`, the peer UID has no `[[uds.peer]]` entry, or the key does not match the entry | Check the harness user's UID against `[[uds.peer]]` and the key in its credential file (`uds_key`) |
| `DCR_PENDING` | Journal `client_registration` and `auth_failure` events | A dynamic client registration is stored and waits for an administrator, or a pending client tried to use it | Approve or deny it in G-11 (`POST /api/v1/clients/{id}/approve` or `/deny`) |
| `DCR_APPROVED`, `DCR_DENIED`, `DCR_REVOKED` | Journal `client_registration` events | An administrator decided a dynamic registration | None |
| `DEVICE_APPROVED`, `DEVICE_DENIED` | Journal `device_authorization` events | A Session Approver approved or denied a device authorization request | None |
| `REMOTE_ACCESS_ENABLED`, `REMOTE_ACCESS_DISABLED`, `REMOTE_ACCESS_RESUMED` | Journal `remote_access` events | The Remote Access Profile was enabled, disabled, or resumed at start | None |
| `REMOTE_LOCKOUT`, `REMOTE_APPROVER_LOCKOUT` | Journal `auth_failure` events | A client ID, caller address or Session Approver reached the remote failure limit and is locked out for a while | Check the source of the failures before clearing; see `docs/remote-access.md` |
| `REMOTE_TEMPLATE_REFUSED` | Journal `session` events | A remote sign-in resolved to a template that is not both listed in `remote.templates` and marked `remote_allowed` in the principal's Framework Profile (FR-16.12) | Add the template to `[remote] templates` and to the profile's `remote_allowed` in a new policy revision, if remote sessions should use it |
| `PROFILE_UNCONFINED` | Server enablement | A `high`-risk server cannot be enabled in the Standalone profile (SR-4-1) | Run it on an Enforced host, or do not enable it |
| `REMOTE_BACKEND_UNSUPPORTED` | Package import | The manifest names a network endpoint; remote backends are out of scope (FR-14.4) | Package the server as a stdio server |
| `SERVER_NOT_ENABLED` | Journal `server` event at start | A configured server revision could not be enabled; the detail gives the reason and the rest of the Gateway runs | Fix the reason in the detail (tool names, manifest, collision) and restart |
| `ALIAS_CONFLICT` | Package enable | The alias is invalid or used by another enabled server | Choose another alias |
| `PUBLIC_NAME_COLLISION` | Package enable | Two tools map to one public name, or a name exceeds 64 characters | Change the alias, or ask the packager to rename the tool |
| `STATEFUL_UNCONTRACTED` | Package enable | The manifest declares stateful tools without a handle contract | Ask the packager to declare the server stateless; stateful servers are not supported in release 1.0 |
| `STATE_TRANSITION_REFUSED` | Package enable, disable, retire | The change is not allowed from the revision's current state | Check the revision's state with `GET /api/v1/packages` |
| `PACKAGE_NOT_ENABLED` | Start | A `[[server]]` entry names a package with no enabled revision | Enable a revision in G-10, or remove the entry |
| `PACKAGE_PIN_MISMATCH` | Start | `package_sha256` differs from the enabled artifact | Update the pin to the enabled revision's digest, or enable the pinned revision |
| `PACKAGE_UNKNOWN` | Control API, CLI | No such package revision | List revisions with `GET /api/v1/packages` |
| `UNSIGNED_SERVER_REFUSED` | Start | `require_signed` is set and a `[[server]]` entry uses `command` | Package the server, or turn off `require_signed` |
| `REGISTRY_LOCKED` | Package import and enable | Another package operation holds the registry lock | Retry when the other operation has finished |
| `IMPORT_FAILED` | Package import receipt | The import failed for a reason the receipt's detail gives | Fix the cause named in the receipt and import again |
| `DOWNGRADE_REFUSED` | Package import | A higher revision of the server is installed | Import a newer revision, or retire the installed one first |
| `REVISION_CONFLICT` | Package import | The revision exists with a different package index | Ask the packager to issue a new revision number |
| `REVOKED` | Package import | The revision is on the revocation feed | Do not use it; import a fixed revision |
| `REVOCATION_INVALID` | Revocation scan | A revocation entry is malformed or unsigned | Check the feed source; the entry is ignored |
| `REVOCATION_FEED_STALE` | Package import, health cause `revocation_feed_stale` | The revocation feed has not been read for more than 24 hours (CP-34); imports are refused (SR-3-4) | Restore access to the feed; imports resume after the next successful read |
| `CLASSIFICATION_OVERRIDDEN`, `CLASSIFICATION_LOOSENING_REFUSED`, `CLASSIFICATION_TOOL_UNKNOWN` | Journal events, control API | A tool classification override was stored, refused because it would loosen the manifest's classification, or named an unknown tool (SR-3.11-1) | Overrides can only tighten; name a tool the revision serves |
| `ARTIFACT_TAMPERED` | Launch | The stored artifact or its unpacked tree changed after import | Treat the host as suspect; re-import the package from its source |
| `MANIFEST_DRIFT` | Start, `list_changed` | The live tool list differs from the signed manifest; the revision is suspended | Ask the packager for a new revision; do not use the server until then |
| `MANIFEST_EXPIRED` | Package enable, scan | The manifest's expiry or re-curation date has passed | Import a re-curated revision |
| `MANIFEST_SCHEMA` | Package verify, import | The manifest violates Appendix J or a rule the schema cannot express | Fix the manifest (`smcpctl package verify` names the rule) |
| `MANIFEST_VERSION_UNSUPPORTED` | Package verify, import | `manifest_version` is not 1 | Rebuild the package with this release's tools |
| `PACKAGE_INDEX_INVALID` | Package verify, import | The index is malformed or names another package than the manifest | Rebuild the package |
| `PACKAGE_INDEX_MISSING`, `PACKAGE_SIGNATURE_MISSING`, `PACKAGE_MANIFEST_MISSING`, `PACKAGE_PROVENANCE_MISSING`, `PACKAGE_ARTIFACT_MISSING`, `SIGNER_KEY_ID_MISSING` | Package verify, import | A package component is missing (FR-5.2) | Rebuild or re-download the package |
| `SIGNATURE_INVALID` | Package verify, import | The signature does not verify, or names another key than the index | Do not use the package; obtain it again from the packager |
| `SIGNER_UNKNOWN` | Package verify, import | The signer is neither the given key nor an enrolled trust anchor | Enroll the packager's key in G-10 after confirming its fingerprint |
| `ANCHOR_EXPIRED` | Package verify, import | The signing trust anchor has expired | Renew the anchor with the packager's current key |
| `ANCHOR_SCOPE` | Package verify, import | The package's risk class is outside the anchor's classes | Widen the anchor's classes if intended, or use another anchor |
| `TRUST_ANCHOR_ENROLLED`, `TRUST_ANCHOR_REMOVED` | Journal events | A trust anchor was enrolled or removed | None |
| `DIGEST_MISMATCH` | Package build, verify, import | A fetched file, listed file or lock entry does not match its digest | Re-download; a persistent mismatch means the source changed |
| `PROVENANCE_BINDING` | Package verify, import | The provenance statement names another artifact, source or package (SR-3.2-1) | Rebuild the package |
| `SOURCE_EVIDENCE_MISSING` | Package verify, import | The provenance statement lacks a source digest or licenses (SR-3.1-1) | Rebuild the package with complete provenance |
| `UNPINNED_LAUNCH` | Package verify, import, start | The launch vector runs a package runner, installer or shell (SR-3.6-1) | Package a pinned executable instead |
| `UNPINNED_REFERENCE` | Package build | The artifact reference has no exact version or digest | Pin the version or digest in the recipe |
| `ERA_UNSUPPORTED` | Package build | The server negotiated a protocol version a manifest cannot declare | Build against a server version that speaks a supported protocol version |
| `FETCH_FAILED` | Package build | The registry or file could not be read | Check network access and the reference |
| `PROBE_FAILED` | Package build | The server did not start, did not answer or listed no tools | Run the server by hand and check its stderr |
| `KEY_ON_COMMAND_LINE` | Package sign, keygen, revoke | A secret key or passphrase was given as an argument | Pass it in a file or on standard input |
| `metadata_blocked` | Journal event | A tool description matched a blocking metadata rule and the tool is suspended (SR-5.9-2) | Review the description; ask the packager for a fixed revision |
| `METADATA_BLOCKED` | Journal `server` event with outcome `metadata_blocked` | Reason code of that event; `detail.findings` names each rule, rule set and version, and `detail.stage` is `import` or `presentation` | As for `metadata_blocked` |
| `artifact_recorded` | Journal `server` event (E-15) at start | The content address of a command-configured server: `detail.digest` and the SHA-256 of the command file and each absolute file argument (SR-3.6-1). A later relaunch whose files differ is refused and the server is suspended with "changed since the server was enabled" | If the change is intended (an upgrade of the server), restart smcpd so the new files are recorded, or update `command_sha256` |
| `REDACTED` | Journal `filter` event | A filter removed or replaced content; the result's provenance disposition is `redact` | None |
| `upgrade_rolled_back` | Journal event | An upgrade failed its health check and the previous version was restored (FR-13.8) | Read the upgrade's log, fix the cause and upgrade again |
| `MEMORY_LIMIT` | Journal `runtime` event | A sandboxed instance reached its memory limit and was killed ([sandbox](sandbox.md)) | Raise the manifest's memory resource if the use is legitimate |
| `PIDS_LIMIT` | Journal `runtime` event | A sandboxed instance reached its PID limit and was killed | Raise the manifest's PID resource if the use is legitimate |
| `UNDECLARED_PROCESS` | Journal `runtime` event | A sandboxed server without `allow_spawn` started a process | Investigate the server; set `allow_spawn` only if the packager declares process spawning |
| `EXEC_INTO_INSTANCE` | Journal `runtime` event | Someone ran `podman exec` in a server's container | Find who ran it; nobody should enter a server container |
| `OPERATOR_KILL` | Journal `runtime` event | An administrator killed an instance with `smcpctl runtime kill` | None |
| `INSTANCE_EXITED_UNEXPECTEDLY` | Journal `runtime` event | A server instance ended without being asked to; its tools fail until the Gateway restarts | Check the server's stderr (`smcpctl runtime show`) and the `server_asserted` events |
| `MONITOR_UNAVAILABLE` | Journal `runtime` event | The Runtime Monitor could not find an instance's cgroup | Check cgroup v2 delegation on the host (`docs/sandbox.md`) |
| `HEALTH_FAIL_CLOSED`, `HEALTH_DEGRADED`, `HEALTH_HEALTHY` | Journal `health` events | The health monitor changed state; the detail lists the causes (`docs/operations/health.md`) | Clear the listed causes; `smcpctl health` shows the current ones |
| `HEALTH_ACK` | Journal event | An administrator acknowledged a latched integrity cause | None |
| `JOURNAL_RECOVERED` | Journal `journal` event at start | The journal's last segment ended in a partial record after a crash, and the Gateway truncated it to the last complete record | Run `smcpctl journal verify`; keep a copy of the directory if verification fails |
| `CONFIG_RELOADED`, `CONFIG_INVALID` | Journal event, `smcpctl reload` | A configuration reload was applied or rejected (`docs/operations/logging-metrics-reload.md`) | Fix the configuration as `smcpctl reload` reports |
| `LISTENER_CERT_ROTATED`, `LISTENER_CERT_RENEWED`, `SERVER_CA_ROTATION_STARTED`, `SERVER_CA_ACTIVATED`, `EVIDENCE_KEY_ROTATED` | Journal `key_rotated` events | A certificate or key was rotated (`docs/operations/keys.md`) | None |
| `BACKUP_WRITTEN`, `BACKUP_FAILED`, `BACKUP_DRAIN_TIMEOUT`, `BACKUP_UNENCRYPTED_REFUSED` | Journal event, `smcpctl backup` | Result of a backup request (`docs/operations/backup.md`) | On failure, follow the message; give a passphrase file for encrypted backups |
| `SECRET_APPROVAL_REQUIRED` | Journal `secret` events | An S2 binding requires approval but the decision carries none | Make the policy rule approval-obligated |
| `SECRET_DELIVERY_FAILED` | Journal `secret` events | Writing the secret file or binding the header failed | Check `runtime_dir` permissions and free space |
| `SECRET_EXPIRED` | Journal `secret` events | The secret's expiry has passed | Rotate it and update `--expires`, or create a new one |
| `SECRET_MODE_UNAVAILABLE` | Journal `secret` events | S1 delivery without an Egress Broker | Set `[egress] enabled = true`, or use S3 or S2 |
| `SECRET_NOT_FOUND` | Journal `secret` events | The bound secret is not in the vault | `smcpctl secrets set NAME` |
| `SECRET_NOT_GRANTED` | Journal `secret` events | A `secret_env` entry has no Secret Use Policy | Add a policy for the slot, or remove the entry |
| `SECRET_NO_INSTANCE` | Journal `secret` events | No running instance prepared the S2 slot | Check that the server started; reload does not add S2 slots to running instances |
| `SECRET_OUTSIDE_WINDOW` | Journal `secret` events | Outside `not_before`, `not_after`, `hours`, or the S4 waiver expired | Wait for the window or change the policy |
| `SECRET_PURPOSE_MISMATCH` | Journal `secret` events | The S2 `session_purpose` differs from the session's purpose | Sign in with the right purpose |
| `SECRET_RATE_LIMITED` | Journal `secret` events | The S2 `calls_per_minute` was reached | Retry later, or raise the limit |
| `SECRET_SUSPENDED` | Journal `secret` events | A leak of this secret was detected | Review, rotate if needed, then `smcpctl secrets resume NAME` |
| `SECRET_UNAVAILABLE` | Journal `secret` events | The value could not be decrypted | Check the vault files and key |
| `SECRET_VERSION_RETIRED` | Journal `secret` events | A pinned secret version was retired | Remove or update `version` in the policy |
| `SECRET_RETIRED` | Journal `secret` events | A secret version was retired (rotated, removed, or its overlap window elapsed) | None |
| `EGRESS_NO_GRANT` | Journal `egress` events, 403 to the server | No grant of the server names this host and port | Add an `[[egress.grant]]` for the server if the destination is intended |
| `EGRESS_METHOD_REFUSED` | Journal `egress` events, 403 | The destination is granted, but not for this method (or not for `CONNECT-TLS`) | Add the method to the grant's `methods` |
| `EGRESS_ADDRESS_REFUSED` | Journal `egress` events, 403 | The destination resolves only to reserved addresses | If the destination is a local service on purpose, list its exact address in `addresses` |
| `EGRESS_BAD_REQUEST` | Journal `egress` events, 400 | A malformed target, a request form the proxy or endpoint does not accept, or a protocol upgrade | Use the proxy for absolute URLs and CONNECT, and the endpoint for paths |
| `EGRESS_PUBLIC_FETCH_PROFILE` | Journal `egress` events, 403 | A public-fetch grant was used with a body, an `Authorization` header or plain HTTP | Public-fetch is for anonymous GET over HTTPS; use an `api` grant otherwise |
| `EGRESS_REDIRECT_REFUSED` | Journal `egress` events, 403 | An endpoint was redirected to an ungranted, non-HTTPS or malformed target, or more than 3 times | Grant the redirect target, or call the final URL directly |
| `EGRESS_RATE_LIMITED` | Journal `egress` events, 429 | The server's `requests_per_minute` was reached | Raise the limit or reduce the server's request rate |
| `EGRESS_BYTE_RATE_LIMITED` | Journal `egress` events, 429 or connection cut | The server's `bytes_per_minute` was reached | Raise the limit |
| `EGRESS_REQUEST_TOO_LARGE` | Journal `egress` events, 413 or connection cut | The request body or tunnel upload is above the limit | Raise `request_bytes` |
| `EGRESS_RESPONSE_TOO_LARGE` | Journal `egress` events, 502 or connection cut | The response body or tunnel download is above the limit | Raise `response_bytes` |
| `EGRESS_TIMEOUT` | Journal `egress` events, 504 or connection cut | `operation_timeout` (or the grant's `timeout`) was reached | Raise the timeout |
| `EGRESS_DNS_FAILED` | Journal `egress` events, 502 | The broker could not resolve the name | Check the host's DNS |
| `EGRESS_UPSTREAM_FAILED` | Journal `egress` events, 502 | Connection, TLS validation or protocol failure at the destination | Check the destination and its certificate |
| `EGRESS_NOT_TLS` | Journal `egress` events, connection closed | A CONNECT tunnel did not start with a TLS ClientHello | Tunnels carry TLS only; use plain-HTTP proxying for `http://` |
| `EGRESS_SNI_MISMATCH` | Journal `egress` events, connection closed | The TLS server name differs from the CONNECT host, or is missing | The server must connect with the granted host name as SNI |
| `EGRESS_EVIDENCE_UNAVAILABLE` | Journal `egress` events, 503 | The journal refused the authorization event | See `smcpctl health`; the journal must be writable |
| `EGRESS_CAPABILITY_REQUIRED` | Journal `egress` events, 403 | The operation carried no `Smcp-Egress-Auth` capability | The server must send a token from the call's `local.smcpgw/egress_auth` metadata; servers that cannot need `[egress] require_capability = false` |
| `EGRESS_CAPABILITY_INVALID`, `EGRESS_CAPABILITY_REPLAYED`, `EGRESS_CAPABILITY_MISMATCH` | Journal `egress` events, 403 | The token was unknown, expired or revoked; already spent; or minted for another instance or destination | Use a fresh token of the current call for the matching destination; raise `capability_tokens` if a call needs more operations |
| `EGRESS_EXCEEDS_MANIFEST` | `server_not_started` event, `servers` of `GET /api/v1/packages` | A configured egress grant of a packaged server exceeds its manifest's egress capabilities (host, port or method named) | Narrow the grant, or publish a package revision that declares the destination |
| `EGRESS_SECRET_DETECTED` | Journal `egress` events, 403 | An outbound request carried a known secret value outside its granted delivery (SR-5.8-2) | Investigate the server; rotate the secret if it may have leaked |
| `ANOMALY_ELEVATED`, `ANOMALY_ABNORMAL`, `ANOMALY_CRITICAL` | Journal `anomaly` events | A call scored in that sigma band against its baseline; the detail carries the score and the actions taken | Review the call in G-06; promote a new baseline if the behavior is the new normal |
| `BASELINE_PROMOTED`, `BASELINE_AUTO_PROMOTED`, `BASELINE_ROLLED_BACK` | Journal events | A baseline snapshot was promoted by an operator or automatically, or rolled back | None |
| `BASELINE_DIGEST_MISMATCH` | Journal `integrity` event | A stored baseline snapshot does not match its recorded digest and was not loaded | Roll back to an earlier snapshot or rebuild the baseline; keep the store for investigation |
| `CAMPAIGN_QUOTA_REACHED` | Journal `research` events | A research campaign reached its record quota and completed | Export its dataset; create a new campaign to continue |
| `DATA_PURGED` | Journal events, `POST /api/v1/observations/purge` | Observation data was purged; the event is the deletion receipt (SR-6.15-1) | None |
| `GRAPH_REBUILD` | Journal `admin` events | An administrator asked for the graph mirror to be rebuilt from the journal | Wait for the mirror's state to return to `ready` (`smcpctl graph status`) |
