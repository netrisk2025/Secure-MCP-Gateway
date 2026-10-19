## Appendix A — Controlled parameters (CP)

Values marked **SEC** are inherited from `MCP_Gateway_Security_SRS.md` Appendix A. Values marked **ARCH** come from `ArchitectureV2.md`. Changing a value requires a controlled revision of this SRS.

| ID | Parameter | Value | Origin |
|---|---|---|---|
| CP-01 | Northbound MCP endpoint path | `/mcp` | New |
| CP-02 | Harness listeners | TLS: `127.0.0.1:8443`; UDS (profile): `/run/smcp/harness.sock` | New |
| CP-03 | Admin listener | `127.0.0.1:8444` (TLS; `[admin_listener] address`) | New |
| CP-04 | Northbound supported protocol versions | `["2026-07-28", "2025-11-25"]`, both served in the baseline | SEC 5.1 |
| CP-05 | Southbound protocol eras | Modern `2026-07-28`; legacy `2025-11-25` | SEC 5.1 |
| CP-06 | Header limit / header deadline | 16 KiB / 5 s | SEC |
| CP-07 | Request body limit / body deadline | 1 MiB / 15 s | SEC |
| CP-08 | Expanded result size / JSON depth | 8 MiB / 32 | SEC |
| CP-09 | Connections / unauthenticated work / per-source rate | 128 / 32 concurrent / 10 req/s, burst 20 | SEC |
| CP-10 | Tool concurrency / queue | 4 per principal, 16 total / 32 | SEC |
| CP-11 | Default principal tool rate | 60 calls/min, burst 10 (at most 10 calls in any 10 s window; `[limits] principal_calls_per_minute`, `principal_call_burst`) | SEC |
| CP-12 | Decision deadline / candidate rules | 500 ms / 256 | SEC |
| CP-13 | Upstream execution / client deadline | 45 s / 60 s | SEC |
| CP-14 | Required filter deadline | 2 s per profile | SEC |
| CP-15 | Credential lifetime / rotation overlap | 30 days / ≤ 24 h | SEC |
| CP-16 | Revocation propagation | ≤ 2 s | SEC |
| CP-17 | Approval lifetime | ≤ 5 min, one use | SEC |
| CP-18 | Session max lifetime / idle timeout / concurrent sessions per principal | 8 h / 30 min / 8 | New |
| CP-19 | Catalog `ttlMs` / page size | 60,000 ms / 100 tools | New |
| CP-20 | Listen keep-alive / listen streams per session | 15 s / 2 | New |
| CP-21 | Progress relay rate | ≤ 10 notifications/s per request | New |
| CP-22 | Gateway error codes | Appendix B | New |
| CP-23 | Gateway metadata names | `_meta` prefix `local.smcpgw/`; session token in `Authorization: Bearer` (RFC 6750 header only) on the TLS listener; on the UDS listener the session is bound to the connection (first message `local.smcpgw/authenticate`, FR-2.15); egress header `Smcp-Egress-Auth`, whose one-use capabilities each call delivers in `_meta` `local.smcpgw/egress_auth` | New |
| CP-24 | Default instance budget | 512 MiB RAM, 1 CPU, 128 PIDs | SEC |
| CP-25 | Retention defaults | Metadata 90 d; payload 7 d; temporary full capture ≤ 24 h | SEC |
| CP-26 | Audit/evidence quota | 10 GiB; warn at 80% | SEC |
| CP-27 | Journal signing lag | Target 5 s; stop when the oldest unsigned event is older than 60 s or more than 1,000 events are unsigned | SEC |
| CP-28 | Argon2id | 64 MiB, t = 3, p = 1, salt ≥ 16 B | SEC |
| CP-29 | Admin session | 15 min idle, 8 h absolute | SEC |
| CP-30 | Anomaly defaults | Bands: normal \|z\| < 2, elevated < 3, abnormal < 4, critical ≥ 4; n_min = 30; σ_floor from catalog | ARCH §9.2 |
| CP-31 | Sampling defaults | Normal band 10%; elevated and above 100% | ARCH §9.5 |
| CP-32 | Performance targets | Decision p95 ≤ 10 ms (ceiling 100 ms); scoring p95 ≤ 2 ms; capture ≤ 1 ms; overhead p95 ≤ 50 ms (ceiling 250 ms); ingest ≥ 2,000 rec/s; snapshot ≤ 60 s / 10k contexts; GUI query p95 ≤ 2 s; idle RSS ≤ 4 GiB | ARCH §14; SEC |
| CP-33 | Default memory budget | Graph heap 1 GiB; graph page cache 1 GiB; DuckDB 512 MiB; baseline cache 128 MiB; capture queues 64 MiB; Gateway core 512 MiB | New |
| CP-34 | Revocation feed maximum staleness | 24 h | New |
| CP-35 | Artifact re-verification | At every instance launch | ARCH §4 E-13 |
| CP-36 | Schema validation bounds | Depth 32; 1,000 subschemas; 50 ms | New |
| CP-37 | stderr capture | 64 KiB per call; 1 MiB ring per instance | New |
| CP-38 | Instance idle teardown | 10 min | New |
| CP-39 | MRTR `requestState` lifetime | 5 min | New |
| CP-40 | Research pseudonym function | HMAC-SHA-256, per-dataset key | ARCH §4 E-32 |
| CP-41 | OAuth parameters | Authorization-code grant (Remote Access listener also: the RFC 8628 device authorization grant used by `smcp-connect`, device code lifetime 10 min, poll interval 5 s); PKCE `S256` only; resource URI `https://127.0.0.1:8443/mcp` (Remote Access listener: the configured public URL followed by `/mcp`); scope prefix `smcp:` with `template`, `purpose`, `project`, `user`; access-token lifetime = CP-18 idle timeout; refresh-token lifetime = CP-18 maximum lifetime; client-secret lifetime = CP-15; `iss` in authorization responses | New |
| CP-42 | Public tool names | `<alias>_<tool>`; alias `[a-z0-9]{1,16}`; tool part `[A-Za-z0-9_]`; whole name ≤ 64 characters | New |
| CP-43 | Adapter credential file | `$XDG_CONFIG_HOME/smcp/credentials.toml` (default `~/.config/smcp/`), mode 0600; refresh at 50% of access-token lifetime | New |
| CP-44 | Manifest classes | Risk class `low`, `moderate` or `high`; `high` = general SQL, code or shell execution, CAD scripting, browser automation, or process spawning beyond the declared argument vector (SEC 3.13). Side-effect class per tool: `read`, `write`, `external`, `execute`. `source_trust` per tool: `trusted` (content originates from the operator's own data) or `untrusted` (content from the Internet, third parties or other agents) | New |
| CP-45 | Approval hold | Hold bound 120 s (`[limits] approval_hold`, configurable 0 to 600 s; 0 disables hold); keep-alive interval 10 s (`[approvals] keepalive`); approval URL `https://<CP-03 admin listener>/approvals/<approvalId>`, or `[approvals] console_url` followed by `/approvals/<approvalId>` when set | New |
| CP-46 | Directories and service identities | **Enforced:** configuration `/etc/smcp` (root:smcp, 0750); state `/var/lib/smcp` with `policy/`, `registry/`, `artifacts/` (owner `smcp-core`, 0700), `journal/` (owner `smcp-evidence`, 0700), `keys/` (owner `smcp-keys`, 0700), `vault/` (owner `smcp-vault`, 0700), `exports/` (owner `smcp-core`, 0750); runtime `/run/smcp` (0750); logs `/var/log/smcp` (0750). Identities `smcp-core`, `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data`, `smcp-console`, and `smcp-srv` with a subordinate range of 65,536 UIDs and GIDs for rootless Podman. **Standalone macOS:** `~/Library/Application Support/smcp-gateway/` with `config/` and `state/`, logs `~/Library/Logs/smcp-gateway/`, all 0700. **Standalone Linux:** configuration `$XDG_CONFIG_HOME/smcp-gateway` (default `~/.config/smcp-gateway`), state `$XDG_STATE_HOME/smcp-gateway` (default `~/.local/state/smcp-gateway`) including `log/`, runtime `$XDG_RUNTIME_DIR/smcp-gateway`, all 0700 | New |
| CP-47 | Upgrade bounds | Health wait after start 60 s; migration time limit 120 s | New |
| CP-48 | Remote listener | The first of `127.0.0.1:8444` and `127.0.0.1:8445` that the CP-03 admin listener does not use (`127.0.0.1:8445` with the default admin listener; `[remote] address` overrides); TLS, Remote Access Profile only; public name set by the operator | New |
| CP-49 | Remote limits | Calls 30/min per client ID, burst 5; OAuth endpoints 10 req/s per source address, burst 20; lockout after 5 consecutive failed sign-ins or token requests, for 15 min; body 256 KiB; headers 8 KiB; concurrency 4 per client, 16 total; remote session maximum lifetime 2 h, idle timeout 15 min; pending dynamic registrations at most 32 in total and 4 per source address (IPv6: per /64), each kept 24 h | New |
| CP-50 | Diagnostic log and reload | Rotate at 10 MiB, keep 5 files. Reloadable keys: `log.level`, `limits.principal_calls_per_minute`, `limits.principal_call_burst`. Restart required: every other key, among them listener addresses, `state.dir`, `profile` and the other `limits.*` (read at startup by the components that hold them); servers are enabled and disabled at run time through G-10, and clients are managed in G-11 | New |
| CP-51 | Metrics endpoint | `127.0.0.1:9464`, path `/metrics`; disabled by default | New |
| CP-52 | Client ID Metadata Document allowlist | Empty by default; entries are added only by `[[client_metadata]]` configuration entries (`smcpctl clients setup` does not add them). Fetch only allowlisted HTTPS URLs; 5 s timeout; 64 KiB limit; cache 24 h; no redirects to other hosts | New |
| CP-53 | Local server CA | Validity 365 days; listener certificate validity 90 days, renewed when 30 days remain; CA name constraints are dNSName subtrees only, permitting `localhost` and the configured listener host names (no iPAddress subtrees, which BoringSSL-based TLS clients reject); listener certificate IP addresses are limited to loopback addresses and the configured listener IP literals; path length 0 | New |

## Appendix B — Gateway error codes and reason codes

Gateway-specific codes lie outside the JSON-RPC reserved range (`-32768` to `-32000`), as the MCP specification recommends. Every error carries `data.reasonCode`, `data.correlationId` and the plain-language `data.message` of Table B.2, plus `data.decisionId` when a decision exists (FR-1.20, FR-1.51).

### B.1 Error codes

| Code | Name | HTTP status (Streamable HTTP) | Meaning |
|---|---|---|---|
| `-31001` | PolicyDenied | 200 | The policy decision denied the request |
| `-31002` | ApprovalRequired | 200 | A human approval is pending; retry after approval (`data.approvalId`, `data.expiresAt`) |
| `-31003` | ResponseWithheld | 200 | The response was withheld by response inspection, scoring or release checks |
| `-31004` | GatewayFailClosed | 503 | Enforcement dependencies are unavailable or the Gateway is stopped |
| `-31005` | RateLimited | 429 | A rate, concurrency, queue or stream limit was reached |
| `-31006` | SessionInvalid | 401 | Missing, invalid, expired, suspended or misbound session |
| `-31007` | BackendError | 200 | The backend failed or returned a protocol error (`data.backendCode`) |
| `-31008` | Timeout | 200 | The client deadline expired |
| `-31009` | IndeterminateOutcome | 200 | A possibly executed mutation lost its outcome; it is not retried |
| `-31010` | InputRequiredUnsupported | 200 | The backend requested client input and the MRTR Relay Profile is disabled |

Standard codes used: `-32700`, `-32600`, `-32601`, `-32602`, `-32603`, `-32020` (HeaderMismatch), `-32022` (UnsupportedProtocolVersion).

### B.2 Reason codes and messages

`docs/troubleshooting.md` repeats this table with the operator's next action for each reason code (FR-18.7).

| Reason code | Code | Meaning | `data.message` |
|---|---|---|---|
| `NO_PERMIT` | `-31001` | No rule of the session's template permits the call | The Gateway's policy does not allow this tool in this session. Ask the Gateway operator to grant it. |
| `NO_TEMPLATE` | `-31001` | The session's template is not in the active policy | This session's policy template no longer exists. Sign in again to start a new session. |
| `TEMPLATE_NOT_PERMITTED` | `-31001` | A session create request named a template the principal's Framework Profile does not permit (FR-2.6) | The requested policy template is not permitted for this agent. Request a template its framework profile allows, or none for the default. |
| `PRINCIPAL_DISABLED` | `-31001` | The principal is disabled or suspended (SR-1.5-1) | This agent's access to the Gateway is suspended. Ask the Gateway operator. |
| `CREDENTIAL_INVALID` | `-31001` | The client credential is expired or revoked (SR-1.5-1) | This agent's Gateway credential is no longer valid. Ask the Gateway operator for a new one. |
| `REVISION_NOT_ENABLED` | `-31001` | The tool's server revision is not enabled (SR-1.5-1) | The tool's server is not enabled on the Gateway. Ask the Gateway operator. |
| `NO_ROUTE` | `-31001` | No route serves the tool's server and tool revision (SR-1.11-1) | The tool's server is not available right now. Try again later or ask the Gateway operator. |
| `AMBIGUOUS_ROUTE` | `-31001` | More than one route is eligible for the tool (SR-1.11-1) | The Gateway could not choose how to reach this tool and refused the call. Ask the Gateway operator. |
| `HIGH_RISK_UNFLAGGED` | `-31001` | The server is in a high-risk class the template or framework profile does not flag (SR-3.13-1) | This tool is in a high-risk class that this session's policy does not allow. |
| `DENY_RULE` | `-31001` | A deny rule of the session's template covers the tool (SR-1.4-1) | The Gateway's policy forbids this tool in this session. |
| `EVAL_BOUND` | `-31001` | The evaluation exceeded the CP-12 deadline or candidate-rule bound (SR-1.20-1) | The Gateway could not finish checking this call within its limits and refused it. Ask the operator to simplify the policy. |
| `APPROVAL_DENIED` | `-31001` | An approver denied the call | A person reviewing this call denied it. |
| `TAINT_DENIED` | `-31001` | The session is tainted and the template denies this side-effect class | This session has read untrusted content, so tools that write or send data are blocked. Start a new session to use them. |
| `ARGUMENTS_INVALID` | `-31001` | The arguments are not valid JSON (`size-limit` and argument filters) | The request arguments could not be read. |
| `ARGUMENTS_TOO_LARGE` | `-31001` | The arguments exceed the `size-limit` byte or string bound | The request is too large for this tool. Send less data in one call. |
| `ARGUMENTS_TOO_DEEP` | `-31001` | The arguments nest deeper than the `size-limit` depth bound | The request is nested too deeply. Simplify the arguments. |
| `UNICODE_CONTROL` | `-31001` | An argument contains bidirectional, invisible or tag characters (`unicode-control`) | The request contains hidden or direction-changing characters. Remove them and try again. |
| `SECRET_IN_ARGUMENTS` | `-31001` | An argument contains a known credential format or a registered secret (`secret-fingerprint`, SR-5.8-1) | The request appears to contain a password, key or token, so it was not sent. Remove the secret and try again. |
| `DATA_CLASS_IN_ARGUMENTS` | `-31001` | An argument matches a data-class rule whose request action is block (`pii-detect` named by the decision, SR-5.8-1) | The request contains personal or classified data that this tool may not receive, so it was not sent. Remove it and try again. |
| `PATH_INVALID` | `-31001` | A path argument uses an encoded separator, NUL, backslash traversal, home-relative or remote file form (`path-canonicalize`) | A file path in the request is not allowed in this form. Use a plain path. |
| `PATH_OUTSIDE_ROOTS` | `-31001` | A path argument resolves outside the granted roots (`path-canonicalize`, SR-1.8-4) | A file path in the request is outside the folders this tool may use. |
| `URL_INVALID` | `-31001` | A URL argument cannot be parsed or canonicalized (`url-canonicalize`) | A web address in the request is not valid. |
| `URL_NOT_ALLOWED` | `-31001` | A URL argument's scheme or host is not allowed, or it carries user information (`url-canonicalize`, SR-1.8-5) | A web address in the request is not allowed for this tool. |
| `URL_PRIVATE_ADDRESS` | `-31001` | A URL argument names a loopback, private, link-local or reserved destination (`url-canonicalize`) | A web address in the request points to a local or private network address, which this tool may not use. |
| `FILTER_UNAVAILABLE` | `-31001` | The decision's obligations name a filter that is not registered | The Gateway could not run a required check for this tool. Give the operator the correlation ID {correlationId}. |
| `FILTER_ERROR` | `-31001`, `-31003` | A required filter failed; the request is blocked or the result withheld (SR-5.10-1) | A Gateway safety check failed, so the call was stopped. Give the operator the correlation ID {correlationId}. |
| `FILTER_TIMEOUT` | `-31001`, `-31003` | A filter chain exceeded the CP-14 deadline (SR-5.10-1) | A Gateway safety check took too long, so the call was stopped. Try a smaller request. |
| `APPROVAL_REQUIRED` | `-31002` | The call is waiting for a person to approve it | This call needs approval. Open {approvalUrl} to approve it, then run the same request again. |
| `TAINT_APPROVAL` | `-31002` | Approval required because the session is tainted | This session has read untrusted content, so this tool needs approval. Open {approvalUrl} to approve it, then run the same request again. |
| `APPROVAL_EXPIRED` | `-31002` | The approval expired (CP-17) while the call was held | The approval for this call expired before it was used. Run the same request again to ask for a new approval. |
| `APPROVAL_CONSUMED` | `-31002` | An identical held call consumed the one-use approval first | The approval for this call was already used by an identical call. Run the same request again to ask for a new approval. |
| `APPROVAL_UNAVAILABLE` | `-31002` | The call needs approval and the Approval Service could not take the request | This call needs approval, but the Gateway's approval service is not available. Ask the Gateway operator to approve the call or check `smcpctl health`, then run the same request again. |
| `FILTER_BLOCKED` | `-31003` | A required response filter blocked the result | The tool's result was withheld by a Gateway content filter. The operator can see why in the audit record {correlationId}. |
| `SECRET_LEAK` | `-31003` | A registered secret fingerprint matched the result | The tool's result was withheld because it appeared to contain a protected secret. |
| `RESULT_TOO_LARGE` | `-31003` | The result exceeded the CP-08 bound | The tool's result was too large to inspect and was withheld. Narrow the request. |
| `RESULT_INVALID` | `-31003` | The backend response failed envelope, request-ID or `CallToolResult` validation, or carried an unrecognized `resultType` (SR-5.20-1, FR-5.23) | The tool's server returned a result the Gateway could not validate, so it was withheld. |
| `RELEASE_REFUSED` | `-31003` | The release recheck failed (session ended, policy changed or stop) | The result was withheld because the session or policy changed while the tool ran. Run the request again. |
| `OUTCOME_UNRECORDED` | `-31003` | The tool ran but its outcome could not be written to the Evidence Journal, so the result is withheld (SR-6.3-1) | The tool ran, but the Gateway could not record its outcome, so the result was withheld. It may have completed the action; check before trying again. The operator can see the cause with `smcpctl health`. |
| `ANOMALY_WITHHELD` | `-31003` | Synchronous scoring placed the call in the Anomaly Response Policy's withhold band (FR-4.15) | The tool's result was withheld because the call looked unusual for this agent. The operator can see why in the audit record {correlationId}. |
| `FAIL_CLOSED` | `-31004` | A critical dependency is unavailable | The Gateway is not accepting tool calls right now because a safety check failed. The operator can see the cause with `smcpctl health`. |
| `EMERGENCY_STOP` | `-31004` | An emergency stop is in effect | The Gateway operator has stopped all tool calls. |
| `NO_SNAPSHOT` | `-31004` | No verified policy revision is loaded | The Gateway has no valid policy loaded and is refusing all tool calls. |
| `JOURNAL_UNAVAILABLE` | `-31004` | The decision intent could not be written to the Evidence Journal | The Gateway could not record this call and did not run it. The operator can see the cause with `smcpctl health`. |
| `POLICY_REVISION_CHANGED` | `-31004` | The policy changed between decision and launch | The Gateway's policy changed while this call was being checked. Run the request again. |
| `CAPABILITY` | `-31004` | The one-use launch capability was missing or already used | The Gateway refused to run this call because an internal check failed. Run the request again; if it repeats, give the operator the correlation ID {correlationId}. |
| `RATE_LIMITED` | `-31005` | A rate limit was reached | Too many tool calls in a short time. Wait a minute and try again. |
| `QUOTA_EXHAUSTED` | `-31005` | The session used its per-session call quota | This session has used all the tool calls its policy allows. Start a new session. |
| `QUEUE_FULL` | `-31005` | The dispatch queue is full | The Gateway is busy. Try again shortly. |
| `SESSION_LIMIT` | `-31005` | A session create request would exceed the CP-18 concurrent-session limit of the principal (FR-2.10) | This agent already has the maximum number of open sessions. End one, then try again. |
| `LISTEN_LIMIT` | `-31005` | The session already holds the CP-20 number of open listen streams | This session already has the maximum number of open listen streams. Close one, then try again. |
| `SESSION_INVALID` | `-31006` | Missing, expired or unknown token | Your Gateway session is not valid. Sign in again. |
| `SESSION_STATE` | `-31006` | The session is suspended or terminated | Your Gateway session has ended. Sign in again. |
| `BACKEND_ERROR` | `-31007` | The backend returned a protocol error | The tool's server reported an error. |
| `DISPATCH_FAILED` | `-31007` | The backend could not be reached or started | The tool's server could not be started or reached. The operator can check it in the Servers view. |
| `BACKEND_OUTPUT_INVALID` | `-31007` | The instance wrote a stdout line that is not a single-line UTF-8 JSON-RPC message; the instance is replaced (FR-5.14) | The tool's server sent data that is not valid MCP, so the call was stopped and the server restarted. |
| `CLIENT_DEADLINE` | `-31008` | The CP-13 client deadline expired | The tool did not finish in time. |
| `UPSTREAM_TIMEOUT` | `-31009` | The backend did not answer within CP-13; it may have acted | The tool's server stopped responding. It may have completed the action; check before trying again. |
| `INSTANCE_FAILED` | `-31009` | The instance ended after a call to a tool of side-effect class `write`, `external` or `execute`, or an unclassified tool, was dispatched; it may have acted and is not retried (SR-7.2-1) | The tool's server stopped while running this call. It may have completed the action; check before trying again. |
| `CANCELLED` | `-31009` | The harness cancelled the call after dispatch; the backend may have acted | The call was cancelled before it finished. It may have completed the action; check before trying again. |
| `INPUT_REQUIRED_UNSUPPORTED` | `-31010` | The backend asked for client input without the MRTR profile | The tool asked for input that the Gateway does not relay. |
| `SCHEMA_INVALID` | `-32602` | Arguments do not match the tool's input schema | The arguments do not match what this tool accepts. |

### B.3 Reason codes no request reaches

The Gateway keeps these Table B.2 codes as defense in depth: an earlier check of the same call always answers first, so no request produces them. FR-1.51's verification confirms their message text through the error builder instead of the wire.

| Reason code | Why no request reaches it |
|---|---|
| `AMBIGUOUS_ROUTE` | Routes are server aliases, which are unique, and a public name resolves to one server, so the decision never sees two eligible routes |
| `NO_ROUTE` | The catalog presents a tool only while the registry resolves it to its server; when the route goes, the name leaves the catalog (an unknown tool, `-32602`) or the server is suspended (`REVISION_NOT_ENABLED`) |
| `DENY_RULE` | The catalog presents only granted tools that no deny rule covers (FR-1.26), so a call to a denied tool is an unknown tool (`-32602`) |
| `CREDENTIAL_INVALID` | Revoking a credential terminates its sessions under the Enforcement Coordinator's barrier (SR-1.16-1), so the session check answers first (`SESSION_INVALID`) |
| `PRINCIPAL_DISABLED` | Suspending a principal terminates its sessions under the same barrier, with the same effect |
| `CAPABILITY` | The launch capability is issued and consumed within one call; only a Gateway defect produces this code |
| `ARGUMENTS_INVALID` | `tools/call` arguments are decoded as a JSON object before the inspection chain runs; any other value is refused with `-32602` by the protocol layer |
| `CANCELLED` | MCP cancellation: the harness that cancelled the call gets no response to it; the code is recorded in the journal only |

## Appendix C — Application role matrix

| Operation | Administrator | Operator | Policy Author | Approver | Session Approver | Auditor | Researcher |
|---|---|---|---|---|---|---|---|
| Emergency stop / resume | Stop + resume | Stop | — | — | — | — | — |
| View health and status | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Edit, simulate policy drafts | ✓ | — | ✓ | — | — | — | Observation drafts and campaigns only |
| Publish / roll back policy | ✓ | — | ✓ | — | — | — | — |
| Approve research campaign | ✓ | — | ✓ | — | — | — | — |
| Decide tool-call approvals | ✓ | — | — | ✓ | — | — | — |
| Approve harness sign-in (OAuth authorization) | — | — | — | — | ✓ | — | — |
| Approve dynamic client registrations (Remote Access) | ✓ | — | — | — | ✓ | — | — |
| Enable / suspend / retire servers; aliases | ✓ | Suspend only | — | — | — | — | — |
| Enroll trust anchors | ✓ | — | — | — | — | — | — |
| Enable or disable the Remote Access Profile | ✓ | — | — | — | — | — | — |
| Principals, credentials, sessions | ✓ | Suspend/terminate sessions | — | — | — | — | — |
| Create Session Approver accounts | ✓ | — | — | — | — | — | — |
| Secret create / rotate / revoke | ✓ | — | — | — | — | — | — |
| Audit query and redacted export | ✓ | ✓ | ✓ | — | — | ✓ | — |
| Observation analytics (S0/S1) | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| Observation S2 fields | ✓ | — | ✓ | — | — | ✓ | Pseudonymized |
| Payload (S3) access | Separate grant | — | — | — | — | Separate grant | Campaign grant only |
| Baseline promotion / rollback | ✓ | — | ✓ | — | — | — | — |
| Memory budgets, backups, key rotation | ✓ | ✓ | — | — | — | — | — |
| Dataset export | ✓ | — | — | — | — | — | ✓ (approved campaigns) |
| Purge | ✓ | — | — | — | — | — | — |

One person may hold several roles; on a single-user installation the Administrator usually also holds Approver and Session Approver accounts. Each role is a separate account with its own password: the Administrator account itself cannot complete a harness sign-in (FR-2.19, FR-2.23), so the Administrator password is never typed into a harness sign-in page. Harness principals have no control-plane role (SR-2.5-1).

The rows name operations. Control API routes the rows do not name follow these rules (FR-8.2):

- Reads. Health, status and the API description are open to every role, and each role reads and ends its own sign-in session. Policy revisions, filters, servers and the tool catalog, decision explanations and the graph investigation queries are read with the audit journal, by the roles of the audit query row. Sessions, principals and their credentials, secret metadata, package revisions, server instances and egress are operational inventory, read by the Administrator, Operator and Auditor. Every other read route is open to the roles of the row it serves: keys and backups to that row, observation status, catalog, analytics, baselines and anomalies to the observation analytics row, client registrations to the Administrator and Session Approver (the Operator also reads the Remote Access Profile state), approvals to the Administrator and Approver, campaigns to the campaign roles and the Auditor, dataset exports to the Administrator and Researcher, Session Approver accounts to the Administrator.
- Restricting operations. Tightening a tool's classification (SR-3.11-1), killing a server instance and scanning the library (which imports and verifies revisions without enabling them) belong to the Operator's suspend permission. Rebuilding the graph mirror belongs to the memory budgets, backups and key rotation row. Verifying the journal belongs to the audit query row. Building a baseline snapshot and excluding a session from learning belong to the baseline row. Publishing an Audit Profile, Observation Policy or Anomaly Response Policy is publishing policy.
- Everything else is the Administrator's alone, including resuming a suspended session, acknowledging a latched integrity cause (FR-7.13), revoking an approved client registration, and reloading the configuration or the Secret Use Policy.
- Observation S2 fields reach the Operator's records removed (SR-6-3); the Researcher sees them only pseudonymized, in dataset exports (FR-10.33). Release 1.0 stores no payloads (SR-6.6-1), so the Payload (S3) row has no control API operation; S3 fields leave the Gateway only in an export of a campaign with a raw-export grant (SR-6-2).

## Appendix D — Graph data model (mirror)

The graph holds a **mirror** of policy, registry, session and audit records, fed from the Policy Store (D-01) and the Evidence Journal (D-06), and is the system of record only for the behavior model (`BaselineContext`, `FeatureStat`, `BaselineSnapshot`, `AbnormalEvent`) and the Parameter Catalog copy (A-9). Every label has a uniqueness constraint on `id` (FR-9.1). Required-property and cardinality checks are enforced by the Data Access Service, because Community Edition lacks Enterprise existence constraints. The evidence mirror derives `AuditEvent`, `Session`, `Principal`, `Invocation` (keyed by correlation ID), `Decision`, `PolicyRevision`, `PolicyControl`, `ServerRevision`, `ToolRevision` and `Approval` from journal events; `Checkpoint` records the mirror's journal position and the schema version (FR-9.2).

| Node label | Key properties | Owner |
|---|---|---|
| `Principal`, `CredentialRef` | id, frameworkType, enabled, profileId, certThumbprint, expiry, revocationEpoch | E-03, E-22 |
| `Session` | id, principalId, templateId, revisionId, observationPolicyId, contextKey, state, created, expires | E-04 |
| `Server`, `ServerRevision`, `ToolRevision` | id, alias, version, artifactDigest, manifestDigest, state, riskClass, sideEffectClass, era | E-14 |
| `ImportReceipt`, `TrustAnchor` | id, signer, results / fingerprint, scope, expiry | E-13, E-22 |
| `PolicyControl` | activeRevisionId, revocationEpoch, stopEpoch | E-12 |
| `PolicyRevision`, `PolicyObject`, `RuleRevision`, `RouteRevision` | id, parentId, digest, schemaVersion, type, effect, predicates | E-05 |
| `Approval` | id, sessionId, argsDigest, state, expiresAt, approver | E-07 |
| `Decision`, `Invocation` | id, outcome, reasonCode, revisionId, snapshotId, correlationId | E-06, E-12 |
| `AuditEvent`, `PayloadRef`, `OutboxRecord`, `Checkpoint` | id, class, phase, origin, policyStatus / digest, keyRef | E-21 |
| `SecretRef`, `SecretUse` | id, slot, mode, version (no value) | E-19, E-20 |
| `BaselineContext`, `FeatureStat`, `BaselineSnapshot`, `AbnormalEvent` | id, dims / feature, n, mean, m2 / digest, promoted | E-30, E-31 |
| `Parameter`, `CatalogVersion` | id, name, unit, sensitivity, cost | E-05 |
| `Campaign`, `Dataset` | id, state, scope, quota / checksum | E-32 |

| Relationship | From → To |
|---|---|
| `CONTAINS` | PolicyRevision → PolicyObject, RuleRevision, RouteRevision |
| `APPLIES_TO` | RuleRevision → ToolRevision |
| `BELONGS_TO` | ToolRevision → ServerRevision; ServerRevision → Server |
| `SELECTS_ROUTE` | RuleRevision → RouteRevision |
| `REQUIRES_AUDIT`, `REQUIRES_OBSERVATION` | RuleRevision → PolicyObject |
| `EVALUATED_UNDER`, `DECIDED_BY`, `CONSIDERED_RULE`, `APPLICABLE_RULE` | Decision → PolicyRevision / RuleRevision |
| `TARGETED`, `SELECTED_ROUTE` | Decision → ServerRevision / RouteRevision |
| `SCORED_AGAINST` | Decision → BaselineSnapshot |
| `AUTHORIZED_BY` | Invocation → Decision |
| `INVOKED` | Invocation → ToolRevision |
| `FOR_DECISION`, `FOR_INVOCATION`, `OBSERVED_FROM`, `RECORDED_UNDER`, `HAS_EXPORT` | AuditEvent → Decision / Invocation / ServerRevision / PolicyObject or PolicyRevision / OutboxRecord; `FOR_INVOCATION` also Approval → Invocation |
| `IN_SESSION`, `OF_PRINCIPAL` | Decision, Invocation, Approval, AuditEvent, Session → Session, Principal |
| `HAS_CONTEXT`, `HAS_STAT`, `INCLUDES`, `IN_CONTEXT`, `NEXT_TOOL` | Principal/ToolRevision → BaselineContext → FeatureStat; BaselineSnapshot → FeatureStat; AbnormalEvent → BaselineContext; ToolRevision → ToolRevision |
| `USES_SECRET` | SecretUse → SecretRef, Decision |
| `VERIFIED_BY`, `SIGNED_BY` | ServerRevision → ImportReceipt → TrustAnchor |
