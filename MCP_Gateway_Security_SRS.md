# MCP Gateway System Requirements Specification — V1

**File:** `MCP_Gateway_SRS.md`  
**Baseline:** V1 — first separate SRS  
**Date:** 2026-10-04 (America/New_York)  
**Owner:** netrisk  
**Related design:** `architecture.md`, revision 2.0  
**Immutable snapshot:** `versions/MCP_Gateway_SRS_V1.md`  
**Git tag:** `mcp-gateway-srs-v1` (created for the matching local baseline commit)  
**Status:** Requirements baseline for development; implementation and operational verification have not been performed.

## Purpose and scope

The system is a local, open-source MCP gateway with a graphical control plane, inspectable server catalog, graph-based access/routing policies, request/response filters and policy-linked audits. It serves Hermes first and separately qualified clients later. The supported baseline requires no paid service, SaaS account, proprietary application or cloud model. Neo4j Community Edition is the selected graph technology, subject to its explicit edition limits.

The SRS is the normative requirement authority. The architecture explains how the requirements are intended to be realized. A repository/source link, working GUI, configured allowlist or passing document check is not evidence of runtime enforcement.

## Requirement conventions and precedence

At the owner’s explicit request, security control statements use **MUST**, including testable leaf controls. This overrides the local workflow’s usual restriction of MUST to broad security parents. Functional, performance and documentation requirements use **SHALL**. Both words are binding; neither describes an already implemented feature. Source best practices are paraphrased into project controls, not presented as quotations or certification requirements.

Each requirement has one primary parent, one verification method, a verification statement, source and rationale. Security parents appear first. Parent verification reviews the complete child-control evidence; leaf tests provide the concrete observations. True roots have an empty parent field. Requirements are numbered hierarchically; the V1 IDs are frozen in the immutable baseline. Future revisions record additions, replacements and retirements without silently redefining V1.

Conditional features such as an overlay, OAuth or public-web profile remain disabled until selected and qualified. Once enabled, their conditional controls are mandatory. Named design constants in Appendix A are part of V1, not suggestions that may be ignored after a failed test.

## System boundary and terminology

| Term | Meaning |
|---|---|
| Principal | Authenticated client security identity; not an LLM model name or self-asserted clientInfo |
| Graph service | Trusted typed API/evaluator holding the authoritative Neo4j credential |
| Gateway | MCP enforcement point controlling dispatch and result release |
| Rule version | Immutable structured predicate/effect/obligation record in a published policy revision |
| Route version | Exact admitted transport/endpoint or executable binding for a server/tool revision |
| Admission | Human-reviewed permission for a fixed artifact to run under a specified sandbox; separate from per-principal tool grants |
| Source inspectability | Locally retained source, license, dependencies and build evidence bound to the running artifact |
| Mandatory metadata | Redacted decision/identity/version/phase/outcome evidence retained independently of optional payload capture |
| Server-asserted event | Untrusted claim from a backend, distinct from gateway-observed execution evidence |
| Dispatch linearization point | Committed authorization-to-launch handoff under the policy/publication barrier; earlier work is in flight |
| Offline profile | Baseline operation without external network access; controlled maintenance downloads are separate |
| Public-web profile | Optional broker-mediated public document retrieval without SaaS accounts or paid APIs |
| Qualified / enforced | The particular versions, profile and deployment have passed their required runtime tests |

Trusted components include the host kernel/administrator, protected gateway/graph-service code, supervisor, broker and audit key custody. A hostile host administrator, compromised graph service, universal prompt-injection detection and guaranteed rollback of already executed external effects are outside the security guarantee. These limits do not waive the concrete controls.

## Requirement index


| Root | Topic | Child controls |
|---|---|---|
| 1 | Graph policy and routing authority | 20 |
| 2 | Identity and administration separation | 14 |
| 3 | Source-inspectable server admission | 14 |
| 4 | Contained local execution | 14 |
| 5 | Protocol and content boundary | 20 |
| 6 | Policy-linked audit integrity and privacy | 20 |
| 7 | Safe operation and recovery | 12 |
| 8 | Local operator product | 10 |
| 9 | Open-source local engineering capabilities | 7 |
| 10 | Qualification and versioned baselines | 9 |

## 1. Graph policy and routing authority

### 1 — Graph policy and routing authority

| Field | Value |
|---|---|
| ID | 1 |
| Parent ID |  |
| Statement | The gateway **MUST** restrict tool execution to authority granted by the active graph policy. |
| Verification Method | Analysis |
| Verification Statement | Review the child-control evidence and the threat model; confirm each identified threat in this scope has an implemented control and passing acceptance evidence. |
| Source | USER; MCP-SEC; OLD-POL |
| Rationale | A stored graph is useful only when its rules govern actual dispatch. |
### 1.1 — Authoritative graph

| Field | Value |
|---|---|
| ID | 1.1 |
| Parent ID | 1 |
| Statement | The graph service **MUST** use the active Neo4j Community Edition policy revision as the sole source of configurable permit, deny, route and audit rules. |
| Verification Method | Inspection |
| Verification Statement | Inspect the configuration and code paths; confirm no independently editable Casbin, file ACL or alternate policy store can grant access. |
| Source | USER; NEO-CE |
| Rationale | Avoid conflicting policy authorities. |
### 1.2 — Graph outage

| Field | Value |
|---|---|
| ID | 1.2 |
| Parent ID | 1 |
| Statement | When the graph service cannot obtain a validated current policy decision, the gateway **MUST** deny new tool dispatch. |
| Verification Method | Test |
| Verification Statement | Stop Neo4j, expire the request budget and simulate an invalid decision; verify zero upstream calls and a durable fault event. |
| Source | USER; OLD-CON |
| Rationale | An unavailable database must not become an access grant. |
### 1.3 — Default denial

| Field | Value |
|---|---|
| ID | 1.3 |
| Parent ID | 1 |
| Statement | When no applicable permit rule exists, the evaluator **MUST** return a deny decision. |
| Verification Method | Test |
| Verification Statement | Submit an unknown principal/tool pair to a healthy empty policy; observe denial before routing. |
| Source | MCP-SEC; OWASP-MCP |
| Rationale | Absence of a grant is not permission. |
### 1.4 — Deny precedence

| Field | Value |
|---|---|
| ID | 1.4 |
| Parent ID | 1 |
| Statement | When an applicable deny rule exists, the evaluator **MUST** return deny even if an applicable permit also exists. |
| Verification Method | Test |
| Verification Statement | Create matching permit and deny fixtures in opposite creation orders; both evaluations must deny. |
| Source | MCP-SEC; DESIGN |
| Rationale | Graph traversal order must not decide privilege. |
### 1.5 — Admission prerequisites

| Field | Value |
|---|---|
| ID | 1.5 |
| Parent ID | 1 |
| Statement | The evaluator **MUST** deny a call whose principal, credential, server version or tool admission is inactive, expired or unapproved. |
| Verification Method | Test |
| Verification Statement | Invalidate each prerequisite separately while retaining a matching permit; each call must be denied. |
| Source | OLD-ADM; OLD-IAM |
| Rationale | A permit cannot bypass revoked identity or artifact approval. |
### 1.6 — Exact scoped rules

| Field | Value |
|---|---|
| ID | 1.6 |
| Parent ID | 1 |
| Statement | The evaluator **MUST** match permits against the authenticated principal, exact server-version ID, exact tool ID and MCP operation. |
| Verification Method | Test |
| Verification Statement | Vary each field independently and verify that only the complete permitted tuple is accepted. |
| Source | USER; MCP-SEC |
| Rationale | Server-level enablement must not grant future or unrelated tools. |
### 1.7 — Typed predicates

| Field | Value |
|---|---|
| ID | 1.7 |
| Parent ID | 1 |
| Statement | The evaluator **MUST** accept only the versioned predicate operators listed in SRS Appendix F. |
| Verification Method | Test |
| Verification Statement | Submit unsupported operators, malformed values and missing attributes; publication or evaluation must deny without executing supplied expressions. |
| Source | DESIGN; NEO-CYPHER |
| Rationale | Constrain policy expressiveness to an auditable implementation. |
### 1.8 — Argument scope

| Field | Value |
|---|---|
| ID | 1.8 |
| Parent ID | 1 |
| Statement | The evaluator **MUST** deny arguments outside the approved tool schema and typed path, destination, method or action constraints. |
| Verification Method | Test |
| Verification Statement | Exercise valid and invalid boundary arguments, traversal and encoded destinations; only conforming inputs may dispatch. |
| Source | OLD-POL; OWASP-SSRF |
| Rationale | Tool names alone do not limit effects. |
### 1.9 — Unambiguous permits

| Field | Value |
|---|---|
| ID | 1.9 |
| Parent ID | 1 |
| Statement | The policy publisher **MUST** reject overlapping permit rules whose argument scopes or routing obligations cannot be combined deterministically. |
| Verification Method | Test |
| Verification Statement | Publish conflicting route and argument fixtures; observe rejection and unchanged active revision. |
| Source | DESIGN |
| Rationale | Avoid accidental scope union or arbitrary winners. |
### 1.10 — Obligation combination

| Field | Value |
|---|---|
| ID | 1.10 |
| Parent ID | 1 |
| Statement | The evaluator **MUST** combine applicable obligations using the precedence table in SRS Appendix F. |
| Verification Method | Test |
| Verification Statement | Evaluate overlapping fixtures; confirm required-filter union, smallest limits and the specified payload-retention precedence. |
| Source | USER; DESIGN |
| Rationale | Policy-directed filtering and auditing require defined combination semantics. |
### 1.11 — Deterministic routing

| Field | Value |
|---|---|
| ID | 1.11 |
| Parent ID | 1 |
| Statement | For an allowed call, the router **MUST** select exactly one approved route bound to the evaluated server version and tool. |
| Verification Method | Test |
| Verification Statement | Supply zero, one and multiple eligible routes; only the one-route fixture may dispatch. |
| Source | USER; DESIGN |
| Rationale | Tool aliases must not select an arbitrary or fallback backend. |
### 1.12 — No semantic authorization

| Field | Value |
|---|---|
| ID | 1.12 |
| Parent ID | 1 |
| Statement | The evaluator **MUST** exclude full-text scores, vector similarity and model-generated conclusions from permission and route selection. |
| Verification Method | Inspection |
| Verification Statement | Trace the decision path and verify that authority uses exact identifiers and typed predicates only. |
| Source | USER; DESIGN |
| Rationale | Search relevance is not evidence of authorization. |
### 1.13 — Fixed query templates

| Field | Value |
|---|---|
| ID | 1.13 |
| Parent ID | 1 |
| Statement | The graph service **MUST** execute only reviewed parameterized Cypher templates for policy, registry and audit operations. |
| Verification Method | Test |
| Verification Statement | Inject Cypher syntax through each user-controlled field; confirm values remain data and template selection cannot be changed. |
| Source | NEO-CYPHER; OWASP-INJ |
| Rationale | Prevent query injection and arbitrary database administration. |
### 1.14 — Immutable revisions

| Field | Value |
|---|---|
| ID | 1.14 |
| Parent ID | 1 |
| Statement | The policy publisher **MUST** create immutable policy and rule versions for each published change. |
| Verification Method | Test |
| Verification Statement | Modify a draft and publish it; confirm old decision links still resolve to the unchanged earlier rules. |
| Source | USER; DESIGN |
| Rationale | Audit explanations must survive later policy edits. |
### 1.15 — Atomic activation

| Field | Value |
|---|---|
| ID | 1.15 |
| Parent ID | 1 |
| Statement | The graph service **MUST** switch the active policy revision in one validated database transaction. |
| Verification Method | Test |
| Verification Statement | Interrupt publication before and after commit; readers must see one complete revision and no mixed rule set. |
| Source | NEO-TX; DESIGN |
| Rationale | Partial publication creates unpredictable authorization. |
### 1.16 — Publication ordering

| Field | Value |
|---|---|
| ID | 1.16 |
| Parent ID | 1 |
| Statement | The graph service **MUST** serialize dispatch authorization, buffered-result release authorization and policy activation through the coordinator barrier defined in SRS Appendix F. |
| Verification Method | Test |
| Verification Statement | Race revocation against approval consumption, dispatch and buffered-result release; verify each handoff follows the defined linearization order and current revision. |
| Source | NEO-TX; DESIGN |
| Rationale | Read-committed transactions alone do not close revocation races. |
### 1.17 — Pre-dispatch and release checks

| Field | Value |
|---|---|
| ID | 1.17 |
| Parent ID | 1 |
| Statement | The gateway **MUST** revalidate current authorization before dispatch and before releasing buffered results. |
| Verification Method | Test |
| Verification Statement | Revoke a rule while queued and while a result is buffered; observe blocked dispatch or withheld result as applicable. |
| Source | OLD-POL; MCP-SEC |
| Rationale | Queued and in-flight work must not retain stale authority. |
### 1.18 — Bound human approval

| Field | Value |
|---|---|
| ID | 1.18 |
| Parent ID | 1 |
| Statement | The dispatcher **MUST** require a valid one-use approval bound to the authenticated principal, server/tool/route revisions, final argument digest, policy revision and five-minute expiry for the approval-trigger classes in SRS Appendix F. |
| Verification Method | Test |
| Verification Statement | Invoke each approval-trigger class without approval, replay an approval and alter each binding field; only the unchanged unexpired first use may dispatch. |
| Source | OLD-POL; OWASP-MCP |
| Rationale | Model text and stale confirmations must not authorize mutations. |
### 1.19 — Rule explanation

| Field | Value |
|---|---|
| ID | 1.19 |
| Parent ID | 1 |
| Statement | The graph service **MUST** return a decision explanation identifying the considered, applicable and decisive rule-version IDs, selected route and effective obligations. |
| Verification Method | Test |
| Verification Statement | Evaluate permit, explicit deny and default-deny fixtures; inspect the corresponding graph links and reasons. |
| Source | USER |
| Rationale | The GUI must explain why a call was routed or blocked. |
### 1.20 — Bounded graph work

| Field | Value |
|---|---|
| ID | 1.20 |
| Parent ID | 1 |
| Statement | The graph service **MUST** terminate authorization queries that exceed a 500 ms deadline or the configured candidate-rule bound. |
| Verification Method | Test |
| Verification Statement | Submit pathological graphs and a delayed query; verify denial, cancellation and no upstream dispatch. |
| Source | NEO-TX; DESIGN |
| Rationale | Graph complexity must not cause unbounded authorization work. |

## 2. Identity and administration separation

### 2 — Identity and administration separation

| Field | Value |
|---|---|
| ID | 2 |
| Parent ID |  |
| Statement | The gateway **MUST** protect credentials and administrative authority from unauthorized principals. |
| Verification Method | Analysis |
| Verification Statement | Review the child-control evidence and the threat model; confirm each identified threat in this scope has an implemented control and passing acceptance evidence. |
| Source | MCP-SEC; OLD-IAM |
| Rationale | Agent identity and human administration are different trust boundaries. |
### 2.1 — Per-request authentication

| Field | Value |
|---|---|
| ID | 2.1 |
| Parent ID | 2 |
| Statement | The gateway **MUST** derive the authorization principal and roles exclusively from credentials verified for that request and protected server-side mappings. |
| Verification Method | Test |
| Verification Statement | Send missing, expired and forged credentials, then a valid low-privilege token claiming another clientInfo identity; verify denial or the token owner’s unchanged authority on each request. |
| Source | MCP-SEC |
| Rationale | Metadata and session possession cannot establish identity. |
### 2.2 — Distinct client credentials

| Field | Value |
|---|---|
| ID | 2.2 |
| Parent ID | 2 |
| Statement | The credential service **MUST** issue independently revocable credentials for each admitted client security principal. |
| Verification Method | Test |
| Verification Statement | Revoke one of two principals and verify the other retains only its own grants. |
| Source | MCP-SEC; USER |
| Rationale | Attribution and revocation require separate credentials. |
### 2.3 — Client-key protection

| Field | Value |
|---|---|
| ID | 2.3 |
| Parent ID | 2 |
| Statement | The credential service **MUST** store only a verifier for locally issued bearer keys generated with at least 256 bits of random entropy. |
| Verification Method | Inspection |
| Verification Statement | Inspect issuance/storage code and stored fixtures; confirm CSPRNG generation, one-time display and no recoverable key plaintext in the graph. |
| Source | OLD-IAM |
| Rationale | Reduce credential recovery from database disclosure. |
### 2.4 — Revocation deadline

| Field | Value |
|---|---|
| ID | 2.4 |
| Parent ID | 2 |
| Statement | The gateway **MUST** prevent new dispatch using a revoked key within two seconds of revocation publication. |
| Verification Method | Test |
| Verification Statement | Continuously invoke a permitted tool while revoking its key; measure the final authorization point against the two-second bound. |
| Source | OLD-IAM |
| Rationale | Revocation must have bounded effect. |
### 2.5 — Admin identity

| Field | Value |
|---|---|
| ID | 2.5 |
| Parent ID | 2 |
| Statement | The control API **MUST** reject MCP client credentials on administrative endpoints. |
| Verification Method | Test |
| Verification Statement | Attempt each administrative endpoint with an otherwise valid agent token; all must reject before mutation. |
| Source | OLD-IAM; OWASP-MCP |
| Rationale | An agent must not edit the rules controlling itself. |
### 2.6 — Protected admin session

| Field | Value |
|---|---|
| ID | 2.6 |
| Parent ID | 2 |
| Statement | The control API **MUST** require an administrator session satisfying the secure-session profile in SRS Appendix F for protected GUI operations. |
| Verification Method | Test |
| Verification Statement | Present missing, expired and altered cookies; verify Secure/HttpOnly/SameSite attributes, login rotation, logout invalidation and the stated idle/absolute expiry. |
| Source | OLD-IAM; OWASP-CSRF |
| Rationale | Keep administrator state under server control. |
### 2.7 — Password verification

| Field | Value |
|---|---|
| ID | 2.7 |
| Parent ID | 2 |
| Statement | The control service **MUST** store administrator passwords only as salted Argon2id verifiers using release-qualified parameters. |
| Verification Method | Inspection |
| Verification Statement | Review password handling and stored records; confirm no plaintext, unique salts and the approved parameter set. |
| Source | OLD-IAM; DESIGN |
| Rationale | Protect human credentials without a paid identity provider. |
### 2.8 — Authenticated transport

| Field | Value |
|---|---|
| ID | 2.8 |
| Parent ID | 2 |
| Statement | The gateway **MUST** use certificate-validated TLS for production MCP and administration HTTP connections. |
| Verification Method | Test |
| Verification Statement | Present an untrusted CA, wrong hostname and expired certificate; each connection must fail without insecure fallback. |
| Source | MCP-HTTP; OLD-DEP |
| Rationale | Loopback is not a replacement for authenticated transport. |
### 2.9 — Origin and Host

| Field | Value |
|---|---|
| ID | 2.9 |
| Parent ID | 2 |
| Statement | The HTTP listeners **MUST** reject disallowed supplied Origin values and unexpected Host values. |
| Verification Method | Test |
| Verification Statement | Exercise hostile Origins, alternate Host names and an authenticated native client without Origin; reject hostile requests and accept only the permitted native-client case. |
| Source | MCP-HTTP |
| Rationale | Prevent browser-mediated localhost and DNS-rebinding attacks. |
### 2.10 — Credential separation

| Field | Value |
|---|---|
| ID | 2.10 |
| Parent ID | 2 |
| Statement | The gateway **MUST** use backend-specific credentials rather than forwarding MCP client bearer credentials upstream. |
| Verification Method | Test |
| Verification Statement | Capture synthetic upstream traffic and verify only the assigned backend credential appears. |
| Source | MCP-SEC |
| Rationale | Prevent token passthrough and confused-deputy behavior. |
### 2.11 — OAuth boundary

| Field | Value |
|---|---|
| ID | 2.11 |
| Parent ID | 2 |
| Statement | When an OAuth profile is enabled, the gateway **MUST** enforce the selected MCP authorization revision including resource audience, redirect, consent and PKCE requirements. |
| Verification Method | Test |
| Verification Statement | Run positive and negative profile conformance fixtures, including wrong audience, unregistered redirect and missing consent. |
| Source | MCP-AUTH; MCP-SEC |
| Rationale | Optional interoperability cannot weaken the private bearer profile. |
### 2.12 — State ownership

| Field | Value |
|---|---|
| ID | 2.12 |
| Parent ID | 2 |
| Statement | The gateway **MUST** enforce principal ownership for legacy sessions and declared application handles through a versioned admitted handle contract or qualified ownership adapter. |
| Verification Method | Test |
| Verification Statement | Present a legacy session or application handle using another principal at every declared consumer operation; verify denial and rejection of expired handles. |
| Source | MCP-SEC |
| Rationale | A handle is not an authentication credential. |
### 2.13 — Encrypted secrets

| Field | Value |
|---|---|
| ID | 2.13 |
| Parent ID | 2 |
| Statement | The secrets service **MUST** encrypt backend credentials and captured payload keys under operator-controlled keys outside agent-readable storage. |
| Verification Method | Inspection |
| Verification Statement | Inspect key custody, file permissions and encryption format; verify agents cannot read the decryption identity. |
| Source | OLD-SECSTORE |
| Rationale | Encryption is ineffective if the same untrusted process can read its key. |
### 2.14 — Minimal backend environment

| Field | Value |
|---|---|
| ID | 2.14 |
| Parent ID | 2 |
| Statement | The supervisor **MUST** construct each backend environment from that backend’s approved variable allowlist. |
| Verification Method | Test |
| Verification Statement | Place synthetic unrelated secrets in the gateway environment and inspect a worker; only specifically assigned values may appear. |
| Source | OLD-SECSTORE; MCP-SEC |
| Rationale | Prevent accidental cross-server credential disclosure. |

## 3. Source-inspectable server admission

### 3 — Source-inspectable server admission

| Field | Value |
|---|---|
| ID | 3 |
| Parent ID |  |
| Statement | The gateway **MUST** restrict execution to reviewed open-source server artifacts with inspectable provenance. |
| Verification Method | Analysis |
| Verification Statement | Review the child-control evidence and the threat model; confirm each identified threat in this scope has an implemented control and passing acceptance evidence. |
| Source | USER; MCP-SEC; OWASP-MCP |
| Rationale | Local code can be malicious even when it uses MCP. |
### 3.1 — Source availability

| Field | Value |
|---|---|
| ID | 3.1 |
| Parent ID | 3 |
| Statement | The registry **MUST** reject production admission without a retrievable source archive for the exact reviewed server revision and its applicable license texts. |
| Verification Method | Test |
| Verification Statement | Omit source, revision or license evidence in separate candidates; each must remain quarantined. |
| Source | USER |
| Rationale | The GUI cannot inspect a binary-only or floating server. |
### 3.2 — Source-to-artifact binding

| Field | Value |
|---|---|
| ID | 3.2 |
| Parent ID | 3 |
| Statement | The admission record **MUST** bind the reviewed source digest to the deployed executable or image digest using recorded build or provenance evidence. |
| Verification Method | Inspection |
| Verification Statement | Inspect an approved fixture’s source, build recipe, dependencies and runtime digest; confirm the chain identifies the executable actually launched. |
| Source | USER; OWASP-MCP |
| Rationale | Repository links alone do not identify running code. |
### 3.3 — Safe source viewer

| Field | Value |
|---|---|
| ID | 3.3 |
| Parent ID | 3 |
| Statement | The GUI **MUST** display the pinned source tree, file contents, license files and version diff as inert bounded content. |
| Verification Method | Test |
| Verification Statement | Open fixtures containing HTML, scripts, traversal names and oversized files; confirm no execution, external load or escape from the snapshot. |
| Source | USER; OWASP-INJ |
| Rationale | Source inspection must not become another execution surface. |
### 3.4 — Dependency inspection

| Field | Value |
|---|---|
| ID | 3.4 |
| Parent ID | 3 |
| Statement | The registry **MUST** expose the server’s dependency lockfiles, SBOM, launcher and sandbox privileges alongside its source. |
| Verification Method | Demonstration |
| Verification Statement | Open a candidate card and navigate from the source revision to each required artifact without Internet access. |
| Source | USER; OWASP-MCP |
| Rationale | Inspectability includes dependencies and startup behavior. |
### 3.5 — Quarantine execution

| Field | Value |
|---|---|
| ID | 3.5 |
| Parent ID | 3 |
| Statement | The admission worker **MUST** probe new candidates without production secrets, production mounts or external network access. |
| Verification Method | Test |
| Verification Statement | Run a synthetic malicious candidate that attempts all three access paths; verify denial and recorded findings. |
| Source | MCP-SEC; OLD-ADM |
| Rationale | Discovery itself executes untrusted code. |
### 3.6 — No runtime bootstrap

| Field | Value |
|---|---|
| ID | 3.6 |
| Parent ID | 3 |
| Statement | The supervisor **MUST** reject launch definitions that install or resolve floating packages during tool execution. |
| Verification Method | Test |
| Verification Statement | Submit npx/uvx-style unpinned installation and mutable-image launch fixtures; confirm rejection until materialized and digest-pinned. |
| Source | MCP-SEC; DESIGN |
| Rationale | First-call downloads evade admission review. |
### 3.7 — Manifest binding

| Field | Value |
|---|---|
| ID | 3.7 |
| Parent ID | 3 |
| Statement | The registry **MUST** bind approval to the digest of the tool names, descriptions, schemas, annotations and enabled non-tool capabilities. |
| Verification Method | Test |
| Verification Statement | Change each manifest class independently and verify that existing approval no longer enables it. |
| Source | OWASP-POISON; OLD-ADM |
| Rationale | A tool description or schema can change the agent’s behavior. |
### 3.8 — Drift suspension

| Field | Value |
|---|---|
| ID | 3.8 |
| Parent ID | 3 |
| Statement | The gateway **MUST** suspend a server version when the observed runtime or approved manifest digest changes. |
| Verification Method | Test |
| Verification Statement | Replace an artifact and alter a description after admission; confirm new calls are blocked pending review. |
| Source | OWASP-POISON |
| Rationale | Prevent post-approval rug pulls. |
### 3.9 — Explicit admission

| Field | Value |
|---|---|
| ID | 3.9 |
| Parent ID | 3 |
| Statement | The control service **MUST** require an authenticated human admission action before enabling a quarantined server version. |
| Verification Method | Test |
| Verification Statement | Run a clean scanner/probe result without approval and confirm no principal can discover or call the candidate. |
| Source | USER; MCP-SEC |
| Rationale | Scanner success is evidence, not authorization. |
### 3.10 — New tools denied

| Field | Value |
|---|---|
| ID | 3.10 |
| Parent ID | 3 |
| Statement | The publisher **MUST** leave newly discovered tools denied until an explicit tool-scoped grant is published. |
| Verification Method | Test |
| Verification Statement | Add a tool to a previously admitted server release; it must remain absent from discovery and reject guessed calls. |
| Source | MCP-SEC; OLD-ADM |
| Rationale | Server approval must not grant future capabilities. |
### 3.11 — Capability classification

| Field | Value |
|---|---|
| ID | 3.11 |
| Parent ID | 3 |
| Statement | The registry **MUST** retain operator-reviewed locality, data sensitivity, side-effect class, file roots, egress scope and secret references for each admitted tool. |
| Verification Method | Inspection |
| Verification Statement | Inspect registry schema and an admitted fixture; confirm the required fields are present and annotations are not used as authority. |
| Source | USER; OWASP-MCP |
| Rationale | Meaningful allowlists require capability characterization. |
### 3.12 — No administrative tool exposure

| Field | Value |
|---|---|
| ID | 3.12 |
| Parent ID | 3 |
| Statement | The gateway **MUST** exclude source-admission, policy-write and credential-administration operations from ordinary agent tool catalogs. |
| Verification Method | Test |
| Verification Statement | List and guess each administrative function using a client credential; none may execute. |
| Source | USER; MCP-SEC |
| Rationale | An agent cannot approve its own tools. |
### 3.13 — High-risk candidates

| Field | Value |
|---|---|
| ID | 3.13 |
| Parent ID | 3 |
| Statement | The admission service **MUST** classify general SQL, code execution, CAD scripting and browser automation as high-risk capabilities requiring separate grants. |
| Verification Method | Inspection |
| Verification Statement | Inspect the curated catalog and admission forms; each named capability must use a high-risk sandbox and independent grant. |
| Source | USER; DESIGN |
| Rationale | Read-only labels do not neutralize embedded execution mechanisms. |
### 3.14 — Stateful tool admission

| Field | Value |
|---|---|
| ID | 3.14 |
| Parent ID | 3 |
| Statement | The admission service **MUST** reject a declared stateful tool without a versioned contract identifying handle-creation outputs, handle-consuming arguments, ownership scope and expiry enforcement. |
| Verification Method | Test |
| Verification Statement | Omit each contract field or its qualified ownership adapter; admission must fail before stateful operations are enabled. |
| Source | MCP-SEC; DESIGN |
| Rationale | The gateway cannot discover arbitrary handle semantics from opaque data. |

## 4. Contained local execution

### 4 — Contained local execution

| Field | Value |
|---|---|
| ID | 4 |
| Parent ID |  |
| Statement | The deployment **MUST** prevent agent and backend processes from bypassing gateway controls. |
| Verification Method | Analysis |
| Verification Statement | Review the child-control evidence and the threat model; confirm each identified threat in this scope has an implemented control and passing acceptance evidence. |
| Source | USER; MCP-SEC; OLD-DEP |
| Rationale | Application settings alone cannot enforce exclusivity. |
### 4.1 — Separate OS identities

| Field | Value |
|---|---|
| ID | 4.1 |
| Parent ID | 4 |
| Statement | The deployment **MUST** separate agent, control, graph-service and backend authority using protected process identities and sandbox boundaries. |
| Verification Method | Inspection |
| Verification Statement | Inspect runtime users, namespaces, mounts and socket permissions; verify the agent cannot obtain another service’s authority. |
| Source | OLD-DEP; NEO-CE |
| Rationale | Community Edition database credentials are broadly privileged. |
### 4.2 — Private graph access

| Field | Value |
|---|---|
| ID | 4.2 |
| Parent ID | 4 |
| Statement | The deployment **MUST** allow access to the authoritative Neo4j listener only from the trusted graph service and an explicit maintenance path. |
| Verification Method | Test |
| Verification Statement | Attempt Bolt/HTTP access from agent, browser and backend namespaces; each must fail. |
| Source | NEO-CE; USER |
| Rationale | No agent or source-inspection screen receives direct database access. |
### 4.3 — CE access boundary

| Field | Value |
|---|---|
| ID | 4.3 |
| Parent ID | 4 |
| Statement | The graph service **MUST** enforce role-specific application APIs without relying on Neo4j Community Edition fine-grained database privileges. |
| Verification Method | Inspection |
| Verification Statement | Inspect API authorization and database accounts; verify the design does not assume Enterprise RBAC or label-level isolation. |
| Source | NEO-CE |
| Rationale | Labels and multiple CE users are not security partitions. |
### 4.4 — Agent network allowlist

| Field | Value |
|---|---|
| ID | 4.4 |
| Parent ID | 4 |
| Statement | The agent sandbox **MUST** restrict network access to the designated MCP gateway and the approved local inference endpoint. |
| Verification Method | Test |
| Verification Statement | Probe public Internet, DNS/DoH, IPv6, UDP/QUIC, host aliases, administration and backend ports from the actual agent process domain; ungranted paths must fail. |
| Source | USER; OLD-HERMES |
| Rationale | Close direct HTTP and alternate-tool bypasses. |
### 4.5 — Backend egress

| Field | Value |
|---|---|
| ID | 4.5 |
| Parent ID | 4 |
| Statement | The backend sandbox **MUST** enforce the published per-server network allowlist independently of application proxy settings. |
| Verification Method | Test |
| Verification Statement | Attempt direct connections and proxy-setting changes from a worker; only the approved destinations remain reachable. |
| Source | MCP-SEC; OWASP-SSRF |
| Rationale | A malicious worker can ignore HTTP_PROXY. |
### 4.6 — Filesystem authority

| Field | Value |
|---|---|
| ID | 4.6 |
| Parent ID | 4 |
| Statement | The backend sandbox **MUST** restrict file access to admitted roots using operating-system mounts and file permissions. |
| Verification Method | Test |
| Verification Statement | Attempt traversal, symlink escape, host home access and writes to read-only roots; verify denial at the worker boundary. |
| Source | MCP-SEC |
| Rationale | MCP roots and textual path checks are not sufficient isolation. |
### 4.7 — Host-management exclusion

| Field | Value |
|---|---|
| ID | 4.7 |
| Parent ID | 4 |
| Statement | The agent and backend sandboxes **MUST** exclude host management sockets, sudo authority, host PID/network namespaces and unapproved devices. |
| Verification Method | Inspection |
| Verification Statement | Inspect sandbox manifests and effective privileges; confirm the controlled exclusion list is absent. |
| Source | MCP-SEC; OLD-DEP |
| Rationale | Container-engine or desktop sockets can bypass filesystem/network policy. |
### 4.8 — Safe process launch

| Field | Value |
|---|---|
| ID | 4.8 |
| Parent ID | 4 |
| Statement | The supervisor **MUST** launch admitted programs using fixed executable identities and argument arrays without a shell command interpreter. |
| Verification Method | Test |
| Verification Statement | Supply shell metacharacters in permitted data fields; verify no additional process is launched. |
| Source | MCP-SEC; OWASP-INJ |
| Rationale | Eliminate shell interpolation from routing. |
### 4.9 — Hermes endpoint

| Field | Value |
|---|---|
| ID | 4.9 |
| Parent ID | 4 |
| Statement | The qualified Hermes profile **MUST** resolve to exactly one MCP endpoint corresponding to this gateway. |
| Verification Method | Test |
| Verification Statement | Inspect the effective profile and attempt plugin/editor injection; additional endpoints must prevent qualified startup or remain blocked. |
| Source | USER; HERMES |
| Rationale | A visible YAML list is not the full runtime configuration. |
### 4.10 — Runtime tool guard

| Field | Value |
|---|---|
| ID | 4.10 |
| Parent ID | 4 |
| Statement | The qualified client **MUST** reject tool-registry changes that introduce names outside its approved gateway tool manifest. |
| Verification Method | Test |
| Verification Statement | Inject a native tool or plugin at startup and refresh; verify the guard blocks service before tool dispatch. |
| Source | HERMES; OLD-HERMES |
| Rationale | Prevent post-startup expansion of native tools. |
### 4.11 — Protected client configuration

| Field | Value |
|---|---|
| ID | 4.11 |
| Parent ID | 4 |
| Statement | The deployment **MUST** prevent the agent from modifying its accepted configuration, launcher, plugin paths or installed code. |
| Verification Method | Test |
| Verification Statement | Attempt modification from the agent account and verify OS denial while authorized session-state writes still work. |
| Source | HERMES; OLD-HERMES |
| Rationale | An agent-writable allowlist is not an enforcement boundary. |
### 4.12 — Local inference path

| Field | Value |
|---|---|
| ID | 4.12 |
| Parent ID | 4 |
| Statement | The qualified client **MUST** keep main and auxiliary model calls on the approved local inference service with cloud and guest fallback disabled. |
| Verification Method | Test |
| Verification Statement | Exercise chat, compression, routing and bootstrap while tracing egress; verify no cloud destination or identity bootstrap. |
| Source | USER; HERMES |
| Rationale | A local main model does not imply local auxiliary processing. |
### 4.13 — Additional clients

| Field | Value |
|---|---|
| ID | 4.13 |
| Parent ID | 4 |
| Statement | The admission service **MUST** withhold an exclusive-gateway qualification label from a client profile that has not passed the same bypass tests as Hermes. |
| Verification Method | Inspection |
| Verification Statement | Inspect client qualification records; untested Codex, ACP, messaging or other profiles must not be marked enforced. |
| Source | USER; OLD-HERMES |
| Rationale | Compatibility is not evidence of containment. |
### 4.14 — Overlay least privilege

| Field | Value |
|---|---|
| ID | 4.14 |
| Parent ID | 4 |
| Statement | When remote-device access is enabled, the deployment **MUST** enforce explicit deny-by-default device-to-port rules in addition to application authentication. |
| Verification Method | Test |
| Verification Statement | Enroll an unauthorized device and test MCP/admin/backend access; verify no allowed path and no public-interface fallback. |
| Source | HEADSCALE; USER |
| Rationale | Overlay membership does not grant tool authority. |

## 5. Protocol and content boundary

### 5 — Protocol and content boundary

| Field | Value |
|---|---|
| ID | 5 |
| Parent ID |  |
| Statement | The gateway **MUST** prevent unapproved protocol behavior and data movement through enabled MCP capabilities. |
| Verification Method | Analysis |
| Verification Statement | Review the child-control evidence and the threat model; confirm each identified threat in this scope has an implemented control and passing acceptance evidence. |
| Source | MCP-HTTP; MCP-SEC; OWASP-MCP |
| Rationale | Every exposed message surface can carry instructions or confidential data. |
### 5.1 — Explicit protocol profiles

| Field | Value |
|---|---|
| ID | 5.1 |
| Parent ID | 5 |
| Statement | The gateway **MUST** process 2026-07-28 and qualified 2025-11-25 requests according to their separate protocol profiles. |
| Verification Method | Test |
| Verification Statement | Exercise stateless modern discovery and legacy initialization fixtures; verify no session or reverse-request semantics leak across profiles. |
| Source | MCP-VERSION; OLD-MCP |
| Rationale | Mixing protocol eras changes the security boundary. |
### 5.2 — Header/body agreement

| Field | Value |
|---|---|
| ID | 5.2 |
| Parent ID | 5 |
| Statement | The gateway **MUST** reject modern HTTP requests whose required decoded protocol headers disagree with the corresponding JSON-RPC body fields. |
| Verification Method | Test |
| Verification Statement | Mismatch version, method, tool name and mirrored arguments independently; verify rejection before graph evaluation or routing. |
| Source | MCP-HTTP |
| Rationale | Different components must not authorize different interpretations. |
### 5.3 — No unsafe downgrade

| Field | Value |
|---|---|
| ID | 5.3 |
| Parent ID | 5 |
| Statement | The gateway **MUST** prevent authentication, authorization and recognized modern protocol errors from triggering a permissive legacy fallback. |
| Verification Method | Test |
| Verification Statement | Return each protected failure while a legacy route is available; confirm the call never bypasses the original denial. |
| Source | MCP-VERSION |
| Rationale | Compatibility recovery must not relax controls. |
### 5.4 — Authorized discovery

| Field | Value |
|---|---|
| ID | 5.4 |
| Parent ID | 5 |
| Statement | The gateway **MUST** expose only capabilities permitted to the authenticated principal by the current graph revision. |
| Verification Method | Test |
| Verification Statement | Compare discovery for two principals and after revocation; verify only currently permitted tool IDs are visible. |
| Source | MCP-SEC; USER |
| Rationale | Discovery must reflect effective policy. |
### 5.5 — Independent invocation check

| Field | Value |
|---|---|
| ID | 5.5 |
| Parent ID | 5 |
| Statement | The gateway **MUST** authorize direct tool invocations independently of earlier catalog visibility. |
| Verification Method | Test |
| Verification Statement | Call a hidden or previously visible revoked tool by name; verify denial. |
| Source | MCP-SEC |
| Rationale | A cached tool list is not authorization. |
### 5.6 — Unqualified capabilities

| Field | Value |
|---|---|
| ID | 5.6 |
| Parent ID | 5 |
| Statement | The gateway **MUST** reject resources, prompts, subscriptions, sampling, elicitation, roots/list or modern root-input interactions, and task/continuation extensions until their enabled profile has passed dedicated tests. |
| Verification Method | Test |
| Verification Statement | Send each unqualified operation or reverse interaction; confirm no forwarding, model call or credential prompt occurs. |
| Source | MCP-SEC; OLD-MCP |
| Rationale | Tools-only testing does not cover additional protocol surfaces. |
### 5.7 — Private caches

| Field | Value |
|---|---|
| ID | 5.7 |
| Parent ID | 5 |
| Statement | The gateway **MUST** prevent authorization-dependent catalogs, results, errors and state from being reused across principals or policy revisions. |
| Verification Method | Test |
| Verification Statement | Reuse cache keys and cursors across identities/revisions; confirm isolation and non-public HTTP/protocol cache directives. |
| Source | MCP-HTTP; MCP-SEC |
| Rationale | Shared caches can disclose denied data. |
### 5.8 — Outgoing filtering

| Field | Value |
|---|---|
| ID | 5.8 |
| Parent ID | 5 |
| Statement | The gateway **MUST** apply required secret and sensitive-data rules to outbound arguments, headers, URLs and request bodies before dispatch. |
| Verification Method | Test |
| Verification Statement | Embed synthetic prohibited values in each supported location and encoding; verify blocked requests produce no external operation. |
| Source | USER; OWASP-PI |
| Rationale | Prevent outbound query and tool-argument disclosure. |
### 5.9 — Incoming filtering

| Field | Value |
|---|---|
| ID | 5.9 |
| Parent ID | 5 |
| Statement | The gateway **MUST** apply required content filters before releasing tool text, structured data, embedded content, errors and diagnostic messages. |
| Verification Method | Test |
| Verification Statement | Place fixtures in each enabled response field; verify the configured action occurs before client delivery. |
| Source | USER; OWASP-PI |
| Rationale | Attack payloads are not limited to plain text results. |
### 5.10 — Filter failure

| Field | Value |
|---|---|
| ID | 5.10 |
| Parent ID | 5 |
| Statement | When a required filter fails or exceeds its deadline, the gateway **MUST** block the affected request or result. |
| Verification Method | Test |
| Verification Statement | Crash, delay and corrupt each required filter response; no affected request dispatch or result release may occur. |
| Source | OLD-FLT; OWASP-PI |
| Rationale | A detector outage cannot silently remove an enforced control. |
### 5.11 — Buffered release

| Field | Value |
|---|---|
| ID | 5.11 |
| Parent ID | 5 |
| Statement | The gateway **MUST** withhold result content until its complete bounded representation passes the required filters. |
| Verification Method | Test |
| Verification Statement | Place a prohibited value in the final stream chunk; verify no earlier content chunk reached the client. |
| Source | OLD-FLT |
| Rationale | Post-release detection is too late to prevent disclosure. |
### 5.12 — Safe transformation

| Field | Value |
|---|---|
| ID | 5.12 |
| Parent ID | 5 |
| Statement | The gateway **MUST** require a newly authorized request when redaction changes action-defining arguments or destinations. |
| Verification Method | Test |
| Verification Statement | Redact a destination or executable argument and verify the original approval cannot dispatch the altered action. |
| Source | OLD-FLT |
| Rationale | Filtering must not silently change the intended operation. |
### 5.13 — Untrusted content treatment

| Field | Value |
|---|---|
| ID | 5.13 |
| Parent ID | 5 |
| Statement | The gateway **MUST** preserve provenance and untrusted-data status on filtered external content. |
| Verification Method | Inspection |
| Verification Statement | Inspect response construction and representative fixtures; verify source identity and transformation reasons survive without promoting text to executable policy. |
| Source | OWASP-PI |
| Rationale | A clean scanner verdict cannot grant authority. |
### 5.14 — Context-sensitive text checks

| Field | Value |
|---|---|
| ID | 5.14 |
| Parent ID | 5 |
| Statement | The filter service **MUST** distinguish prohibited control-character patterns from permitted multilingual text and source-code literals using a versioned regression corpus. |
| Verification Method | Test |
| Verification Statement | Run malicious-control, benign-language and code fixtures; require the corpus’s expected decisions without silent content mutation. |
| Source | OWASP-PI; OLD-FLT |
| Rationale | Blind Unicode stripping corrupts legitimate engineering data. |
### 5.15 — Connection-time destination checks

| Field | Value |
|---|---|
| ID | 5.15 |
| Parent ID | 5 |
| Statement | The web broker **MUST** validate resolved destination addresses and each redirect against the approved network policy at connection time. |
| Verification Method | Test |
| Verification Statement | Exercise rebinding, private IPv4/IPv6, metadata addresses and redirects; verify no prohibited connection is established. |
| Source | OWASP-SSRF; MCP-SEC |
| Rationale | Hostname checks alone do not prevent SSRF. |
### 5.16 — One-use web authorization

| Field | Value |
|---|---|
| ID | 5.16 |
| Parent ID | 5 |
| Statement | The trusted web broker **MUST** require a gateway-issued one-use capability bound to the canonical request, graph decision and policy revision. |
| Verification Method | Test |
| Verification Statement | Replay or alter a ticket and attempt a second request to an allowed host; confirm rejection and an audit record. |
| Source | USER; DESIGN |
| Rationale | Network allowlists alone do not account for each outgoing request. |
### 5.17 — Web content execution

| Field | Value |
|---|---|
| ID | 5.17 |
| Parent ID | 5 |
| Statement | The baseline web-fetch worker **MUST** process fetched pages without executing scripts or inheriting browser cookies. |
| Verification Method | Test |
| Verification Statement | Fetch a page with a script-triggered request and a cookie probe; neither script execution nor ambient credentials may appear. |
| Source | OWASP-PI; OLD-WEB |
| Rationale | Fetching a document must not turn into browser automation. |
### 5.18 — Uninspected binary content

| Field | Value |
|---|---|
| ID | 5.18 |
| Parent ID | 5 |
| Statement | The gateway **MUST** block binary, archive and media content unless an admitted bounded extraction path supplies the representation required by policy. |
| Verification Method | Test |
| Verification Statement | Submit unsupported media and decompression-bomb fixtures; confirm blocking before release and enforcement of expanded-size limits. |
| Source | OLD-FLT |
| Rationale | Opaque data can bypass text-only controls. |
### 5.19 — Public-fetch method profile

| Field | Value |
|---|---|
| ID | 5.19 |
| Parent ID | 5 |
| Statement | The baseline public-web broker **MUST** limit operations to HTTPS GET without ambient credentials, uploads, arbitrary Authorization headers, WebSockets or CONNECT tunneling. |
| Verification Method | Test |
| Verification Statement | Attempt POST, upload, CONNECT, WebSocket and credential-injection requests; each must be denied while a permitted public GET succeeds. |
| Source | USER; OWASP-SSRF; OLD-WEB |
| Rationale | The normative web profile must not silently become a generic authenticated proxy. |
### 5.20 — Response conformance

| Field | Value |
|---|---|
| ID | 5.20 |
| Parent ID | 5 |
| Statement | The response processor **MUST** validate MCP response envelopes, request correlation and any approved declared output schema before filtering and release. |
| Verification Method | Test |
| Verification Statement | Return malformed envelopes, wrong request IDs and schema-invalid structured output; each must be blocked before content release. |
| Source | MCP-HTTP; OWASP-MCP; DESIGN |
| Rationale | Filters cannot safely interpret a malformed or misattributed result. |

## 6. Policy-linked audit integrity and privacy

### 6 — Policy-linked audit integrity and privacy

| Field | Value |
|---|---|
| ID | 6 |
| Parent ID |  |
| Statement | The system **MUST** preserve attributable evidence of gateway decisions without unauthorized disclosure of audit data. |
| Verification Method | Analysis |
| Verification Statement | Review the child-control evidence and the threat model; confirm each identified threat in this scope has an implemented control and passing acceptance evidence. |
| Source | USER; OWASP-LOG; OLD-AUD |
| Rationale | Audit records must explain policy effects while avoiding a new secret repository. |
### 6.1 — Mandatory security metadata

| Field | Value |
|---|---|
| ID | 6.1 |
| Parent ID | 6 |
| Statement | The audit service **MUST** retain metadata for authentication failures, decisions, dispatches, outcomes, filter actions and administrative changes regardless of optional payload policy. |
| Verification Method | Test |
| Verification Statement | Disable payload capture and exercise each event class; metadata records must remain. |
| Source | USER; OWASP-LOG |
| Rationale | Policy may choose detail, not erase security evidence. |
### 6.2 — Atomic decision and intent

| Field | Value |
|---|---|
| ID | 6.2 |
| Parent ID | 6 |
| Statement | The graph service **MUST** commit the decision, invocation intent, exact rule/server/profile relationships and export-outbox record in one transaction before dispatch. |
| Verification Method | Test |
| Verification Statement | Inject a failure at each write boundary; observe either a complete linked committed intent or no dispatch. |
| Source | USER; NEO-TX |
| Rationale | Prevent an authorized operation without its explanation. |
### 6.3 — Outcome before release

| Field | Value |
|---|---|
| ID | 6.3 |
| Parent ID | 6 |
| Statement | The graph service **MUST** commit the outcome and delivery decision before the gateway releases result content. |
| Verification Method | Test |
| Verification Statement | Make the outcome transaction fail after execution; verify result withholding and an indeterminate/failure recovery record. |
| Source | OLD-AUD; USER |
| Rationale | Delivery and audit must not diverge silently. |
### 6.4 — Exact historical links

| Field | Value |
|---|---|
| ID | 6.4 |
| Parent ID | 6 |
| Statement | Each audit event for an evaluated request **MUST** reference its exact decision, evaluated policy version, decisive rule versions, target identity and effective audit-profile version. |
| Verification Method | Test |
| Verification Statement | Change policy and server versions after an invocation; historical queries must still return the original identities and rule text. |
| Source | USER |
| Rationale | Audits must associate with the rule and MCP server involved. |
### 6.5 — Event origin versus target

| Field | Value |
|---|---|
| ID | 6.5 |
| Parent ID | 6 |
| Statement | The audit service **MUST** distinguish gateway-generated denials from backend-generated results without attributing execution to an uncalled server. |
| Verification Method | Test |
| Verification Statement | Exercise unknown tool, invalid key and pre-dispatch denial cases; verify system-control reasons and unresolved/target links without fabricated backend execution. |
| Source | USER; OWASP-LOG |
| Rationale | An attempted target is not the event producer. |
### 6.6 — Policy-directed payload storage

| Field | Value |
|---|---|
| ID | 6.6 |
| Parent ID | 6 |
| Statement | The audit service **MUST** use the evaluated audit profile to determine optional redacted payload capture, retention and approved local storage class. |
| Verification Method | Test |
| Verification Statement | Invoke two tools with different audit profiles; compare capture flags, retention expiry and storage references. |
| Source | USER |
| Rationale | The graph rules direct audit organization and detail. |
### 6.7 — Secret removal

| Field | Value |
|---|---|
| ID | 6.7 |
| Parent ID | 6 |
| Statement | The audit service **MUST** remove protected credentials from retained payloads and error messages before persistence. |
| Verification Method | Test |
| Verification Statement | Inject synthetic secrets into requests, responses and errors; search persisted graph, spool and exported records and find no secret value. |
| Source | OWASP-LOG; OLD-AUD |
| Rationale | Encrypted logs still require data minimization. |
### 6.8 — Payload encryption

| Field | Value |
|---|---|
| ID | 6.8 |
| Parent ID | 6 |
| Statement | The audit service **MUST** store optional payload bodies as encrypted local blobs referenced by ciphertext digest and key reference from the graph. |
| Verification Method | Inspection |
| Verification Statement | Inspect storage and graph properties; verify no plaintext payload body or decryption key is stored in Neo4j. |
| Source | USER; OLD-AUD |
| Rationale | Keep large/sensitive bodies out of mutable graph properties. |
### 6.9 — Retention conflict

| Field | Value |
|---|---|
| ID | 6.9 |
| Parent ID | 6 |
| Statement | The publisher **MUST** reject an audit policy whose required retention exceeds a governing maximum or whose payload requirement contradicts a no-capture classification. |
| Verification Method | Test |
| Verification Statement | Publish conflicting fixtures; observe rejection without relaxing the privacy rule. |
| Source | USER; DESIGN |
| Rationale | More logging is not automatically the safest policy. |
### 6.10 — Idempotent evidence export

| Field | Value |
|---|---|
| ID | 6.10 |
| Parent ID | 6 |
| Statement | The evidence exporter **MUST** process committed graph outbox events idempotently by event ID. |
| Verification Method | Test |
| Verification Statement | Crash and replay the exporter; verify one logical exported event per ID and successful reconciliation. |
| Source | NEO-TX; DESIGN |
| Rationale | Neo4j and local files do not share a transaction. |
### 6.11 — Export lag boundary

| Field | Value |
|---|---|
| ID | 6.11 |
| Parent ID | 6 |
| Statement | The gateway **MUST** stop new dispatch when signed-evidence export lag exceeds 60 seconds or 1,000 events. |
| Verification Method | Test |
| Verification Statement | Pause the exporter while generating events; verify dispatch stop at the first threshold and operator alert. |
| Source | DESIGN; OLD-AUD |
| Rationale | Bound the window in which only mutable graph evidence exists. |
### 6.12 — Independent tamper evidence

| Field | Value |
|---|---|
| ID | 6.12 |
| Parent ID | 6 |
| Statement | The evidence exporter **MUST** produce signed chained segment checkpoints whose signing key and retained checkpoint copies are outside graph-service, agent and backend write authority. |
| Verification Method | Test |
| Verification Statement | Attempt checkpoint/key modification with graph-service, agent and worker credentials and verify denial; alter or remove a segment and verify detection against the independent checkpoint. |
| Source | OWASP-LOG; OLD-AUD |
| Rationale | Neo4j CE is mutable, not a WORM audit ledger. |
### 6.13 — Failure evidence spool

| Field | Value |
|---|---|
| ID | 6.13 |
| Parent ID | 6 |
| Statement | When Neo4j is unavailable, the gateway **MUST** preserve rejection and service-failure evidence in a bounded protected local spool without authorizing calls. |
| Verification Method | Test |
| Verification Statement | Stop Neo4j and submit requests; verify denial, durable bounded spool events and later graph reconciliation. |
| Source | DESIGN; OLD-AUD |
| Rationale | Fail-closed operation still needs evidence. |
### 6.14 — Historical retention

| Field | Value |
|---|---|
| ID | 6.14 |
| Parent ID | 6 |
| Statement | The graph service **MUST** retain referenced rule, route, server, tool and profile versions until their dependent audit retention has ended. |
| Verification Method | Test |
| Verification Statement | Retire a server and policy while dependent events remain; deletion must preserve the required historical graph. |
| Source | USER |
| Rationale | Historical records must not become orphaned after cleanup. |
### 6.15 — Controlled purge

| Field | Value |
|---|---|
| ID | 6.15 |
| Parent ID | 6 |
| Statement | The audit service **MUST** create a retained deletion receipt for each authorized payload or metadata-segment purge. |
| Verification Method | Test |
| Verification Statement | Purge an allowed retention scope; confirm a receipt identifies actor, reason, scope and integrity checkpoint without restoring the deleted payload. |
| Source | OWASP-LOG; OLD-AUD |
| Rationale | Deletion must be visible and explainable. |
### 6.16 — Audit access

| Field | Value |
|---|---|
| ID | 6.16 |
| Parent ID | 6 |
| Statement | The control service **MUST** authorize audit queries and exports by the authenticated operator’s application role. |
| Verification Method | Test |
| Verification Statement | Compare administrator, auditor and agent access to metadata, payloads, exports and purge; verify the defined role matrix. |
| Source | NEO-CE; USER |
| Rationale | CE database privileges cannot implement the GUI’s audit roles. |
### 6.17 — Inert audit rendering

| Field | Value |
|---|---|
| ID | 6.17 |
| Parent ID | 6 |
| Statement | The GUI **MUST** render audit content without executing embedded HTML, scripts, spreadsheet formulas or remote media loads. |
| Verification Method | Test |
| Verification Statement | View and export adversarial records; verify inert rendering and formula-safe tabular exports. |
| Source | OWASP-LOG; OWASP-INJ |
| Rationale | Attackers can target the operator through logs. |
### 6.18 — Server-asserted evidence

| Field | Value |
|---|---|
| ID | 6.18 |
| Parent ID | 6 |
| Statement | The audit collector **MUST** label upstream-supplied event claims as server-asserted evidence attributed to the authenticated connection. |
| Verification Method | Test |
| Verification Statement | Have one worker claim another server identity and fabricated completion; verify the stored origin remains the actual connection and unverified claim status. |
| Source | OWASP-LOG; DESIGN |
| Rationale | Untrusted server text cannot create trusted execution evidence. |
### 6.19 — Unevaluated failure evidence

| Field | Value |
|---|---|
| ID | 6.19 |
| Parent ID | 6 |
| Statement | For an event that could not evaluate policy, the audit service **MUST** record a stable system-control reason and policy_status of not_evaluated or unavailable without inventing a policy decision. |
| Verification Method | Test |
| Verification Statement | Exercise invalid authentication and a graph outage, then reconcile the spool; the original status and any explicitly labeled last-known revision must remain unchanged. |
| Source | USER; OWASP-LOG; DESIGN |
| Rationale | Failure evidence must preserve uncertainty instead of fabricating authorization history. |
### 6.20 — Direct decision links

| Field | Value |
|---|---|
| ID | 6.20 |
| Parent ID | 6 |
| Statement | The audit service **MUST** link evaluated-request events directly to their decision whether or not an invocation was authorized. |
| Verification Method | Test |
| Verification Statement | Query known-target denies and successful calls through FOR_DECISION; both must appear without representing a denied request as an authorized invocation. |
| Source | USER; DESIGN |
| Rationale | Denied attempts belong in server/rule history too. |

## 7. Safe operation and recovery

### 7 — Safe operation and recovery

| Field | Value |
|---|---|
| ID | 7 |
| Parent ID |  |
| Statement | The system **MUST** preserve policy and audit boundaries during failures, maintenance and recovery. |
| Verification Method | Analysis |
| Verification Statement | Review the child-control evidence and the threat model; confirm each identified threat in this scope has an implemented control and passing acceptance evidence. |
| Source | NEO-CE; MCP-SEC; OLD-CON |
| Rationale | Operational convenience must not reopen direct routes. |
### 7.1 — Transaction retry safety

| Field | Value |
|---|---|
| ID | 7.1 |
| Parent ID | 7 |
| Statement | The graph service **MUST** exclude external side effects from retryable Neo4j transaction callbacks. |
| Verification Method | Test |
| Verification Statement | Force a driver retry while authorizing a call; confirm database retry produces no duplicated MCP execution, HTTP request or filesystem action. |
| Source | NEO-DRIVER |
| Rationale | Managed transactions can execute callback bodies more than once. |
### 7.2 — Indeterminate mutation

| Field | Value |
|---|---|
| ID | 7.2 |
| Parent ID | 7 |
| Statement | The dispatcher **MUST** mark a possibly executed mutation indeterminate instead of automatically replaying it after a lost acknowledgement or crash. |
| Verification Method | Test |
| Verification Statement | Crash after dispatch but before outcome commit; restart and confirm no automatic second invocation. |
| Source | OLD-MCP; NEO-DRIVER |
| Rationale | Exactly-once external side effects cannot be inferred from a database commit. |
### 7.3 — Graph integrity validation

| Field | Value |
|---|---|
| ID | 7.3 |
| Parent ID | 7 |
| Statement | The graph service **MUST** validate required fields, property types, enumeration values and relationship cardinalities at publication and startup. |
| Verification Method | Test |
| Verification Statement | Inject missing, mistyped and multiply linked fixture data through a maintenance path; activation or startup must deny serving calls. |
| Source | NEO-CONSTRAINTS |
| Rationale | CE uniqueness constraints alone do not enforce the rule schema. |
### 7.4 — Neo4j hardening

| Field | Value |
|---|---|
| ID | 7.4 |
| Parent ID | 7 |
| Statement | The deployment **MUST** disable unused Neo4j HTTP interfaces, unapproved procedures/plugins, file imports, usage reporting and outbound Internet access. |
| Verification Method | Inspection |
| Verification Statement | Inspect the pinned runtime configuration and effective network/extension permissions against the hardening checklist. |
| Source | NEO-SEC; NEO-TELEMETRY |
| Rationale | Database extensions and telemetry create unnecessary paths. |
### 7.5 — Secure bootstrap

| Field | Value |
|---|---|
| ID | 7.5 |
| Parent ID | 7 |
| Statement | The control service **MUST** require a protected one-use local bootstrap credential for initial administrator creation. |
| Verification Method | Test |
| Verification Statement | Attempt remote/agent bootstrap and reuse the credential after success; each must fail. |
| Source | OLD-IAM |
| Rationale | There must be no public or default-password setup path. |
### 7.6 — Emergency stop

| Field | Value |
|---|---|
| ID | 7.6 |
| Parent ID | 7 |
| Statement | The control service **MUST** serialize an emergency stop through the dispatch barrier so subsequent launch authorizations are denied. |
| Verification Method | Test |
| Verification Statement | Trigger stop under concurrent load; verify no later authorization passes and in-flight work is distinguished from unstarted work. |
| Source | USER; DESIGN |
| Rationale | A stop must have a defined effect under concurrency. |
### 7.7 — CE-compatible backup

| Field | Value |
|---|---|
| ID | 7.7 |
| Parent ID | 7 |
| Statement | The recovery service **MUST** support a fail-closed offline backup procedure for Neo4j CE and the associated protected configuration, secret references and evidence checkpoints. |
| Verification Method | Demonstration |
| Verification Statement | Execute the documented stopped-DB backup on a fixture deployment and verify no gateway dispatch occurs during maintenance. |
| Source | NEO-BACKUP |
| Rationale | Online Enterprise backup must not become a hidden dependency. |
### 7.8 — Verified restoration

| Field | Value |
|---|---|
| ID | 7.8 |
| Parent ID | 7 |
| Statement | The deployment **MUST** pass an isolated restore test that preserves graph relationships and current revocations before restored service is enabled. |
| Verification Method | Test |
| Verification Statement | Restore a backup, apply retained later revocations and verify linked audits, secret availability and denied retired credentials. |
| Source | NEO-BACKUP; OLD-AUD |
| Rationale | Restoring old state must not resurrect access. |
### 7.9 — Safe rollback

| Field | Value |
|---|---|
| ID | 7.9 |
| Parent ID | 7 |
| Statement | The release process **MUST** preserve current revocations and server suspensions when rolling back application or policy versions. |
| Verification Method | Test |
| Verification Statement | Rollback a fixture after revoking a key; the key and suspended route must remain unusable. |
| Source | OLD-SUPPLY |
| Rationale | Version recovery is not permission recovery. |
### 7.10 — Audit capacity

| Field | Value |
|---|---|
| ID | 7.10 |
| Parent ID | 7 |
| Statement | The gateway **MUST** stop new dispatch before the audit graph, evidence spool or payload store lacks capacity for the required durable event. |
| Verification Method | Test |
| Verification Statement | Apply quotas and exhaust each store; verify alerting and no dispatch without durable intent. |
| Source | OWASP-LOG; OLD-AUD |
| Rationale | Storage exhaustion must not silently drop accountability. |
### 7.11 — Pre-routing bounds

| Field | Value |
|---|---|
| ID | 7.11 |
| Parent ID | 7 |
| Statement | The HTTP listeners **MUST** enforce the request, header, parsing and concurrency bounds in the controlled limit table before unbounded parsing or buffering. |
| Verification Method | Test |
| Verification Statement | Send oversized, slow, deeply nested and excessive concurrent requests; measure bounds and confirm normal traffic recovery. |
| Source | MCP-HTTP; OLD-LIMITS |
| Rationale | Prevent denial of service before authentication and policy routing. |
### 7.12 — Cancellation propagation

| Field | Value |
|---|---|
| ID | 7.12 |
| Parent ID | 7 |
| Statement | The dispatcher **MUST** propagate cancellation through the applicable MCP profile without treating cancellation as proof that an external side effect was undone. |
| Verification Method | Test |
| Verification Statement | Cancel queued and executing fixture calls; observe correct status and no automatic mutation retry. |
| Source | MCP-VERSION; OLD-MCP |
| Rationale | Protocol cancellation and rollback are different operations. |

## 8. Local operator product

### 8 — Local operator product

| Field | Value |
|---|---|
| ID | 8 |
| Parent ID |  |
| Statement | The system **SHALL** provide a local graphical control interface for gateway administration. |
| Verification Method | Analysis |
| Verification Statement | Review the child GUI demonstration/test evidence and local asset inventory; confirm each workflow has passing evidence without a hosted-service dependency. |
| Source | USER |
| Rationale | The operator needs inspectable server and policy management without hand-editing rules. |
### 8.1 — Server lifecycle GUI

| Field | Value |
|---|---|
| ID | 8.1 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** provide draft, quarantine, test, approve, enable, suspend and retire actions for server versions. |
| Verification Method | Demonstration |
| Verification Statement | Take a synthetic server through each state and inspect the resulting graph and audit timeline. |
| Source | USER |
| Rationale | Make server allowlist maintenance explicit. |
### 8.2 — Policy GUI

| Field | Value |
|---|---|
| ID | 8.2 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** provide structured editors for principal/tool scopes, typed predicates, routes, filters and audit profiles. |
| Verification Method | Demonstration |
| Verification Statement | Create and simulate a restricted read-only rule without entering Cypher; publish it and inspect its effective scope. |
| Source | USER |
| Rationale | The graph is manageable without exposing arbitrary query execution. |
### 8.3 — Policy graph explanation

| Field | Value |
|---|---|
| ID | 8.3 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** display a navigable path from a decision through its rule and route versions to the associated server and audit events. |
| Verification Method | Demonstration |
| Verification Statement | Open a historical decision and navigate to exact rule text, server source snapshot and associated outcomes. |
| Source | USER |
| Rationale | Expose the relationships the graph was selected to organize. |
### 8.4 — Operator graph search

| Field | Value |
|---|---|
| ID | 8.4 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** support bounded audit and registry queries by time, principal, server, tool, rule, outcome and source revision. |
| Verification Method | Demonstration |
| Verification Statement | Run each filter against a mixed fixture dataset and confirm correct scoped results and pagination. |
| Source | USER |
| Rationale | Make engineering investigations practical. |
### 8.5 — Credential management

| Field | Value |
|---|---|
| ID | 8.5 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** provide write-only secret creation, rotation and revocation with reference-impact preview. |
| Verification Method | Demonstration |
| Verification Statement | Rotate a synthetic backend secret and confirm affected routes are identified without displaying saved plaintext. |
| Source | USER; OLD-SECSTORE |
| Rationale | Centralize credential lifecycle for local tools. |
### 8.6 — Filter workbench

| Field | Value |
|---|---|
| ID | 8.6 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** provide a synthetic filter-test workbench showing rule matches, transformations and final disposition. |
| Verification Method | Demonstration |
| Verification Statement | Run allowed, blocked and redacted fixtures and inspect the effective profiles without making an upstream call. |
| Source | USER |
| Rationale | Operators need to tune filters before production use. |
### 8.7 — Enforcement status

| Field | Value |
|---|---|
| ID | 8.7 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** display graph availability, active policy revision, export lag, audit capacity, credential/admission expiry and client qualification state. |
| Verification Method | Demonstration |
| Verification Statement | Change each fixture condition and confirm a visible status update that distinguishes configured from tested enforcement. |
| Source | USER |
| Rationale | Health must expose failures in the actual controls. |
### 8.8 — Local UI assets

| Field | Value |
|---|---|
| ID | 8.8 |
| Parent ID | 8 |
| Statement | The GUI **SHALL** load its production scripts, styles, fonts and help from local storage. |
| Verification Method | Test |
| Verification Statement | Disconnect Internet access and exercise the GUI while capturing attempted connections; no external asset request may occur. |
| Source | USER |
| Rationale | Avoid SaaS/CDN dependencies and telemetry. |
### 8.9 — GUI request protection

| Field | Value |
|---|---|
| ID | 8.9 |
| Parent ID | 8 |
| Statement | The control API **MUST** require CSRF protection and revision preconditions for authenticated browser mutations. |
| Verification Method | Test |
| Verification Statement | Submit missing-token and stale-revision edits; both must fail without graph changes. |
| Source | OWASP-CSRF; OLD-GUI |
| Rationale | Prevent forged requests and lost concurrent edits. |
### 8.10 — Application roles

| Field | Value |
|---|---|
| ID | 8.10 |
| Parent ID | 8 |
| Statement | The control service **SHALL** implement administrator and auditor roles with the operation matrix in SRS Appendix F. |
| Verification Method | Test |
| Verification Statement | Run the role matrix against the API directly; verify read-only auditors cannot publish policy, issue keys or purge evidence. |
| Source | USER; NEO-CE |
| Rationale | Role separation belongs to the application in CE. |

## 9. Open-source local engineering capabilities

### 9 — Open-source local engineering capabilities

| Field | Value |
|---|---|
| ID | 9 |
| Parent ID |  |
| Statement | The baseline **SHALL** operate without paid services, purchased applications or SaaS accounts. |
| Verification Method | Analysis |
| Verification Statement | Review the complete runtime/dependency inventory and offline-workflow test evidence; confirm no required entitlement, paid service or cloud account remains. |
| Source | USER |
| Rationale | This is a binding product constraint, not a preference for free tiers. |
### 9.1 — Open-source inventory

| Field | Value |
|---|---|
| ID | 9.1 |
| Parent ID | 9 |
| Statement | The release **SHALL** identify an OSI-approved license or public-domain status for each baseline software component and bundled dependency. |
| Verification Method | Inspection |
| Verification Statement | Review the pinned SBOM, license texts and notices; reject missing, proprietary or noncommercial-only required components. |
| Source | USER |
| Rationale | Open-source headlines do not license transitive code. |
### 9.2 — Community Edition

| Field | Value |
|---|---|
| ID | 9.2 |
| Parent ID | 9 |
| Statement | The baseline **SHALL** use self-hosted Neo4j Community Edition without requiring Aura or Enterprise features. |
| Verification Method | Inspection |
| Verification Statement | Compare deployment features against the CE qualification checklist, including access control, backup and database count. |
| Source | USER; NEO-CE |
| Rationale | Meet the graph requirement without a commercial dependency. |
### 9.3 — Local execution

| Field | Value |
|---|---|
| ID | 9.3 |
| Parent ID | 9 |
| Statement | The baseline **SHALL** execute MCP servers, graph storage, filters, audits and model inference on approved owned hosts. |
| Verification Method | Test |
| Verification Statement | Run baseline engineering workflows while recording process placement and egress; confirm no cloud computation dependency. |
| Source | USER |
| Rationale | Local hosting keeps work data under operator control. |
### 9.4 — Curated engineering catalog

| Field | Value |
|---|---|
| ID | 9.4 |
| Parent ID | 9 |
| Statement | The release **SHALL** include the source-linked engineering catalog in architecture section 8 with admission status, license, local dependencies and capability limits. |
| Verification Method | Inspection |
| Verification Statement | Check each catalog entry against the required fields and confirm proposed adapters are not labeled implemented. |
| Source | USER |
| Rationale | Common engineering functions need a practical sourcing plan. |
### 9.5 — Initial functions

| Field | Value |
|---|---|
| ID | 9.5 |
| Parent ID | 9 |
| Statement | The initial qualified catalog **SHALL** provide scoped file reading, local repository inspection, local document search and local tabular-data analysis. |
| Verification Method | Demonstration |
| Verification Statement | Complete one synthetic engineering task per function using only the gateway and admitted local services. |
| Source | USER; DESIGN |
| Rationale | These functions cover useful non-SaaS engineering work. |
### 9.6 — Public web exception

| Field | Value |
|---|---|
| ID | 9.6 |
| Parent ID | 9 |
| Statement | When explicitly enabled, the controlled-web profile **SHALL** access approved public documents through the audited broker without paid search APIs or SaaS account credentials. |
| Verification Method | Test |
| Verification Statement | Fetch an allowlisted public document and reject an authenticated/paid-provider fixture; inspect policy and egress evidence. |
| Source | USER; OLD-WEB |
| Rationale | Public documentation access is distinct from a SaaS integration. |
### 9.7 — Conditional client scope

| Field | Value |
|---|---|
| ID | 9.7 |
| Parent ID | 9 |
| Statement | The release documentation **SHALL** label Grok Bot and unqualified client profiles as outside the local no-paid baseline. |
| Verification Method | Inspection |
| Verification Statement | Inspect compatibility guidance and verify no subscription, cloud connector or guessed client configuration is presented as required setup. |
| Source | USER; OLD-CLIENTS |
| Rationale | Technical compatibility does not imply constraint compliance. |

## 10. Qualification and versioned baselines

### 10 — Qualification and versioned baselines

| Field | Value |
|---|---|
| ID | 10 |
| Parent ID |  |
| Statement | The release **SHALL** provide traceable requirements, configuration baselines and verification evidence. |
| Verification Method | Analysis |
| Verification Statement | Inspect the SRS baseline, architecture mapping, requirement records and release evidence; confirm identities and verification status are unambiguous. |
| Source | USER; REQ-WORKFLOW |
| Rationale | Version control must preserve what V1 required. |
### 10.1 — SRS baseline identity

| Field | Value |
|---|---|
| ID | 10.1 |
| Parent ID | 10 |
| Statement | The documentation release **SHALL** identify this SRS as V1 in its title, change record and immutable version snapshot. |
| Verification Method | Inspection |
| Verification Statement | Compare the active file and versions/MCP_Gateway_SRS_V1.md byte-for-byte and inspect the V1 change entry. |
| Source | USER |
| Rationale | Make the requested starting baseline explicit. |
### 10.2 — Local version control

| Field | Value |
|---|---|
| ID | 10.2 |
| Parent ID | 10 |
| Statement | The documentation release **SHALL** record the V1 SRS and matching architecture in local Git with a named V1 tag. |
| Verification Method | Inspection |
| Verification Statement | Inspect tracked paths, commit and tag; confirm the tagged SRS matches the immutable snapshot without requiring a remote service. |
| Source | USER |
| Rationale | Provide recoverable version history without SaaS. |
### 10.3 — Requirement records

| Field | Value |
|---|---|
| ID | 10.3 |
| Parent ID | 10 |
| Statement | The SRS **SHALL** assign each requirement a unique hierarchical ID, parent, source, rationale, verification method and verification statement. |
| Verification Method | Inspection |
| Verification Statement | Validate the records for required fields, unique IDs and exactly one permitted verification method. |
| Source | REQ-WORKFLOW |
| Rationale | Make obligations reviewable and testable. |
### 10.4 — Document authority

| Field | Value |
|---|---|
| ID | 10.4 |
| Parent ID | 10 |
| Statement | The architecture **SHALL** reference the SRS as the normative requirement baseline rather than maintain a competing requirement set. |
| Verification Method | Inspection |
| Verification Statement | Inspect both documents for conflicting policy authorities, outdated requirements and missing SRS references. |
| Source | USER |
| Rationale | Splitting the files must not split the source of truth. |
### 10.5 — Performance qualification

| Field | Value |
|---|---|
| ID | 10.5 |
| Parent ID | 10 |
| Statement | The implementation **SHALL** meet the performance targets in the controlled limit table on recorded reference hardware. |
| Verification Method | Test |
| Verification Statement | Measure the specified graph/gateway latency, GUI query time and memory under the defined datasets and concurrency; record measured results. |
| Source | DESIGN; OLD-LIMITS |
| Rationale | Neo4j changes the footprint and requires measured qualification. |
### 10.6 — Acceptance evidence

| Field | Value |
|---|---|
| ID | 10.6 |
| Parent ID | 10 |
| Statement | The release **SHALL** retain a pass/fail record for each required scenario in the acceptance matrix before claiming enforcement. |
| Verification Method | Inspection |
| Verification Statement | Match requirement verification statements to scenario evidence; any failed or unexecuted mandatory scenario prevents an enforced release label. |
| Source | OLD-CON; REQ-WORKFLOW |
| Rationale | A specification is not proof of a working control. |
### 10.7 — Release provenance

| Field | Value |
|---|---|
| ID | 10.7 |
| Parent ID | 10 |
| Statement | The release **SHALL** include source commits, artifact digests, build recipes, dependency lockfiles, SBOM and license notices. |
| Verification Method | Inspection |
| Verification Statement | Reconcile the installed fixture artifacts against the recorded inventory and build inputs. |
| Source | USER; OWASP-MCP |
| Rationale | Support repeatable source inspection and updates. |
### 10.8 — Local security review

| Field | Value |
|---|---|
| ID | 10.8 |
| Parent ID | 10 |
| Statement | The admission pipeline **SHALL** retain locally generated dependency-vulnerability and source-review findings for each release candidate. |
| Verification Method | Inspection |
| Verification Statement | Inspect reports and unresolved-findings dispositions; confirm scanner unavailability is recorded as missing evidence rather than a clean result. |
| Source | OWASP-MCP; OLD-SUPPLY |
| Rationale | Curated candidates still require release-specific review. |
### 10.9 — Operator procedures

| Field | Value |
|---|---|
| ID | 10.9 |
| Parent ID | 10 |
| Statement | The release **SHALL** include tested procedures for Hermes cutover, revocation, emergency stop, offline backup, restore and rollback. |
| Verification Method | Demonstration |
| Verification Statement | Execute the procedures on an isolated fixture deployment and record each observed outcome. |
| Source | USER; OLD-HERMES |
| Rationale | Clear steps forward must remain usable after implementation. |

## Appendix A — Controlled limits and initial performance targets

These values are part of V1. Future measured changes require a new controlled revision. Safety limits apply before the work they bound; post-parse checks alone do not satisfy pre-routing limits.

| Item | V1 value / reference conditions |
|---|---|
| Total HTTP headers / header deadline | 16 KiB / five seconds |
| Request body / body deadline | 1 MiB while reading / fifteen seconds |
| Source-view bounds | 256 KiB per text page; 1,000 tree entries per page; source snapshots capped at the approved manifest size, with 1 GiB default expanded-size limit |
| Administrator password hashing | Argon2id: memory 64 MiB, iterations 3, parallelism 1, random salt at least 16 bytes; future parameter changes require a qualified revision |
| Expanded result / JSON depth | 8 MiB including decoded content / depth 32 |
| Global connections / unauthenticated work | 128 connections; 32 concurrent unauthenticated requests; per-source 10 requests/s, burst 20 |
| Tool concurrency / queue | Four per principal, sixteen total; bounded waiting queue 32 |
| Principal tool rate | 60 calls/minute, burst 10; policy may reduce limits |
| Graph decision deadline / candidates | 500 ms hard deadline / at most 256 candidate rules; bound traversal to the fixed V1 schema |
| Upstream execution / client deadline | 45 seconds / 60 seconds by default; profile budgets leave time for filtering, graph commit and release |
| Required filter deadline | Two seconds per request or response profile |
| Public fetch redirects | At most three, each independently checked |
| Credential life / rotation overlap | Default 30 days / at most 24 hours; explicit expiry on each key |
| Revocation propagation | Block new launch authorization within two seconds of publication |
| Human approval lifetime | Five minutes maximum, one use, exact final argument/revision binding |
| Admission probe | Two-minute timeout; default no network, secrets or production mounts |
| Simple worker budget | Initial 512 MiB RAM, one CPU, 128 PIDs; any larger admitted profile is explicit and tested |
| Admission re-review | 90 days maximum absent an earlier artifact/advisory/configuration change |
| Metadata / payload retention | 90 days / seven days defaults, subject to validated min/max retention policy |
| Temporary full-payload window | At most 24 hours; secret redaction and no-capture data classes still apply |
| Audit/evidence storage | Initial combined quota 10 GiB; alert at 80%; stop before required durable-event capacity is lost |
| Independent evidence export | Five-second normal target; stop new dispatch above 60 seconds lag or 1,000 pending events |
| Test reference dataset | 10,000 rule/registry nodes, 100,000 event nodes, at most 256 candidates/decision; eight concurrent calls |
| Graph decision performance | p95 ≤100 ms for the reference dataset on recorded hardware |
| Gateway+graph+audit overhead | p95 ≤250 ms for a 64 KiB local result at eight concurrent calls, excluding upstream execution/inference |
| GUI graph/audit query | p95 ≤2 seconds for bounded queries over the reference dataset |
| Core idle footprint | ≤4 GiB combined gateway/control/graph RSS, excluding browser, workers and models |

The graph introduces a larger footprint than the earlier SQLite index. Performance and resource targets are unmeasured until qualification. Timeouts, limits and memory values are not claims about the current workstation.

## Appendix B — Acceptance scenario matrix

Each requirement’s verification statement is authoritative for its scope. These combined scenarios organize implementation testing; none has been executed in this documentation task.

| Scenario | Required observation | Main requirement roots |
|---|---|---|
| AT-01 Identity and local HTTP | Invalid/expired/forged credentials, Host/Origin/TLS and header/body mismatches fail before dispatch | 2, 5 |
| AT-02 Exact authorization | Default deny, deny-overrides, argument bounds and guessed hidden-tool calls behave deterministically | 1, 5 |
| AT-03 Graph authority and outage | No alternate policy grant; failed/invalid/timed-out graph evaluation denies; failure spool reconciles | 1, 6, 7 |
| AT-04 Routing and overlap | Zero/multiple routes, invalid predicates and overlapping incompatible rules cannot authorize | 1 |
| AT-05 Publication/revocation race | Only complete revisions; serialized handoff; queued work reauthorized; revocation bound measured | 1, 2, 7 |
| AT-06 Source and build evidence | Missing source/license/provenance blocks admission; runtime/source/manifest drift suspends | 3, 10 |
| AT-07 Safe source GUI | Malicious filenames/HTML/macros/scripts and oversized source previews stay inert | 3, 8 |
| AT-08 Worker containment | Path/symlink escapes, host sockets, process privilege and IPv4/IPv6/DNS/proxy bypasses fail | 4 |
| AT-09 Request/response filters | Synthetic secrets/injection and malformed/binary/oversized content follow profiles without raw streaming leakage | 5, 6 |
| AT-10 Web broker | One-use authorization, private/reserved addresses, rebinding and redirected destinations enforced | 4, 5 |
| AT-11 Audit graph linkage | Rule/server/tool/profile versions remain correct after rename/update/removal; denied targets not reported as executing | 1, 6 |
| AT-12 Audit consistency | Transaction faults, replayed outbox, lag thresholds and duplicate IDs preserve one logical linked event | 6, 7 |
| AT-13 Integrity/privacy/retention | Checkpoint detects tampering; no raw secrets; contradictory retention rejected; purge receipt retained | 6 |
| AT-14 Transaction retry/crash | Driver retries cause no external side effects; uncertain mutations are not replayed | 7 |
| AT-15 GUI authority | Agent credentials, auditor mutations, CSRF, stale edits and approval replays denied | 2, 8 |
| AT-16 Hermes cutover | Sole MCP endpoint, protected classic-CLI profile, native/plugin/ACP escape denial, local auxiliary inference | 4, 9 |
| AT-17 Offline engineering workflow | Files/Git/document search/tabular analysis work with no SaaS credential or external network | 3, 9 |
| AT-18 Optional client/overlay | Per-client repeated isolation tests; device deny-all; no relay or listener fail-open | 4, 9 |
| AT-19 CE backup/restore/rollback | Offline maintenance blocks calls; restoration verifies graph links and carries forward revocations | 7 |
| AT-20 Limits and load | Pre-routing bounds, latency/query/memory targets, disk exhaustion and restart behavior observed | 1, 7, 10 |
| AT-21 Version baseline | Current SRS equals V1 snapshot; hierarchy/source/verification checks pass; Git tag resolves matching files | 10 |

## Appendix C — Research sources and requirement derivation

Primary online sources were reviewed on 2026-10-04. Statements in this SRS are project paraphrases and design-derived controls. They do not claim certification to MCP, OWASP or Neo4j standards. Current protocol guidance is applied separately from explicitly supported legacy behavior.

| Key | Source | Location / interpretation |
|---|---|---|
| USER | Owner instructions, 2026-10-04 | Split architecture/SRS; consider Neo4j CE as rules/routing/audit system; MUST controls; SRS V1; inspectable OSS local engineering servers; prior no-paid/no-SaaS scope. |
| DESIGN | Project-specific derivation | Explicit design choices in architecture.md sections 2–10, derived from the owner needs and identified failure cases; not claimed verbatim from a standard. |
| REQ-WORKFLOW | Local requirement workflow | `Skills.md` (this repository) and the owner's `Resource.md`, with user-requested MUST terminology override documented here. |
| MCP-SEC | MCP security best practices | [MCP security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) |
| MCP-AUTH | MCP authorization | [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) |
| MCP-HTTP | MCP Streamable HTTP | [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) |
| MCP-VERSION | MCP versioning | [MCP versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) |
| OWASP-MCP | OWASP MCP security guidance | [OWASP MCP security guidance](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) |
| OWASP-POISON | OWASP tool poisoning | [OWASP tool poisoning](https://community.owasp.org/attacks/MCP_Tool_Poisoning) |
| OWASP-PI | OWASP prompt injection prevention | [OWASP prompt injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) |
| OWASP-SSRF | OWASP SSRF prevention | [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) |
| OWASP-LOG | OWASP logging | [OWASP logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| OWASP-INJ | OWASP injection prevention | [OWASP injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) |
| OWASP-CSRF | OWASP CSRF prevention | [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |
| NEO-CE | Neo4j CE access/edition boundaries | [Neo4j CE access/edition boundaries](https://neo4j.com/docs/operations-manual/current/authentication-authorization/) |
| NEO-CYPHER | Neo4j query parameters | [Neo4j query parameters](https://neo4j.com/docs/cypher-manual/current/syntax/parameters/) |
| NEO-TX | Neo4j concurrent access/isolation | [Neo4j concurrent access/isolation](https://neo4j.com/docs/operations-manual/current/database-internals/concurrent-data-access/) |
| NEO-DRIVER | Neo4j driver transactions/retries | [Neo4j driver transactions/retries](https://neo4j.com/docs/go-manual/current/transactions/) |
| NEO-CONSTRAINTS | Neo4j constraint availability | [Neo4j constraint availability](https://neo4j.com/docs/cypher-manual/current/schema/constraints/create-constraints/) |
| NEO-SEC | Neo4j security checklist | [Neo4j security checklist](https://neo4j.com/docs/operations-manual/current/security/checklist/) |
| NEO-TELEMETRY | Neo4j usage reporting | [Neo4j usage reporting](https://neo4j.com/docs/operations-manual/current/configuration/configuration-settings/#config_dbms.usage_report.enabled) |
| NEO-BACKUP | Neo4j offline backup | [Neo4j offline backup](https://neo4j.com/docs/operations-manual/current/backup-restore/offline-backup/) |
| HERMES | Hermes MCP configuration and pinned source | [Hermes MCP configuration and pinned source](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference) |
| HEADSCALE | Headscale explicit network policy | [Headscale explicit network policy](https://headscale.net/0.29.1/ref/policy/) |
| OLD-CON | Prior combined specification, section 1 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-POL | Prior combined specification, section 8 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-IAM | Prior combined specification, section 7 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-DEP | Prior combined specification, section 5 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-ADM | Prior combined specification, section 8 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-SECSTORE | Prior combined specification, section 7 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-FLT | Prior combined specification, section 9 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-WEB | Prior combined specification, section 9 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-AUD | Prior combined specification, section 10 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-MCP | Prior combined specification, section 6 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-GUI | Prior combined specification, section 11 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-HERMES | Prior combined specification, section 12 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-CLIENTS | Prior combined specification, section 14 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-LIMITS | Prior combined specification, section 16 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |
| OLD-SUPPLY | Prior combined specification, section 15 | archive/architecture-pre-srs-v1-2026-10-04.md; requirements preserved or explicitly replaced as mapped in Appendix D. |

Additional research: OWASP authorization and supply-chain guidance, NIST SP 800-207 zero trust, MCP tools security, and vendor repositories/licenses listed in architecture section 8. Use these as supporting evidence, not permission to bypass the concrete source/admission controls.

- [OWASP authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP software supply chain](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [NIST zero trust](https://csrc.nist.gov/pubs/sp/800/207/final)
- [MCP tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

## Appendix D — Migration from the combined specification

The 88 previous IDs remain historical and are not reused as V1 SRS IDs. This crosswalk identifies the authoritative replacement families. No legacy requirement remains normative merely because it appears in an archived document.

| Previous family | V1 hierarchy | Disposition |
|---|---|---|
| CON, SEC | 1–10 | Preserved as scoped constraints/security parents with testable children |
| DEP | 4, 7 | Preserved; private Neo4j/CE boundary added |
| MCP | 5 | Preserved with explicit modern/legacy profiles |
| IAM, SECSTORE | 2 | Preserved and separated into atomic controls |
| ADM | 3 | Extended to locally inspectable source/build evidence and curated candidates |
| POL | 1 | Casbin implementation replaced by graph-authoritative deterministic evaluator |
| FLT, WEB | 5 | Preserved; optional public-web distinct from offline engineering profile |
| AUD | 6 | SQLite audit index replaced by Neo4j primary metadata/relationships plus encrypted blobs and signed evidence outbox |
| GUI | 8 | Extended with graph explanation and safe source inspection |
| HERMES | 4, 9 | Preserved; detailed vendor-specific procedure remains in architecture |
| ZT | 4 | Optional network controls retained; Tailscale hosted control plane excluded |
| SUPPLY | 3, 7, 10 | Preserved as admission, update/recovery and release-evidence controls |
| Former performance table / T01–T19 | Appendix A / AT-01–AT-21 | Retained and expanded for CE footprint, graph races, outbox consistency and baseline versioning |

## Appendix E — Quality review and version control

The workflow drafted the complete candidate set before final hierarchical IDs, assigned one verification method per record, then reviewed necessity, clarity, singularity, feasibility, traceability and verification coverage. Set review checked consistency, scope and meaningful parentage. All roots are intentional; each security parent has concrete children; leaves have explicit verification paths. No unresolved orphan/barren requirement is claimed as accepted. Optional capabilities remain clearly conditional.

Automated document checks verify hierarchy, unique IDs, required fields, source-key resolution, uppercase/bold imperative form and snapshot identity. Independent reviews cover CE constraints, curated server licensing/source claims and security controls. These are document-quality checks, not runtime test results.

| Baseline | Date | Change |
|---|---|---|
| V1 | 2026-10-04 | First separate SRS; graph-authoritative policy/routing and linked audit requirements; researched MUST security controls; inspectable OSS engineering catalog; local Git baseline |

V1 is retained in `versions/MCP_Gateway_SRS_V1.md` and the matching Git tag. Later revisions update the active SRS, add a new immutable version snapshot and change entry, and tag their matching architecture/evidence. Do not overwrite the V1 snapshot or move its tag to a different baseline.


## Appendix F — Frozen V1 graph semantics and application roles

These semantics are normative references for the requirement records. Architecture edits alone cannot alter them. The matching architecture revision 2.0 is retained by the V1 Git tag; changes to these semantics require a new SRS baseline.

**Predicate operators:** exact equality; exact set membership; inclusive numeric range; canonical path containment; validated scheme/host/port membership; data-class membership; UTC expiry interval; required approval state. Missing attributes, malformed values and unsupported operators produce denial. V1 role membership uses bounded direct mappings, not recursive inheritance. Rule matching uses exact IDs and typed values; fuzzy/full-text/vector/model scores are excluded.

| Dimension | V1 rule |
|---|---|
| Prerequisites | Disabled/expired/revoked/unapproved identity, credential, artifact or capability denies |
| Deny/permit | Any applicable deny wins; otherwise a complete matching explicit permit is required |
| Candidate bound | At most 256 candidate rules per evaluation and a 500 ms hard graph deadline |
| Overlap | Complete request scope must match; unresolvable overlapping scopes or routes prevent publication/evaluation |
| Routing | Exactly one admitted immutable route; zero or multiple eligible routes deny |
| Required filters | Union of applicable required controls; observation mode cannot weaken a required filter |
| Resource limits | Smallest applicable size/rate/time/resource bound |
| Audit metadata | Mandatory floor for each event class; ordinary rules cannot disable it |
| Payload capture | No-capture classification wins; capture otherwise requires explicit opt-in profile; contradictory mandatory capture/no-capture blocks publication |
| Retention | Greatest applicable minimum and smallest applicable maximum; an impossible interval blocks publication |
| Storage | Administrator-defined local storage-class ID only; no rule-supplied arbitrary path, network URL or executable |
| Approval | Most restrictive applicable approval scope with exact final arguments/revision and one-use five-minute maximum expiry |

**Approval triggers:** one-use approval is mandatory for any admitted project-file write/delete/rename, Git state mutation, database write/schema change, CAD model mutation, externally transmitted upload/POST, export classified sensitive, or general code/shell execution. These classes remain denied until separately qualified and explicitly granted; an approval alone cannot admit a capability. Policy can require approval for additional actions but cannot remove this floor. Binding includes principal, exact server/tool/route revisions, final canonical arguments, policy revision and at most five minutes expiry.

**Stateful contracts:** each declared stateful tool identifies output JSON paths that create handles, input paths/operations consuming them, principal ownership and expiry checks. A qualified backend ownership adapter may implement the contract. Uncontracted stateful tools remain unadmitted; the gateway does not guess handle meaning from arbitrary strings.

**Secure administrator session:** server-side random session ID; cookie flags Secure, HttpOnly and SameSite=Strict; exact local origin with CSRF protection; session ID rotation on successful login and privilege change; immediate logout/revocation invalidation; 15-minute idle and eight-hour absolute maximum lifetime. Password verification uses the Argon2id profile in Appendix A. Successful login must not preserve an attacker-supplied session identifier.

**Coordinator ordering:** one V1 coordinator serializes publication, revocation, emergency stop, dispatch authorization/handoff and buffered-result release authorization/handoff. The two handoffs are the respective linearization points after durable graph commit while holding the same gate. Work or bytes handed off before revocation are in flight; the system does not claim to recall them. Queued work reauthorizes. A restart invalidates unconsumed handoffs; uncertain side effects are not replayed. External operations never run inside a retryable database callback.

**Audit linkage:** an evaluated request has a Decision, and its events link directly using FOR_DECISION. An authorized execution additionally has an Invocation linked to that Decision. Pre-dispatch denial does not create a fictional authorized execution. Unevaluated authentication/fault events reference versioned system-control reasons with policy_status=not_evaluated/unavailable; any last-known policy is explicitly non-authoritative. Replay preserves this status. Observed backend identity and requested target are distinct; server-asserted text cannot change either.

| Application role | Permitted operations | Explicitly excluded |
|---|---|---|
| Administrator | Inspect sources/audits; admit/suspend servers; edit/simulate/publish rules; issue/revoke keys; approve actions; manage retention; emergency stop | Ordinary GUI direct database/host shell; executing source previews |
| Auditor | Read source/admission metadata, historical rules and redacted audit; permitted redacted exports | Policy/admission changes; key/secret operations; purge; payload bodies without a separate grant |
| MCP principal | Discover/call its exact permitted catalog | Control-plane, policy-write, admission, secret and audit administration |

These are service-enforced roles, not Neo4j CE database privileges. The policy/audit Neo4j instance is never a general engineering-query MCP backend.

