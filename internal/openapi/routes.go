package openapi

// op describes one control API operation. The table is maintained by hand
// next to the route registrations; TestEveryRouteIsDescribed fails when a
// registered route is missing here or a row names no registered route.
type op struct {
	Pattern string   // "METHOD /path", exactly as registered
	Tag     string   // owning element
	Summary string   // one line
	Doc     string   // reference page under docs/api
	Query   []string // query parameters
	Stream  bool     // text/event-stream response
	File    bool     // attachment response
}

var ops = []op{
	// adminapi (E-24 base)
	{Pattern: "POST /admin/v1/login", Tag: "access", Summary: "Sign in as the Administrator; returns a bearer token valid for 30 minutes", Doc: "console.md"},
	{Pattern: "POST /admin/v1/logout", Tag: "access", Summary: "End the Administrator session token", Doc: "console.md"},
	{Pattern: "POST /admin/v1/session/logout", Tag: "access", Summary: "End the caller's browser session (cookie and X-CSRF-Token; SR-2.6-1)", Doc: "console.md"},
	{Pattern: "POST /admin/v1/bootstrap", Tag: "access", Summary: "Redeem the one-use bootstrap token and set the Administrator password", Doc: "console.md"},
	{Pattern: "GET /admin/v1/health", Tag: "control", Summary: "Enforcement state, health causes, profile, policy revision and session count", Doc: "console.md"},
	{Pattern: "POST /admin/v1/stop", Tag: "control", Summary: "Emergency stop: refuse every tool call (FR-4.14)", Doc: "console.md"},
	{Pattern: "POST /admin/v1/resume", Tag: "control", Summary: "Leave the emergency stop", Doc: "console.md"},
	{Pattern: "POST /admin/v1/policy/reload", Tag: "policy", Summary: "Validate and publish the configured policy file", Doc: "policy.md"},
	{Pattern: "GET /admin/v1/approvals", Tag: "approvals", Summary: "Pending approvals (Administrator form of GET /api/v1/approvals)", Doc: "approvals.md"},
	{Pattern: "POST /admin/v1/approvals/{id}", Tag: "approvals", Summary: "Decide an approval (Administrator form)", Doc: "approvals.md"},

	// consoleauth (E-24 roles)
	{Pattern: "POST /api/v1/console/login", Tag: "access", Summary: "Sign in an Operator, Policy Author, Auditor, Researcher or Session Approver account", Doc: "console.md"},
	{Pattern: "POST /api/v1/console/logout", Tag: "access", Summary: "End a console sign-in token", Doc: "console.md"},
	{Pattern: "GET /api/v1/console/session", Tag: "access", Summary: "The caller's actor and role and every route's permitted roles", Doc: "console.md"},
	{Pattern: "GET /api/v1/openapi.json", Tag: "access", Summary: "This OpenAPI 3.1 document (FR-8.1)", Doc: "console.md"},

	// consoleapi (E-24)
	{Pattern: "GET /api/v1/sessions", Tag: "sessions", Summary: "Active harness sessions", Doc: "console.md"},
	{Pattern: "GET /api/v1/sessions/principals", Tag: "sessions", Summary: "Principals, OAuth clients and Session Approver accounts", Doc: "console.md"},
	{Pattern: "GET /api/v1/sessions/{id}", Tag: "sessions", Summary: "One session", Doc: "console.md"},
	{Pattern: "POST /api/v1/sessions/{id}/terminate", Tag: "sessions", Summary: "Terminate a session", Doc: "console.md"},
	{Pattern: "POST /api/v1/sessions/{id}/suspend", Tag: "sessions", Summary: "Suspend an active session (its tokens and calls are refused until resumed)", Doc: "console.md"},
	{Pattern: "POST /api/v1/sessions/{id}/resume", Tag: "sessions", Summary: "Resume a suspended session", Doc: "console.md"},
	{Pattern: "GET /api/v1/principals", Tag: "sessions", Summary: "Principals of smcp.toml and the principal directory, with their credentials and session counts", Doc: "console.md"},
	{Pattern: "POST /api/v1/principals", Tag: "sessions", Summary: "Create a principal in the principal directory", Doc: "console.md"},
	{Pattern: "POST /api/v1/principals/{id}/suspend", Tag: "sessions", Summary: "Suspend a principal: refuse new sessions and suspend its active ones", Doc: "console.md"},
	{Pattern: "POST /api/v1/principals/{id}/enable", Tag: "sessions", Summary: "Enable a suspended principal", Doc: "console.md"},
	{Pattern: "POST /api/v1/principals/{id}/credentials", Tag: "sessions", Summary: "Issue an OAuth client credential for a principal; a confidential client's secret is returned once", Doc: "console.md"},
	{Pattern: "POST /api/v1/credentials/{client_id}/revoke", Tag: "sessions", Summary: "Revoke an issued credential and terminate its sessions", Doc: "console.md"},
	{Pattern: "GET /api/v1/approvers", Tag: "sessions", Summary: "Session Approver accounts of smcp.toml and the principal directory (no password hashes)", Doc: "console.md"},
	{Pattern: "POST /api/v1/approvers", Tag: "sessions", Summary: "Create a Session Approver account whose password differs from the Administrator's", Doc: "console.md"},
	{Pattern: "POST /api/v1/approvers/{username}/remove", Tag: "sessions", Summary: "Remove a Session Approver account of the directory and end its console sessions", Doc: "console.md"},
	{Pattern: "GET /api/v1/servers", Tag: "servers", Summary: "Configured servers with state, revision and manifest source", Doc: "console.md"},
	{Pattern: "GET /api/v1/servers/{alias}", Tag: "servers", Summary: "One server with its launch specification and tools", Doc: "console.md"},
	{Pattern: "GET /api/v1/catalog", Tag: "servers", Summary: "Public tool catalog per Session Allow template", Doc: "console.md", Query: []string{"template"}},
	{Pattern: "GET /api/v1/audit/events", Tag: "audit", Summary: "Journal browser with filters and paging", Doc: "console.md",
		Query: []string{"class", "phase", "outcome", "reason_code", "session_id", "correlation_id", "principal_id", "decision_id", "origin", "server", "tool", "rule", "policy_revision", "q", "since", "until", "limit", "before"}},
	{Pattern: "GET /api/v1/audit/events/{id}", Tag: "audit", Summary: "One evidence event with its related phases", Doc: "console.md"},
	{Pattern: "GET /api/v1/decisions/{id}/explanation", Tag: "audit", Summary: "Decision explanation: considered, applicable and decisive rule revisions, route, obligations and anomaly evidence (SR-1.19-1)", Doc: "policy.md"},
	{Pattern: "GET /api/v1/audit/export", Tag: "audit", Summary: "Export matching events as CSV or JSON Lines", Doc: "console.md", File: true,
		Query: []string{"format", "class", "phase", "outcome", "reason_code", "session_id", "correlation_id", "principal_id", "decision_id", "origin", "server", "tool", "rule", "policy_revision", "q", "since", "until"}},
	{Pattern: "GET /api/v1/audit/verify", Tag: "audit", Summary: "Result of the last journal verification", Doc: "console.md"},
	{Pattern: "POST /api/v1/audit/verify", Tag: "audit", Summary: "Verify the journal now", Doc: "console.md"},
	{Pattern: "GET /api/v1/audit/stream", Tag: "audit", Summary: "Server-sent events: one per journal event (FR-8.23)", Doc: "console.md", Stream: true},

	// approval (E-07)
	{Pattern: "POST /api/v1/approvals/login", Tag: "approvals", Summary: "Sign in an Approver account", Doc: "approvals.md"},
	{Pattern: "POST /api/v1/approvals/logout", Tag: "approvals", Summary: "End an Approver token", Doc: "approvals.md"},
	{Pattern: "GET /api/v1/approvals", Tag: "approvals", Summary: "Approvals by state (default pending)", Doc: "approvals.md", Query: []string{"state"}},
	{Pattern: "GET /api/v1/approvals/watch", Tag: "approvals", Summary: "Server-sent events of approval changes", Doc: "approvals.md", Stream: true},
	{Pattern: "GET /api/v1/approvals/{id}", Tag: "approvals", Summary: "One approval with its bound request", Doc: "approvals.md"},
	{Pattern: "POST /api/v1/approvals/{id}/approve", Tag: "approvals", Summary: "Approve a pending call", Doc: "approvals.md"},
	{Pattern: "POST /api/v1/approvals/{id}/deny", Tag: "approvals", Summary: "Deny a pending call", Doc: "approvals.md"},

	// policyadmin (E-05)
	{Pattern: "GET /api/v1/policy", Tag: "policy", Summary: "Policy store status and the active revision", Doc: "policy.md"},
	{Pattern: "GET /api/v1/policy/revisions", Tag: "policy", Summary: "Published revisions, newest first", Doc: "policy.md"},
	{Pattern: "GET /api/v1/policy/revisions/{id}", Tag: "policy", Summary: "One revision with its canonical document", Doc: "policy.md"},
	{Pattern: "GET /api/v1/policy/revisions/{id}/permissions", Tag: "policy", Summary: "Effective permissions of a template", Doc: "policy.md", Query: []string{"template", "principal"}},
	{Pattern: "POST /api/v1/policy/revisions", Tag: "policy", Summary: "Publish and activate a policy document", Doc: "policy.md"},
	{Pattern: "POST /api/v1/policy/validate", Tag: "policy", Summary: "Validate a draft document", Doc: "policy.md"},
	{Pattern: "POST /api/v1/policy/diff", Tag: "policy", Summary: "Diff a draft or revision against another revision", Doc: "policy.md"},
	{Pattern: "POST /api/v1/policy/simulate", Tag: "policy", Summary: "Replay journal calls or fixtures against a draft", Doc: "policy.md"},
	{Pattern: "POST /api/v1/policy/rollback", Tag: "policy", Summary: "Publish an earlier revision's content as a new revision", Doc: "policy.md"},

	// filters (E-09, E-11)
	{Pattern: "GET /api/v1/filters", Tag: "filters", Summary: "Built-in filters per stage, mandatory lists and rule sets", Doc: "filters.md"},
	{Pattern: "POST /api/v1/filters/scan", Tag: "filters", Summary: "Run selected filters on synthetic input (filter test workbench)", Doc: "filters.md"},

	// egress (E-18)
	{Pattern: "GET /api/v1/egress", Tag: "egress", Summary: "Egress Broker limits and attached instances", Doc: "egress.md"},
	{Pattern: "GET /api/v1/egress/grants", Tag: "egress", Summary: "Effective egress grants", Doc: "egress.md", Query: []string{"server"}},
	{Pattern: "GET /api/v1/egress/connections", Tag: "egress", Summary: "Recent egress operations", Doc: "egress.md", Query: []string{"server", "decision", "since", "limit"}},

	// secrets (E-19, E-20)
	{Pattern: "GET /api/v1/secrets", Tag: "secrets", Summary: "Vault status, Secret Use Policy and secret metadata", Doc: "secrets.md"},
	{Pattern: "POST /api/v1/secrets", Tag: "secrets", Summary: "Create a secret (value write-only)", Doc: "secrets.md"},
	{Pattern: "POST /api/v1/secrets/reload", Tag: "secrets", Summary: "Validate and activate the Secret Use Policy file", Doc: "secrets.md"},
	{Pattern: "GET /api/v1/secrets/{name}", Tag: "secrets", Summary: "One secret's metadata", Doc: "secrets.md"},
	{Pattern: "DELETE /api/v1/secrets/{name}", Tag: "secrets", Summary: "Revoke a secret: retire every version and delete it", Doc: "secrets.md"},
	{Pattern: "POST /api/v1/secrets/{name}/rotate", Tag: "secrets", Summary: "Rotate a secret to a new value", Doc: "secrets.md"},
	{Pattern: "GET /api/v1/secrets/{name}/impact", Tag: "secrets", Summary: "References to a secret (impact preview)", Doc: "secrets.md"},
	{Pattern: "POST /api/v1/secrets/{name}/resume", Tag: "secrets", Summary: "Lift a leak suspension", Doc: "secrets.md"},
	{Pattern: "GET /api/v1/secret-use-policy", Tag: "secrets", Summary: "The active Secret Use Policy document, its file and the published revisions (G-02 editor)", Doc: "secrets.md"},
	{Pattern: "POST /api/v1/secret-use-policy/validate", Tag: "secrets", Summary: "Validate a Secret Use Policy draft", Doc: "secrets.md"},
	{Pattern: "POST /api/v1/secret-use-policy", Tag: "secrets", Summary: "Publish a Secret Use Policy draft to use_policy_file and activate it", Doc: "secrets.md"},
	{Pattern: "POST /api/v1/secret-use-policy/rollback", Tag: "secrets", Summary: "Publish an earlier Secret Use Policy revision again", Doc: "secrets.md"},

	// graph (E-25, E-26, E-28)
	{Pattern: "GET /api/v1/graph/status", Tag: "graph", Summary: "Graph mirror state, memory and counts", Doc: "graph.md", Query: []string{"detail"}},
	{Pattern: "POST /api/v1/graph/rebuild", Tag: "graph", Summary: "Queue a rebuild of the mirror from the journal", Doc: "graph.md"},
	{Pattern: "GET /api/v1/graph/neighborhood", Tag: "graph", Summary: "A node and its bounded neighborhood", Doc: "graph.md", Query: []string{"label", "id", "limit"}},
	{Pattern: "GET /api/v1/graph/events/{id}/path", Tag: "graph", Summary: "Investigation path of one evidence event", Doc: "graph.md", Query: []string{"limit"}},
	{Pattern: "GET /api/v1/graph/queries", Tag: "graph", Summary: "Canned read-only queries", Doc: "graph.md"},
	{Pattern: "GET /api/v1/graph/queries/{name}", Tag: "graph", Summary: "Run a canned query", Doc: "graph.md", Query: []string{"limit"}},

	// sandbox (E-15, E-17)
	{Pattern: "GET /api/v1/runtime", Tag: "runtime", Summary: "Launcher summary", Doc: "runtime.md"},
	{Pattern: "GET /api/v1/runtime/instances", Tag: "runtime", Summary: "Server instances with usage and observations", Doc: "runtime.md"},
	{Pattern: "GET /api/v1/runtime/instances/{id}", Tag: "runtime", Summary: "One instance and its stderr tail", Doc: "runtime.md"},
	{Pattern: "POST /api/v1/runtime/instances/{id}/kill", Tag: "runtime", Summary: "Kill a running instance", Doc: "runtime.md"},
	{Pattern: "GET /api/v1/runtime/doctor", Tag: "runtime", Summary: "Enforced-profile prerequisite checks", Doc: "runtime.md"},

	// analytics (SS-10, E-27)
	{Pattern: "GET /api/v1/observations/status", Tag: "observation", Summary: "Observation collector, store and baseline status", Doc: "observation.md"},
	{Pattern: "GET /api/v1/observations/parameters", Tag: "observation", Summary: "Parameter Catalog with the current selection", Doc: "observation.md"},
	{Pattern: "GET /api/v1/observations", Tag: "observation", Summary: "Stored observation records", Doc: "observation.md",
		Query: []string{"from", "to", "principal", "server", "tool", "session", "limit"}},
	{Pattern: "GET /api/v1/observations/aggregate", Tag: "observation", Summary: "Aggregate of one numeric feature", Doc: "observation.md",
		Query: []string{"feature", "table", "group_by", "bucket", "quantiles", "histogram", "from", "to", "principal", "server", "tool", "session"}},
	{Pattern: "GET /api/v1/observations/metrics", Tag: "observation", Summary: "System meta-metrics rows", Doc: "observation.md", Query: []string{"from", "to", "limit"}},
	{Pattern: "POST /api/v1/observations/purge", Tag: "observation", Summary: "Delete observation data of every day before a date; the deletion receipt is journaled first (SR-6.15-1)", Doc: "observation.md"},
	{Pattern: "GET /api/v1/observations/cost", Tag: "observation", Summary: "Time per stage, policy revision and Observation Policy", Doc: "observation.md", Query: []string{"from", "to", "principal", "tool"}},
	{Pattern: "GET /api/v1/observations/objects", Tag: "observation", Summary: "Audit Profile, Observation Policy, Anomaly Response Policy and memory budget: active revision, revision in force, pending, effective settings", Doc: "observation.md"},
	{Pattern: "GET /api/v1/observations/objects/{kind}", Tag: "observation", Summary: "Revisions of one observation object kind, newest first", Doc: "observation.md"},
	{Pattern: "POST /api/v1/observations/audit-profile", Tag: "observation", Summary: "Publish an Audit Profile revision (retention, optional capture; G-03)", Doc: "observation.md"},
	{Pattern: "POST /api/v1/observations/observation-policy", Tag: "observation", Summary: "Publish an Observation Policy revision (parameters, sampling, contexts, bands; G-04)", Doc: "observation.md"},
	{Pattern: "POST /api/v1/observations/anomaly-response", Tag: "observation", Summary: "Publish an Anomaly Response Policy revision (restrict-only action per band; G-06)", Doc: "observation.md"},
	{Pattern: "POST /api/v1/observations/memory-budget", Tag: "observation", Summary: "Publish the Observation Store memory budget (G-08)", Doc: "observation.md"},
	{Pattern: "GET /api/v1/baselines", Tag: "observation", Summary: "Baseline status, snapshots and promotion history", Doc: "observation.md"},
	{Pattern: "POST /api/v1/baselines/snapshots", Tag: "observation", Summary: "Build a baseline snapshot now", Doc: "observation.md"},
	{Pattern: "POST /api/v1/baselines/flags", Tag: "observation", Summary: "Exclude a session from learning or include it again", Doc: "observation.md"},
	{Pattern: "GET /api/v1/baselines/{id}", Tag: "observation", Summary: "One baseline snapshot", Doc: "observation.md"},
	{Pattern: "GET /api/v1/baselines/{id}/drift", Tag: "observation", Summary: "Drift of a snapshot against the promoted one", Doc: "observation.md"},
	{Pattern: "POST /api/v1/baselines/{id}/promote", Tag: "observation", Summary: "Promote a snapshot (an older one is a rollback)", Doc: "observation.md"},
	{Pattern: "GET /api/v1/anomalies", Tag: "observation", Summary: "Scoring records of band elevated or worse", Doc: "observation.md",
		Query: []string{"from", "to", "band", "principal", "tool", "session", "limit"}},
	{Pattern: "GET /api/v1/research/campaigns", Tag: "research", Summary: "Research campaigns", Doc: "observation.md"},
	{Pattern: "POST /api/v1/research/campaigns", Tag: "research", Summary: "Create a campaign in draft", Doc: "observation.md"},
	{Pattern: "GET /api/v1/research/campaigns/{id}", Tag: "research", Summary: "One campaign", Doc: "observation.md"},
	{Pattern: "POST /api/v1/research/campaigns/{id}/{action}", Tag: "research", Summary: "Submit, approve, reject, stop or expire a campaign", Doc: "observation.md"},
	{Pattern: "GET /api/v1/research/exports", Tag: "research", Summary: "Dataset exports", Doc: "observation.md"},
	{Pattern: "POST /api/v1/research/exports", Tag: "research", Summary: "Export a dataset", Doc: "observation.md"},
	{Pattern: "GET /api/v1/research/exports/{id}", Tag: "research", Summary: "One export manifest", Doc: "observation.md"},
	{Pattern: "GET /api/v1/research/exports/{id}/files/{name}", Tag: "research", Summary: "Download one file of an export", Doc: "observation.md", File: true},

	// remote (FR-16)
	{Pattern: "GET /api/v1/remote", Tag: "remote", Summary: "Remote Access Profile state", Doc: "remote.md"},
	{Pattern: "POST /api/v1/remote/enable", Tag: "remote", Summary: "Enable the Remote Access Profile", Doc: "remote.md"},
	{Pattern: "POST /api/v1/remote/disable", Tag: "remote", Summary: "Disable the Remote Access Profile", Doc: "remote.md"},
	{Pattern: "GET /api/v1/clients", Tag: "remote", Summary: "Remote clients: dynamic registrations and pre-registered clients", Doc: "remote.md", Query: []string{"status"}},
	{Pattern: "GET /api/v1/clients/{id}", Tag: "remote", Summary: "One remote client", Doc: "remote.md"},
	{Pattern: "POST /api/v1/clients/{id}/approve", Tag: "remote", Summary: "Approve a pending registration and bind it to a principal", Doc: "remote.md"},
	{Pattern: "POST /api/v1/clients/{id}/deny", Tag: "remote", Summary: "Deny a pending registration", Doc: "remote.md"},
	{Pattern: "POST /api/v1/clients/{id}/revoke", Tag: "remote", Summary: "Revoke an approved registration", Doc: "remote.md"},

	// ops (E-21, E-22, E-23)
	{Pattern: "GET /api/v1/health/status", Tag: "operations", Summary: "Health monitor report", Doc: "ops.md"},
	{Pattern: "POST /api/v1/health/ack", Tag: "operations", Summary: "Acknowledge a latched integrity cause", Doc: "ops.md"},
	{Pattern: "GET /api/v1/keys", Tag: "operations", Summary: "Key inventory", Doc: "ops.md"},
	{Pattern: "POST /api/v1/keys/rotate", Tag: "operations", Summary: "Rotate the listener certificate, server CA or evidence key", Doc: "ops.md"},
	{Pattern: "GET /api/v1/backup", Tag: "operations", Summary: "Backups in the backup directory", Doc: "ops.md"},
	{Pattern: "POST /api/v1/backup", Tag: "operations", Summary: "Take an online encrypted backup", Doc: "ops.md"},
	{Pattern: "POST /api/v1/config/reload", Tag: "operations", Summary: "Reload the configuration file", Doc: "ops.md"},

	// library (E-13, E-14)
	{Pattern: "GET /api/v1/packages", Tag: "packages", Summary: "Package revisions, packaged servers and trust anchors", Doc: "packages.md"},
	{Pattern: "GET /api/v1/packages/receipts", Tag: "packages", Summary: "Recent import receipts", Doc: "packages.md"},
	{Pattern: "POST /api/v1/packages/scan", Tag: "packages", Summary: "Scan the library now", Doc: "packages.md"},
	{Pattern: "GET /api/v1/packages/{id}/{rev}", Tag: "packages", Summary: "One revision with its signed manifest and provenance", Doc: "packages.md"},
	{Pattern: "POST /api/v1/packages/{id}/{rev}/enable", Tag: "packages", Summary: "Enable a revision, optionally under another alias", Doc: "packages.md"},
	{Pattern: "POST /api/v1/packages/{id}/{rev}/disable", Tag: "packages", Summary: "Suspend a revision (verified-disabled)", Doc: "packages.md"},
	{Pattern: "POST /api/v1/packages/{id}/{rev}/classification", Tag: "packages", Summary: "Tighten a tool's side-effect class, source trust or risk class; loosening is refused (SR-3.11-1)", Doc: "packages.md"},
	{Pattern: "POST /api/v1/packages/trust", Tag: "packages", Summary: "Enroll a trust anchor (minisign public key scoped to risk classes)", Doc: "packages.md"},
	{Pattern: "DELETE /api/v1/packages/trust/{name}", Tag: "packages", Summary: "Remove a trust anchor", Doc: "packages.md"},
	{Pattern: "POST /api/v1/packages/{id}/{rev}/retire", Tag: "packages", Summary: "Retire a revision (final)", Doc: "packages.md"},
}
