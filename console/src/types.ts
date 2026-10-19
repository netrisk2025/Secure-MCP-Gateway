// Shapes of the control API responses the console reads. See
// docs/api/console.md and docs/api/approvals.md.

export interface Health {
  state: "healthy" | "degraded" | "fail-closed" | string;
  causes: string[];
  profile: string;
  release_label: string;
  profile_reasons?: string[];
  version: string;
  policy_revision?: string;
  sessions: number;
  launcher: string;
  servers: string[];
  unverified_servers?: string[];
}

export interface SessionView {
  id: string;
  state: string;
  end_reason?: string;
  principal_id: string;
  framework?: string;
  profile?: string;
  client_id?: string;
  template: string;
  policy_revision?: string;
  purpose?: string;
  project?: string;
  end_user?: string;
  approved_by?: string;
  harness_version?: string;
  listener?: string;
  created_at: string;
  idle_deadline?: string;
  max_deadline?: string;
  ended_at?: string;
}

export interface Principals {
  principals: { id: string; framework: string; display_name?: string; profile: string; enabled: boolean; active_sessions: number }[];
  clients: { client_id: string; principal: string; confidential: boolean; redirect_uris: string[] }[];
  session_approvers: { username: string }[];
}

/** GET /api/v1/approvers (FR-2.23). */
export interface SessionApprovers {
  approvers: { username: string; source: "file" | "console"; created_by?: string; created_at?: string }[];
}

export interface PrincipalDirectory {
  principals: {
    id: string;
    framework: string;
    display_name?: string;
    profile: string;
    source: "file" | "console";
    enabled: boolean;
    suspension?: { by: string; at: string; reason?: string };
    created_by?: string;
    created_at?: string;
    active_sessions: number;
    suspended_sessions: number;
    credentials: {
      client_id: string;
      source: "file" | "console";
      confidential: boolean;
      redirect_uris: string[];
      created_by?: string;
      created_at?: string;
      revoked_by?: string;
      revoked_at?: string;
    }[];
  }[];
  frameworks: string[];
  profiles: string[];
}

export interface ServerView {
  alias: string;
  state: string;
  revision?: string;
  era?: string;
  verified: boolean;
  manifest_source?: string;
  tool_count: number;
  command: string;
  args: string[];
  dir?: string;
  env_keys: string[];
  secret_slots: string[];
  risk_classes: string[];
  launcher: string;
  confined: boolean;
  oversized_frames: number;
}

export interface ToolView {
  name: string;
  public_name: string;
  title?: string;
  description?: string;
  revision: string;
  input_schema?: unknown;
  annotations?: unknown;
}

export interface Catalog {
  policy_revision: string;
  templates: {
    name: string;
    profiles: string[];
    default_for: string[];
    tools: { public_name: string; server: string; tool: string; rule_id: string; approval: boolean; filters: string[]; available: boolean }[];
  }[];
  tools: ToolView[];
}

export interface AuditEvent {
  event_id: string;
  time: string;
  class: string;
  phase?: string;
  origin: string;
  correlation_id?: string;
  session_id?: string;
  principal_id?: string;
  decision_id?: string;
  policy_revision?: string;
  server_revision?: string;
  tool_revision?: string;
  outcome?: string;
  reason_code?: string;
  policy_status: string;
  detail?: unknown;
}

export interface EventPage {
  events: AuditEvent[];
  next_before: string;
  journal_events: number;
}

export interface VerifyResult {
  status: "verified" | "failed" | "not_run";
  error?: string;
  segments: number;
  events: number;
  open_segment?: string;
  truncated_tail: boolean;
  recovered: string[];
  anchor_segment: number;
  findings: string[];
  checked_at?: string;
  duration_ms: number;
  checked_by?: string;
}

export interface ApprovalSummary {
  id: string;
  state: string;
  public_name: string;
  server: string;
  server_revision: string;
  session_id: string;
  principal_id: string;
  created_at: string;
  expires_at: string;
  approval_url?: string;
  decided_by?: string;
  decided_at?: string;
}

/** Anomaly Scorer evidence of an approval an anomaly band required (FR-3.18). */
export interface AnomalyEvidence {
  band: string;
  contributing_feature?: string;
  z_score: number;
  snapshot_id?: string;
  context?: string;
}

export interface ApprovalRecord extends ApprovalSummary {
  tool: string;
  tool_revision: string;
  policy_revision: string;
  arguments_digest: string;
  template?: string;
  manifest_source?: string;
  correlation_id?: string;
  decision_id?: string;
  decisive_rules?: string[];
  anomaly?: AnomalyEvidence;
  arguments?: unknown;
  comment?: string;
  consumed_at?: string;
  consumed_correlation_id?: string;
}
