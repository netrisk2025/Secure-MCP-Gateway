// G-01 Gateway control: enforcement state, health causes, active policy
// revision and session count, emergency stop and resume (FR-8.3), policy
// reload, journal verification and the first-run checklist (FR-8.31).
import { useState, type ReactNode } from "react";
import { ApiError, post } from "../api";
import { useResource } from "../data";
import { causeText, useHealth } from "../health";
import { usePerm } from "../perm";
import { Link } from "../router";
import type { EventPage, Principals, ServerView, VerifyResult } from "../types";
import { DataTable, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, StateLabel, Time, toneOf, type Column } from "../ui";

export function VerifyPanel() {
  const perm = usePerm();
  const res = useResource<VerifyResult>(perm.can("GET /api/v1/audit/verify") ? "/api/v1/audit/verify" : null, { live: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      await post("/api/v1/audit/verify", {});
      res.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setBusy(false);
    }
  };
  if (!perm.can("GET /api/v1/audit/verify")) return null;
  return (
    <Section
      title="Journal verification"
      actions={
        perm.can("POST /api/v1/audit/verify") && (
          <button type="button" onClick={() => void run()} disabled={busy}>
            {busy ? "Verifying" : "Verify the journal now"}
          </button>
        )
      }
    >
      {error && <ErrorBlock error={error} />}
      <Loaded res={res} what="the last verification" route="/api/v1/audit/verify">
        {(v) =>
          v.status === "not_run" ? (
            <p className="empty">The journal has not been verified since smcpd started. Verify it now to check every segment signature, the hash chain and the anchor.</p>
          ) : (
            <KV
              rows={[
                ["Result", <StateLabel tone={toneOf(v.status)}>{v.status === "verified" ? "verified" : "failed"}</StateLabel>],
                ...(v.error ? ([["Failure", <Mono>{v.error}</Mono>]] as [string, ReactNode][]) : []),
                ["Segments", <Mono>{v.segments}</Mono>],
                ["Events", <Mono>{v.events}</Mono>],
                ["Open segment", v.open_segment ? <Mono>{v.open_segment}</Mono> : "none"],
                ["Anchor segment", <Mono>{v.anchor_segment}</Mono>],
                ["Findings", v.findings.length ? <ul className="plain">{v.findings.map((f) => <li key={f}>{f}</li>)}</ul> : "none"],
                ["Checked", <><Time value={v.checked_at} /> by <Mono>{v.checked_by}</Mono> in {v.duration_ms} ms</>],
              ]}
            />
          )
        }
      </Loaded>
    </Section>
  );
}

function ReloadPolicy() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<{ revision: string; digest: string; changed: boolean } | null>(null);
  const health = useHealth();
  const run = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await post("/admin/v1/policy/reload", {}));
      health?.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="action-row">
      <div>
        <strong>Reload policy</strong>
        <p className="small">Validates the policy file named in the configuration and activates it if its revision is new.</p>
      </div>
      <button type="button" onClick={() => void run()} disabled={busy}>
        {busy ? "Reloading" : "Reload policy"}
      </button>
      {result && (
        <p role="status" className="small">
          {result.changed ? "Activated" : "Unchanged:"} revision <Mono>{result.revision}</Mono>, digest <Mono>{result.digest.slice(0, 19)}</Mono>.
        </p>
      )}
      {error && <ErrorBlock error={error} />}
    </div>
  );
}

interface CheckItem {
  item: string;
  done: boolean | null; // null: cannot be determined in this build
  detail: ReactNode;
  to: string;
  action: string;
}

function Checklist() {
  const health = useHealth();
  const perm = usePerm();
  const ifCan = (route: string, path: string) => (perm.can(route) ? path : null);
  const principals = useResource<Principals>(ifCan("GET /api/v1/sessions/principals", "/api/v1/sessions/principals"));
  const servers = useResource<{ servers: ServerView[] }>(ifCan("GET /api/v1/servers", "/api/v1/servers"));
  const sessions = useResource<EventPage>(ifCan("GET /api/v1/audit/events", "/api/v1/audit/events?class=session&limit=1"));
  const approved = useResource<EventPage>(ifCan("GET /api/v1/audit/events", "/api/v1/audit/events?class=approval&outcome=approved&limit=1"));
  const denied = useResource<EventPage>(ifCan("GET /api/v1/audit/events", "/api/v1/audit/events?class=approval&outcome=denied&limit=1"));
  const backup = useResource<unknown>(ifCan("GET /api/v1/backup", "/api/v1/backup"));
  const h = health?.status === "ok" ? health.data : undefined;
  const approvers = principals.status === "ok" ? principals.data.session_approvers.length : null;
  const srv = servers.status === "ok" ? servers.data.servers : null;
  const packaged = srv ? srv.filter((s) => s.state === "running" && s.verified).length : null;
  const running = srv ? srv.filter((s) => s.state === "running").length : 0;
  const harness = sessions.status === "ok" ? sessions.data.events.length > 0 || (h?.sessions ?? 0) > 0 : null;
  const tested = approved.status === "ok" && denied.status === "ok" ? approved.data.events.length + denied.data.events.length > 0 : null;
  let backupDone: boolean | null = null;
  let backupDetail: ReactNode = "Backups are not available in this build.";
  if (backup.status === "ok") {
    const b = backup.data as Record<string, unknown> | unknown[];
    backupDone = Array.isArray(b) ? b.length > 0 : !!(b && (b["configured"] === true || (Array.isArray(b["backups"]) && (b["backups"] as unknown[]).length > 0)));
    backupDetail = backupDone ? "A backup is configured." : "No backup is configured yet.";
  } else if (backup.status === "error" && !backup.error.unavailable) {
    backupDetail = `Backup status could not be read: ${backup.error.message}`;
  }
  const items: CheckItem[] = [
    {
      item: "Administrator created",
      done: true,
      detail: perm.role === "administrator" ? "You are signed in with the administrator account or operator token." : "The Gateway was bootstrapped with an administrator.",
      to: "/sessions",
      action: "Accounts",
    },
    {
      item: "Session Approver created",
      done: approvers === null ? null : approvers > 0,
      detail: approvers === null ? "Unknown" : `${approvers} Session Approver account${approvers === 1 ? "" : "s"} configured.`,
      to: "/sessions",
      action: "Sessions and principals",
    },
    {
      item: "First server packaged and enabled",
      done: packaged === null ? null : packaged > 0,
      detail:
        packaged === null
          ? "Unknown"
          : packaged > 0
            ? `${packaged} server${packaged === 1 ? "" : "s"} enabled from a verified package.`
            : `${running} server${running === 1 ? "" : "s"} enabled, none from a verified package.`,
      to: "/servers",
      action: "Servers and library",
    },
    {
      item: "First policy revision published",
      done: h ? !!h.policy_revision : null,
      detail: h?.policy_revision ? <>Revision <Mono>{h.policy_revision}</Mono> is active.</> : "No policy revision is active.",
      to: "/policy",
      action: "Policy studio",
    },
    {
      item: "First harness connected",
      done: harness,
      detail: harness ? "A harness session has been recorded in the journal." : "No harness session has been recorded yet.",
      to: "/sessions",
      action: "Sessions and principals",
    },
    {
      item: "Approval tested",
      done: tested,
      detail: tested ? "An approval has been decided." : "No tool-call approval has been decided yet.",
      to: "/approvals",
      action: "Approvals",
    },
    { item: "Backup configured", done: backupDone, detail: backupDetail, to: "/data-server", action: "Data server and memory" },
  ];
  const columns: Column<CheckItem>[] = [
    { key: "item", label: "Item", render: (r) => r.item },
    {
      key: "state",
      label: "State",
      render: (r) =>
        r.done === null ? <StateLabel tone="neutral">unknown</StateLabel> : r.done ? <StateLabel tone="ok">done</StateLabel> : <StateLabel tone="pending">to do</StateLabel>,
    },
    { key: "detail", label: "From Gateway state", render: (r) => r.detail },
    { key: "to", label: "Where", render: (r) => <Link to={r.to}>{r.action}</Link> },
  ];
  const left = items.filter((i) => i.done !== true).length;
  return (
    <Section title={left ? `First-run checklist: ${left} of ${items.length} open` : "First-run checklist: complete"}>
      <DataTable caption="First-run checklist" columns={columns} rows={items} rowKey={(r) => r.item} empty="" />
    </Section>
  );
}

interface MonitorCause {
  name: string;
  critical: boolean;
  detail: string;
  active: boolean;
  since?: string;
  cleared_at?: string;
  ack_required?: boolean;
  acked_by?: string;
}

/** Health monitor causes, including latched ones that need acknowledgment (FR-7.13). */
function Causes() {
  const perm = usePerm();
  const res = useResource<{ state: string; causes: MonitorCause[]; checked_at: string }>(perm.can("GET /api/v1/health/status") ? "/api/v1/health/status" : null);
  const [error, setError] = useState<ApiError | null>(null);
  if (!perm.can("GET /api/v1/health/status")) return null;
  const ack = async (cause: string) => {
    setError(null);
    try {
      await post("/api/v1/health/ack", { cause });
      res.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    }
  };
  return (
    <Section title="Health monitor">
      {error && <ErrorBlock error={error} />}
      <Loaded res={res} what="the health monitor" route="/api/v1/health/status">
        {(h) => (
          <DataTable
            caption="Health monitor causes"
            rows={h.causes}
            rowKey={(c) => c.name}
            empty="The health monitor reports no cause. A cause appears here when a monitored condition degrades the Gateway."
            columns={[
              { key: "name", label: "Cause", sort: (c) => c.name, render: (c) => <Mono>{c.name}</Mono> },
              { key: "state", label: "State", sort: (c) => String(c.active), render: (c) => (c.active ? <StateLabel tone={c.critical ? "bad" : "warn"}>{c.critical ? "active, critical" : "active"}</StateLabel> : <StateLabel tone="ok">cleared</StateLabel>) },
              { key: "detail", label: "Detail", render: (c) => c.detail },
              { key: "since", label: "Since", render: (c) => <Time value={c.since} /> },
              {
                key: "ack",
                label: "Acknowledgment",
                render: (c) =>
                  c.ack_required ? (
                    perm.can("POST /api/v1/health/ack") ? (
                      <button type="button" className="link" onClick={() => void ack(c.name)}>
                        Acknowledge {c.name}
                      </button>
                    ) : (
                      "required"
                    )
                  ) : c.acked_by ? (
                    <Mono>{c.acked_by}</Mono>
                  ) : (
                    <span className="muted">not needed</span>
                  ),
              },
            ]}
          />
        )}
      </Loaded>
    </Section>
  );
}

export function Control() {
  const health = useHealth();
  const perm = usePerm();
  return (
    <>
      <PageHeader code="G-01" title="Gateway control">
        <p>Enforcement state of this Gateway, why it is in that state, and the controls that change it. Emergency stop is in the bar at the top of every view.</p>
      </PageHeader>
      <Help>
        <p>
          <strong>Emergency stop</strong> refuses every tool call until someone resumes. Use it when a harness or server behaves in a way policy did not
          anticipate. <strong>Reload policy</strong> activates the policy file after you edit it. Health states: healthy (all controls active), degraded (the
          Gateway runs with a reduced guarantee, listed under causes) and fail-closed (every call is refused).
        </p>
      </Help>
      {health && (
        <Section title="Enforcement">
          <Loaded res={health} what="health" route="/admin/v1/health">
            {(h) => (
              <>
                <KV
                  rows={[
                    ["State", <StateLabel tone={toneOf(h.state)}>{h.state}</StateLabel>],
                    ["Profile", <>{h.profile} <span className="muted">({h.release_label})</span></>],
                    ["Policy revision", h.policy_revision ? <Mono>{h.policy_revision}</Mono> : <span className="muted">none</span>],
                    ["Active sessions", <Mono>{h.sessions}</Mono>],
                    ["Launcher", <Mono>{h.launcher}</Mono>],
                    ["Servers", h.servers.length ? h.servers.map((s) => <Mono key={s}>{s} </Mono>) : "none"],
                    ["Version", <Mono>{h.version}</Mono>],
                  ]}
                />
                <h3 className="sub">Causes</h3>
                {h.causes.length === 0 ? (
                  <p className="empty">No cause reduces enforcement.</p>
                ) : (
                  <DataTable
                    caption="Health causes"
                    columns={[
                      { key: "cause", label: "Cause", render: (c: string) => <Mono>{c}</Mono> },
                      { key: "meaning", label: "Meaning", render: (c: string) => causeText[c] ?? "See docs/troubleshooting.md." },
                    ]}
                    rows={h.causes}
                    rowKey={(c) => c}
                    empty=""
                  />
                )}
                {h.profile_reasons && h.profile_reasons.length > 0 && (
                  <>
                    <h3 className="sub">Enforced-profile requirements this host does not meet</h3>
                    <ul className="plain">
                      {h.profile_reasons.map((r) => (
                        <li key={r}>{r}</li>
                      ))}
                    </ul>
                  </>
                )}
              </>
            )}
          </Loaded>
        </Section>
      )}
      <Causes />
      {perm.can("POST /admin/v1/policy/reload") && (
        <Section title="Actions">
          <ReloadPolicy />
        </Section>
      )}
      <VerifyPanel />
      <Checklist />
    </>
  );
}
