// G-13 Approvals: pending tool-call approvals with remaining validity, the
// bound request evidence (FR-3.18) and approve and deny actions (FR-8.21).
// Reads the Approval Service routes /api/v1/approvals* (E-07).
import { useState, type ReactNode } from "react";
import { ApiError, post } from "../api";
import { useNow, useResource } from "../data";
import { Link, match, useLocation } from "../router";
import type { ApprovalRecord, ApprovalSummary } from "../types";
import { Crumbs, DataTable, ErrorBlock, Help, JsonBlock, KV, Loaded, Mono, PageHeader, Section, ShortId, StateLabel, Time, toneOf, type Column } from "../ui";

const states = ["pending", "approved", "denied", "expired", "consumed", "all"] as const;

export function remaining(expiresAt: string, now: number): string {
  const ms = new Date(expiresAt).getTime() - now;
  if (Number.isNaN(ms)) return "unknown";
  if (ms <= 0) return "expired";
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function ApprovalList() {
  const { query } = useLocation();
  const state = (states as readonly string[]).includes(query.get("state") ?? "") ? query.get("state")! : "pending";
  const res = useResource<{ approvals: ApprovalSummary[] }>(`/api/v1/approvals?state=${state}`);
  const now = useNow(1000);
  const columns: Column<ApprovalSummary>[] = [
    { key: "tool", label: "Tool", sort: (a) => a.public_name, render: (a) => <Link to={`/approvals/${a.id}`}><Mono>{a.public_name}</Mono></Link> },
    { key: "server", label: "Server", sort: (a) => a.server, render: (a) => <Mono>{a.server}</Mono> },
    { key: "principal", label: "Principal", sort: (a) => a.principal_id, render: (a) => <Mono>{a.principal_id}</Mono> },
    { key: "session", label: "Session", sort: (a) => a.session_id, render: (a) => <ShortId id={a.session_id} /> },
    { key: "created", label: "Requested", sort: (a) => a.created_at, render: (a) => <Time value={a.created_at} now={now} /> },
    {
      key: "left",
      label: "Valid for",
      sort: (a) => a.expires_at,
      render: (a) => <Mono>{a.state === "pending" ? remaining(a.expires_at, now) : "n/a"}</Mono>,
      className: "num",
    },
    { key: "state", label: "State", sort: (a) => a.state, render: (a) => <StateLabel tone={toneOf(a.state)}>{a.state}</StateLabel> },
    { key: "id", label: "Approval", sort: (a) => a.id, render: (a) => <ShortId id={a.id} /> },
  ];
  return (
    <>
      <nav aria-label="Approval states" className="tabs">
        {states.map((s) => (
          <Link key={s} to={s === "pending" ? "/approvals" : `/approvals?state=${s}`} aria-current={state === s ? "page" : undefined}>
            {s}
          </Link>
        ))}
      </nav>
      <Loaded res={res} what="approvals" route="/api/v1/approvals">
        {(d) => (
          <DataTable
            caption={`Approvals: ${state}`}
            columns={columns}
            rows={d.approvals}
            rowKey={(a) => a.id}
            initialSort="created"
            initialDir="desc"
            empty={
              state === "pending"
                ? "No call is waiting for approval. A call appears here when a policy rule with approval required is used; this list updates by itself."
                : `No approval is in the state ${state}.`
            }
          />
        )}
      </Loaded>
    </>
  );
}

function Decide({ rec, onDone }: { rec: ApprovalRecord; onDone: () => void }) {
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState<"" | "approve" | "deny">("");
  const [error, setError] = useState<ApiError | null>(null);
  const [done, setDone] = useState("");
  const now = useNow(1000);
  const left = remaining(rec.expires_at, now);
  const act = async (d: "approve" | "deny") => {
    setBusy(d);
    setError(null);
    try {
      const r = await post<ApprovalRecord>(`/api/v1/approvals/${encodeURIComponent(rec.id)}/${d}`, comment.trim() ? { comment: comment.trim() } : {});
      setDone(r.state === "approved" ? "Approved. The held call continues, or the next identical call uses this approval." : "Denied. The held call ends with an error.");
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
      onDone();
    } finally {
      setBusy("");
    }
  };
  if (rec.state !== "pending") return done ? <p role="status" className="notice notice-ok">{done}</p> : null;
  return (
    <Section title="Decision">
      <p>
        Valid for <Mono>{left}</Mono>. Approve only if you expect this exact call: the approval is bound to the argument digest, the server and tool revisions
        and the policy revision shown above, and is used once.
      </p>
      <label className="field field-wide">
        <span>Comment (optional, recorded with the decision)</span>
        <textarea value={comment} onChange={(e) => setComment(e.target.value)} maxLength={1000} rows={2} />
      </label>
      {error && <ErrorBlock error={error} />}
      <div className="decide-actions">
        <button type="button" className="btn-primary" disabled={!!busy || left === "expired"} onClick={() => void act("approve")}>
          {busy === "approve" ? "Approving" : "Approve this call"}
        </button>
        <button type="button" className="btn-danger" disabled={!!busy || left === "expired"} onClick={() => void act("deny")}>
          {busy === "deny" ? "Denying" : "Deny this call"}
        </button>
      </div>
    </Section>
  );
}

function ApprovalDetail({ id }: { id: string }) {
  const res = useResource<ApprovalRecord>(`/api/v1/approvals/${encodeURIComponent(id)}`);
  const none = <span className="muted">none</span>;
  const opt = (v?: string): ReactNode => (v ? <Mono>{v}</Mono> : none);
  return (
    <>
      <Crumbs items={[["Approvals", "/approvals"], [`Approval ${id.slice(0, 8)}`, null]]} />
      <PageHeader code="G-13" title="Approval">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the approval" route="/api/v1/approvals/{id}">
        {(r) => (
          <>
            <Section title="Bound request">
              <KV
                rows={[
                  ["State", <StateLabel tone={toneOf(r.state)}>{r.state}</StateLabel>],
                  ["Public tool", <Mono>{r.public_name}</Mono>],
                  ["Server and tool", <><Mono>{r.server}</Mono> / <Mono>{r.tool}</Mono></>],
                  ["Server revision", opt(r.server_revision)],
                  ["Tool revision", opt(r.tool_revision)],
                  ["Manifest source", opt(r.manifest_source)],
                  ["Policy revision", opt(r.policy_revision)],
                  ["Decisive rules", r.decisive_rules?.length ? <Mono>{r.decisive_rules.join(" ")}</Mono> : none],
                  ["Argument digest", opt(r.arguments_digest)],
                  ["Session", <Mono>{r.session_id}</Mono>],
                  ["Principal", <Mono>{r.principal_id}</Mono>],
                  ["Template", opt(r.template)],
                  ["Requested", <Time value={r.created_at} />],
                  ["Expires", <Time value={r.expires_at} />],
                  ["Anomaly band", r.anomaly ? <Mono>{r.anomaly.band}</Mono> : none],
                  ...(r.anomaly
                    ? ([
                        ["Contributing feature", opt(r.anomaly.contributing_feature)],
                        ["z-score", <Mono>{r.anomaly.z_score.toFixed(2)}</Mono>],
                        ["Baseline snapshot", opt(r.anomaly.snapshot_id)],
                      ] as [string, ReactNode][])
                    : []),
                  ...(r.decided_by
                    ? ([
                        ["Decided by", <Mono>{r.decided_by}</Mono>],
                        ["Decided", <Time value={r.decided_at} />],
                        ["Comment", r.comment || none],
                      ] as [string, ReactNode][])
                    : []),
                  ...(r.consumed_at ? ([["Used by call", opt(r.consumed_correlation_id)]] as [string, ReactNode][]) : []),
                ]}
              />
              <JsonBlock value={r.arguments ?? {}} label="Arguments (canonical, as the server will receive them)" />
            </Section>
            <Decide rec={r} onDone={res.reload} />
          </>
        )}
      </Loaded>
    </>
  );
}

export function Approvals({ path }: { path: string }) {
  const m = match("/approvals/:id", path);
  if (m?.id) return <ApprovalDetail id={m.id} />;
  return (
    <>
      <PageHeader code="G-13" title="Approvals">
        <p>Tool calls that a policy rule holds for a person's decision.</p>
      </PageHeader>
      <Help>
        <p>
          While a call is held the harness waits, for up to the hold bound (two minutes by default). Approve during the hold and the call continues; after
          the hold the harness gets an error that tells the person to approve here and run the request again. An approval expires five minutes after the
          request. Open an approval to see the exact arguments before you decide.
        </p>
      </Help>
      <ApprovalList />
    </>
  );
}

