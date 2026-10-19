// G-14 Audit investigation: the evidence journal browser with filters,
// paging, export and verification status, and per-event drill-down to the
// other phases of the same call and to the graph mirror when installed.
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError, download } from "../api";
import { useResource } from "../data";
import { Link, match, navigate, useLocation } from "../router";
import type { AuditEvent, EventPage } from "../types";
import { Crumbs, DataTable, ErrorBlock, Help, JsonBlock, KV, Loaded, Mono, PageHeader, Section, ShortId, StateLabel, Time, toneOf, type Column } from "../ui";
import { VerifyPanel } from "./Control";
import { EventPathGraph, NeighborhoodGraph, type EventPath, type Neighborhood } from "../graph";
import { usePerm } from "../perm";
import { SelectField, TextField } from "../ui";

const filterKeys = ["class", "outcome", "reason_code", "origin", "session_id", "correlation_id", "principal_id", "decision_id", "q", "since", "until"] as const;
const primaryFilters: readonly (typeof filterKeys)[number][] = ["class", "outcome", "reason_code", "session_id", "q"];
const filterLabels: Record<(typeof filterKeys)[number], string> = {
  class: "Class",
  outcome: "Outcome",
  reason_code: "Reason code",
  origin: "Origin element",
  session_id: "Session ID",
  correlation_id: "Correlation ID",
  principal_id: "Principal",
  decision_id: "Decision ID",
  q: "Text",
  since: "From (RFC 3339)",
  until: "Until (RFC 3339)",
};

function eventColumns(): Column<AuditEvent>[] {
  return [
    { key: "time", label: "Time (UTC)", sort: (e) => e.time, render: (e) => <Link to={`/audit/events/${e.event_id}`}><Mono>{e.time.slice(0, 19).replace("T", " ")}</Mono></Link> },
    { key: "class", label: "Class", sort: (e) => e.class, render: (e) => <Mono>{e.class}</Mono> },
    { key: "phase", label: "Phase", sort: (e) => e.phase ?? "", render: (e) => (e.phase ? <Mono>{e.phase}</Mono> : <span className="muted">none</span>) },
    { key: "outcome", label: "Outcome", sort: (e) => e.outcome ?? "", render: (e) => (e.outcome ? <StateLabel tone={toneOf(e.outcome)}>{e.outcome}</StateLabel> : <span className="muted">none</span>) },
    { key: "reason", label: "Reason code", sort: (e) => e.reason_code ?? "", render: (e) => <Mono>{e.reason_code}</Mono> },
    { key: "origin", label: "Origin", sort: (e) => e.origin, render: (e) => <Mono>{e.origin}</Mono> },
    { key: "session", label: "Session", sort: (e) => e.session_id ?? "", render: (e) => (e.session_id ? <ShortId id={e.session_id} /> : <span className="muted">none</span>) },
    { key: "corr", label: "Call", sort: (e) => e.correlation_id ?? "", render: (e) => (e.correlation_id ? <ShortId id={e.correlation_id} /> : <span className="muted">none</span>) },
  ];
}

function query(params: URLSearchParams, extra: Record<string, string>): string {
  const q = new URLSearchParams();
  for (const k of filterKeys) {
    const v = params.get(k);
    if (v) q.set(k, v);
  }
  for (const [k, v] of Object.entries(extra)) if (v) q.set(k, v);
  return q.toString();
}

function Journal() {
  const { query: params } = useLocation();
  const [form, setForm] = useState<Record<string, string>>(() => Object.fromEntries(filterKeys.map((k) => [k, params.get(k) ?? ""])));
  const [pages, setPages] = useState<string[]>([""]);
  const base = query(params, {});
  useEffect(() => {
    setForm(Object.fromEntries(filterKeys.map((k) => [k, params.get(k) ?? ""])));
    setPages([""]);
  }, [base]);
  const before = pages[pages.length - 1] ?? "";
  const res = useResource<EventPage>(`/api/v1/audit/events?${query(params, { limit: "100", before })}`, { live: pages.length === 1 });
  const [exportError, setExportError] = useState<ApiError | null>(null);
  const apply = (e: FormEvent) => {
    e.preventDefault();
    const q = new URLSearchParams();
    for (const k of filterKeys) if (form[k]?.trim()) q.set(k, form[k]!.trim());
    navigate(`/audit${q.toString() ? `?${q}` : ""}`);
  };
  const exp = async (format: "csv" | "jsonl") => {
    setExportError(null);
    try {
      await download(`/api/v1/audit/export?${query(params, { format })}`, `journal.${format}`);
    } catch (e) {
      setExportError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    }
  };
  const active = filterKeys.filter((k) => params.get(k));
  const field = (k: (typeof filterKeys)[number]) => (
    <label key={k} className="field">
      <span>{filterLabels[k]}</span>
      <input name={k} value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} spellCheck={false} autoComplete="off" />
    </label>
  );
  return (
    <>
      <Section title="Filter">
        <form className="filters" onSubmit={apply} aria-label="Journal filter">
          {primaryFilters.map(field)}
          <details className="more-filters" open={filterKeys.some((k) => !primaryFilters.includes(k) && params.get(k))}>
            <summary>More filters</summary>
            <div className="filters">{filterKeys.filter((k) => !primaryFilters.includes(k)).map(field)}</div>
          </details>
          <div className="filter-actions">
            <button type="submit" className="btn-primary">
              Apply filter
            </button>
            {active.length > 0 && (
              <button type="button" onClick={() => navigate("/audit")}>
                Clear filter
              </button>
            )}
          </div>
        </form>
      </Section>
      <Section
        title={active.length ? `Events matching ${active.map((k) => `${filterLabels[k].toLowerCase()} ${params.get(k)}`).join(", ")}` : "Events, newest first"}
        actions={
          <>
            <button type="button" onClick={() => void exp("csv")}>
              Export CSV
            </button>
            <button type="button" onClick={() => void exp("jsonl")}>
              Export JSON Lines
            </button>
          </>
        }
      >
        {exportError && <ErrorBlock error={exportError} doing="the export" />}
        <Loaded res={res} what="journal events" route="/api/v1/audit/events">
          {(p) => (
            <>
              <p className="small muted">
                {p.journal_events} events in the journal. Page {pages.length}, {p.events.length} shown.
              </p>
              <DataTable
                caption="Journal events"
                columns={eventColumns()}
                rows={p.events}
                rowKey={(e) => e.event_id}
                rowClass={(e) => (e.outcome === "deny" || e.phase === "denied" ? "row-bad" : undefined)}
                empty={active.length ? "No event matches this filter. Clear the filter or widen the time range." : "The journal holds no events yet."}
              />
              <div className="pager">
                {pages.length > 1 && (
                  <button type="button" onClick={() => setPages(pages.slice(0, -1))}>
                    Newer events
                  </button>
                )}
                {p.next_before && (
                  <button type="button" onClick={() => setPages([...pages, p.next_before])}>
                    Older events
                  </button>
                )}
              </div>
            </>
          )}
        </Loaded>
      </Section>
    </>
  );
}

function EventDetail({ id }: { id: string }) {
  const res = useResource<{ event: AuditEvent; position: number; related: AuditEvent[] }>(`/api/v1/audit/events/${encodeURIComponent(id)}`, { live: false });
  const perm = usePerm();
  const graph = useResource<EventPath>(perm.can("GET /api/v1/graph/events/{id}/path") ? `/api/v1/graph/events/${encodeURIComponent(id)}/path` : null, { live: false });
  const link = (k: string, v?: string): ReactNode => (v ? <Link to={`/audit?${k}=${encodeURIComponent(v)}`}><Mono>{v}</Mono></Link> : <span className="muted">none</span>);
  return (
    <>
      <Crumbs items={[["Audit investigation", "/audit"], [`Event ${id.slice(0, 8)}`, null]]} />
      <PageHeader code="G-14" title="Evidence event">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the event" route="/api/v1/audit/events/{id}">
        {({ event: e, position, related }) => (
          <>
            <Section title="Event">
              <KV
                rows={[
                  ["Time", <Time value={e.time} />],
                  ["Position in journal", <Mono>{position}</Mono>],
                  ["Class", <Mono>{e.class}</Mono>],
                  ["Phase", e.phase ? <Mono>{e.phase}</Mono> : <span className="muted">none</span>],
                  ["Outcome", e.outcome ? <StateLabel tone={toneOf(e.outcome)}>{e.outcome}</StateLabel> : <span className="muted">none</span>],
                  ["Reason code", e.reason_code ? <Mono>{e.reason_code}</Mono> : <span className="muted">none</span>],
                  ["Origin element", <Mono>{e.origin}</Mono>],
                  ["Policy status", <Mono>{e.policy_status}</Mono>],
                  ["Decision", e.decision_id ? <Link to={`/audit/decisions/${encodeURIComponent(e.decision_id)}`}><Mono>{e.decision_id}</Mono></Link> : <span className="muted">none</span>],
                  ["Call", link("correlation_id", e.correlation_id)],
                  ["Session", e.session_id ? <Link to={`/sessions/${e.session_id}`}><Mono>{e.session_id}</Mono></Link> : <span className="muted">none</span>],
                  ["Principal", link("principal_id", e.principal_id)],
                  ["Policy revision", e.policy_revision ? <Mono>{e.policy_revision}</Mono> : <span className="muted">none</span>],
                  ["Server revision", e.server_revision ? <Mono>{e.server_revision}</Mono> : <span className="muted">none</span>],
                  ["Tool revision", e.tool_revision ? <Mono>{e.tool_revision}</Mono> : <span className="muted">none</span>],
                ]}
              />
              {e.detail !== undefined && <JsonBlock value={e.detail} label="Detail (as recorded)" />}
            </Section>
            {related.length > 0 && (
              <Section title={`Phases of this call (${related.length})`}>
                <DataTable caption="Events of the same call" columns={eventColumns()} rows={related} rowKey={(r) => r.event_id} rowClass={(r) => (r.event_id === e.event_id ? "row-current" : undefined)} empty="" />
              </Section>
            )}
          </>
        )}
      </Loaded>
      {perm.can("GET /api/v1/graph/events/{id}/path") && (
        <Section title="Investigation graph" actions={<Link to={`/audit/graph?label=AuditEvent&id=${encodeURIComponent(id)}`}>Explore the neighborhood</Link>}>
          <Loaded res={graph} what="the investigation graph" route="/api/v1/graph/events/{id}/path">
            {(g) => <EventPathGraph path={g} />}
          </Loaded>
        </Section>
      )}
    </>
  );
}

const labels = ["AuditEvent", "Session", "Principal", "Invocation", "Decision", "PolicyRevision", "ServerRevision", "ToolRevision", "Approval"];

function GraphExplorer() {
  const { query } = useLocation();
  const label = labels.includes(query.get("label") ?? "") ? query.get("label")! : "Session";
  const id = query.get("id") ?? "";
  const limit = ["25", "50", "100"].includes(query.get("limit") ?? "") ? query.get("limit")! : "50";
  const [form, setForm] = useState({ label, id, limit });
  useEffect(() => setForm({ label, id, limit }), [label, id, limit]);
  const res = useResource<Neighborhood>(id ? `/api/v1/graph/neighborhood?label=${label}&id=${encodeURIComponent(id)}&limit=${limit}` : null, { live: false });
  const go = (l: string, i: string, n = limit) => navigate(`/audit/graph?label=${l}&id=${encodeURIComponent(i)}&limit=${n}`);
  return (
    <>
      <Crumbs items={[["Audit investigation", "/audit"], ["Graph", null]]} />
      <PageHeader code="G-14" title="Investigation graph">
        <p>Any mirrored node and its neighbors: sessions, principals, calls, decisions, policy, server and tool revisions and approvals.</p>
      </PageHeader>
      <form
        className="filters"
        aria-label="Graph node"
        onSubmit={(e) => {
          e.preventDefault();
          if (form.id.trim()) go(form.label, form.id.trim(), form.limit);
        }}
      >
        <SelectField label="Node kind" value={form.label} onChange={(v) => setForm({ ...form, label: v })} options={labels} />
        <TextField label="Node ID" value={form.id} onChange={(v) => setForm({ ...form, id: v })} mono required />
        <SelectField label="Neighbors shown at most" value={form.limit} onChange={(v) => setForm({ ...form, limit: v })} options={["25", "50", "100"]} />
        <div className="filter-actions">
          <button type="submit" className="btn-primary">
            Show neighborhood
          </button>
        </div>
      </form>
      {id ? (
        <Loaded res={res} what="the neighborhood" route="/api/v1/graph/neighborhood">
          {(d) => (
            <>
              <NeighborhoodGraph data={d} label={label} onRecenter={(l, i) => go(l, i)} />
              <DataTable
                caption="Relationships"
                rows={d.edges.map((e, i) => ({ ...e, i, other: d.neighbors.find((n) => n.id === (e.from === d.node.id ? e.to : e.from)) }))}
                rowKey={(e) => String(e.i)}
                empty="The node has no relationship in the mirror."
                columns={[
                  { key: "type", label: "Relationship", sort: (e) => e.type, render: (e) => <Mono>{e.type}</Mono> },
                  { key: "dir", label: "Direction", render: (e) => (e.from === d.node.id ? "outgoing" : "incoming") },
                  { key: "kind", label: "Neighbor kind", sort: (e) => e.other?.labels?.[0] ?? "", render: (e) => e.other?.labels?.[0] ?? "" },
                  {
                    key: "id",
                    label: "Neighbor",
                    render: (e) =>
                      e.other ? (
                        <button type="button" className="link" onClick={() => go(e.other!.labels?.[0] ?? "AuditEvent", e.other!.id)}>
                          <Mono>{e.other.id}</Mono>
                        </button>
                      ) : null,
                  },
                ]}
              />
            </>
          )}
        </Loaded>
      ) : (
        <p className="empty">Enter a node kind and ID, or open the graph from an event, to see its neighborhood.</p>
      )}
    </>
  );
}

export function Audit({ path }: { path: string }) {
  const m = match("/audit/events/:id", path);
  if (m?.id) return <EventDetail id={m.id} />;
  const dm = match("/audit/decisions/:id", path);
  if (dm?.id) return <DecisionDetail id={dm.id} />;
  if (path === "/audit/graph") return <GraphExplorer />;
  return (
    <>
      <PageHeader code="G-14" title="Audit investigation">
        <p>The signed evidence journal: every decision, call phase and administrative action, with its verification status.</p>
      </PageHeader>
      <Help>
        <p>
          Events are read from the journal files on disk, newest first. Filters match exact values, except Text, which matches any part of the event. Select
          an event's time to see all phases of the same call. Exports are recorded in the journal; spreadsheet formulas in CSV cells are neutralised with a
          leading apostrophe.
        </p>
      </Help>
      <VerifyPanel />
      <Journal />
    </>
  );
}

// A decision's own page (FR-8.22, FR-8.28): the decision record of the
// journal with links to its rule revisions, route, server revision,
// baseline snapshot, session and the other phases of the call.
interface Explanation {
  decision_id: string;
  superseded_by?: string;
  note?: string;
  event_id?: string;
  correlation_id?: string;
  session_id?: string;
  principal_id?: string;
  policy_revision?: string;
  server_revision?: string;
  tool_revision?: string;
  time?: string;
  phase?: string;
  reason_code?: string;
  outcome?: string;
  template?: string;
  route?: string;
  considered_rules?: string[];
  applicable_rules?: string[];
  decisive_rules?: string[];
  obligations?: unknown;
  side_effect?: string;
  source_trust?: string;
  tainted?: boolean;
  baseline_snapshot_id?: string;
  failed_predicate?: string;
  anomaly?: { event_id: string; class: string; outcome?: string; reason_code?: string }[];
}

interface RuleRow {
  id: string;
  kind: string;
  rule?: Record<string, unknown>;
}

function DecisionDetail({ id }: { id: string }) {
  const res = useResource<Explanation>(`/api/v1/decisions/${encodeURIComponent(id)}/explanation`, { live: false });
  const perm = usePerm();
  const d = res.status === "ok" ? res.data : undefined;
  const canPolicy = perm.can("GET /api/v1/policy/revisions/{id}");
  const doc = useResource<{ document: { templates?: Record<string, { rules?: Record<string, unknown>[] }> } }>(
    d?.policy_revision && canPolicy ? `/api/v1/policy/revisions/${encodeURIComponent(d.policy_revision)}` : null,
    { live: false },
  );
  const phases = useResource<EventPage>(d?.correlation_id ? `/api/v1/audit/events?correlation_id=${encodeURIComponent(d.correlation_id)}&limit=50` : null, { live: false });
  const graph = useResource<EventPath>(d?.event_id && perm.can("GET /api/v1/graph/events/{id}/path") ? `/api/v1/graph/events/${encodeURIComponent(d.event_id)}/path` : null, { live: false });
  const none = <span className="muted">none</span>;
  const ruleOf = (rid: string): Record<string, unknown> | undefined => {
    if (doc.status !== "ok") return undefined;
    const [, tpl, rule] = rid.split("/");
    return doc.data.document.templates?.[tpl ?? ""]?.rules?.find((r) => r["id"] === rule);
  };
  const rules: RuleRow[] = d
    ? [
        ...(d.decisive_rules ?? []).map((r) => ({ id: r, kind: "decisive" })),
        ...(d.applicable_rules ?? []).filter((r) => !(d.decisive_rules ?? []).includes(r)).map((r) => ({ id: r, kind: "applicable" })),
        ...(d.considered_rules ?? []).filter((r) => !(d.applicable_rules ?? []).includes(r) && !(d.decisive_rules ?? []).includes(r)).map((r) => ({ id: r, kind: "considered" })),
      ].map((r) => ({ ...r, rule: ruleOf(r.id) }))
    : [];
  const revLink = (rev?: string) => (rev ? canPolicy ? <Link to={`/policy/revisions/${encodeURIComponent(rev)}`}><Mono>{rev}</Mono></Link> : <Mono>{rev}</Mono> : none);
  return (
    <>
      <Crumbs items={[["Audit investigation", "/audit"], [`Decision ${id.slice(0, 8)}`, null]]} />
      <PageHeader code="G-14" title="Decision">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the decision" route="/api/v1/decisions/{id}/explanation">
        {(x) =>
          x.superseded_by ? (
            <Section title="Superseded">
              <p>
                {x.note ?? "This decision was replaced."} The call was decided again as{" "}
                <Link to={`/audit/decisions/${encodeURIComponent(x.superseded_by)}`}>
                  <Mono>{x.superseded_by}</Mono>
                </Link>
                .
              </p>
            </Section>
          ) : (
            <>
              <Section title="Decision record">
                <KV
                  rows={[
                    ["Outcome", x.outcome ? <StateLabel tone={toneOf(x.outcome)}>{x.outcome}</StateLabel> : none],
                    ["Reason code", x.reason_code ? <Mono>{x.reason_code}</Mono> : none],
                    ["Time", <Time value={x.time} />],
                    ["Decision event", x.event_id ? <Link to={`/audit/events/${encodeURIComponent(x.event_id)}`}><Mono>{x.event_id}</Mono></Link> : none],
                    ["Policy revision", revLink(x.policy_revision)],
                    ["Session Allow template", x.template ? <Mono>{x.template}</Mono> : none],
                    ["Route (server alias)", x.route ? <Link to={`/servers/${encodeURIComponent(x.route)}`}><Mono>{x.route}</Mono></Link> : none],
                    ["Server revision", x.server_revision ? (x.route ? <Link to={`/servers/${encodeURIComponent(x.route)}`}><Mono>{x.server_revision}</Mono></Link> : <Mono>{x.server_revision}</Mono>) : none],
                    ["Tool revision", x.tool_revision ? <Mono>{x.tool_revision}</Mono> : none],
                    ["Baseline snapshot", x.baseline_snapshot_id ? <Link to={`/analytics/snapshots/${encodeURIComponent(x.baseline_snapshot_id)}`}><Mono>{x.baseline_snapshot_id}</Mono></Link> : <span className="muted">none in force</span>],
                    ["Session", x.session_id ? <Link to={`/sessions/${encodeURIComponent(x.session_id)}`}><Mono>{x.session_id}</Mono></Link> : none],
                    ["Principal", x.principal_id ? <Mono>{x.principal_id}</Mono> : none],
                    ["Side effect and source trust", <Mono>{`${x.side_effect ?? "unknown"} / ${x.source_trust ?? "unknown"}${x.tainted ? " / tainted" : ""}`}</Mono>],
                    ["Failed predicate", x.failed_predicate ? <Mono>{x.failed_predicate}</Mono> : none],
                  ]}
                />
                {x.obligations !== undefined && <JsonBlock value={x.obligations} label="Obligations" />}
              </Section>
              <Section title={`Rule revisions (${rules.length})`}>
                <DataTable
                  caption="Rule revisions of the decision"
                  rows={rules}
                  rowKey={(r) => `${r.kind}:${r.id}`}
                  empty="No rule matched: the decision is the template's default."
                  columns={[
                    { key: "kind", label: "Role", render: (r) => (r.kind === "decisive" ? <StateLabel tone="neutral">decisive</StateLabel> : r.kind) },
                    { key: "id", label: "Rule revision", render: (r) => <Mono>{r.id}</Mono> },
                    { key: "effect", label: "Effect", render: (r) => (r.rule?.["effect"] ? <Mono>{String(r.rule["effect"])}</Mono> : <span className="muted">see the revision</span>) },
                    { key: "rule", label: "Rule as published", render: (r) => (r.rule ? <Mono>{JSON.stringify(r.rule)}</Mono> : revLink(r.id.split("/")[0])) },
                  ]}
                />
              </Section>
              {x.anomaly && x.anomaly.length > 0 && (
                <Section title="Anomaly evidence">
                  <DataTable
                    caption="Anomaly events of the call"
                    rows={x.anomaly}
                    rowKey={(a) => a.event_id}
                    empty=""
                    columns={[
                      { key: "event", label: "Event", render: (a) => <Link to={`/audit/events/${encodeURIComponent(a.event_id)}`}><Mono>{a.event_id.slice(0, 8)}</Mono></Link> },
                      { key: "class", label: "Class", render: (a) => <Mono>{a.class}</Mono> },
                      { key: "outcome", label: "Outcome", render: (a) => <Mono>{a.outcome ?? ""}</Mono> },
                      { key: "reason", label: "Reason code", render: (a) => <Mono>{a.reason_code ?? ""}</Mono> },
                    ]}
                  />
                </Section>
              )}
              {x.correlation_id && (
                <Section title="Phases of this call">
                  <Loaded res={phases} what="the phases of the call" route="/api/v1/audit/events">
                    {(p) => <DataTable caption="Events of the decided call" columns={eventColumns()} rows={[...p.events].reverse()} rowKey={(e) => e.event_id} empty="No event of this call is in the journal." />}
                  </Loaded>
                </Section>
              )}
              {x.event_id && perm.can("GET /api/v1/graph/events/{id}/path") && (
                <Section title="Investigation graph" actions={<Link to={`/audit/graph?label=Decision&id=${encodeURIComponent(x.decision_id)}`}>Explore the neighborhood</Link>}>
                  <Loaded res={graph} what="the investigation graph" route="/api/v1/graph/events/{id}/path">
                    {(g) => <EventPathGraph path={g} />}
                  </Loaded>
                </Section>
              )}
            </>
          )
        }
      </Loaded>
    </>
  );
}
