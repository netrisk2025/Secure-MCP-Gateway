// G-05 Behavior analytics (FR-8.13): per-context feature distributions,
// the z-score timeline of scored calls, the abnormal-event list with
// drill-down to the journal, baseline snapshots with their drift and the
// promote and rollback actions, and learning exclusion of a session.
// Routes: /api/v1/baselines*, /api/v1/anomalies, /api/v1/observations/
// aggregate and /parameters.
import { useState, type ReactNode } from "react";
import { post } from "../api";
import { BarChart, ScoreTimeline, type Dot } from "../charts";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Link, match, navigate } from "../router";
import { Crumbs, DataTable, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, ShortId, StateLabel, TextField, Time, compact, useAction } from "../ui";
import type { ObsStatus, Parameter } from "./Observations";

interface Snapshot {
  id: string;
  digest?: string;
  created_at?: string;
  trigger?: string;
  window?: { from: string; to: string };
  records?: number;
  contexts?: number;
  characterized?: number;
  promoted?: boolean;
  error?: string;
}

interface Drift {
  candidate: string;
  promoted: string;
  contexts: { context: string; features: { feature: string; mean_shift_sigma: number; sigma_ratio: number }[] }[];
  new_contexts: string[];
  max_abs_mean_shift_sigma: number;
  max_sigma_factor: number;
}

interface Baselines {
  status: { contexts: number; characterized: number; learned: number; excluded: Record<string, number>; flagged_sessions: number; promoted?: string; snapshots: number; records_since_build: number };
  snapshots: Snapshot[];
  history: { id: string; at: string; by: string; mode: string }[];
  flagged_sessions: { session_id: string; reason?: string; at?: string }[] | string[];
  last_drift: Drift | null;
}

interface AnomalyRow {
  ts: string;
  correlation_id: string;
  snapshot_id: string;
  context: string;
  combined: number;
  contributing_feature: string;
  band: string;
  actions: string;
  principal_id?: string;
  tool_name?: string;
  session_id?: string;
}

function DriftTable({ d }: { d: Drift }) {
  const rows = d.contexts.flatMap((c) => c.features.map((f) => ({ ...f, context: c.context })));
  return (
    <>
      <p className="small">
        Against the promoted snapshot <ShortId id={d.promoted} />: largest mean shift <Mono>{d.max_abs_mean_shift_sigma.toFixed(2)}σ</Mono>, largest spread factor{" "}
        <Mono>{d.max_sigma_factor.toFixed(2)}</Mono>, {d.new_contexts.length} new context{d.new_contexts.length === 1 ? "" : "s"}.
      </p>
      <DataTable
        caption="Drift per context and feature"
        rows={rows}
        rowKey={(r) => r.context + r.feature}
        initialSort="shift"
        initialDir="desc"
        empty="No context is characterized in both snapshots. Build snapshots after more calls to compare them."
        columns={[
          { key: "ctx", label: "Context", sort: (r) => r.context, render: (r) => <Mono>{r.context}</Mono> },
          { key: "f", label: "Feature", sort: (r) => r.feature, render: (r) => <Mono>{r.feature}</Mono> },
          { key: "shift", label: "Mean shift (σ)", sort: (r) => Math.abs(r.mean_shift_sigma), render: (r) => <Mono>{r.mean_shift_sigma.toFixed(2)}</Mono>, className: "num" },
          { key: "ratio", label: "Spread ratio", sort: (r) => r.sigma_ratio, render: (r) => <Mono>{r.sigma_ratio.toFixed(2)}</Mono>, className: "num" },
        ]}
      />
    </>
  );
}

function SnapshotsSection() {
  const res = useResource<Baselines>("/api/v1/baselines");
  const perm = usePerm();
  const build = useAction<{ snapshot: Snapshot; drift?: Drift; promoted: boolean }>();
  const promote = useAction<{ promotion: { id: string; mode: string } }>();
  return (
    <Loaded res={res} what="baselines" route="/api/v1/baselines">
      {(b) => {
        const promotedAt = b.snapshots.find((s) => s.promoted)?.created_at ?? "";
        return (
          <>
            <Section
              title="Baseline"
              actions={
                perm.can("POST /api/v1/baselines/snapshots") && (
                  <button type="button" disabled={build.busy} onClick={() => void build.run(() => post("/api/v1/baselines/snapshots", {}), res.reload)}>
                    {build.busy ? "Building" : "Build a snapshot now"}
                  </button>
                )
              }
            >
              {build.error && <ErrorBlock error={build.error} doing="the snapshot" />}
              {build.result && (
                <Done>
                  Built snapshot {build.result.snapshot.id.slice(0, 8)} from {build.result.snapshot.records} records{build.result.promoted ? " and promoted it within the automatic limits" : "; review the drift before promoting it"}.
                </Done>
              )}
              <KV
                rows={[
                  ["Contexts / characterized", <Mono>{b.status.contexts} / {b.status.characterized}</Mono>],
                  ["Records learned", <Mono>{compact(b.status.learned)}</Mono>],
                  ["Excluded from learning", <Mono>{Object.entries(b.status.excluded).map(([k, v]) => `${k} ${v}`).join(", ") || "none"}</Mono>],
                  ["Promoted snapshot", b.status.promoted ? <Link to={`/analytics/snapshots/${b.status.promoted}`}><ShortId id={b.status.promoted} /></Link> : <span className="muted">none: scoring reports uncharacterized</span>],
                  ["Records since the last build", <Mono>{compact(b.status.records_since_build)}</Mono>],
                ]}
              />
              {promote.error && <ErrorBlock error={promote.error} doing="the promotion" />}
              {promote.result && <Done>Snapshot {promote.result.promotion.id.slice(0, 8)} is promoted ({promote.result.promotion.mode}).</Done>}
              <h3 className="sub">Snapshots</h3>
              <DataTable
                caption="Baseline snapshots"
                rows={b.snapshots}
                rowKey={(s) => s.id}
                initialSort="created"
                initialDir="desc"
                empty="No snapshot is built. Build one after enough calls have been learned; until a snapshot is promoted every call scores uncharacterized."
                columns={[
                  { key: "id", label: "Snapshot", render: (s) => <Link to={`/analytics/snapshots/${s.id}`}><ShortId id={s.id} /></Link> },
                  { key: "created", label: "Built", sort: (s) => s.created_at ?? "", render: (s) => (s.error ? <StateLabel tone="bad">{s.error}</StateLabel> : <Time value={s.created_at} />) },
                  { key: "trigger", label: "Trigger", render: (s) => s.trigger ?? "" },
                  { key: "records", label: "Records", sort: (s) => s.records ?? 0, render: (s) => <Mono>{compact(s.records)}</Mono>, className: "num" },
                  { key: "ctx", label: "Characterized", render: (s) => <Mono>{s.characterized ?? 0} of {s.contexts ?? 0}</Mono> },
                  { key: "state", label: "State", sort: (s) => String(s.promoted), render: (s) => (s.promoted ? <StateLabel tone="ok">promoted</StateLabel> : <span className="muted">candidate</span>) },
                  {
                    key: "act",
                    label: "Action",
                    render: (s) =>
                      !s.promoted && !s.error && perm.can("POST /api/v1/baselines/{id}/promote") ? (
                        <button type="button" className="link" disabled={promote.busy} onClick={() => void promote.run(() => post(`/api/v1/baselines/${s.id}/promote`, {}), res.reload)}>
                          {promotedAt && (s.created_at ?? "") < promotedAt ? "Roll back to this snapshot" : "Promote"}
                        </button>
                      ) : (
                        <span className="muted">none</span>
                      ),
                  },
                ]}
              />
              {b.last_drift && (
                <>
                  <h3 className="sub">Drift of the last build</h3>
                  <DriftTable d={b.last_drift} />
                </>
              )}
              <h3 className="sub">Promotion history</h3>
              <DataTable
                caption="Promotion history"
                rows={b.history}
                rowKey={(h) => h.id + h.at}
                initialSort="at"
                initialDir="desc"
                empty="No snapshot has been promoted. Promote a built snapshot to start scoring calls."
                columns={[
                  { key: "at", label: "Time", sort: (h) => h.at, render: (h) => <Time value={h.at} /> },
                  { key: "id", label: "Snapshot", render: (h) => <ShortId id={h.id} /> },
                  { key: "mode", label: "Mode", render: (h) => h.mode },
                  { key: "by", label: "By", render: (h) => <Mono>{h.by}</Mono> },
                ]}
              />
            </Section>
            {perm.can("POST /api/v1/baselines/flags") && <FlagSession onDone={res.reload} />}
          </>
        );
      }}
    </Loaded>
  );
}

function FlagSession({ onDone }: { onDone: () => void }) {
  const [sid, setSid] = useState("");
  const [reason, setReason] = useState("");
  const a = useAction<{ session_id: string; flagged: boolean }>();
  return (
    <Section title="Exclude a session from learning">
      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          void a.run(() => post("/api/v1/baselines/flags", { session_id: sid.trim(), flagged: true, reason: reason.trim() }), onDone);
        }}
      >
        <TextField label="Session ID" value={sid} onChange={setSid} mono required />
        <TextField label="Reason" value={reason} onChange={setReason} />
        <button type="submit" disabled={a.busy || !sid.trim()}>
          Exclude
        </button>
      </form>
      {a.error && <ErrorBlock error={a.error} />}
      {a.result && <Done>Session {a.result.session_id.slice(0, 8)} is excluded from learning.</Done>}
    </Section>
  );
}

const ranges: [string, string][] = [
  ["1h", "last hour"],
  ["24h", "last 24 hours"],
  ["168h", "last 7 days"],
  ["720h", "last 30 days"],
];

function AnomaliesSection() {
  const [range, setRange] = useState("24h");
  const [band, setBand] = useState("");
  const status = useResource<ObsStatus>("/api/v1/observations/status", { live: false });
  const res = useResource<{ rows: AnomalyRow[] }>(`/api/v1/anomalies?from=${range}&limit=1000${band ? `&band=${band}` : ""}`);
  const thresholds = status.status === "ok" && status.data.thresholds ? status.data.thresholds : { elevated: 2, abnormal: 3, critical: 4 };
  const open = (corr: string) => navigate(`/audit?correlation_id=${encodeURIComponent(corr)}`);
  return (
    <Section title="Abnormal events">
      <div className="filters">
        <SelectField label="Time range" value={range} onChange={setRange} options={ranges} />
        <SelectField label="Band" value={band} onChange={setBand} options={[["", "elevated or worse"], "elevated", "abnormal", "critical"]} />
      </div>
      <Loaded res={res} what="anomalies" route="/api/v1/anomalies">
        {(d) => {
          const dots: Dot[] = d.rows.map((r) => ({ x: new Date(r.ts).getTime(), y: r.combined, band: r.band, label: `${r.context}, ${r.contributing_feature}`, href: r.correlation_id }));
          return (
            <>
              <ScoreTimeline title="z-score timeline" dots={dots} thresholds={thresholds} onOpen={(dot) => dot.href && open(dot.href)} />
              <DataTable
                caption="Abnormal events"
                rows={d.rows}
                rowKey={(r) => r.correlation_id + r.ts}
                initialSort="ts"
                initialDir="desc"
                empty="No call scored elevated or worse in this range. Scores appear after tool calls while a promoted baseline snapshot is in force."
                columns={[
                  { key: "ts", label: "Time", sort: (r) => r.ts, render: (r) => <Time value={r.ts} /> },
                  { key: "band", label: "Band", sort: (r) => r.band, render: (r) => <StateLabel tone={r.band === "critical" ? "bad" : r.band === "abnormal" ? "warn" : "pending"}>{r.band}</StateLabel> },
                  { key: "z", label: "Combined z", sort: (r) => r.combined, render: (r) => <Mono>{r.combined.toFixed(2)}</Mono>, className: "num" },
                  { key: "feature", label: "Main feature", sort: (r) => r.contributing_feature, render: (r) => <Mono>{r.contributing_feature}</Mono> },
                  { key: "ctx", label: "Context", sort: (r) => r.context, render: (r) => <Mono>{r.context}</Mono> },
                  { key: "actions", label: "Actions taken", render: (r) => <Mono>{safeList(r.actions)}</Mono> },
                  {
                    key: "call",
                    label: "Call",
                    render: (r) => (
                      <Link to={`/audit?correlation_id=${encodeURIComponent(r.correlation_id)}`}>
                        <ShortId id={r.correlation_id} />
                      </Link>
                    ),
                  },
                ]}
              />
            </>
          );
        }}
      </Loaded>
    </Section>
  );
}

function safeList(s: string): string {
  try {
    const v = JSON.parse(s) as unknown;
    return Array.isArray(v) ? v.join(" ") : s;
  } catch {
    return s;
  }
}

interface AggRow {
  group: Record<string, string>;
  count: number;
  mean: number;
  variance: number;
  min: number;
  max: number;
  quantiles?: number[];
  histogram?: number[];
}

function niceBounds(min: number, max: number, n = 8): number[] {
  if (!(max > min)) return [min];
  const step = (max - min) / n;
  return Array.from({ length: n - 1 }, (_, i) => Number((min + step * (i + 1)).toPrecision(3)));
}

function Distributions() {
  const cat = useResource<{ parameters: Parameter[] }>("/api/v1/observations/parameters", { live: false });
  const [feature, setFeature] = useState("gateway_overhead");
  const [range, setRange] = useState("24h");
  const overall = useResource<{ rows: AggRow[] }>(`/api/v1/observations/aggregate?feature=${encodeURIComponent(feature)}&from=${range}&quantiles=0.5,0.95,0.99`, { live: false });
  const r0 = overall.status === "ok" ? overall.data.rows[0] : undefined;
  const bounds = r0 && r0.count > 1 ? niceBounds(r0.min, r0.max) : [];
  const hist = useResource<{ rows: AggRow[] }>(bounds.length ? `/api/v1/observations/aggregate?feature=${encodeURIComponent(feature)}&from=${range}&histogram=${bounds.join(",")}` : null, { live: false });
  const ctx = useResource<{ rows: AggRow[] }>(`/api/v1/observations/aggregate?feature=${encodeURIComponent(feature)}&from=${range}&group_by=context&quantiles=0.5,0.95`, { live: false });
  const numeric = cat.status === "ok" ? cat.data.parameters.filter((p) => p.baselinable && (p.data_type === "number" || p.data_type === "integer")).map((p) => p.name) : [feature];
  const h = hist.status === "ok" ? hist.data.rows[0]?.histogram : undefined;
  const labels = bounds.length ? [`≤ ${bounds[0]}`, ...bounds.slice(1).map((b, i) => `${bounds[i]} to ${b}`), `> ${bounds[bounds.length - 1]}`] : [];
  return (
    <Section title="Feature distributions">
      <div className="filters">
        <SelectField label="Feature" value={feature} onChange={setFeature} options={numeric.length ? numeric : [feature]} />
        <SelectField label="Time range" value={range} onChange={setRange} options={ranges} />
      </div>
      <Loaded res={overall} what="the distribution" route="/api/v1/observations/aggregate">
        {(d) =>
          !d.rows[0] || d.rows[0].count === 0 ? (
            <p className="empty">No stored record has {feature} in this range. Records appear after tool calls when observation is enabled.</p>
          ) : (
            <>
              <KV
                rows={[
                  ["Records", <Mono>{compact(d.rows[0].count)}</Mono>],
                  ["Mean / standard deviation", <Mono>{compact(d.rows[0].mean)} / {compact(Math.sqrt(d.rows[0].variance))}</Mono>],
                  ["p50 / p95 / p99", <Mono>{(d.rows[0].quantiles ?? []).map((q) => compact(q)).join(" / ")}</Mono>],
                  ["Range", <Mono>{compact(d.rows[0].min)} to {compact(d.rows[0].max)}</Mono>],
                ]}
              />
              {h && <BarChart title={`Distribution of ${feature}`} unit="records" bars={h.map((v, i) => ({ label: labels[i] ?? String(i), value: v }))} />}
            </>
          )
        }
      </Loaded>
      <h3 className="sub">Per baseline context</h3>
      <Loaded res={ctx} what="per-context statistics" route="/api/v1/observations/aggregate">
        {(d) => (
          <DataTable
            caption={`${feature} per context`}
            rows={d.rows}
            rowKey={(r) => JSON.stringify(r.group)}
            initialSort="count"
            initialDir="desc"
            empty="No context has records in this range. Records appear after tool calls when observation is enabled."
            columns={[
              { key: "ctx", label: "Context", sort: (r) => JSON.stringify(r.group), render: (r) => <Mono>{Object.entries(r.group).map(([k, v]) => `${k}=${v}`).join(" ")}</Mono> },
              { key: "count", label: "Records", sort: (r) => r.count, render: (r) => <Mono>{r.count}</Mono>, className: "num" },
              { key: "mean", label: "Mean", sort: (r) => r.mean, render: (r) => <Mono>{compact(r.mean)}</Mono>, className: "num" },
              { key: "sd", label: "Std dev", sort: (r) => r.variance, render: (r) => <Mono>{compact(Math.sqrt(r.variance))}</Mono>, className: "num" },
              { key: "p50", label: "p50", render: (r) => <Mono>{compact(r.quantiles?.[0])}</Mono>, className: "num" },
              { key: "p95", label: "p95", render: (r) => <Mono>{compact(r.quantiles?.[1])}</Mono>, className: "num" },
            ]}
          />
        )}
      </Loaded>
    </Section>
  );
}

function SnapshotDetail({ id }: { id: string }) {
  const res = useResource<{ id: string; digest: string; created_at: string; trigger: string; records: number; contexts: Record<string, { dims: Record<string, string>; count: number; features?: Record<string, { mean: number; std: number; n: number }> }> | { dims: Record<string, string>; count: number }[] }>(
    `/api/v1/baselines/${encodeURIComponent(id)}`,
    { live: false },
  );
  const drift = useResource<Drift>(`/api/v1/baselines/${encodeURIComponent(id)}/drift`, { live: false });
  return (
    <>
      <Crumbs items={[["Behavior analytics", "/analytics"], [`Snapshot ${id.slice(0, 8)}`, null]]} />
      <PageHeader code="G-05" title="Baseline snapshot">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the snapshot" route="/api/v1/baselines/{id}">
        {(s) => {
          const ctxs = Array.isArray(s.contexts) ? s.contexts.map((c, i) => ({ key: String(i), ...c })) : Object.entries(s.contexts ?? {}).map(([k, c]) => ({ key: k, ...c }));
          return (
            <Section title="Contexts">
              <KV
                rows={[
                  ["Built", <Time value={s.created_at} />],
                  ["Trigger", s.trigger],
                  ["Records", <Mono>{s.records}</Mono>],
                  ["Digest", <Mono>{s.digest}</Mono>],
                ]}
              />
              <DataTable
                caption="Snapshot contexts"
                rows={ctxs}
                rowKey={(c) => c.key}
                initialSort="count"
                initialDir="desc"
                empty="The snapshot has no context."
                columns={[
                  { key: "dims", label: "Context", render: (c) => <Mono>{Object.entries(c.dims ?? {}).map(([k, v]) => `${k}=${v}`).join(" ") || c.key}</Mono> },
                  { key: "count", label: "Records", sort: (c) => c.count, render: (c) => <Mono>{c.count}</Mono>, className: "num" },
                  {
                    key: "features",
                    label: "Features (mean ± std)",
                    render: (c) => {
                      const f = (c as { features?: Record<string, { mean: number; std: number }> }).features;
                      return <Mono>{f ? Object.entries(f).slice(0, 3).map(([k, v]) => `${k} ${compact(v.mean)}±${compact(v.std)}`).join("; ") : ""}</Mono>;
                    },
                  },
                ]}
              />
            </Section>
          );
        }}
      </Loaded>
      <Section title="Drift against the promoted snapshot">
        <Loaded res={drift} what="the drift report" route="/api/v1/baselines/{id}/drift">
          {(d) => <DriftTable d={d} />}
        </Loaded>
      </Section>
    </>
  );
}

export function Analytics({ path }: { path: string }): ReactNode {
  const m = match("/analytics/snapshots/:id", path);
  const perm = usePerm();
  if (m?.id) return <SnapshotDetail id={m.id} />;
  return (
    <>
      <PageHeader code="G-05" title="Behavior analytics">
        <p>How calls normally look per context, which calls departed from it and by how many standard deviations, and the baseline snapshots behind the scores.</p>
      </PageHeader>
      <Help>
        <p>
          A <strong>context</strong> is a combination of baseline dimensions (for example principal and tool). A snapshot records each feature's distribution per
          context; once promoted, every call is scored by its combined z-score against it: elevated from 2σ, abnormal from 3σ, critical from 4σ by default.
          Select a dot or a row to open the call in the journal. Build snapshots after enough traffic; review the drift and promote, or roll back by promoting an
          older snapshot.
        </p>
      </Help>
      {perm.can("GET /api/v1/anomalies") && <AnomaliesSection />}
      {perm.can("GET /api/v1/observations/aggregate") && <Distributions />}
      {perm.can("GET /api/v1/baselines") && <SnapshotsSection />}
    </>
  );
}
