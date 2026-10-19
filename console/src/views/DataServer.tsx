// G-08 Data server & memory (FR-8.16): graph mirror memory against its
// budget, store sizes and counts, observation queue use and degradation
// stage, storage quota levels, the last backups and taking one, and the key
// inventory with rotation. Routes: /api/v1/graph/status,
// /api/v1/graph/rebuild, /api/v1/observations/status,
// /api/v1/health/status (quotas), /api/v1/backup, /api/v1/keys*.
import { ObjectState, Publish, useObjects } from "./objects";
import { useState, type ReactNode } from "react";
import { post } from "../api";
import { Meter } from "../charts";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { DataTable, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, StateLabel, TextField, Time, bytes, compact, useAction } from "../ui";
import type { ObsStatus } from "./Observations";

interface GraphStatus {
  enabled: boolean;
  state: string;
  uri: string;
  error?: string;
  schema_version: number;
  checkpoint: { segment: number; events: number };
  live_applied: number;
  live_dropped: number;
  last_catch_up?: string;
  last_retention?: string;
  hardening: { setting: string; value: string; want: string; reason: string }[];
  memory: { budget: { heap_bytes: number; page_cache_bytes: number }; heap_used: number; heap_max: number; page_cache_configured: number; pressure: boolean; sampled_at?: string };
  counts?: Record<string, number>;
}

interface Backup {
  path: string;
  sha256: string;
  size: number;
  created_at: string;
  components: string[];
  result: string;
}

function Graph() {
  const res = useResource<GraphStatus>("/api/v1/graph/status");
  const perm = usePerm();
  const rebuild = useAction<{ status: string }>();
  return (
    <Section
      title="Graph mirror"
      actions={
        perm.can("POST /api/v1/graph/rebuild") && (
          <button type="button" disabled={rebuild.busy} onClick={() => void rebuild.run(() => post("/api/v1/graph/rebuild", {}), res.reload)}>
            Rebuild from the journal
          </button>
        )
      }
    >
      {rebuild.error && <ErrorBlock error={rebuild.error} doing="the rebuild" />}
      {rebuild.result && <Done>A rebuild is queued.</Done>}
      <Loaded res={res} what="the graph mirror" route="/api/v1/graph/status">
        {(g) => (
          <>
            <KV
              rows={[
                ["State", <StateLabel tone={g.state === "ready" ? "ok" : g.state === "disabled" ? "neutral" : "warn"}>{g.state}</StateLabel>],
                ["Database", <Mono>{g.uri}</Mono>],
                ...(g.error ? ([["Error", <Mono>{g.error}</Mono>]] as [string, ReactNode][]) : []),
                ["Journal checkpoint", <Mono>segment {g.checkpoint.segment}, {compact(g.checkpoint.events)} events</Mono>],
                ["Live events applied / dropped", <Mono>{compact(g.live_applied)} / {compact(g.live_dropped)}</Mono>],
                ["Last catch-up", <Time value={g.last_catch_up} />],
                ["Last retention run", <Time value={g.last_retention} />],
              ]}
            />
            {!g.enabled && <p className="empty">The graph mirror is disabled ([graph] enabled = false). Enforcement never depends on it. To use it, install Neo4j and set [graph] enabled = true (docs/graph.md).</p>}
            {g.enabled && (
              <>
                <Meter label="Heap in use against budget" used={g.memory.heap_used} budget={g.memory.budget.heap_bytes} format={bytes} />
                <Meter label="Page cache configured against budget" used={g.memory.page_cache_configured} budget={g.memory.budget.page_cache_bytes} format={bytes} />
                {g.memory.pressure && <p className="notice notice-warn">The database reports memory pressure.</p>}
              </>
            )}
            {g.counts && (
              <DataTable
                caption="Mirrored nodes"
                rows={Object.entries(g.counts)}
                rowKey={(r) => r[0]}
                initialSort="n"
                initialDir="desc"
                empty=""
                columns={[
                  { key: "k", label: "Kind", sort: (r) => r[0], render: (r) => <Mono>{r[0]}</Mono> },
                  { key: "n", label: "Count", sort: (r) => r[1], render: (r) => <Mono>{compact(r[1])}</Mono>, className: "num" },
                ]}
              />
            )}
            {g.hardening.length > 0 && (
              <>
                <h3 className="sub">Database settings that differ from the hardening profile</h3>
                <DataTable
                  caption="Hardening findings"
                  rows={g.hardening}
                  rowKey={(h) => h.setting}
                  empty=""
                  columns={[
                    { key: "s", label: "Setting", render: (h) => <Mono>{h.setting}</Mono> },
                    { key: "v", label: "Value", render: (h) => <Mono>{h.value}</Mono> },
                    { key: "w", label: "Wanted", render: (h) => <Mono>{h.want}</Mono> },
                    { key: "r", label: "Why", render: (h) => h.reason },
                  ]}
                />
              </>
            )}
          </>
        )}
      </Loaded>
    </Section>
  );
}

/** The Observation Store memory budget (FR-8.16), published as a revision. */
function MemoryBudget() {
  const objects = useObjects();
  const eff = objects.status === "ok" ? (objects.data.effective?.memory_limit_bytes as number | undefined) : undefined;
  const [mib, setMib] = useState<string | null>(null);
  const value = mib ?? (eff ? String(Math.round(eff / (1 << 20))) : "512");
  const n = Number(value);
  const ok = Number.isInteger(n) && n >= 64 && n <= 65536;
  return (
    <Section title="Memory budget">
      <Loaded res={objects} what="the memory budget" route="/api/v1/observations/objects">
        {(o) => (
          <>
            <KV rows={[["Observation Store budget (published or configured)", <Mono>{eff ? bytes(eff) : "default 512 MiB"}</Mono>]]} />
            <ObjectState objects={o} kind="memory_budget" label="memory budget" />
            <div className="rule-grid">
              <TextField label="Observation Store memory budget (MiB)" value={value} onChange={setMib} type="number" hint="64 MiB to 64 GiB; DuckDB memory_limit" />
            </div>
            {!ok && (
              <p className="notice notice-bad" role="alert">
                The budget must be a whole number of MiB from 64 to 65536.
              </p>
            )}
            <Publish route="/api/v1/observations/memory-budget" label="memory budget" body={{ observation_memory_limit_bytes: n * (1 << 20) }} disabled={!ok} onPublished={objects.reload} />
          </>
        )}
      </Loaded>
    </Section>
  );
}

function ObservationStore() {
  const res = useResource<ObsStatus>("/api/v1/observations/status");
  return (
    <Section title="Observation Store">
      <Loaded res={res} what="the observation store" route="/api/v1/observations/status">
        {(s) =>
          !s.enabled ? (
            <p className="empty">Observation is disabled.</p>
          ) : (
            <>
              <KV
                rows={[
                  ["Backend", s.store ? <Mono>{s.store.backend}</Mono> : <StateLabel tone="bad">{s.store_error ?? "unavailable"}</StateLabel>],
                  ["Size", s.store ? <Mono>{bytes(s.store.bytes)} in {s.store.files} files</Mono> : "none"],
                  ["Rows written", <Mono>{Object.entries(s.store?.rows_written ?? {}).map(([k, v]) => `${k} ${compact(v)}`).join(", ") || "none"}</Mono>],
                  ["Retention", <Mono>{s.retention}</Mono>],
                  ["Dropped", <Mono>{Object.entries(s.collector?.drops ?? {}).map(([k, v]) => `${k} ${compact(v)}`).join(", ") || "none"}</Mono>],
                  [
                    "Degradation stage",
                    s.degradation ? (
                      <>
                        <StateLabel tone={s.degradation.stage === 0 ? "ok" : "warn"}>{s.degradation.name}</StateLabel>
                        {s.degradation.reason && <span className="muted small"> {s.degradation.reason}</span>}
                      </>
                    ) : (
                      "not reported"
                    ),
                  ],
                ]}
              />
              {s.collector && <Meter label="Collector queue" used={s.collector.queue_depth} budget={s.collector.queue_capacity} />}
            </>
          )
        }
      </Loaded>
    </Section>
  );
}

interface QuotaLevel {
  name: string;
  bytes: number;
  limit_bytes: number;
  percent: number;
  warning: boolean;
  measured_at: string;
  error?: string;
}

/** Storage quota levels the Health & Safety Monitor reports (FR-9.15, CP-26). */
function Quotas() {
  const res = useResource<{ quotas?: QuotaLevel[] }>("/api/v1/health/status");
  return (
    <Section title="Storage quotas">
      <Loaded res={res} what="the quota levels" route="/api/v1/health/status">
        {(h) => (
          <DataTable
            caption="Storage quotas"
            rows={h.quotas ?? []}
            rowKey={(q) => q.name}
            initialSort="pct"
            initialDir="desc"
            empty="No store has a quota."
            columns={[
              { key: "name", label: "Store", sort: (q) => q.name, render: (q) => <Mono>{q.name}</Mono> },
              { key: "used", label: "Used", sort: (q) => q.bytes, render: (q) => <Mono>{bytes(q.bytes)}</Mono>, className: "num" },
              { key: "limit", label: "Quota", sort: (q) => q.limit_bytes, render: (q) => <Mono>{bytes(q.limit_bytes)}</Mono>, className: "num" },
              {
                key: "pct",
                label: "Percent of quota",
                sort: (q) => q.percent,
                render: (q) => <StateLabel tone={q.warning ? "warn" : "ok"}>{`${q.percent.toFixed(1)}%`}</StateLabel>,
                className: "num",
              },
              { key: "at", label: "Measured", sort: (q) => q.measured_at, render: (q) => (q.error ? <StateLabel tone="bad">{q.error}</StateLabel> : <Time value={q.measured_at} />) },
            ]}
          />
        )}
      </Loaded>
    </Section>
  );
}

function Backups() {
  const res = useResource<{ dir: string; backups: Backup[] }>("/api/v1/backup");
  const perm = usePerm();
  const [mode, setMode] = useState("passphrase");
  const [secret, setSecret] = useState("");
  const take = useAction<{ path: string; sha256: string; size: number }>();
  return (
    <Section title="Backups">
      <Loaded res={res} what="backups" route="/api/v1/backup">
        {(d) => (
          <>
            <p className="small">
              Backups are written to <Mono>{d.dir}</Mono>. Last result:{" "}
              {d.backups[0] ? <StateLabel tone={d.backups[0].result === "ok" ? "ok" : "bad"}>{d.backups[0].result}</StateLabel> : <span className="muted">no backup yet</span>}
            </p>
            <DataTable
              caption="Backups"
              rows={d.backups}
              rowKey={(b) => b.path}
              initialSort="created"
              initialDir="desc"
              empty="No backup has been taken. Take one below or with smcpctl backup."
              columns={[
                { key: "created", label: "Taken", sort: (b) => b.created_at, render: (b) => <Time value={b.created_at} /> },
                { key: "result", label: "Result", sort: (b) => b.result, render: (b) => <StateLabel tone={b.result === "ok" ? "ok" : "bad"}>{b.result}</StateLabel> },
                { key: "size", label: "Size", sort: (b) => b.size, render: (b) => <Mono>{bytes(b.size)}</Mono>, className: "num" },
                { key: "components", label: "Components", render: (b) => b.components.join(", ") },
                { key: "sha", label: "SHA-256", render: (b) => <Mono>{b.sha256.slice(0, 12)}</Mono> },
              ]}
            />
          </>
        )}
      </Loaded>
      {perm.can("POST /api/v1/backup") && (
        <form
          className="inline-form"
          aria-label="Take a backup"
          onSubmit={(e) => {
            e.preventDefault();
            const v = secret;
            setSecret("");
            void take.run(() => post("/api/v1/backup", mode === "passphrase" ? { passphrase: v } : { recipients: v.split(/[\s,]+/).filter(Boolean) }), res.reload);
          }}
        >
          <SelectField label="Encrypt to" value={mode} onChange={setMode} options={[["passphrase", "a passphrase"], ["recipients", "age recipients"]]} />
          {mode === "passphrase" ? (
            <TextField label="Passphrase" value={secret} onChange={setSecret} type="password" autoComplete="new-password" required />
          ) : (
            <TextField label="Recipients (age1…)" value={secret} onChange={setSecret} mono required />
          )}
          <button type="submit" className="btn-primary" disabled={take.busy || !secret}>
            {take.busy ? "Taking backup" : "Take a backup now"}
          </button>
        </form>
      )}
      <p className="small">A backup briefly stops tool calls while it drains in-flight calls, then resumes.</p>
      {take.error && <ErrorBlock error={take.error} doing="the backup" />}
      {take.result && <Done>Backup written: {take.result.path} ({bytes(take.result.size)}).</Done>}
    </Section>
  );
}

function Keys() {
  const res = useResource<Record<string, unknown>>("/api/v1/keys");
  const perm = usePerm();
  const rotate = useAction<Record<string, unknown>>();
  const cert = (v: unknown): ReactNode => {
    const c = v as { subject?: string; not_after?: string; sha256?: string } | undefined;
    return c ? <><Mono>{c.subject}</Mono>, until <Time value={c.not_after} /></> : <span className="muted">none</span>;
  };
  return (
    <Section title="Keys">
      <Loaded res={res} what="the key inventory" route="/api/v1/keys">
        {(k) => (
          <KV
            rows={[
              ["Server CA", cert(k.server_ca)],
              ["Listener certificate", cert(k.listener_certificate)],
              ["CA rotation", k.ca_rotation ? <Mono>{JSON.stringify(k.ca_rotation)}</Mono> : "none in progress"],
              ["Renewal due", <>{k.ca_due ? <StateLabel tone="warn">CA due</StateLabel> : "CA not due"}; {k.listener_due ? <StateLabel tone="warn">listener due</StateLabel> : "listener not due"}</>],
              ["Evidence public key", <Mono>{String(k.evidence_public_key ?? "").slice(0, 24)}</Mono>],
              ["Installation", <Mono>{String(k.installation_id ?? "")}</Mono>],
            ]}
          />
        )}
      </Loaded>
      {perm.can("POST /api/v1/keys/rotate") && (
        <div className="filter-actions">
          <button type="button" disabled={rotate.busy} onClick={() => void rotate.run(() => post("/api/v1/keys/rotate", { kind: "tls" }), res.reload)}>
            Rotate the listener certificate
          </button>
          <button type="button" disabled={rotate.busy} onClick={() => void rotate.run(() => post("/api/v1/keys/rotate", { kind: "evidence" }), res.reload)}>
            Rotate the evidence key
          </button>
        </div>
      )}
      {rotate.error && <ErrorBlock error={rotate.error} doing="the rotation" />}
      {rotate.result && <Done>Rotated: {String(rotate.result.kind)}.</Done>}
    </Section>
  );
}

export function DataServer() {
  const perm = usePerm();
  return (
    <>
      <PageHeader code="G-08" title="Data server and memory">
        <p>Memory use against budget, store sizes, queue use, degradation stage, quota levels, backups and keys.</p>
      </PageHeader>
      <Help>
        <p>
          The Data Server (graph mirror and Observation Store) is optional: enforcement never waits for it, and when it is full or down, observations are
          dropped and counted rather than slowing calls. The Observation Store memory budget is published here and takes effect at the next start of smcpd; the graph memory budget is set in the [graph] table. Backups are encrypted with
          age; keep the passphrase or identity elsewhere.
        </p>
      </Help>
      {perm.can("GET /api/v1/graph/status") && <Graph />}
      {perm.can("GET /api/v1/observations/status") && <ObservationStore />}
      {perm.can("GET /api/v1/observations/objects") && <MemoryBudget />}
      {perm.can("GET /api/v1/health/status") && <Quotas />}
      {perm.can("GET /api/v1/backup") && <Backups />}
      {perm.can("GET /api/v1/keys") && <Keys />}
    </>
  );
}
