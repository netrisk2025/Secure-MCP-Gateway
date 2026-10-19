// G-09 Research campaigns & export (FR-8.17): create a campaign with a
// scope built from lists (no free-text scope), submit, approve, reject,
// stop and expire it, export its dataset, download the files and read the
// data dictionary of each dataset. Routes: /api/v1/research/*,
// /api/v1/observations/parameters and /aggregate (for scope lists).
import { useEffect, useState, type ReactNode } from "react";
import { download, getText, post } from "../api";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Link, match, navigate, useLocation } from "../router";
import { CheckList, Crumbs, DataTable, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, ShortId, StateLabel, TextField, Time, bytes, compact, useAction, type Tone } from "../ui";
import type { Parameter } from "./Observations";

interface Campaign {
  id: string;
  name: string;
  purpose?: string;
  state: string;
  scope: { principals?: string[]; servers?: string[]; tools?: string[]; templates?: string[] };
  parameters: string[];
  sampling: number;
  start: string;
  end: string;
  quota_bytes: number;
  used_bytes: number;
  records: number;
  raw_export_grant: boolean;
  created_by: string;
  created_at: string;
  history: { from: string; to: string; at: string; by: string; reason?: string }[];
}

interface Manifest {
  dataset_id: string;
  created_at: string;
  created_by: string;
  format: string;
  campaign: { id: string; name: string } | null;
  rows: number;
  columns: string[];
  catalog_version: string;
  pseudonymization?: { function: string; key: string };
  files: { name: string; bytes: number; sha256: string }[];
  time_range?: { first: string; last: string };
}

const tone = (s: string): Tone => (s === "active" ? "ok" : s === "submitted" || s === "approved" ? "pending" : s === "expired" ? "bad" : "neutral");

/** Values seen in stored observations for a column, for scope lists. */
function useObserved(column: string): string[] {
  const res = useResource<{ rows: { group: Record<string, string> }[] }>(`/api/v1/observations/aggregate?feature=request_bytes&group_by=${column}&from=2160h`, { live: false });
  return res.status === "ok" ? (res.data.rows ?? []).map((r) => r.group[column] ?? "").filter(Boolean).sort() : [];
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function NewCampaign() {
  const { query } = useLocation();
  const cat = useResource<{ parameters: Parameter[] }>("/api/v1/observations/parameters", { live: false });
  const principals = useObserved("principal_id");
  const servers = useObserved("server_id");
  const tools = useObserved("tool_name");
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState("");
  const [scope, setScope] = useState<{ principals: string[]; servers: string[]; tools: string[] }>({ principals: [], servers: [], tools: [] });
  const [params, setParams] = useState<string[]>(() => (query.get("parameters") ?? "").split(",").filter(Boolean));
  const [sampling, setSampling] = useState("1");
  const [start, setStart] = useState(() => iso(new Date(Date.now() + 60_000)));
  const [end, setEnd] = useState(() => iso(new Date(Date.now() + 86_400_000)));
  const [quota, setQuota] = useState("50000000");
  const [grant, setGrant] = useState(false);
  const create = useAction<Campaign>();
  useEffect(() => {
    if (cat.status === "ok" && params.length === 0) setParams(cat.data.parameters.filter((p) => p.selected).map((p) => p.name));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cat.status]);
  const names = cat.status === "ok" ? cat.data.parameters.filter((p) => grant || p.sensitivity !== "S3").map((p) => p.name) : [];
  return (
    <>
      <Crumbs items={[["Research campaigns", "/research"], ["New campaign", null]]} />
      <PageHeader code="G-09" title="New research campaign">
        <p>A time-boxed capture with its own scope and parameters. It is created as a draft and needs approval by a Policy Author or Administrator.</p>
      </PageHeader>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const sc = Object.fromEntries(Object.entries(scope).filter(([, v]) => v.length));
          void create.run(
            () =>
              post("/api/v1/research/campaigns", {
                name: name.trim(),
                purpose: purpose.trim(),
                scope: sc,
                parameters: params,
                sampling: Number(sampling),
                start,
                end,
                quota_bytes: Number(quota),
                raw_export_grant: grant,
              }),
            (c) => navigate(`/research/campaigns/${c.id}`),
          );
        }}
      >
        <Section title="Campaign">
          <div className="rule-grid">
            <TextField label="Name" value={name} onChange={setName} required />
            <TextField label="Purpose" value={purpose} onChange={setPurpose} />
            <TextField label="Sampling (0 to 1)" value={sampling} onChange={setSampling} type="number" />
            <TextField label="Storage quota (bytes)" value={quota} onChange={setQuota} type="number" hint={bytes(Number(quota))} />
            <TextField label="Start (RFC 3339)" value={start} onChange={setStart} mono />
            <TextField label="End (RFC 3339)" value={end} onChange={setEnd} mono />
          </div>
          <label className="check">
            <input type="checkbox" checked={grant} onChange={(e) => setGrant(e.target.checked)} />
            Request the raw export grant (allows S3 parameters; needs approval)
          </label>
        </Section>
        <Section title="Scope">
          <p className="small">Choose from principals, servers and tools seen in stored observations. Leave a list empty to include all.</p>
          <CheckList legend="Principals" options={principals} value={scope.principals} onChange={(v) => setScope({ ...scope, principals: v })} />
          <CheckList legend="Servers" options={servers} value={scope.servers} onChange={(v) => setScope({ ...scope, servers: v })} />
          <CheckList legend="Tools" options={tools} value={scope.tools} onChange={(v) => setScope({ ...scope, tools: v })} />
        </Section>
        <Section title={`Parameters (${params.length})`}>
          <Loaded res={cat} what="the Parameter Catalog" route="/api/v1/observations/parameters">
            {() => <CheckList legend="Parameters to capture" options={names} value={params} onChange={setParams} />}
          </Loaded>
        </Section>
        {create.error && <ErrorBlock error={create.error} doing="the campaign" />}
        <button type="submit" className="btn-primary" disabled={create.busy || !name.trim() || params.length === 0}>
          Create draft campaign
        </button>
      </form>
    </>
  );
}

const transitions: Record<string, [string, string][]> = {
  draft: [["submit", "Submit for approval"]],
  submitted: [
    ["approve", "Approve"],
    ["reject", "Reject (back to draft)"],
  ],
  approved: [["expire", "Expire"]],
  active: [["stop", "Stop now"]],
  completed: [["expire", "Expire"]],
  exported: [["expire", "Expire"]],
};

function Dictionary({ id }: { id: string }) {
  const [rows, setRows] = useState<Record<string, unknown>[] | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    getText(`/api/v1/research/exports/${encodeURIComponent(id)}/files/dictionary.json`).then(
      (t) => {
        try {
          const v = JSON.parse(t) as unknown;
          const list = Array.isArray(v) ? v : ((v as { columns?: unknown[] }).columns ?? Object.entries(v as object).map(([k, x]) => ({ column: k, ...(x as object) })));
          setRows(list as Record<string, unknown>[]);
        } catch (e) {
          setError(String(e));
        }
      },
      (e: unknown) => setError(String((e as Error).message)),
    );
  }, [id]);
  if (error) return <p className="notice notice-bad">The data dictionary could not be read: {error}</p>;
  if (!rows) return <p className="loading">Loading the data dictionary</p>;
  const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))].slice(0, 7);
  return (
    <DataTable
      caption="Data dictionary"
      rows={rows.map((r, i) => ({ r, i }))}
      rowKey={(x) => String(x.i)}
      empty="The dictionary lists no column."
      columns={keys.map((k) => ({
        key: k,
        label: k.replace(/_/g, " "),
        sort: (x: { r: Record<string, unknown> }) => String(x.r[k] ?? ""),
        render: (x: { r: Record<string, unknown> }) => {
          const v = x.r[k];
          return typeof v === "string" && v.length > 60 ? <span className="clamp">{v}</span> : <Mono>{v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v)}</Mono>;
        },
      }))}
    />
  );
}

function ExportView({ m }: { m: Manifest }) {
  const dl = useAction();
  return (
    <>
      <KV
        rows={[
          ["Dataset", <Mono>{m.dataset_id}</Mono>],
          ["Format", m.format],
          ["Rows", <Mono>{compact(m.rows)}</Mono>],
          ["Columns", <Mono>{m.columns.length}</Mono>],
          ["Created", <><Time value={m.created_at} /> by <Mono>{m.created_by}</Mono></>],
          ["Time range", m.time_range ? <><Time value={m.time_range.first} /> to <Time value={m.time_range.last} /></> : <span className="muted">no records</span>],
          ["Pseudonymization", m.pseudonymization ? <Mono>{m.pseudonymization.function}</Mono> : "none"],
          ["Catalog version", <Mono>{m.catalog_version}</Mono>],
        ]}
      />
      <h3 className="sub">Files</h3>
      <DataTable
        caption="Export files"
        rows={m.files}
        rowKey={(f) => f.name}
        empty=""
        columns={[
          { key: "n", label: "File", render: (f) => <Mono>{f.name}</Mono> },
          { key: "b", label: "Size", render: (f) => <Mono>{bytes(f.bytes)}</Mono>, className: "num" },
          { key: "s", label: "SHA-256", render: (f) => <Mono>{f.sha256.slice(0, 16)}</Mono> },
          {
            key: "d",
            label: "Download",
            render: (f) => (
              <button type="button" className="link" onClick={() => void dl.run(() => download(`/api/v1/research/exports/${encodeURIComponent(m.dataset_id)}/files/${encodeURIComponent(f.name)}`, f.name))}>
                Download {f.name}
              </button>
            ),
          },
        ]}
      />
      {dl.error && <ErrorBlock error={dl.error} doing="the download" />}
      <h3 className="sub">Data dictionary</h3>
      <Dictionary id={m.dataset_id} />
    </>
  );
}

function CampaignDetail({ id }: { id: string }) {
  const res = useResource<Campaign>(`/api/v1/research/campaigns/${encodeURIComponent(id)}`);
  const perm = usePerm();
  const act = useAction<Campaign>();
  const exp = useAction<Manifest>();
  const [format, setFormat] = useState("csv");
  const [reason, setReason] = useState("");
  const can = (a: string) => perm.can("POST /api/v1/research/campaigns/{id}/{action}") && (perm.role !== "researcher" || a === "submit" || a === "stop");
  return (
    <>
      <Crumbs items={[["Research campaigns", "/research"], [`Campaign ${id.slice(0, 8)}`, null]]} />
      <Loaded res={res} what="the campaign" route="/api/v1/research/campaigns/{id}">
        {(c) => (
          <>
            <PageHeader code="G-09" title={`Campaign ${c.name}`}>
              <p>{c.purpose || "No purpose given."}</p>
            </PageHeader>
            <Section title="Campaign">
              <KV
                rows={[
                  ["State", <StateLabel tone={tone(c.state)}>{c.state}</StateLabel>],
                  ["Window", <><Time value={c.start} /> to <Time value={c.end} /></>],
                  ["Scope", <Mono>{Object.entries(c.scope).map(([k, v]) => `${k}: ${(v ?? []).join(" ")}`).join("; ") || "everything"}</Mono>],
                  ["Parameters", <Mono>{c.parameters.join(" ")}</Mono>],
                  ["Sampling", <Mono>{c.sampling}</Mono>],
                  ["Records / storage", <Mono>{compact(c.records)} records, {bytes(c.used_bytes)} of {bytes(c.quota_bytes)}</Mono>],
                  ["Raw export grant", c.raw_export_grant ? <StateLabel tone="warn">requested</StateLabel> : "no"],
                  ["Created", <><Time value={c.created_at} /> by <Mono>{c.created_by}</Mono></>],
                ]}
              />
              {(transitions[c.state] ?? []).some(([a]) => can(a)) && (
                <div className="filter-actions">
                  <TextField label="Reason (optional, recorded)" value={reason} onChange={setReason} />
                  {(transitions[c.state] ?? [])
                    .filter(([a]) => can(a))
                    .map(([a, label]) => (
                      <button
                        key={a}
                        type="button"
                        className={a === "approve" || a === "submit" ? "btn-primary" : undefined}
                        disabled={act.busy}
                        onClick={() => void act.run(() => post(`/api/v1/research/campaigns/${encodeURIComponent(c.id)}/${a}`, reason.trim() ? { reason: reason.trim() } : {}), res.reload)}
                      >
                        {label}
                      </button>
                    ))}
                </div>
              )}
              {act.error && <ErrorBlock error={act.error} />}
              {act.result && <Done>The campaign is now {act.result.state}.</Done>}
              <h3 className="sub">History</h3>
              <DataTable
                caption="Campaign history"
                rows={c.history}
                rowKey={(h) => h.at + h.to}
                empty=""
                columns={[
                  { key: "at", label: "Time", render: (h) => <Time value={h.at} /> },
                  { key: "t", label: "Change", render: (h) => <Mono>{h.from || "(new)"} to {h.to}</Mono> },
                  { key: "by", label: "By", render: (h) => <Mono>{h.by}</Mono> },
                  { key: "r", label: "Reason", render: (h) => h.reason ?? "" },
                ]}
              />
            </Section>
            {["active", "completed", "exported"].includes(c.state) && perm.can("POST /api/v1/research/exports") && (
              <Section title="Export the dataset">
                <form
                  className="inline-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void exp.run(() => post("/api/v1/research/exports", { format, campaign_id: c.id }), res.reload);
                  }}
                >
                  <SelectField label="Format" value={format} onChange={setFormat} options={[["csv", "CSV"], ["jsonl", "JSON Lines"], ["parquet", "Parquet (DuckDB store)"], ["graphml", "GraphML behavior model"]]} />
                  <button type="submit" className="btn-primary" disabled={exp.busy}>
                    {exp.busy ? "Exporting" : "Export"}
                  </button>
                </form>
                {exp.error && <ErrorBlock error={exp.error} doing="the export" />}
                {exp.result && <ExportView m={exp.result} />}
              </Section>
            )}
          </>
        )}
      </Loaded>
    </>
  );
}

function ExportDetail({ id }: { id: string }) {
  const res = useResource<Manifest>(`/api/v1/research/exports/${encodeURIComponent(id)}`, { live: false });
  return (
    <>
      <Crumbs items={[["Research campaigns", "/research"], [`Dataset ${id.slice(0, 8)}`, null]]} />
      <PageHeader code="G-09" title="Dataset export">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Section title="Manifest">
        <Loaded res={res} what="the export" route="/api/v1/research/exports/{id}">
          {(m) => <ExportView m={m} />}
        </Loaded>
      </Section>
    </>
  );
}

function Lists() {
  const perm = usePerm();
  const camps = useResource<{ campaigns: Campaign[] }>(perm.can("GET /api/v1/research/campaigns") ? "/api/v1/research/campaigns" : null);
  const exps = useResource<{ exports: Manifest[] }>(perm.can("GET /api/v1/research/exports") ? "/api/v1/research/exports" : null);
  return (
    <>
      {perm.can("GET /api/v1/research/campaigns") && (
        <Section title="Campaigns" actions={perm.can("POST /api/v1/research/campaigns") && <Link to="/research/new">New campaign</Link>}>
          <Loaded res={camps} what="campaigns" route="/api/v1/research/campaigns">
            {(d) => (
              <DataTable
                caption="Research campaigns"
                rows={d.campaigns}
                rowKey={(c) => c.id}
                initialSort="created"
                initialDir="desc"
                empty="No campaign exists. Create one to capture more than the default observation policy for a bounded time."
                columns={[
                  { key: "name", label: "Campaign", sort: (c) => c.name, render: (c) => <Link to={`/research/campaigns/${c.id}`}>{c.name}</Link> },
                  { key: "state", label: "State", sort: (c) => c.state, render: (c) => <StateLabel tone={tone(c.state)}>{c.state}</StateLabel> },
                  { key: "window", label: "Window", sort: (c) => c.start, render: (c) => <><Time value={c.start} /> to <Time value={c.end} /></> },
                  { key: "records", label: "Records", sort: (c) => c.records, render: (c) => <Mono>{compact(c.records)}</Mono>, className: "num" },
                  { key: "params", label: "Parameters", render: (c) => <Mono>{c.parameters.length}</Mono>, className: "num" },
                  { key: "created", label: "Created", sort: (c) => c.created_at, render: (c) => <Time value={c.created_at} /> },
                ]}
              />
            )}
          </Loaded>
        </Section>
      )}
      {perm.can("GET /api/v1/research/exports") && (
        <Section title="Dataset exports">
          <Loaded res={exps} what="exports" route="/api/v1/research/exports">
            {(d) => (
              <DataTable
                caption="Dataset exports"
                rows={d.exports}
                rowKey={(m) => m.dataset_id}
                initialSort="created"
                initialDir="desc"
                empty="No dataset has been exported. Export one from an active or completed campaign."
                columns={[
                  { key: "id", label: "Dataset", render: (m) => <Link to={`/research/exports/${m.dataset_id}`}><ShortId id={m.dataset_id} /></Link> },
                  { key: "format", label: "Format", sort: (m) => m.format, render: (m) => m.format },
                  { key: "rows", label: "Rows", sort: (m) => m.rows, render: (m) => <Mono>{compact(m.rows)}</Mono>, className: "num" },
                  { key: "campaign", label: "Campaign", render: (m) => (m.campaign ? <Link to={`/research/campaigns/${m.campaign.id}`}>{m.campaign.name}</Link> : <span className="muted">time range</span>) },
                  { key: "created", label: "Created", sort: (m) => m.created_at, render: (m) => <Time value={m.created_at} /> },
                ]}
              />
            )}
          </Loaded>
        </Section>
      )}
    </>
  );
}

export function Research({ path }: { path: string }): ReactNode {
  const c = match("/research/campaigns/:id", path);
  if (c?.id) return <CampaignDetail id={c.id} />;
  const e = match("/research/exports/:id", path);
  if (e?.id) return <ExportDetail id={e.id} />;
  if (path === "/research/new") return <NewCampaign />;
  return (
    <>
      <PageHeader code="G-09" title="Research campaigns">
        <p>Capture campaigns, their approval, dataset exports and the data dictionary of each dataset.</p>
      </PageHeader>
      <Help>
        <p>
          A campaign captures a chosen parameter set within a scope for a bounded time and storage quota. Researchers create and submit campaigns; a Policy
          Author or Administrator approves them. Between start and end the campaign is active; afterwards its dataset can be exported. S2 values are
          pseudonymized per dataset with a keyed hash, and S3 parameters need the raw export grant.
        </p>
      </Help>
      <Lists />
    </>
  );
}
