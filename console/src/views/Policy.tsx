// G-02 Policy studio (FR-8.4, FR-8.27): published revisions with their
// documents and effective permissions, rollback, a draft editor with
// structured editors for every object of the policy document (Framework
// Profiles, Session Allow templates and their rules) plus the full
// document as JSON, validation, diff against the active revision,
// simulation from the journal and publication; the filter test
// workbench; and the Secret Use Policy editor (SecretUse.tsx). Routes: /api/v1/policy* (E-05) and /api/v1/filters* (E-09,
// E-11).
import { useEffect, useId, useMemo, useState, type ReactNode } from "react";
import { asApiError, get, post, type ApiError } from "../api";
import { useResource } from "../data";
import { helpFor, policyHelp } from "../policyhelp";
import { Can, usePerm } from "../perm";
import { Link, match, navigate, useLocation } from "../router";
import { SecretUse } from "./SecretUse";
import {
  CheckList,
  Crumbs,
  DataTable,
  Dialog,
  Done,
  ErrorBlock,
  Help,
  JsonBlock,
  KV,
  Loaded,
  Loading,
  Mono,
  PageHeader,
  Section,
  SelectField,
  ShortId,
  StateLabel,
  TextField,
  Time,
  useAction,
  type Column,
} from "../ui";

interface RevisionRecord {
  revision: string;
  sequence: number;
  parent?: string;
  digest: string;
  schema_version: string;
  evaluator_version: string;
  actor: string;
  published_at: string;
  simulation_ref?: string;
  key_id: string;
  origin: string;
  rollback_of?: string;
}

interface PolicyStatus {
  active?: RevisionRecord;
  active_error?: string;
  loaded_revision: string;
  fault: string;
  key_id: string;
  revisions: number;
  damaged?: string[];
}

export interface Rule {
  id: string;
  server: string;
  tools: string[];
  effect?: "permit" | "deny";
  approval?: boolean;
  calls_per_minute?: number;
  calls_per_session?: number;
  side_effect?: string;
  source_trust?: string;
  filters?: string[];
}

export interface Template {
  description?: string;
  rules: Rule[];
  calls_per_minute?: number;
  calls_per_session?: number;
  taint_action?: string;
}

export interface Profile {
  templates: string[];
  default_template: string;
  calls_per_minute?: number;
  remote_allowed?: string[];
}

export interface PolicyDoc {
  revision: string;
  framework_profiles: Record<string, Profile>;
  templates: Record<string, Template>;
  [k: string]: unknown;
}

interface DiffResult {
  from: string;
  to: string;
  same: boolean;
  widening: boolean;
  changes: { kind: string; template?: string; profile?: string; server?: string; tool?: string; rule?: string; before?: string; after?: string }[];
}

interface SimResult {
  simulation_id: string;
  source: string;
  active_revision: string;
  candidate_revision: string;
  fixtures: number;
  changed: number;
  counts: Record<string, number>;
  results: {
    index: number;
    fixture: Record<string, string>;
    active: { outcome: string; reason_code: string; decisive_rules?: string[] };
    candidate: { outcome: string; reason_code: string; decisive_rules?: string[] };
    change: string;
  }[];
}

function Tabs({ current }: { current: "revisions" | "draft" | "filters" | "secret-use" }) {
  const perm = usePerm();
  return (
    <nav aria-label="Policy studio sections" className="tabs">
      <Link to="/policy" aria-current={current === "revisions" ? "page" : undefined}>
        Revisions
      </Link>
      {perm.can("POST /api/v1/policy/validate") && (
        <Link to="/policy/draft" aria-current={current === "draft" ? "page" : undefined}>
          Draft
        </Link>
      )}
      {perm.can("POST /api/v1/filters/scan") && (
        <Link to="/policy/filters" aria-current={current === "filters" ? "page" : undefined}>
          Filter workbench
        </Link>
      )}
      {perm.can("GET /api/v1/secret-use-policy") && (
        <Link to="/policy/secret-use" aria-current={current === "secret-use" ? "page" : undefined}>
          Secret Use Policy
        </Link>
      )}
    </nav>
  );
}

function RollbackDialog({ to, open, onClose }: { to: string; open: boolean; onClose: () => void }) {
  const [rev, setRev] = useState("");
  const act = useAction<{ record: RevisionRecord }>();
  return (
    <Dialog open={open} onClose={onClose} title={`Roll back to ${to}`}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void act.run(() => post("/api/v1/policy/rollback", rev.trim() ? { to, revision: rev.trim() } : { to }), () => {
            onClose();
            navigate("/policy");
          });
        }}
      >
        <p>
          Publishes the content of <Mono>{to}</Mono> as a new revision and activates it. Sessions see the new catalog at once. The rollback is recorded in the
          journal.
        </p>
        <TextField label="New revision ID (optional)" value={rev} onChange={setRev} mono hint={`Default ${to}-rb<n>.`} />
        {act.error && <ErrorBlock error={act.error} />}
        <div className="dialog-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={act.busy}>
            Roll back
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function Revisions() {
  const status = useResource<PolicyStatus>("/api/v1/policy");
  const list = useResource<{ active: string; revisions: RevisionRecord[] }>("/api/v1/policy/revisions");
  const [rollback, setRollback] = useState("");
  const perm = usePerm();
  const columns: Column<RevisionRecord & { active: boolean }>[] = [
    { key: "rev", label: "Revision", sort: (r) => r.revision, render: (r) => <Link to={`/policy/revisions/${encodeURIComponent(r.revision)}`}><Mono>{r.revision}</Mono></Link> },
    { key: "seq", label: "Sequence", sort: (r) => r.sequence, render: (r) => <Mono>{r.sequence}</Mono>, className: "num" },
    { key: "state", label: "State", sort: (r) => String(r.active), render: (r) => (r.active ? <StateLabel tone="ok">active</StateLabel> : <span className="muted">published</span>) },
    { key: "origin", label: "Origin", sort: (r) => r.origin, render: (r) => <>{r.origin}{r.rollback_of && <> of <Mono>{r.rollback_of}</Mono></>}</> },
    { key: "actor", label: "Actor", sort: (r) => r.actor, render: (r) => <Mono>{r.actor}</Mono> },
    { key: "time", label: "Published", sort: (r) => r.published_at, render: (r) => <Time value={r.published_at} /> },
    { key: "digest", label: "Digest", render: (r) => <ShortId id={r.digest} /> },
    {
      key: "act",
      label: "Action",
      render: (r) =>
        !r.active && perm.can("POST /api/v1/policy/rollback") ? (
          <button type="button" className="link" onClick={() => setRollback(r.revision)}>
            Roll back to {r.revision}
          </button>
        ) : (
          <span className="muted">none</span>
        ),
    },
  ];
  return (
    <>
      <Section title="Policy store">
        <Loaded res={status} what="the policy store" route="/api/v1/policy">
          {(s) => (
            <KV
              rows={[
                ["Active revision", s.active ? <Link to={`/policy/revisions/${encodeURIComponent(s.active.revision)}`}><Mono>{s.active.revision}</Mono></Link> : <StateLabel tone="bad">{s.active_error ?? "none"}</StateLabel>],
                ["Fault", s.fault ? <StateLabel tone="bad">{s.fault}</StateLabel> : "none"],
                ["Published revisions", <Mono>{s.revisions}</Mono>],
                ["Signing key", <Mono>{s.key_id}</Mono>],
                ...(s.damaged?.length ? ([["Damaged files", <Mono>{s.damaged.join(" ")}</Mono>]] as [string, ReactNode][]) : []),
              ]}
            />
          )}
        </Loaded>
      </Section>
      <Section title="Revisions" actions={<Can route="POST /api/v1/policy/validate"><Link to="/policy/draft">Start a draft from the active revision</Link></Can>}>
        <Loaded res={list} what="policy revisions" route="/api/v1/policy/revisions">
          {(d) => (
            <DataTable
              caption="Policy revisions"
              columns={columns}
              rows={d.revisions.map((r) => ({ ...r, active: r.revision === d.active }))}
              rowKey={(r) => r.revision}
              initialSort="seq"
              initialDir="desc"
              empty="No revision is published. The policy file is imported as the first revision when smcpd starts."
            />
          )}
        </Loaded>
      </Section>
      <RollbackDialog to={rollback} open={!!rollback} onClose={() => setRollback("")} />
    </>
  );
}

function DiffTable({ d }: { d: DiffResult }) {
  if (d.same) return <p className="empty">No difference: the documents grant the same authority.</p>;
  return (
    <>
      <p>
        {d.changes.length} change{d.changes.length === 1 ? "" : "s"} from <Mono>{d.from}</Mono> to <Mono>{d.to}</Mono>.{" "}
        {d.widening ? <StateLabel tone="warn">widens authority</StateLabel> : <StateLabel tone="ok">does not widen authority</StateLabel>}
      </p>
      <DataTable
        caption="Policy changes"
        rows={d.changes.map((c, i) => ({ ...c, i }))}
        rowKey={(c) => String(c.i)}
        empty=""
        rowClass={(c) => (c.kind.endsWith("_added") && c.kind.startsWith("grant") ? "row-bad" : undefined)}
        columns={[
          { key: "kind", label: "Change", sort: (c) => c.kind, render: (c) => <Mono>{c.kind}</Mono> },
          { key: "where", label: "Template or profile", sort: (c) => c.template ?? c.profile ?? "", render: (c) => <Mono>{c.template ?? c.profile ?? ""}</Mono> },
          { key: "tool", label: "Server / tool", render: (c) => (c.server ? <Mono>{c.server}/{c.tool}</Mono> : <span className="muted">none</span>) },
          { key: "rule", label: "Rule", render: (c) => <Mono>{c.rule ?? ""}</Mono> },
          { key: "before", label: "Before", render: (c) => <Mono>{c.before ?? ""}</Mono> },
          { key: "after", label: "After", render: (c) => <Mono>{c.after ?? ""}</Mono> },
        ]}
      />
    </>
  );
}

function Permissions({ rev, templates }: { rev: string; templates: string[] }) {
  const [t, setT] = useState(templates[0] ?? "");
  const res = useResource<{ permissions: { server: string; tool: string; rule: string; approval: boolean; side_effect?: string; filters?: string[] }[] }>(
    t ? `/api/v1/policy/revisions/${encodeURIComponent(rev)}/permissions?template=${encodeURIComponent(t)}` : null,
    { live: false },
  );
  if (templates.length === 0) return <p className="empty">This revision has no template.</p>;
  return (
    <>
      <SelectField label="Template" value={t} onChange={setT} options={templates} />
      <Loaded res={res} what="effective permissions" route="/api/v1/policy/revisions/{id}/permissions">
        {(d) => (
          <DataTable
            caption={`Effective permissions of ${t}`}
            rows={d.permissions}
            rowKey={(p) => p.server + "/" + p.tool}
            initialSort="tool"
            empty="This template permits no tool after deny rules."
            columns={[
              { key: "tool", label: "Server / tool", sort: (p) => p.server + p.tool, render: (p) => <Mono>{p.server}/{p.tool}</Mono> },
              { key: "rule", label: "Rule", sort: (p) => p.rule, render: (p) => <Mono>{p.rule}</Mono> },
              { key: "approval", label: "Approval", sort: (p) => String(p.approval), render: (p) => (p.approval ? <StateLabel tone="pending">required</StateLabel> : "no") },
              { key: "se", label: "Side effect", render: (p) => p.side_effect ?? <span className="muted">unset</span> },
              { key: "filters", label: "Filters", render: (p) => (p.filters?.length ? <Mono>{p.filters.join(" ")}</Mono> : <span className="muted">mandatory only</span>) },
            ]}
          />
        )}
      </Loaded>
    </>
  );
}

function RevisionDetail({ id }: { id: string }) {
  const res = useResource<{ record: RevisionRecord; active: boolean; document: PolicyDoc }>(`/api/v1/policy/revisions/${encodeURIComponent(id)}`, { live: false });
  const diff = useAction<DiffResult>();
  const [rollback, setRollback] = useState(false);
  const perm = usePerm();
  return (
    <>
      <Crumbs items={[["Policy studio", "/policy"], [`Revision ${id}`, null]]} />
      <PageHeader code="G-02" title={`Policy revision ${id}`}>
        <p>The signed record and canonical document of one published revision.</p>
      </PageHeader>
      <Loaded res={res} what="the revision" route="/api/v1/policy/revisions/{id}">
        {(r) => (
          <>
            <Section
              title="Record"
              actions={
                <>
                  {perm.can("POST /api/v1/policy/validate") && <Link to={`/policy/draft?from=${encodeURIComponent(r.record.revision)}`}>Open as draft</Link>}
                  {perm.can("POST /api/v1/policy/diff") && !r.active && (
                    <button type="button" onClick={() => void diff.run(() => post("/api/v1/policy/diff", { to: r.record.revision }))}>
                      Diff against the active revision
                    </button>
                  )}
                  {perm.can("POST /api/v1/policy/rollback") && !r.active && (
                    <button type="button" onClick={() => setRollback(true)}>
                      Roll back to this revision
                    </button>
                  )}
                </>
              }
            >
              <KV
                rows={[
                  ["State", r.active ? <StateLabel tone="ok">active</StateLabel> : "published"],
                  ["Sequence", <Mono>{r.record.sequence}</Mono>],
                  ["Parent", r.record.parent ? <Link to={`/policy/revisions/${encodeURIComponent(r.record.parent)}`}><Mono>{r.record.parent}</Mono></Link> : <span className="muted">none</span>],
                  ["Origin", <>{r.record.origin}{r.record.rollback_of && <> of <Mono>{r.record.rollback_of}</Mono></>}</>],
                  ["Actor", <Mono>{r.record.actor}</Mono>],
                  ["Published", <Time value={r.record.published_at} />],
                  ["Digest", <Mono>{r.record.digest}</Mono>],
                  ["Simulation", r.record.simulation_ref ? <Mono>{r.record.simulation_ref}</Mono> : <span className="muted">none</span>],
                  ["Signing key", <Mono>{r.record.key_id}</Mono>],
                  ["Schema and evaluator", <Mono>{r.record.schema_version} / {r.record.evaluator_version}</Mono>],
                ]}
              />
              {diff.error && <ErrorBlock error={diff.error} />}
              {diff.result && <DiffTable d={diff.result} />}
            </Section>
            <Section title="Effective permissions">
              <Permissions rev={r.record.revision} templates={Object.keys(r.document.templates ?? {}).sort()} />
            </Section>
            <Section title="Document">
              <JsonBlock value={r.document} label="Canonical document" />
            </Section>
            <RollbackDialog to={r.record.revision} open={rollback} onClose={() => setRollback(false)} />
          </>
        )}
      </Loaded>
    </>
  );
}

const numOrUndef = (s: string): number | undefined => (s.trim() === "" ? undefined : Number(s));

function clean<T extends object>(o: T): T {
  const out = { ...o } as Record<string, unknown>;
  for (const k of Object.keys(out)) if (out[k] === undefined || out[k] === "" || (Array.isArray(out[k]) && (out[k] as unknown[]).length === 0 && k === "filters")) delete out[k];
  return out as T;
}

function RuleRow({ rule, onChange, onRemove, servers, filterIds }: { rule: Rule; onChange: (r: Rule) => void; onRemove: () => void; servers: string[]; filterIds: string[] }) {
  const deny = rule.effect === "deny";
  const hid = useId();
  return (
    <fieldset className="rule">
      <legend>
        Rule <span className="mono">{rule.id || "(no ID)"}</span>
      </legend>
      <div className="rule-grid">
        <TextField label="Rule ID" value={rule.id} onChange={(v) => onChange({ ...rule, id: v })} mono required hint={helpFor("templates[].rules[].id")} />
        <SelectField label="Effect" value={rule.effect ?? "permit"} onChange={(v) => onChange(clean({ ...rule, effect: v === "deny" ? "deny" : undefined, ...(v === "deny" ? { approval: undefined, filters: undefined, calls_per_minute: undefined, calls_per_session: undefined, side_effect: undefined, source_trust: undefined } : {}) }))} options={["permit", "deny"]} hint={helpFor("templates[].rules[].effect")} />
        <SelectField label="Server" value={rule.server} onChange={(v) => onChange({ ...rule, server: v })} options={[...new Set([rule.server, ...servers])].filter(Boolean)} hint={helpFor("templates[].rules[].server")} />
        <TextField label="Tools (space separated)" value={rule.tools.join(" ")} onChange={(v) => onChange({ ...rule, tools: v.split(/[\s,]+/).filter(Boolean) })} mono hint={helpFor("templates[].rules[].tools")} />
        {!deny && (
          <>
            <div className="field">
              <label className="check">
                <input type="checkbox" checked={!!rule.approval} onChange={(e) => onChange(clean({ ...rule, approval: e.target.checked || undefined }))} aria-describedby={`${hid}-approval`} />
                Requires approval
              </label>
              <span className="hint" id={`${hid}-approval`}>
                {helpFor("templates[].rules[].approval")}
              </span>
            </div>
            <TextField label="Calls per minute" value={rule.calls_per_minute?.toString() ?? ""} onChange={(v) => onChange(clean({ ...rule, calls_per_minute: numOrUndef(v) }))} type="number" hint={helpFor("templates[].rules[].calls_per_minute")} />
            <TextField label="Calls per session" value={rule.calls_per_session?.toString() ?? ""} onChange={(v) => onChange(clean({ ...rule, calls_per_session: numOrUndef(v) }))} type="number" hint={helpFor("templates[].rules[].calls_per_session")} />
            <SelectField label="Side effect" value={rule.side_effect ?? ""} onChange={(v) => onChange(clean({ ...rule, side_effect: v || undefined }))} options={[["", "from manifest"], "read", "write", "external", "execute"]} hint={helpFor("templates[].rules[].side_effect")} />
            <SelectField label="Source trust" value={rule.source_trust ?? ""} onChange={(v) => onChange(clean({ ...rule, source_trust: v || undefined }))} options={[["", "from manifest"], "trusted", "untrusted"]} hint={helpFor("templates[].rules[].source_trust")} />
          </>
        )}
      </div>
      {!deny && <CheckList legend="Optional filters that must run" options={filterIds} value={rule.filters ?? []} onChange={(v) => onChange(clean({ ...rule, filters: v }))} hint={helpFor("templates[].rules[].filters")} />}
      <button type="button" className="link" onClick={onRemove}>
        Remove rule {rule.id}
      </button>
    </fieldset>
  );
}

function TemplateEditor({ name, t, onChange, onRemove, servers, filterIds }: { name: string; t: Template; onChange: (t: Template) => void; onRemove: () => void; servers: string[]; filterIds: string[] }) {
  return (
    <details className="editor" open>
      <summary>
        Template{" "}<span className="mono">{name}</span>{" "}({t.rules.length} rule{t.rules.length === 1 ? "" : "s"})
      </summary>
      <div className="editor-body">
        <div className="rule-grid">
          <TextField label="Description" value={t.description ?? ""} onChange={(v) => onChange(clean({ ...t, description: v || undefined }))} hint={helpFor("templates[].description")} />
          <TextField label="Calls per minute" value={t.calls_per_minute?.toString() ?? ""} onChange={(v) => onChange(clean({ ...t, calls_per_minute: numOrUndef(v) }))} type="number" hint={helpFor("templates[].calls_per_minute")} />
          <TextField label="Calls per session" value={t.calls_per_session?.toString() ?? ""} onChange={(v) => onChange(clean({ ...t, calls_per_session: numOrUndef(v) }))} type="number" hint={helpFor("templates[].calls_per_session")} />
          <SelectField label="Tainted session, non-read tools" value={t.taint_action ?? "approve"} onChange={(v) => onChange(clean({ ...t, taint_action: v === "approve" ? undefined : v }))} options={["approve", "deny"]} hint={helpFor("templates[].taint_action")} />
        </div>
        {t.rules.map((r, i) => (
          <RuleRow
            key={i}
            rule={r}
            servers={servers}
            filterIds={filterIds}
            onChange={(nr) => onChange({ ...t, rules: t.rules.map((x, j) => (j === i ? nr : x)) })}
            onRemove={() => onChange({ ...t, rules: t.rules.filter((_, j) => j !== i) })}
          />
        ))}
        <div className="filter-actions">
          <button type="button" onClick={() => onChange({ ...t, rules: [...t.rules, { id: `rule-${t.rules.length + 1}`, server: servers[0] ?? "", tools: [] }] })}>
            Add a rule to {name}
          </button>
          <button type="button" className="link" onClick={onRemove}>
            Remove template {name}
          </button>
        </div>
      </div>
    </details>
  );
}

function ProfileEditor({ name, p, templates, onChange, onRemove }: { name: string; p: Profile; templates: string[]; onChange: (p: Profile) => void; onRemove: () => void }) {
  return (
    <details className="editor" open>
      <summary>
        Framework Profile{" "}<span className="mono">{name}</span>
      </summary>
      <div className="editor-body">
        <CheckList legend="Templates sessions of this profile may use" options={templates} value={p.templates} onChange={(v) => onChange({ ...p, templates: v, default_template: v.includes(p.default_template) ? p.default_template : (v[0] ?? ""), ...(p.remote_allowed ? { remote_allowed: p.remote_allowed.filter((x) => v.includes(x)) } : {}) })} hint={helpFor("framework_profiles[].templates")} />
        <div className="rule-grid">
          <SelectField label="Default template" value={p.default_template} onChange={(v) => onChange({ ...p, default_template: v })} options={p.templates.length ? p.templates : [""]} hint={helpFor("framework_profiles[].default_template")} />
          <TextField label="Calls per minute" value={p.calls_per_minute?.toString() ?? ""} onChange={(v) => onChange(clean({ ...p, calls_per_minute: numOrUndef(v) }))} type="number" hint={helpFor("framework_profiles[].calls_per_minute")} />
        </div>
        <button type="button" className="link" onClick={onRemove}>
          Remove profile {name}
        </button>
      </div>
    </details>
  );
}

function AddNamed({ label, onAdd, taken, help }: { label: string; onAdd: (name: string) => void; taken: string[]; help: string }) {
  const [v, setV] = useState("");
  const bad = v.trim() !== "" && taken.includes(v.trim());
  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (v.trim() && !bad) {
          onAdd(v.trim());
          setV("");
        }
      }}
    >
      <TextField label={label} value={v} onChange={setV} mono hint={bad ? "That name is in use." : help} />
      <button type="submit" disabled={!v.trim() || bad}>
        Add
      </button>
    </form>
  );
}

function Draft() {
  const { query } = useLocation();
  const from = query.get("from") ?? "active";
  const perm = usePerm();
  const [doc, setDoc] = useState<PolicyDoc | null>(null);
  const [base, setBase] = useState<{ revision: string; active: string } | null>(null);
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  const [json, setJson] = useState("");
  const [jsonError, setJsonError] = useState("");
  const servers = useResource<{ servers: { alias: string }[] }>(perm.can("GET /api/v1/servers") ? "/api/v1/servers" : null, { live: false });
  const filterList = useResource<{ request: string[]; response: string[]; mandatory_request: string[]; mandatory_response: string[] }>(perm.can("GET /api/v1/filters") ? "/api/v1/filters" : null, { live: false });
  const validate = useAction<{ valid: boolean; summary: Record<string, unknown> }>();
  const diff = useAction<DiffResult>();
  const sim = useAction<SimResult>();
  const publish = useAction<{ record: RevisionRecord; created: boolean; changed: boolean }>();
  const [validated, setValidated] = useState("");
  const [limit, setLimit] = useState("1000");
  useEffect(() => {
    const ctl = new AbortController();
    Promise.all([
      get<{ record: RevisionRecord; document: PolicyDoc }>(`/api/v1/policy/revisions/${encodeURIComponent(from)}`, ctl.signal),
      get<{ active: string }>("/api/v1/policy/revisions", ctl.signal),
    ]).then(
      ([r, l]) => {
        const d = structuredClone(r.document);
        if (d.revision === l.active || d.revision === r.record.revision) d.revision = nextRevision(d.revision);
        setDoc(d);
        setBase({ revision: r.record.revision, active: l.active });
      },
      (e: unknown) => {
        if ((e as Error).name !== "AbortError") setLoadError(asApiError(e));
      },
    );
    return () => ctl.abort();
  }, [from]);
  const text = useMemo(() => (doc ? JSON.stringify(doc, null, 2) : ""), [doc]);
  useEffect(() => {
    setJson(text);
    setJsonError("");
  }, [text]);
  if (loadError) return <ErrorBlock error={loadError} what="the base revision" />;
  if (!doc || !base) return <Loading what="the base revision" />;
  const update = (d: PolicyDoc) => {
    setDoc(d);
    setValidated("");
    sim.reset();
    publish.reset();
  };
  const serverNames = servers.status === "ok" ? servers.data.servers.map((s) => s.alias) : [];
  // Optional filters: those not mandatory in their stage.
  const filterIds =
    filterList.status === "ok"
      ? [...new Set([...filterList.data.request.filter((f) => !filterList.data.mandatory_request.includes(f)), ...filterList.data.response.filter((f) => !filterList.data.mandatory_response.includes(f))])]
      : [];
  const templates = Object.keys(doc.templates).sort();
  const profiles = Object.keys(doc.framework_profiles).sort();
  const current = text;
  const applyJson = () => {
    try {
      const d = JSON.parse(json) as PolicyDoc;
      if (typeof d !== "object" || !d || typeof d.templates !== "object" || typeof d.framework_profiles !== "object") throw new Error("the document needs framework_profiles and templates objects");
      update(d);
      setJsonError("");
    } catch (e) {
      setJsonError(String((e as Error).message));
    }
  };
  return (
    <>
      <p className="tab-lede">
        Draft based on <Mono>{base.revision}</Mono>; the active revision is <Mono>{base.active}</Mono>. The draft is kept in this page only until you publish it.
      </p>
      <Section title="Document">
        <TextField label="Revision ID of the draft" value={doc.revision} onChange={(v) => update({ ...doc, revision: v })} mono required hint={helpFor("revision")} />
      </Section>
      <Section title="Session Allow templates">
        {templates.map((name) => (
          <TemplateEditor
            key={name}
            name={name}
            t={doc.templates[name]!}
            servers={serverNames}
            filterIds={filterIds}
            onChange={(t) => update({ ...doc, templates: { ...doc.templates, [name]: t } })}
            onRemove={() => {
              const ts = { ...doc.templates };
              delete ts[name];
              const fp = Object.fromEntries(Object.entries(doc.framework_profiles).map(([k, p]) => [k, { ...p, templates: p.templates.filter((x) => x !== name), default_template: p.default_template === name ? "" : p.default_template, ...(p.remote_allowed ? { remote_allowed: p.remote_allowed.filter((x) => x !== name) } : {}) }]));
              update({ ...doc, templates: ts, framework_profiles: fp });
            }}
          />
        ))}
        <AddNamed label="New template name" help={helpFor("templates")} taken={templates} onAdd={(n) => update({ ...doc, templates: { ...doc.templates, [n]: { rules: [] } } })} />
      </Section>
      <Section title="Framework Profiles">
        {profiles.map((name) => (
          <ProfileEditor
            key={name}
            name={name}
            p={doc.framework_profiles[name]!}
            templates={templates}
            onChange={(p) => update({ ...doc, framework_profiles: { ...doc.framework_profiles, [name]: p } })}
            onRemove={() => {
              const fp = { ...doc.framework_profiles };
              delete fp[name];
              update({ ...doc, framework_profiles: fp });
            }}
          />
        ))}
        <AddNamed label="New profile name" help={helpFor("framework_profiles")} taken={profiles} onAdd={(n) => update({ ...doc, framework_profiles: { ...doc.framework_profiles, [n]: { templates: [], default_template: "" } } })} />
      </Section>
      <Section title="Field reference">
        <details className="editor">
          <summary>Help for every policy field</summary>
          <dl className="kv" data-testid="policy-field-help">
            {Object.entries(policyHelp).map(([path, text]) => (
              <div key={path} className="kv-row">
                <dt>
                  <Mono>{path}</Mono>
                </dt>
                <dd>{text}</dd>
              </div>
            ))}
          </dl>
        </details>
      </Section>
      <Section title="Full document (JSON)">
        <details className="editor">
          <summary>Edit the whole document as JSON</summary>
          <div className="field field-wide">
            <label htmlFor="policy-json">Policy document</label>
            <textarea id="policy-json" className="mono" rows={18} value={json} onChange={(e) => setJson(e.target.value)} spellCheck={false} />
          </div>
          {jsonError && (
            <p className="notice notice-bad" role="alert">
              The JSON could not be applied: {jsonError}
            </p>
          )}
          <button type="button" onClick={applyJson} disabled={json === current}>
            Apply JSON to the draft
          </button>
        </details>
      </Section>
      <Section title="Check and publish">
        <div className="filter-actions">
          <button type="button" disabled={validate.busy} onClick={() => void validate.run(() => post("/api/v1/policy/validate", { document: doc }), () => setValidated(current))}>
            Validate
          </button>
          <Can route="POST /api/v1/policy/diff">
            <button type="button" disabled={diff.busy} onClick={() => void diff.run(() => post("/api/v1/policy/diff", { document: doc, from: base.active }))}>
              Diff against the active revision
            </button>
          </Can>
          <Can route="POST /api/v1/policy/simulate">
            <TextField label="Journal calls to replay" value={limit} onChange={setLimit} type="number" />
            <button type="button" disabled={sim.busy} onClick={() => void sim.run(() => post("/api/v1/policy/simulate", { document: doc, limit: Number(limit) || 1000 }))}>
              {sim.busy ? "Simulating" : "Simulate"}
            </button>
          </Can>
        </div>
        {validate.error && <ErrorBlock error={validate.error} doing="validation" />}
        {validate.result && validated === current && (
          <Done>
            Valid: revision <Mono>{String(validate.result.summary.revision)}</Mono>, {String(validate.result.summary.templates)} templates, {String(validate.result.summary.rules)} rules,{" "}
            {String(validate.result.summary.grants)} grants.
          </Done>
        )}
        {diff.error && <ErrorBlock error={diff.error} doing="the diff" />}
        {diff.result && (
          <>
            <h3 className="sub">Diff against {base.active}</h3>
            <DiffTable d={diff.result} />
          </>
        )}
        {sim.error && <ErrorBlock error={sim.error} doing="the simulation" />}
        {sim.result && <SimTable s={sim.result} />}
        <Can route="POST /api/v1/policy/revisions">
          <div className="action-row">
            <div>
              <strong>Publish {doc.revision}</strong>
              <p className="small">
                Signs, stores and activates the draft with parent <Mono>{base.active}</Mono>
                {sim.result ? <> and simulation <Mono>{sim.result.simulation_id}</Mono></> : null}. Validate first; publication refuses if another revision became
                active meanwhile.
              </p>
            </div>
            <button
              type="button"
              className="btn-primary"
              disabled={publish.busy || validated !== current}
              onClick={() =>
                void publish.run(
                  () => post("/api/v1/policy/revisions", { document: doc, parent: base.active, ...(sim.result ? { simulation_ref: sim.result.simulation_id } : {}) }),
                  (r) => navigate(`/policy/revisions/${encodeURIComponent(r.record.revision)}`),
                )
              }
            >
              Publish
            </button>
            {publish.error && <ErrorBlock error={publish.error} doing="publication" />}
          </div>
        </Can>
      </Section>
    </>
  );
}

function nextRevision(r: string): string {
  const m = /^(.*?)(\d+)$/.exec(r);
  return m ? `${m[1]}${Number(m[2]) + 1}` : `${r}-2`;
}

function SimTable({ s }: { s: SimResult }) {
  return (
    <>
      <h3 className="sub">Simulation {s.simulation_id.slice(0, 8)}</h3>
      <p>
        {s.fixtures} call{s.fixtures === 1 ? "" : "s"} replayed from the {s.source}; {s.changed} decision{s.changed === 1 ? "" : "s"} change.{" "}
        {Object.entries(s.counts)
          .map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`)
          .join(", ")}
        .
      </p>
      <DataTable
        caption="Changed decisions"
        rows={s.results}
        rowKey={(r) => String(r.index)}
        empty="No replayed decision changes under the draft."
        columns={[
          { key: "i", label: "Call", sort: (r) => r.index, render: (r) => <Mono>{r.index}</Mono>, className: "num" },
          { key: "t", label: "Template", sort: (r) => r.fixture.template ?? "", render: (r) => <Mono>{r.fixture.template}</Mono> },
          { key: "tool", label: "Server / tool", render: (r) => <Mono>{r.fixture.server}/{r.fixture.tool}</Mono> },
          { key: "a", label: "Active", render: (r) => <><StateLabel tone={r.active.outcome === "permit" ? "ok" : "bad"}>{r.active.outcome}</StateLabel> <Mono>{r.active.reason_code}</Mono></> },
          { key: "c", label: "Draft", render: (r) => <><StateLabel tone={r.candidate.outcome === "permit" ? "ok" : "bad"}>{r.candidate.outcome}</StateLabel> <Mono>{r.candidate.reason_code}</Mono></> },
          { key: "change", label: "Change", sort: (r) => r.change, render: (r) => <Mono>{r.change}</Mono> },
        ]}
      />
    </>
  );
}

interface ScanReport {
  stage: string;
  disposition: string;
  reasonCode?: string;
  finding?: string;
  filters: { id: string; version: string; action: string; reasonCode?: string; durationUs: number; findings?: { rule?: string; class?: string; action?: string; path?: string; [k: string]: unknown }[] }[];
  output?: string;
  inputBytes: number;
  durationUs: number;
}

const samples: Record<string, string> = {
  response: "Contact jane@example.com or call (555) 234-5678 about the invoice.",
  request: '{"path": "../../etc/passwd", "url": "http://169.254.169.254/latest"}',
};

function Workbench() {
  const list = useResource<{ request: string[]; response: string[]; mandatory_request: string[]; mandatory_response: string[]; rule_sets: { id: string; version: string; rules: number; in_effect: boolean; digest: string }[] }>("/api/v1/filters", { live: false });
  const [stage, setStage] = useState<"request" | "response">("response");
  const [sel, setSel] = useState<string[] | null>(null);
  const [input, setInput] = useState(samples.response!);
  const scan = useAction<ScanReport>();
  return (
    <Loaded res={list} what="the filters" route="/api/v1/filters">
      {(l) => {
        const ids = stage === "request" ? l.request : l.response;
        const chosen = sel ?? ids;
        return (
          <>
            <Section title="Test a filter profile">
              <p>Runs the selected filters, with this Gateway's rule sets and limits, on text you supply. Nothing is sent to a server and nothing is journaled.</p>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void scan.run(() => post("/api/v1/filters/scan", { stage, filters: chosen, input }));
                }}
              >
                <SelectField
                  label="Stage"
                  value={stage}
                  onChange={(v) => {
                    const s = v === "request" ? "request" : "response";
                    setStage(s);
                    setSel(null);
                    setInput(samples[s]!);
                    scan.reset();
                  }}
                  options={[["response", "Response (tool result text)"], ["request", "Request (tool arguments)"]]}
                />
                <CheckList legend="Filters to run" options={ids} value={chosen} onChange={setSel} />
                <div className="field field-wide">
                  <label htmlFor="scan-input">{stage === "request" ? "Arguments (JSON object, or text)" : "Result text"}</label>
                  <textarea id="scan-input" className="mono" rows={5} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} />
                </div>
                <button type="submit" className="btn-primary" disabled={scan.busy || chosen.length === 0}>
                  {scan.busy ? "Running" : "Run filters"}
                </button>
              </form>
              {scan.error && <ErrorBlock error={scan.error} doing="the scan" />}
            </Section>
            {scan.result && <ScanResult r={scan.result} />}
            <Section title="Rule sets">
              <DataTable
                caption="Rule sets"
                rows={l.rule_sets}
                rowKey={(r) => r.id + r.version}
                initialSort="id"
                empty="No rule set is loaded."
                columns={[
                  { key: "id", label: "Rule set", sort: (r) => r.id, render: (r) => <Mono>{r.id}</Mono> },
                  { key: "v", label: "Version", sort: (r) => r.version, render: (r) => <Mono>{r.version}</Mono> },
                  { key: "n", label: "Rules", sort: (r) => r.rules, render: (r) => <Mono>{r.rules}</Mono>, className: "num" },
                  { key: "e", label: "In effect", sort: (r) => String(r.in_effect), render: (r) => (r.in_effect ? <StateLabel tone="ok">in effect</StateLabel> : <span className="muted">available</span>) },
                  { key: "d", label: "Digest", render: (r) => <ShortId id={r.digest} /> },
                ]}
              />
            </Section>
          </>
        );
      }}
    </Loaded>
  );
}

function ScanResult({ r }: { r: ScanReport }) {
  const tone = r.disposition === "block" || r.disposition === "withhold" ? "bad" : r.disposition === "release" ? "ok" : "warn";
  return (
    <Section title="Result">
      <KV
        rows={[
          ["Disposition", <StateLabel tone={tone}>{r.disposition}</StateLabel>],
          ...(r.reasonCode ? ([["Reason code", <Mono>{r.reasonCode}</Mono>]] as [string, ReactNode][]) : []),
          ...(r.finding ? ([["Finding", r.finding]] as [string, ReactNode][]) : []),
          ["Input", <Mono>{r.inputBytes} bytes</Mono>],
          ["Chain time", <Mono>{r.durationUs} µs</Mono>],
        ]}
      />
      <DataTable
        caption="Filter runs"
        rows={r.filters}
        rowKey={(f) => f.id}
        empty="No filter ran."
        columns={[
          { key: "id", label: "Filter", render: (f) => <Mono>{f.id}</Mono> },
          { key: "v", label: "Version", render: (f) => <Mono>{f.version}</Mono> },
          { key: "a", label: "Action", sort: (f) => f.action, render: (f) => <StateLabel tone={f.action === "pass" ? "neutral" : f.action === "block" ? "bad" : "warn"}>{f.action}</StateLabel> },
          { key: "m", label: "Matches", sort: (f) => f.findings?.length ?? 0, render: (f) => <Mono>{f.findings?.length ?? 0}</Mono>, className: "num" },
          { key: "rules", label: "Rules matched", render: (f) => <Mono>{[...new Set((f.findings ?? []).map((x) => String(x.rule ?? x.class ?? "")))].join(" ")}</Mono> },
          { key: "t", label: "Time (µs)", sort: (f) => f.durationUs, render: (f) => <Mono>{f.durationUs}</Mono>, className: "num" },
          { key: "rc", label: "Reason", render: (f) => <Mono>{f.reasonCode ?? ""}</Mono> },
        ]}
      />
      {r.output !== undefined && <JsonBlock value={r.output} label="Transformed output" />}
    </Section>
  );
}

export function Policy({ path }: { path: string }) {
  const m = match("/policy/revisions/:id", path);
  if (m?.id) return <RevisionDetail id={m.id} />;
  const tab = path === "/policy/draft" ? "draft" : path === "/policy/filters" ? "filters" : path === "/policy/secret-use" ? "secret-use" : "revisions";
  return (
    <>
      <PageHeader code="G-02" title="Policy studio">
        <p>Session Allow templates and Framework Profiles: drafts, diffs, simulation against recent calls, publication and rollback, and filter tests; the Secret Use Policy.</p>
      </PageHeader>
      <Help>
        <p>
          A <strong>Framework Profile</strong> lists the templates a kind of harness may use. A <strong>Session Allow template</strong> holds permit and deny
          rules; a deny rule wins over every permit for the same tool. <strong>Approval</strong> holds a call for a person's decision. Optional{" "}
          <strong>filters</strong> run in addition to the mandatory ones. Validate a draft before you publish it; the diff marks changes that widen authority,
          and the simulation replays recent calls from the journal under the draft. Published revisions are signed and never change; a rollback publishes an
          earlier content under a new ID. The filter workbench runs request or response filters on text you supply. See docs/policy-reference.md.
        </p>
      </Help>
      <Tabs current={tab} />
      {tab === "draft" ? <Draft /> : tab === "filters" ? <Workbench /> : tab === "secret-use" ? <SecretUse /> : <Revisions />}
    </>
  );
}
