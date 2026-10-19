// G-04 Observation & Parameter Workbench (FR-8.6 to FR-8.12): the Parameter
// Catalog grouped by capture point with search, description, unit,
// sensitivity and a cost indicator; the controls are generated from the
// catalog data, so a parameter added by a release appears without a
// console change; presets (the five of FR-8.8 plus saved ones); a cost
// preview of the selection; and up to 20 recent records shown with
// sensitivity masking. The selection is applied as the [observation]
// parameters key or used for a research campaign. Routes:
// /api/v1/observations/*.
import { ObjectState, Publish, useObjects } from "./objects";
import { useMemo, useState, type ReactNode } from "react";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { navigate } from "../router";
import { CheckList, DataTable, Done, Help, JsonBlock, KV, Loaded, Loading, Mono, PageHeader, Section, SelectField, StateLabel, TextField, bytes, compact } from "../ui";
import type { Catalog, PrincipalDirectory, ServerView } from "../types";

export interface Parameter {
  id: string;
  name: string;
  description: string;
  unit: string;
  data_type: string;
  sensitivity: string;
  capture_point: string;
  baselinable: boolean;
  selected: boolean;
  escalation: boolean;
  cost_class?: string;
  derivation?: string;
  source_element?: string;
}

/** Cost classes of the catalog (docs/parameters.json). */
export const costText: Record<string, string> = {
  C0: "counter or timestamp already on the hot path",
  C1: "per-call computation over metadata or structure",
  C2: "scan over argument or result content",
  C3: "stores a payload copy",
};

export interface ObsStatus {
  enabled: boolean;
  policy_id?: string;
  catalog_version?: string;
  scoring?: string;
  require_approval_band?: string;
  withhold_band?: string;
  /** Lowest band whose calls get capture escalation ("off": alert only). */
  escalate_capture_band?: string;
  /** Action in the uncharacterized state: record, escalate or approve. */
  uncharacterized?: string;
  sampling_rate?: number;
  /** Extra escalation parameters per band (FR-8.10). */
  escalation_bands?: Record<string, string[]> | null;
  /** Baselined features with their statistics options (FR-8.10). */
  features?: { name: string; kind: string; transform: { kind: string; lambda?: number }; robust?: boolean; sigma_floor: number }[];
  /** Observation Policy scope (FR-8.9). */
  scope?: Scope;
  parameters?: string[];
  escalation_parameters?: string[] | null;
  retention?: string;
  collector?: { assembled: number; captured: number; pending: number; queue_depth: number; queue_capacity: number; sessions: number; drops: Record<string, number> };
  baseline?: { contexts: number; characterized: number; learned: number; snapshots: number; promoted?: string };
  thresholds?: Record<string, number>;
  contexts?: string[];
  store?: { backend: string; dir: string; bytes: number; files: number; rows_written?: Record<string, number> };
  store_error?: string;
  /** Degradation stage of the observation path (FR-9.12). */
  degradation?: { stage: number; name: string; reason: string; backpressure: boolean };
}

/** Bytes per captured record a parameter adds, by data type (cost class). */
export function costOf(p: Parameter): number {
  switch (p.data_type) {
    case "boolean":
      return 1;
    case "integer":
    case "number":
    case "float":
      return 8;
    case "timestamp":
      return 8;
    case "object":
    case "array":
    case "json":
      return 96;
    default:
      return p.unit === "id" ? 36 : 24;
  }
}


type Preset = { name: string; pick: (p: Parameter) => boolean; builtin: boolean };

const builtin: Preset[] = [
  { name: "Minimal security floor", builtin: true, pick: (p) => p.sensitivity === "S0" && ["decision", "release", "session-establishment"].some((c) => p.capture_point.startsWith(c)) },
  { name: "Security standard", builtin: true, pick: (p) => (p.sensitivity === "S0" || p.sensitivity === "S1") && (p.cost_class ?? "C0") <= "C1" },
  { name: "Behavior characterization", builtin: true, pick: (p) => p.baselinable || p.unit === "id" },
  { name: "Performance profiling", builtin: true, pick: (p) => p.unit === "ms" || p.capture_point === "periodic" || p.unit === "id" },
  { name: "Research — full capture", builtin: true, pick: (p) => p.sensitivity !== "S3" },
];

const STORE = "smcp.console.presets";

function savedPresets(): Record<string, string[]> {
  try {
    return JSON.parse(localStorage.getItem(STORE) ?? "{}") as Record<string, string[]>;
  } catch {
    return {};
  }
}

function savePreset(name: string, ids: string[]): void {
  try {
    localStorage.setItem(STORE, JSON.stringify({ ...savedPresets(), [name]: ids }));
  } catch {
    // Storage blocked: the preset lasts until the page is left.
  }
}

const masked = new Set(["S2", "S3"]);

/** Whether a stored record falls within the draft's scope (FR-8.9, FR-8.12). */
function inScope(r: Record<string, unknown>, scope: Scope): boolean {
  const has = (list: string[] | undefined, v: unknown) => !list?.length || list.includes(String(v ?? ""));
  if (!has(scope.principals, r.principal_id) || !has(scope.frameworks, r.framework_type) || !has(scope.templates, r.session_template) || !has(scope.servers, r.server_id)) return false;
  return !scope.tools?.length || scope.tools.includes(`${String(r.server_id ?? "")}/${String(r.tool_name ?? "")}`);
}

/**
 * Up to 20 recent stored records as the draft would have recorded them
 * (FR-8.12): records outside the draft's scope are left out, the columns
 * are the draft's parameters in catalog order, S2 and S3
 * values are masked, and a parameter the policy in force did not capture
 * is marked as such (stored records cannot be derived again).
 */
function Preview({ selected, catalog, scope, inForce }: { selected: string[]; catalog: Parameter[]; scope: Scope; inForce?: string[] }) {
  const res = useResource<{ rows: Record<string, unknown>[] }>("/api/v1/observations?limit=200", { live: false });
  const byName = new Map(catalog.map((p) => [p.name, p]));
  const cols = catalog.filter((p) => selected.includes(p.name)).map((p) => p.name);
  const captured = new Set(inForce ?? []);
  return (
    <Loaded res={res} what="recent records" route="/api/v1/observations">
      {(d) =>
        cols.length === 0 ? (
          <p className="empty">Select parameters to preview them.</p>
        ) : (
          <DataTable
            caption="Recent records with the selected parameters"
            rows={(d.rows ?? [])
              .filter((r) => inScope(r, scope))
              .slice(-20)
              .map((r, i) => ({ r, i }))}
            rowKey={(x) => String(x.i)}
            empty="No stored record falls within the draft's scope. Records appear after tool calls when observation is enabled."
            initialSort="ts"
            initialDir="desc"
            columns={[
              // The record time is always shown and sortable, whatever the
              // selection (masked parameters do not sort).
              {
                key: "ts",
                label: "Time",
                sort: (x: { r: Record<string, unknown> }) => String(x.r.ts ?? ""),
                render: (x: { r: Record<string, unknown> }) => <Mono>{String(x.r.ts ?? "")}</Mono>,
              },
              ...cols.map((c) => ({
                key: c,
                label: c,
                sort: masked.has(byName.get(c)!.sensitivity)
                  ? undefined
                  : (x: { r: Record<string, unknown> }) => {
                      const v = x.r[c];
                      return typeof v === "number" ? v : v === null || v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v);
                    },
                render: (x: { r: Record<string, unknown> }) => {
                  const v = x.r[c];
                  if (masked.has(byName.get(c)!.sensitivity)) return <span className="muted">masked ({byName.get(c)!.sensitivity})</span>;
                  if (inForce && !captured.has(c) && (v === null || v === undefined)) return <span className="muted">not captured in force</span>;
                  if (v === null || v === undefined) return <span className="muted">null</span>;
                  const s = typeof v === "string" ? v : JSON.stringify(v);
                  return <Mono>{s.length > 40 ? s.slice(0, 39) + "…" : s}</Mono>;
                },
              })),
            ]}
          />
        )
      }
    </Loaded>
  );
}

/** Observation Policy scope: lists chosen from registered values (FR-8.9). */
export interface Scope {
  principals?: string[];
  frameworks?: string[];
  templates?: string[];
  servers?: string[];
  tools?: string[];
}

/** One baselined feature and its statistics options (FR-8.10). */
interface Feature {
  parameter: string;
  kind: string;
  transform: string;
  robust: boolean;
  sigma_floor: string;
}

const scopeKeys: [keyof Scope, string][] = [
  ["principals", "Principals"],
  ["frameworks", "Framework types"],
  ["templates", "Session templates"],
  ["servers", "Servers"],
  ["tools", "Tools"],
];

/** Builds the scope from lists of registered principals, framework types, templates, servers and tools; no free text (FR-8.9). */
function ScopeBuilder({ value, onChange }: { value: Scope; onChange: (v: Scope) => void }) {
  const perm = usePerm();
  const dir = useResource<PrincipalDirectory & { frameworks?: string[] }>(perm.can("GET /api/v1/principals") ? "/api/v1/principals" : null, { live: false });
  const cat = useResource<Catalog>(perm.can("GET /api/v1/catalog") ? "/api/v1/catalog" : null, { live: false });
  const srv = useResource<{ servers: ServerView[] }>(perm.can("GET /api/v1/servers") ? "/api/v1/servers" : null, { live: false });
  const uniq = (xs: string[]) => [...new Set(xs)].sort();
  const lists: Record<keyof Scope, string[]> = {
    principals: uniq(dir.data?.principals.map((p) => p.id) ?? []),
    frameworks: uniq(dir.data?.frameworks ?? dir.data?.principals.map((p) => p.framework) ?? []),
    templates: uniq(cat.data?.templates.map((t) => t.name) ?? []),
    servers: uniq(srv.data?.servers.map((s) => s.alias) ?? []),
    tools: uniq(cat.data?.templates.flatMap((t) => t.tools.map((x) => `${x.server}/${x.tool}`)) ?? []),
  };
  return (
    <div className="scope-builder">
      <p className="small">
        The policy samples and escalates only calls that match every list with a choice; an empty list matches all. Research campaigns keep their own scope.
      </p>
      {scopeKeys.map(([k, label]) => (
        <CheckList key={k} legend={label} options={lists[k]} value={value[k] ?? []} onChange={(v) => onChange({ ...value, [k]: v })} />
      ))}
    </div>
  );
}

const escBands = ["elevated", "abnormal", "critical"] as const;

/** Per-band escalation parameters (FR-8.10): parameters a band adds for its escalated calls and those of higher bands. */
function EscalationEditor({ catalog, selected, value, onChange }: { catalog: Parameter[]; selected: string[]; value: Record<string, string[]>; onChange: (v: Record<string, string[]>) => void }) {
  const rows = catalog.filter((p) => p.capture_point !== "periodic" && p.sensitivity !== "S3" && !selected.includes(p.name));
  const chosen = escBands.reduce((n, b) => n + (value[b]?.length ?? 0), 0);
  return (
    <details className="editor">
      <summary>Escalation parameters per band ({chosen} chosen)</summary>
      <p className="small">An escalated call records the policy's parameters plus those of its band and of every lower band. Parameters already selected above are not listed.</p>
      <DataTable
        caption="Escalation parameters per band"
        rows={rows}
        rowKey={(p) => p.name}
        initialSort="name"
        empty="Every per-call parameter is already selected."
        columns={[
          { key: "name", label: "Parameter", sort: (p) => p.name, render: (p) => <Mono>{p.name}</Mono> },
          { key: "sens", label: "Sensitivity", sort: (p) => p.sensitivity, render: (p) => p.sensitivity },
          ...escBands.map((b) => ({
            key: b,
            label: b,
            render: (p: Parameter) => (
              <input
                type="checkbox"
                aria-label={`${p.name} ${b}`}
                checked={value[b]?.includes(p.name) ?? false}
                onChange={(e) => onChange({ ...value, [b]: e.target.checked ? [...(value[b] ?? []), p.name] : (value[b] ?? []).filter((x) => x !== p.name) })}
              />
            ),
          })),
        ]}
      />
    </details>
  );
}

const transforms: [string, string][] = [
  ["none", "none"],
  ["log1p", "log1p"],
  ["box-cox(0.5)", "box-cox(0.5)"],
  ["box-cox(0)", "box-cox(0)"],
];

/** Baselined features and their statistics options (FR-8.10). */
function FeatureEditor({ catalog, value, onChange }: { catalog: Parameter[]; value: Feature[]; onChange: (v: Feature[]) => void }) {
  const numeric = catalog.filter((p) => p.baselinable && (p.data_type === "integer" || p.data_type === "number") && !value.some((f) => f.parameter === p.name));
  const [add, setAdd] = useState("");
  const set = (i: number, f: Partial<Feature>) => onChange(value.map((x, j) => (j === i ? { ...x, ...f } : x)));
  return (
    <details className="editor">
      <summary>Baselined features and statistics ({value.length})</summary>
      <DataTable
        caption="Baselined features"
        rows={value.map((f, i) => ({ f, i }))}
        rowKey={(r) => r.f.parameter}
        empty="No feature is baselined; add one below."
        columns={[
          { key: "p", label: "Feature", sort: (r) => r.f.parameter, render: (r) => <Mono>{r.f.parameter}</Mono> },
          { key: "k", label: "Kind", sort: (r) => r.f.kind, render: (r) => r.f.kind },
          {
            key: "t",
            label: "Transform",
            render: (r) =>
              r.f.kind === "categorical" ? (
                <span className="muted">none</span>
              ) : (
                <SelectField
                  label={`${r.f.parameter} transform`}
                  value={r.f.transform}
                  onChange={(v) => set(r.i, { transform: v })}
                  options={transforms.some((t) => t[0] === r.f.transform) ? transforms : [...transforms, [r.f.transform, r.f.transform]]}
                />
              ),
          },
          {
            key: "r",
            label: "Robust (median, MAD)",
            render: (r) => <input type="checkbox" aria-label={`${r.f.parameter} robust statistics`} checked={r.f.robust} onChange={(e) => set(r.i, { robust: e.target.checked })} />,
          },
          {
            key: "s",
            label: "σ floor",
            render: (r) => <TextField label={`${r.f.parameter} sigma floor`} value={r.f.sigma_floor} onChange={(v) => set(r.i, { sigma_floor: v })} type="number" />,
          },
          {
            key: "x",
            label: "Remove",
            render: (r) => (
              <button type="button" className="btn-quiet" onClick={() => onChange(value.filter((_, j) => j !== r.i))}>
                Remove {r.f.parameter}
              </button>
            ),
          },
        ]}
      />
      <div className="inline-form">
        <SelectField label="Add a numeric feature" value={add} onChange={setAdd} options={[["", "choose a parameter"], ...numeric.map((p): [string, string] => [p.name, p.name])]} />
        <button
          type="button"
          disabled={!add}
          onClick={() => {
            onChange([...value, { parameter: add, kind: "numeric", transform: "none", robust: false, sigma_floor: "" }]);
            setAdd("");
          }}
        >
          Add feature
        </button>
      </div>
    </details>
  );
}

const tfText = (t: { kind: string; lambda?: number }) => (t.kind === "box-cox" ? `box-cox(${t.lambda ?? 0})` : t.kind);

/** Baseline context dimensions the Observation Policy may key on. */
const contextDims = ["principal", "framework_type", "session_template", "end_user", "server", "server_revision", "tool", "hour", "weekday"];

function Workbench({ catalog, version, status }: { catalog: Parameter[]; version: string; status?: ObsStatus }) {
  const perm = usePerm();
  const objects = useObjects();
  const [policyId, setPolicyId] = useState(status?.policy_id ?? "default");
  const [sampling, setSampling] = useState(String(status?.sampling_rate ?? 0.1));
  const [contexts, setContexts] = useState<string[]>(status?.contexts?.length ? status.contexts : ["principal", "tool"]);
  const th = status?.thresholds ?? {};
  const [bandsText, setBandsText] = useState<[string, string, string]>([String(th.elevated ?? 2), String(th.abnormal ?? 3), String(th.critical ?? 4)]);
  const [scope, setScope] = useState<Scope>(status?.scope ?? {});
  const [escalation, setEscalation] = useState<Record<string, string[]>>(status?.escalation_bands ?? {});
  const [features, setFeatures] = useState<Feature[]>(() =>
    (status?.features ?? []).map((f) => ({ parameter: f.name, kind: f.kind, transform: tfText(f.transform), robust: !!f.robust, sigma_floor: String(f.sigma_floor) })),
  );
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string[]>(() => catalog.filter((p) => p.selected).map((p) => p.name));
  const [presetName, setPresetName] = useState("");
  const [saved, setSaved] = useState(savedPresets);
  const [note, setNote] = useState("");
  const [shown, setShown] = useState(false);
  const term = q.trim().toLowerCase();
  const match = (p: Parameter) => !term || [p.id, p.name, p.description, p.unit, p.capture_point].some((s) => s.toLowerCase().includes(term));
  const groups = useMemo(() => {
    const m = new Map<string, Parameter[]>();
    for (const p of catalog) if (match(p)) m.set(p.capture_point, [...(m.get(p.capture_point) ?? []), p]);
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog, term]);
  const chosen = catalog.filter((p) => sel.includes(p.name));
  const perRecord = chosen.reduce((n, p) => n + costOf(p), 0);
  const rate = status?.sampling_rate ?? 1;
  const assembled = status?.collector?.assembled ?? 0;
  const apply = (ids: string[], name: string) => {
    setSel(ids);
    setNote(`Applied preset ${name}: ${ids.length} parameters.`);
    setShown(false);
  };
  const presets: Preset[] = [...builtin, ...Object.keys(saved).map((n) => ({ name: n, builtin: false, pick: (p: Parameter) => saved[n]!.includes(p.name) }))];
  return (
    <>
      <Section title="Presets">
        <div className="preset-row">
          {presets.map((p) => (
            <button key={p.name} type="button" onClick={() => apply(catalog.filter(p.pick).map((x) => x.name), p.name)}>
              {p.name}
              {!p.builtin && " (saved)"}
            </button>
          ))}
          <button
            type="button"
            className="btn-quiet"
            onClick={() => {
              setSel([]);
              setNote("Cleared the selection.");
              setShown(false);
            }}
          >
            Clear the selection
          </button>
        </div>
        <form
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (!presetName.trim()) return;
            savePreset(presetName.trim(), sel);
            setSaved(savedPresets());
            setNote(`Saved the selection as preset ${presetName.trim()} in this browser.`);
            setPresetName("");
          }}
        >
          <TextField label="Save the selection as a preset" value={presetName} onChange={setPresetName} />
          <button type="submit" disabled={!presetName.trim()}>
            Save preset
          </button>
        </form>
        {note && <Done>{note}</Done>}
      </Section>
      <Section title={`Parameter Catalog ${version}: ${sel.length} of ${catalog.length} selected`}>
        <TextField label="Search parameters (name, description, unit, capture point)" value={q} onChange={setQ} />
        {groups.length === 0 && <p className="empty">No parameter matches "{q}".</p>}
        {groups.map(([group, ps]) => (
          <details key={group} className="editor" open={!!term || groups.length <= 3}>
            <summary>
              {group} ({ps.filter((p) => sel.includes(p.name)).length} of {ps.length} selected)
            </summary>
            <div className="params">
              <DataTable
                caption={`Parameters captured at ${group}`}
                rows={ps}
                rowKey={(p) => p.id}
                initialSort="id"
                empty=""
                columns={[
                  {
                    key: "capture",
                    label: "Capture",
                    sort: (p) => (sel.includes(p.name) ? 0 : 1),
                    render: (p) => (
                      <input
                        type="checkbox"
                        aria-label={`Capture ${p.name}`}
                        checked={sel.includes(p.name)}
                        onChange={(e) => setSel(e.target.checked ? [...sel, p.name] : sel.filter((x) => x !== p.name))}
                      />
                    ),
                  },
                  { key: "id", label: "ID", sort: (p) => p.id, className: "mono", render: (p) => p.id },
                  { key: "name", label: "Name", sort: (p) => p.name, className: "mono", render: (p) => p.name },
                  { key: "description", label: "Description", render: (p) => p.description },
                  { key: "unit", label: "Unit", sort: (p) => p.unit, className: "mono", render: (p) => p.unit },
                  {
                    key: "sensitivity",
                    label: "Sensitivity",
                    sort: (p) => p.sensitivity,
                    render: (p) => <StateLabel tone={p.sensitivity === "S0" || p.sensitivity === "S1" ? "neutral" : "warn"}>{p.sensitivity}</StateLabel>,
                  },
                  {
                    key: "cost",
                    label: "Cost class",
                    sort: (p) => p.cost_class ?? "",
                    render: (p) => (
                      <>
                        <span className="mono" title={costText[p.cost_class ?? ""] ?? ""}>
                          {p.cost_class ?? "none"}
                        </span>{" "}
                        <span className="muted small">{costText[p.cost_class ?? ""] ?? ""}</span>
                      </>
                    ),
                  },
                ]}
              />
            </div>
          </details>
        ))}
      </Section>
      <Section title="Cost preview">
        <KV
          rows={[
            ["Selected parameters", <Mono>{sel.length}</Mono>],
            ["Bytes per captured record (estimate)", <Mono>{perRecord} B</Mono>],
            ["Content scans (C2) and payload copies (C3)", <Mono>{chosen.filter((p) => p.cost_class === "C2").length} / {chosen.filter((p) => p.cost_class === "C3").length}</Mono>],
            ["Sampling rate in force", <Mono>{rate}</Mono>],
            ["Records assembled since start", <Mono>{compact(assembled)}</Mono>],
            ["Store growth at that volume", <Mono>{bytes(perRecord * assembled * rate)}</Mono>],
            ["S2 or S3 parameters", chosen.some((p) => masked.has(p.sensitivity)) ? <StateLabel tone="warn">included: raw values need a separate grant</StateLabel> : "none"],
          ]}
        />
        <div className="filter-actions">
          <button type="button" className="btn-primary" disabled={sel.length === 0} onClick={() => setShown(true)}>
            Show the configuration for this selection
          </button>
          {perm.can("POST /api/v1/research/campaigns") && (
            <button type="button" disabled={sel.length === 0} onClick={() => navigate(`/research/new?parameters=${encodeURIComponent(sel.join(","))}`)}>
              Start a research campaign with this selection
            </button>
          )}
        </div>
        {shown && (
          <>
            <p className="small">
              The same selection as <Mono>[observation]</Mono> configuration for smcp.toml; the cost preview above is computed from it.
            </p>
            <JsonBlock value={`[observation]\nparameters = [${sel.map((s) => JSON.stringify(s)).join(", ")}]\n`} label="Configuration" />
          </>
        )}
      </Section>
      <PolicyEditor
        objects={objects}
        policyId={policyId}
        setPolicyId={setPolicyId}
        sampling={sampling}
        setSampling={setSampling}
        contexts={contexts}
        setContexts={setContexts}
        bandsText={bandsText}
        setBandsText={setBandsText}
        scope={scope}
        setScope={setScope}
        escalation={escalation}
        setEscalation={setEscalation}
        features={features}
        setFeatures={setFeatures}
        catalog={catalog}
        selected={chosen.filter((x) => x.capture_point !== "periodic" && x.sensitivity !== "S3").map((x) => x.name)}
        excluded={chosen.filter((x) => x.capture_point === "periodic" || x.sensitivity === "S3").length}
        perRecord={perRecord}
      />
      {perm.can("GET /api/v1/observations") && (
        <Section title="Live record preview">
          <p className="small">
            The 20 most recent stored records within the draft&apos;s scope, limited to the selected parameters in catalog order (scroll sideways for more). S2 and S3
            values are masked. A parameter the Observation Policy in force does not capture has no stored value.
          </p>
          <Preview selected={sel} catalog={catalog} scope={scope} inForce={status?.parameters} />
        </Section>
      )}
    </>
  );
}

/** The Observation Policy draft: sampling and baseline controls (FR-8.10) and publication after the cost preview (FR-8.11). */
function PolicyEditor(p: {
  objects: ReturnType<typeof useObjects>;
  policyId: string;
  setPolicyId: (v: string) => void;
  sampling: string;
  setSampling: (v: string) => void;
  contexts: string[];
  setContexts: (v: string[]) => void;
  bandsText: [string, string, string];
  setBandsText: (v: [string, string, string]) => void;
  scope: Scope;
  setScope: (v: Scope) => void;
  escalation: Record<string, string[]>;
  setEscalation: (v: Record<string, string[]>) => void;
  features: Feature[];
  setFeatures: (v: Feature[]) => void;
  catalog: Parameter[];
  selected: string[];
  excluded: number;
  perRecord: number;
}) {
  const rate = Number(p.sampling);
  const bands = p.bandsText.map(Number);
  const rateOk = rate > 0 && rate <= 1;
  const bandsOk = bands.every((n, i) => n > 0 && (i === 0 || n > bands[i - 1]!));
  const floorsOk = p.features.every((f) => f.sigma_floor.trim() === "" || Number(f.sigma_floor) > 0);
  const ok = rateOk && bandsOk && floorsOk && p.selected.length > 0 && p.policyId.trim() !== "" && p.contexts.length > 0 && p.features.length > 0;
  const scope = Object.fromEntries(Object.entries(p.scope).filter(([, v]) => v && v.length));
  const escalation = Object.fromEntries(Object.entries(p.escalation).filter(([, v]) => v.length));
  const features = p.features.map((f) => ({
    parameter: f.parameter,
    kind: f.kind,
    ...(f.kind === "categorical" ? {} : { transform: f.transform }),
    robust: f.robust,
    ...(f.sigma_floor.trim() ? { sigma_floor: Number(f.sigma_floor) } : {}),
  }));
  const labels = ["elevated", "abnormal", "critical"] as const;
  return (
    <Section title="Observation Policy: sampling and baseline">
      {p.objects.status === "ok" && <ObjectState objects={p.objects.data} kind="observation_policy" label="Observation Policy" />}
      <div className="rule-grid">
        <TextField label="Observation Policy ID" value={p.policyId} onChange={p.setPolicyId} mono />
        <TextField label="Normal-band sampling rate (0 to 1)" value={p.sampling} onChange={p.setSampling} type="number" />
        {labels.map((b, i) => (
          <TextField
            key={b}
            label={`${b} band from |z|`}
            value={p.bandsText[i]!}
            onChange={(v) => {
              const next = [...p.bandsText] as [string, string, string];
              next[i] = v;
              p.setBandsText(next);
            }}
            type="number"
          />
        ))}
      </div>
      <CheckList legend="Baseline context dimensions" options={contextDims} value={p.contexts} onChange={p.setContexts} />
      <h3>Scope</h3>
      <ScopeBuilder value={p.scope} onChange={p.setScope} />
      <EscalationEditor catalog={p.catalog} selected={p.selected} value={p.escalation} onChange={p.setEscalation} />
      <FeatureEditor catalog={p.catalog} value={p.features} onChange={p.setFeatures} />
      {!floorsOk && (
        <p className="notice notice-bad" role="alert">
          A σ floor must be a positive number or empty (the catalog default).
        </p>
      )}
      {!rateOk && (
        <p className="notice notice-bad" role="alert">
          The sampling rate must be above 0 and at most 1.
        </p>
      )}
      {!bandsOk && (
        <p className="notice notice-bad" role="alert">
          Band bounds must be positive and increase from elevated to critical.
        </p>
      )}
      <p className="small">
        Publishing uses the parameter selection above ({p.selected.length} per-call parameters, about {p.perRecord} bytes per captured record at sampling rate {rateOk ? rate : "?"}).
        {p.excluded > 0 && ` ${p.excluded} selected periodic meta-metrics or S3 payload parameters are not per-call capture and are left out; the meta-metrics are sampled on their own.`}
      </p>
      <Publish
        route="/api/v1/observations/observation-policy"
        label="Observation Policy"
        body={{
          policy_id: p.policyId.trim(),
          parameters: p.selected,
          sampling_rate: rate,
          contexts: p.contexts,
          bands,
          features,
          ...(Object.keys(escalation).length ? { escalation } : {}),
          ...(Object.keys(scope).length ? { scope } : {}),
        }}
        disabled={!ok}
        onPublished={p.objects.reload}
      />
    </Section>
  );
}

export function Observations(): ReactNode {
  const cat = useResource<{ catalog_version: string; parameters: Parameter[] }>("/api/v1/observations/parameters", { live: false });
  const status = useResource<ObsStatus>("/api/v1/observations/status");
  return (
    <>
      <PageHeader code="G-04" title="Observation workbench">
        <p>Choose what the Gateway records about each call from the Parameter Catalog, see the cost before you apply it, and check recent records.</p>
      </PageHeader>
      <Help>
        <p>
          Each parameter is one measured property of a call, a session or the Gateway itself, with a unit and a sensitivity class: S0 and S1 are metadata, S2
          may identify people or content and is pseudonymized for researchers, S3 is payload and needs a separate grant. Start from a preset, adjust the
          selection, check the cost preview, then publish it as the Observation Policy (it takes effect at once; a change of baseline contexts at the next start of smcpd) or use it for a research campaign. The list is built from the catalog the
          Gateway serves, so new parameters appear here when the Gateway is upgraded.
        </p>
      </Help>
      <Section title="Collector">
        <Loaded res={status} what="the observation status" route="/api/v1/observations/status">
          {(s) =>
            !s.enabled ? (
              <p className="empty">Observation is disabled. Set [observation] enabled = true and restart smcpd.</p>
            ) : (
              <KV
                rows={[
                  ["Observation policy", <Mono>{s.policy_id}</Mono>],
                  ["Parameters captured", <Mono>{s.parameters?.length ?? 0}</Mono>],
                  ["Sampling rate", <Mono>{s.sampling_rate}</Mono>],
                  ["Records assembled / captured", <Mono>{compact(s.collector?.assembled)} / {compact(s.collector?.captured)}</Mono>],
                  ["Queue", <Mono>{s.collector?.queue_depth} of {s.collector?.queue_capacity}</Mono>],
                  ["Store", s.store ? <Mono>{s.store.backend}, {bytes(s.store.bytes)} in {s.store.files} files</Mono> : <StateLabel tone="bad">{s.store_error ?? "unavailable"}</StateLabel>],
                  ["Retention", <Mono>{s.retention}</Mono>],
                ]}
              />
            )
          }
        </Loaded>
      </Section>
      <Loaded res={cat} what="the Parameter Catalog" route="/api/v1/observations/parameters">
        {(c) =>
          // The editors start from the settings in force, so wait for them.
          status.status === "loading" ? (
            <Loading what="the observation settings" />
          ) : (
            <Workbench catalog={c.parameters} version={c.catalog_version} status={status.status === "ok" ? status.data : undefined} />
          )
        }
      </Loaded>
    </>
  );
}
