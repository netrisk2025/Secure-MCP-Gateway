// G-02 Policy studio, Secret Use Policy (FR-8.4, FR-3.1): a structured
// editor for the slots servers declare and the bindings of secrets to them,
// validation, a diff of the draft against the active document, publication
// to the configured use_policy_file and rollback to an earlier published
// revision. Routes: /api/v1/secret-use-policy* (E-20), /api/v1/servers and
// /api/v1/secrets for the choices. Administrator only (Appendix C).
import { useEffect, useState } from "react";
import { post } from "../api";
import { useResource } from "../data";
import {
  CheckList,
  DataTable,
  Done,
  ErrorBlock,
  JsonBlock,
  Loaded,
  Mono,
  Section,
  SelectField,
  ShortId,
  StateLabel,
  TextField,
  Time,
  useAction,
} from "../ui";

const modes = ["S1", "S2", "S3", "S4"];

/** One slot a server declares; fields the editor does not show are kept. */
interface Slot {
  server: string;
  name: string;
  modes: string[];
  env?: string;
  file_env?: string;
  header?: string;
  header_template?: string;
  destination?: string;
  [k: string]: unknown;
}

/** One binding of a secret to a slot; fields the editor does not show are kept. */
interface Binding {
  id: string;
  secret: string;
  server: string;
  slot: string;
  mode: string;
  tools: string[];
  purpose: string;
  destination?: string;
  calls_per_minute?: number;
  approval?: boolean;
  [k: string]: unknown;
}

interface UseDoc {
  revision: string;
  slots: Slot[];
  policies: Binding[];
  [k: string]: unknown;
}

interface UseState {
  file: string;
  active?: { revision: string; digest: string; bindings: number };
  document?: UseDoc;
  revisions: { revision: string; digest: string; published_at: string }[];
}

/** Drops empty optional fields so the document matches the schema. */
function clean<T extends Record<string, unknown>>(o: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined || v === "" || (k === "approval" && v === false)) continue;
    out[k] = v;
  }
  return out as T;
}

function draftOf(doc: UseDoc | undefined, revision: string): UseDoc {
  return { ...(doc ?? {}), revision, slots: doc?.slots ?? [], policies: doc?.policies ?? [] };
}

function nextRevision(s: UseState): string {
  const taken = new Set([s.active?.revision, ...(s.revisions ?? []).map((r) => r.revision)]);
  const base = (s.active?.revision ?? "u").replace(/-\d+$/, "");
  for (let i = 2; ; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
}

interface Change {
  change: string;
  kind: string;
  id: string;
}

/** The slots and bindings the draft adds, removes or changes against the active document. */
function diff(active: UseDoc | undefined, draft: UseDoc): Change[] {
  const out: Change[] = [];
  const cmp = <T,>(kind: string, a: T[], b: T[], key: (x: T) => string) => {
    const before = new Map(a.map((x) => [key(x), JSON.stringify(x)]));
    const after = new Map(b.map((x) => [key(x), JSON.stringify(x)]));
    for (const [k, v] of after) {
      if (!before.has(k)) out.push({ change: "added", kind, id: k });
      else if (before.get(k) !== v) out.push({ change: "changed", kind, id: k });
    }
    for (const k of before.keys()) if (!after.has(k)) out.push({ change: "removed", kind, id: k });
  };
  cmp("slot", active?.slots ?? [], draft.slots.map(clean), (s) => `${s.server}/${s.name}`);
  cmp("binding", active?.policies ?? [], draft.policies.map(clean), (p) => p.id);
  return out;
}

function SlotEditor({ s, servers, onChange, onRemove }: { s: Slot; servers: string[]; onChange: (s: Slot) => void; onRemove: () => void }) {
  return (
    <fieldset className="rule">
      <legend>
        Slot <span className="mono">{`${s.server}/${s.name}`}</span>
      </legend>
      <div className="rule-grid">
        <SelectField label="Server" value={s.server} onChange={(v) => onChange({ ...s, server: v })} options={[...new Set([s.server, ...servers])].filter(Boolean)} />
        <TextField label="Slot name" value={s.name} onChange={(v) => onChange({ ...s, name: v })} mono />
        <TextField label="Environment variable (S4)" value={s.env ?? ""} onChange={(v) => onChange({ ...s, env: v || undefined })} mono />
        <TextField label="File variable (S2, S3)" value={s.file_env ?? ""} onChange={(v) => onChange({ ...s, file_env: v || undefined })} mono />
        <TextField label="Header (S1)" value={s.header ?? ""} onChange={(v) => onChange({ ...s, header: v || undefined })} mono />
        <TextField label="Header template (S1, with {secret})" value={s.header_template ?? ""} onChange={(v) => onChange({ ...s, header_template: v || undefined })} mono />
        <TextField label="Destination host (S1)" value={s.destination ?? ""} onChange={(v) => onChange({ ...s, destination: v || undefined })} mono />
      </div>
      <CheckList legend="Delivery modes the slot supports" options={modes} value={s.modes} onChange={(v) => onChange({ ...s, modes: modes.filter((m) => v.includes(m)) })} />
      <button type="button" className="link" onClick={onRemove}>
        Remove slot {`${s.server}/${s.name}`}
      </button>
    </fieldset>
  );
}

function BindingEditor({ b, slots, secrets, onChange, onRemove }: { b: Binding; slots: Slot[]; secrets: string[]; onChange: (b: Binding) => void; onRemove: () => void }) {
  const servers = [...new Set(slots.map((s) => s.server))];
  const ofServer = slots.filter((s) => s.server === b.server);
  const slot = ofServer.find((s) => s.name === b.slot);
  return (
    <fieldset className="rule">
      <legend>
        Binding <span className="mono">{b.id}</span>
      </legend>
      <div className="rule-grid">
        <TextField label="Binding ID" value={b.id} onChange={(v) => onChange({ ...b, id: v })} mono />
        <SelectField label="Secret" value={b.secret} onChange={(v) => onChange({ ...b, secret: v })} options={[...new Set([b.secret, ...secrets])].filter(Boolean)} />
        <SelectField
          label="Server"
          value={b.server}
          onChange={(v) => {
            const first = slots.find((s) => s.server === v);
            onChange({ ...b, server: v, slot: first?.name ?? "", mode: first?.modes[0] ?? b.mode });
          }}
          options={[...new Set([b.server, ...servers])].filter(Boolean)}
        />
        <SelectField
          label="Slot"
          value={b.slot}
          onChange={(v) => onChange({ ...b, slot: v, mode: ofServer.find((s) => s.name === v)?.modes[0] ?? b.mode })}
          options={[...new Set([b.slot, ...ofServer.map((s) => s.name)])].filter(Boolean)}
        />
        <SelectField label="Mode" value={b.mode} onChange={(v) => onChange({ ...b, mode: v })} options={[...new Set([b.mode, ...(slot?.modes ?? modes)])].filter(Boolean)} />
        <TextField label="Tools (space separated, * for all)" value={b.tools.join(" ")} onChange={(v) => onChange({ ...b, tools: v.split(/[\s,]+/).filter(Boolean) })} mono />
        <TextField label="Purpose" value={b.purpose} onChange={(v) => onChange({ ...b, purpose: v })} />
        <TextField label="Destination host (S1)" value={b.destination ?? ""} onChange={(v) => onChange({ ...b, destination: v || undefined })} mono />
        <TextField
          label="Calls per minute"
          value={b.calls_per_minute?.toString() ?? ""}
          onChange={(v) => onChange({ ...b, calls_per_minute: v.trim() === "" ? undefined : Number(v) })}
          type="number"
        />
        <div className="field">
          <label className="check">
            <input type="checkbox" checked={!!b.approval} onChange={(e) => onChange({ ...b, approval: e.target.checked || undefined })} />
            Each use requires approval
          </label>
        </div>
      </div>
      <button type="button" className="link" onClick={onRemove}>
        Remove binding {b.id}
      </button>
    </fieldset>
  );
}

function Editor({ state, reload }: { state: UseState; reload: () => void }) {
  const servers = useResource<{ servers: { alias: string }[] }>("/api/v1/servers", { live: false });
  const secrets = useResource<{ secrets?: { name: string }[] }>("/api/v1/secrets", { live: false });
  const [draft, setDraft] = useState<UseDoc>(() => draftOf(state.document, nextRevision(state)));
  const [reason, setReason] = useState("");
  const [shown, setShown] = useState<Change[] | null>(null);
  const validate = useAction<{ revision: string; digest: string; bindings: number }>();
  const publish = useAction<{ revision: string; bindings: number }>();
  const rollback = useAction<{ revision: string; bindings: number }>();
  useEffect(() => setShown(null), [draft]);
  // A publication or rollback changes the active document: start the next
  // draft from it.
  useEffect(() => {
    setDraft(draftOf(state.document, nextRevision(state)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.active?.digest]);
  const aliases = servers.status === "ok" ? servers.data.servers.map((s) => s.alias) : [];
  const names = secrets.status === "ok" ? (secrets.data.secrets ?? []).map((s) => s.name) : [];
  const doc: UseDoc = { ...draft, revision: draft.revision.trim(), slots: draft.slots.map(clean), policies: draft.policies.map(clean) };
  const after = () => reload();
  return (
    <>
      <Section title="Draft">
        <p className="small">
          The draft starts from the active document. Publishing writes it to <Mono>{state.file || "(no use_policy_file configured)"}</Mono> and activates it at once.
        </p>
        <div className="rule-grid">
          <TextField label="Revision ID of the draft" value={draft.revision} onChange={(v) => setDraft({ ...draft, revision: v })} mono />
        </div>
        <h3 className="sub">Slots ({draft.slots.length})</h3>
        {draft.slots.map((s, i) => (
          <SlotEditor
            key={i}
            s={s}
            servers={aliases}
            onChange={(ns) => setDraft({ ...draft, slots: draft.slots.map((x, j) => (j === i ? ns : x)) })}
            onRemove={() => setDraft({ ...draft, slots: draft.slots.filter((_, j) => j !== i) })}
          />
        ))}
        <div className="filter-actions">
          <button type="button" onClick={() => setDraft({ ...draft, slots: [...draft.slots, { server: aliases[0] ?? "", name: `slot-${draft.slots.length + 1}`, modes: ["S3"], file_env: "" }] })}>
            Add a slot
          </button>
        </div>
        <h3 className="sub">Bindings ({draft.policies.length})</h3>
        {draft.policies.map((b, i) => (
          <BindingEditor
            key={i}
            b={b}
            slots={draft.slots}
            secrets={names}
            onChange={(nb) => setDraft({ ...draft, policies: draft.policies.map((x, j) => (j === i ? nb : x)) })}
            onRemove={() => setDraft({ ...draft, policies: draft.policies.filter((_, j) => j !== i) })}
          />
        ))}
        <div className="filter-actions">
          <button
            type="button"
            disabled={draft.slots.length === 0}
            onClick={() => {
              const s = draft.slots[0]!;
              setDraft({
                ...draft,
                policies: [...draft.policies, { id: `binding-${draft.policies.length + 1}`, secret: names[0] ?? "", server: s.server, slot: s.name, mode: s.modes[0] ?? "S3", tools: ["*"], purpose: "" }],
              });
            }}
          >
            Add a binding
          </button>
        </div>
        <div className="filter-actions">
          <button type="button" disabled={validate.busy} onClick={() => void validate.run(() => post("/api/v1/secret-use-policy/validate", { document: doc }))}>
            Validate
          </button>
          <button type="button" onClick={() => setShown(diff(state.document, doc))}>
            Diff against the active document
          </button>
        </div>
        {validate.error && <ErrorBlock error={validate.error} doing="the validation" />}
        {validate.result && (
          <Done>
            Valid: revision {validate.result.revision}, {validate.result.bindings} binding{validate.result.bindings === 1 ? "" : "s"}.
          </Done>
        )}
        {shown && (
          <DataTable
            caption="Secret Use Policy changes"
            rows={shown}
            rowKey={(c) => c.kind + c.id}
            initialSort="kind"
            empty="The draft has the same slots and bindings as the active document."
            columns={[
              { key: "change", label: "Change", sort: (c) => c.change, render: (c) => c.change },
              { key: "kind", label: "Object", sort: (c) => c.kind, render: (c) => c.kind },
              { key: "id", label: "ID", sort: (c) => c.id, render: (c) => <Mono>{c.id}</Mono> },
            ]}
          />
        )}
        <JsonBlock value={doc} label="Draft document" />
        <form
          aria-label="Publish the Secret Use Policy"
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            void publish.run(() => post("/api/v1/secret-use-policy", { document: doc, reason: reason.trim() }), after);
          }}
        >
          <TextField label="Reason for this revision (recorded in the journal)" value={reason} onChange={setReason} />
          <button type="submit" className="btn-primary" disabled={publish.busy || !doc.revision}>
            Publish the Secret Use Policy
          </button>
        </form>
        {publish.error && <ErrorBlock error={publish.error} doing="the publication" />}
        {publish.result && (
          <Done>
            Published Secret Use Policy revision {publish.result.revision} ({publish.result.bindings} binding{publish.result.bindings === 1 ? "" : "s"}). It is active.
          </Done>
        )}
      </Section>
      <Section title="Published revisions">
        <DataTable
          caption="Secret Use Policy revisions"
          rows={state.revisions ?? []}
          rowKey={(r) => r.revision}
          initialSort="at"
          initialDir="desc"
          empty="No revision has been published from the console. The active document was loaded from the file."
          columns={[
            { key: "rev", label: "Revision", sort: (r) => r.revision, render: (r) => <Mono>{r.revision}</Mono> },
            { key: "digest", label: "Digest", render: (r) => <ShortId id={r.digest} /> },
            { key: "at", label: "Published", sort: (r) => r.published_at, render: (r) => <Time value={r.published_at} /> },
            {
              key: "state",
              label: "State",
              render: (r) =>
                r.digest === state.active?.digest ? (
                  <StateLabel tone="ok">active</StateLabel>
                ) : (
                  <button type="button" className="link" disabled={rollback.busy} onClick={() => void rollback.run(() => post("/api/v1/secret-use-policy/rollback", { revision: r.revision, reason: "" }), after)}>
                    Roll back to {r.revision}
                  </button>
                ),
            },
          ]}
        />
        {rollback.error && <ErrorBlock error={rollback.error} doing="the rollback" />}
        {rollback.result && <Done>Rolled back: Secret Use Policy revision {rollback.result.revision} is active.</Done>}
      </Section>
    </>
  );
}

export function SecretUse() {
  const res = useResource<UseState>("/api/v1/secret-use-policy", { live: false });
  return (
    <Loaded res={res} what="the Secret Use Policy" route="/api/v1/secret-use-policy">
      {(s) => (
        <>
          <Section title="Active Secret Use Policy">
            {s.active ? (
              <p>
                Revision <Mono>{s.active.revision}</Mono>, {s.active.bindings} binding{s.active.bindings === 1 ? "" : "s"}, digest <ShortId id={s.active.digest} />.
              </p>
            ) : (
              <p className="empty">No Secret Use Policy is active.</p>
            )}
          </Section>
          <Editor state={s} reload={res.reload} />
        </>
      )}
    </Loaded>
  );
}
