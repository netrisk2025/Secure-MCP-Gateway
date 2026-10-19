// G-12 Secrets (FR-8.20): vault status, Secret Use Policy bindings, secret
// metadata, write-only creation and rotation, reference-impact preview,
// revocation and leak-suspension resume. No response of these routes
// carries a value, and the console never shows one: value inputs are
// password fields that are cleared as soon as the request is sent.
// Routes: /api/v1/secrets* (E-19, E-20).
import { useState, type ReactNode } from "react";
import { del, post } from "../api";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Link, match, navigate } from "../router";
import { Crumbs, DataTable, Dialog, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, StateLabel, TextField, Time, useAction } from "../ui";

interface Version {
  version: number;
  created: string;
  state: string;
  deliverable_until?: string;
  retired_at?: string;
}

interface SecretMeta {
  ref: string;
  name: string;
  type: string;
  owner: string;
  description?: string;
  created: string;
  rotated?: string;
  expires?: string;
  current_version: number;
  versions: Version[];
}

interface Binding {
  id: string;
  secret: string;
  server: string;
  slot: string;
  mode: string;
  tools: string[];
  purpose?: string;
}

interface SecretsDoc {
  vault: { vault_id: string; key_source: string; runtime_dir: string; runtime_tmpfs: boolean; rotation_overlap: string; fingerprints: number; suspended?: Record<string, string> };
  use_policy?: { revision: string; digest: string; slots: { server: string; name: string; modes: string[]; file_env?: string }[]; bindings: Binding[] };
  secrets: SecretMeta[];
}

interface Impact {
  secret: string;
  ref: string;
  references: { use_policy?: string; server: string; server_revision?: string; slot: string; mode?: string; tools?: string[]; source: string; active: boolean }[];
}

const types = ["generic", "api_key", "token", "password", "certificate", "connection_string"];

function CreateSecret({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [type, setType] = useState("generic");
  const [description, setDescription] = useState("");
  const [expires, setExpires] = useState("");
  const [value, setValue] = useState("");
  const a = useAction<SecretMeta>();
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const v = value;
        setValue("");
        void a.run(
          () => post("/api/v1/secrets", { name: name.trim(), type, description: description.trim(), ...(expires.trim() ? { expires: expires.trim() } : {}), value: v }),
          () => {
            setName("");
            setDescription("");
            setExpires("");
            onDone();
          },
        );
      }}
      aria-label="Create a secret"
    >
      <div className="rule-grid">
        <TextField label="Name" value={name} onChange={setName} mono required />
        <SelectField label="Type" value={type} onChange={setType} options={types} />
        <TextField label="Description" value={description} onChange={setDescription} />
        <TextField label="Expires (RFC 3339, optional)" value={expires} onChange={setExpires} placeholder="2027-01-01T00:00:00Z" mono />
      </div>
      <TextField label="Value (write-only, 8 to 32768 bytes)" value={value} onChange={setValue} type="password" autoComplete="new-password" required hint="The value is sent once over the loopback TLS connection and never shown again." />
      {a.error && <ErrorBlock error={a.error} doing="the secret" />}
      {a.result && <Done>Created {a.result.name} as version {a.result.current_version}.</Done>}
      <button type="submit" className="btn-primary" disabled={a.busy || !name.trim() || value.length < 8}>
        Create secret
      </button>
    </form>
  );
}

function SecretList() {
  const res = useResource<SecretsDoc>("/api/v1/secrets");
  const perm = usePerm();
  const reload = useAction<{ revision: string; digest: string; bindings: number }>();
  return (
    <Loaded res={res} what="the secret vault" route="/api/v1/secrets">
      {(d) => (
        <>
          <Section title="Vault">
            <KV
              rows={[
                ["Vault", <Mono>{d.vault.vault_id}</Mono>],
                ["Master key source", d.vault.key_source],
                ["Runtime directory", <><Mono>{d.vault.runtime_dir}</Mono> {d.vault.runtime_tmpfs ? "(tmpfs)" : <StateLabel tone="warn">not a tmpfs</StateLabel>}</>],
                ["Rotation overlap", <Mono>{d.vault.rotation_overlap}</Mono>],
                ["Leak fingerprints", <Mono>{d.vault.fingerprints}</Mono>],
                ["Suspended for a leak", Object.keys(d.vault.suspended ?? {}).length ? <Mono>{Object.keys(d.vault.suspended ?? {}).length}</Mono> : "none"],
              ]}
            />
          </Section>
          <Section title="Secrets">
            <DataTable
              caption="Secrets"
              rows={d.secrets}
              rowKey={(s) => s.ref}
              initialSort="name"
              rowClass={(s) => (d.vault.suspended?.[s.ref] ? "row-bad" : undefined)}
              empty="No secret is stored. Create one below or with smcpctl secrets add."
              columns={[
                { key: "name", label: "Name", sort: (s) => s.name, render: (s) => <Link to={`/secrets/${encodeURIComponent(s.name)}`}><Mono>{s.name}</Mono></Link> },
                { key: "type", label: "Type", sort: (s) => s.type, render: (s) => s.type },
                { key: "owner", label: "Owner", sort: (s) => s.owner, render: (s) => <Mono>{s.owner}</Mono> },
                { key: "ver", label: "Version", sort: (s) => s.current_version, render: (s) => <Mono>{s.current_version}</Mono>, className: "num" },
                { key: "rotated", label: "Rotated", sort: (s) => s.rotated ?? s.created, render: (s) => <Time value={s.rotated ?? s.created} /> },
                { key: "expires", label: "Expires", sort: (s) => s.expires ?? "", render: (s) => <Time value={s.expires} /> },
                { key: "state", label: "Delivery", render: (s) => (d.vault.suspended?.[s.ref] ? <StateLabel tone="bad">suspended</StateLabel> : <StateLabel tone="ok">deliverable</StateLabel>) },
              ]}
            />
            {perm.can("POST /api/v1/secrets") && (
              <details className="editor">
                <summary>Create a secret</summary>
                <div className="editor-body">
                  <CreateSecret onDone={res.reload} />
                </div>
              </details>
            )}
          </Section>
          <Section
            title="Secret Use Policy"
            actions={
              perm.can("POST /api/v1/secrets/reload") && (
                <button type="button" disabled={reload.busy} onClick={() => void reload.run(() => post("/api/v1/secrets/reload", {}), res.reload)}>
                  Reload the Secret Use Policy file
                </button>
              )
            }
          >
            {reload.error && <ErrorBlock error={reload.error} doing="the Secret Use Policy" />}
            {reload.result && <Done>Activated revision {reload.result.revision} with {reload.result.bindings} bindings.</Done>}
            {d.use_policy ? (
              <>
                <p className="small">
                  Revision <Mono>{d.use_policy.revision || "none"}</Mono>, digest <Mono>{d.use_policy.digest.slice(0, 16)}</Mono>.
                </p>
                <DataTable
                  caption="Bindings"
                  rows={d.use_policy.bindings}
                  rowKey={(b) => b.id}
                  initialSort="id"
                  empty="The Secret Use Policy binds no secret."
                  columns={[
                    { key: "id", label: "Binding", sort: (b) => b.id, render: (b) => <Mono>{b.id}</Mono> },
                    { key: "secret", label: "Secret", sort: (b) => b.secret, render: (b) => <Link to={`/secrets/${encodeURIComponent(b.secret)}`}><Mono>{b.secret}</Mono></Link> },
                    { key: "server", label: "Server / slot", render: (b) => <Mono>{b.server}/{b.slot}</Mono> },
                    { key: "mode", label: "Delivery", sort: (b) => b.mode, render: (b) => <Mono>{b.mode}</Mono> },
                    { key: "tools", label: "Tools", render: (b) => <Mono>{b.tools.join(" ")}</Mono> },
                    { key: "purpose", label: "Purpose", render: (b) => b.purpose ?? "" },
                  ]}
                />
              </>
            ) : (
              <p className="empty">No Secret Use Policy file is configured, so no secret is delivered. Set [secrets] use_policy_file.</p>
            )}
          </Section>
        </>
      )}
    </Loaded>
  );
}

function ImpactTable({ name }: { name: string }) {
  const res = useResource<Impact>(`/api/v1/secrets/${encodeURIComponent(name)}/impact`, { live: false });
  return (
    <Loaded res={res} what="the reference impact" route="/api/v1/secrets/{name}/impact">
      {(d) => (
        <DataTable
          caption={`References to ${name}`}
          rows={d.references}
          rowKey={(r) => r.server + r.slot + (r.use_policy ?? "")}
          empty="Nothing references this secret: no binding and no server secret_env slot."
          columns={[
            { key: "server", label: "Server / slot", sort: (r) => r.server, render: (r) => <Mono>{r.server}/{r.slot}</Mono> },
            { key: "rev", label: "Server revision", render: (r) => <Mono>{r.server_revision ?? ""}</Mono> },
            { key: "src", label: "Source", sort: (r) => r.source, render: (r) => <>{r.source}{r.use_policy && <> <Mono>{r.use_policy}</Mono></>}</> },
            { key: "mode", label: "Delivery", render: (r) => <Mono>{r.mode ?? ""}</Mono> },
            { key: "active", label: "In use now", sort: (r) => String(r.active), render: (r) => (r.active ? <StateLabel tone="warn">delivered to a running instance</StateLabel> : "no") },
          ]}
        />
      )}
    </Loaded>
  );
}

function SecretDetail({ name }: { name: string }) {
  const res = useResource<{ secret: SecretMeta; suspended: boolean; suspended_reason: string }>(`/api/v1/secrets/${encodeURIComponent(name)}`);
  const perm = usePerm();
  const [dialog, setDialog] = useState<"" | "rotate" | "revoke">("");
  const [value, setValue] = useState("");
  const [overlap, setOverlap] = useState("");
  const rotate = useAction<SecretMeta>();
  const revoke = useAction();
  const resume = useAction<{ resumed: boolean }>();
  const close = () => {
    setDialog("");
    setValue("");
  };
  return (
    <>
      <Crumbs items={[["Secrets", "/secrets"], [name, null]]} />
      <PageHeader code="G-12" title={`Secret ${name}`}>
        <p>Metadata and references of one secret. The value is never shown.</p>
      </PageHeader>
      <Loaded res={res} what="the secret" route="/api/v1/secrets/{name}">
        {({ secret: s, suspended, suspended_reason }) => (
          <>
            <Section
              title="Metadata"
              actions={
                <>
                  {perm.can("POST /api/v1/secrets/{name}/rotate") && (
                    <button type="button" onClick={() => setDialog("rotate")}>
                      Rotate
                    </button>
                  )}
                  {perm.can("DELETE /api/v1/secrets/{name}") && (
                    <button type="button" className="btn-danger" onClick={() => setDialog("revoke")}>
                      Revoke
                    </button>
                  )}
                </>
              }
            >
              {rotate.result && <Done>Rotated to version {rotate.result.current_version}.</Done>}
              {suspended && (
                <div className="notice notice-bad" role="alert">
                  <p>
                    <strong>S2 delivery is suspended:</strong> {suspended_reason}
                  </p>
                  {perm.can("POST /api/v1/secrets/{name}/resume") && (
                    <button type="button" disabled={resume.busy} onClick={() => void resume.run(() => post(`/api/v1/secrets/${encodeURIComponent(name)}/resume`, {}), res.reload)}>
                      Resume delivery
                    </button>
                  )}
                  {resume.error && <ErrorBlock error={resume.error} />}
                </div>
              )}
              <KV
                rows={[
                  ["Reference", <Mono>{s.ref}</Mono>],
                  ["Type", s.type],
                  ["Owner", <Mono>{s.owner}</Mono>],
                  ["Description", s.description || <span className="muted">none</span>],
                  ["Created", <Time value={s.created} />],
                  ["Rotated", <Time value={s.rotated} />],
                  ["Expires", <Time value={s.expires} />],
                  ["Current version", <Mono>{s.current_version}</Mono>],
                ]}
              />
              <h3 className="sub">Versions</h3>
              <DataTable
                caption="Versions"
                rows={s.versions}
                rowKey={(v) => String(v.version)}
                initialSort="v"
                initialDir="desc"
                empty=""
                columns={[
                  { key: "v", label: "Version", sort: (v) => v.version, render: (v) => <Mono>{v.version}</Mono>, className: "num" },
                  { key: "state", label: "State", sort: (v) => v.state, render: (v) => <StateLabel tone={v.state === "current" ? "ok" : v.state === "overlap" ? "warn" : "neutral"}>{v.state}</StateLabel> },
                  { key: "created", label: "Created", render: (v) => <Time value={v.created} /> },
                  { key: "until", label: "Deliverable until", render: (v) => (v.deliverable_until ? <Time value={v.deliverable_until} /> : v.retired_at ? <>retired <Time value={v.retired_at} /></> : <span className="muted">no limit</span>) },
                ]}
              />
            </Section>
            <Section title="Reference impact">
              <ImpactTable name={name} />
            </Section>
          </>
        )}
      </Loaded>
      <Dialog open={dialog === "rotate"} onClose={close} title={`Rotate ${name}`}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const v = value;
            setValue("");
            void rotate.run(() => post(`/api/v1/secrets/${encodeURIComponent(name)}/rotate`, overlap.trim() ? { value: v, overlap: overlap.trim() } : { value: v }), () => {
              close();
              res.reload();
            });
          }}
        >
          <p>The new value becomes the current version. The previous version stays deliverable for the overlap, then it is retired and deleted.</p>
          <TextField label="New value (write-only)" value={value} onChange={setValue} type="password" autoComplete="new-password" required />
          <TextField label="Overlap (Go duration, optional)" value={overlap} onChange={setOverlap} placeholder="1h, or 0s to retire at once" mono />
          {rotate.error && <ErrorBlock error={rotate.error} />}
          <div className="dialog-actions">
            <button type="button" onClick={close}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={rotate.busy || value.length < 8}>
              Rotate
            </button>
          </div>
        </form>
      </Dialog>
      <Dialog open={dialog === "revoke"} onClose={close} title={`Revoke ${name}`}>
        <p>Every version is retired and the record is deleted. These references lose the secret:</p>
        <ImpactTable name={name} />
        {revoke.error && <ErrorBlock error={revoke.error} />}
        <div className="dialog-actions">
          <button type="button" onClick={close}>
            Cancel
          </button>
          <button type="button" className="btn-danger" disabled={revoke.busy} onClick={() => void revoke.run(() => del(`/api/v1/secrets/${encodeURIComponent(name)}`), () => navigate("/secrets"))}>
            Revoke {name}
          </button>
        </div>
      </Dialog>
    </>
  );
}

export function Secrets({ path }: { path: string }): ReactNode {
  const m = match("/secrets/:name", path);
  if (m?.name) return <SecretDetail name={m.name} />;
  return (
    <>
      <PageHeader code="G-12" title="Secrets">
        <p>Secret metadata, Secret Use Policy bindings, rotation and revocation. Values are write-only and are never shown.</p>
      </PageHeader>
      <Help>
        <p>
          Secrets are stored encrypted in the Secret Vault and delivered to servers only as the Secret Use Policy binds them: S1 injected into egress headers, S2
          as a file the tool call reads, S3 as a file for the server's lifetime, S4 as an environment variable. A value appearing in a tool result is detected by
          its fingerprint, and S2 delivery of that secret is suspended until you resume it. Rotation keeps the previous version deliverable for the overlap.
        </p>
      </Help>
      <SecretList />
    </>
  );
}
