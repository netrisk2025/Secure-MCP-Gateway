// G-10 library part (FR-8.18): signed package revisions with their state,
// alias, manifest, attestation (signer and trust anchor), drift and
// revocation status; enable (with alias), suspend and retire actions; the
// packaged [[server]] entries; trust anchors; import receipts; library
// scan. Routes: /api/v1/packages* (E-13, E-14).
import { useState, type ReactNode } from "react";
import { del, post } from "../api";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Link } from "../router";
import { CheckList, Crumbs, DataTable, Dialog, Done, ErrorBlock, EVIDENCE_PAGE_BYTES, JsonBlock, KV, Loaded, Mono, PageHeader, Section, ShortId, StateLabel, TextField, Time, blockText, useAction, utf8Length, type Column, type Tone } from "../ui";

export interface PackageRevision {
  server_id: string;
  revision: string;
  state: string;
  state_reason?: string;
  state_changed_at?: string;
  state_actor?: string;
  alias: string;
  risk_class: string;
  artifact_type: string;
  manifest_sha256: string;
  artifact_sha256: string;
  enablement_sha256?: string;
  signer_key_id: string;
  anchor: string;
  imported_at: string;
  expires?: string;
  recuration_due?: string;
  tools: string[];
}

interface PackagedServer {
  alias: string;
  package: string;
  revision?: string;
  status: string;
  reason_code?: string;
  reason?: string;
}

interface Anchor {
  name: string;
  key_id: string;
  classes: string[];
  expires?: string;
}

interface Receipt {
  time: string;
  actor: string;
  server_id: string;
  revision: string;
  result: string;
  reason_code?: string;
  error?: string;
  anchor?: string;
  signer_key_id?: string;
  checks?: string[];
}

export function stateTone(s: string): Tone {
  switch (s) {
    case "enabled":
    case "running":
      return "ok";
    case "verified-disabled":
    case "suspended":
    case "starting":
      return "warn";
    case "revoked":
    case "retired":
    case "not_started":
      return "bad";
    default:
      return "neutral";
  }
}

type Act = { kind: "enable" | "disable" | "retire"; rev: PackageRevision } | null;

function ActionDialog({ act, onClose, onDone }: { act: Act; onClose: () => void; onDone: (msg: string) => void }) {
  const [alias, setAlias] = useState("");
  const [reason, setReason] = useState("");
  const a = useAction<{ revision: PackageRevision; restart_required?: boolean }>();
  if (!act) return null;
  const { kind, rev } = act;
  const title = kind === "enable" ? `Enable ${rev.server_id} ${rev.revision}` : kind === "disable" ? `Suspend ${rev.server_id} ${rev.revision}` : `Retire ${rev.server_id} ${rev.revision}`;
  const route = `/api/v1/packages/${encodeURIComponent(rev.server_id)}/${encodeURIComponent(rev.revision)}/${kind}`;
  return (
    <Dialog open onClose={onClose} title={title}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const body = kind === "enable" ? (alias.trim() ? { alias: alias.trim() } : {}) : reason.trim() ? { reason: reason.trim() } : {};
          void a.run(() => post(route, body), (r) => {
            onDone(
              kind === "enable"
                ? `Enabled ${rev.server_id} ${rev.revision} as ${r.revision.alias}.${r.restart_required ? " Restart smcpd to launch it." : ""}`
                : kind === "disable"
                  ? `Suspended ${rev.server_id} ${rev.revision}. A running instance was stopped and its tools left the catalog.`
                  : `Retired ${rev.server_id} ${rev.revision}. This cannot be undone.`,
            );
            onClose();
          });
        }}
      >
        {kind === "enable" && (
          <>
            <p>The revision becomes the enabled one for its server ID. Servers are launched at Gateway start, so a restart is usually needed.</p>
            <TextField label="Alias (optional)" value={alias} onChange={setAlias} mono hint={`1 to 16 characters a-z 0-9; default ${rev.alias}.`} />
          </>
        )}
        {kind === "disable" && <p>The revision changes to verified-disabled. A running instance is torn down at once and its tools leave the catalog. It can be enabled again.</p>}
        {kind === "retire" && (
          <p>
            <strong>Retiring is final.</strong> The revision can never be enabled again; a running instance is torn down and the cached artifact is deleted when no other
            revision uses it.
          </p>
        )}
        {kind !== "enable" && <TextField label="Reason (optional, recorded)" value={reason} onChange={setReason} />}
        {a.error && <ErrorBlock error={a.error} />}
        <div className="dialog-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className={kind === "enable" ? "btn-primary" : "btn-danger"} disabled={a.busy}>
            {kind === "enable" ? "Enable" : kind === "disable" ? "Suspend" : "Retire"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function LibrarySections() {
  const res = useResource<{ library: string; revisions: PackageRevision[]; servers: PackagedServer[]; trust_anchors: Anchor[] }>("/api/v1/packages");
  const receipts = useResource<{ receipts: Receipt[] }>("/api/v1/packages/receipts");
  const perm = usePerm();
  const [act, setAct] = useState<Act>(null);
  const [done, setDone] = useState("");
  const removeAnchor = useAction();
  const scan = useAction<{ imported: string[]; rejected: string[]; revoked: string[]; suspended: string[]; errors: string[] }>();
  const base = (_r: PackageRevision, k: string) => `POST /api/v1/packages/{id}/{rev}/${k}`;
  const columns: Column<PackageRevision>[] = [
    {
      key: "id",
      label: "Package",
      sort: (r) => r.server_id,
      render: (r) => (
        <Link to={`/library/${encodeURIComponent(r.server_id)}/${encodeURIComponent(r.revision)}`}>
          <Mono>{r.server_id}</Mono>
        </Link>
      ),
    },
    { key: "rev", label: "Revision", sort: (r) => r.revision, render: (r) => <Mono>{r.revision}</Mono> },
    { key: "state", label: "State", sort: (r) => r.state, render: (r) => <StateLabel tone={stateTone(r.state)}>{r.state}</StateLabel> },
    { key: "reason", label: "Why", sort: (r) => r.state_reason ?? "", render: (r) => <Mono>{r.state_reason ?? ""}</Mono> },
    { key: "alias", label: "Alias", sort: (r) => r.alias, render: (r) => <Mono>{r.alias}</Mono> },
    { key: "risk", label: "Risk class", sort: (r) => r.risk_class, render: (r) => r.risk_class },
    { key: "signer", label: "Signed by (anchor)", sort: (r) => r.anchor, render: (r) => <Mono>{r.anchor}</Mono> },
    { key: "manifest", label: "Manifest", render: (r) => <ShortId id={r.manifest_sha256} /> },
    {
      key: "act",
      label: "Actions",
      render: (r) => (
        <span className="row-actions">
          {r.state !== "enabled" && r.state !== "retired" && r.state !== "revoked" && perm.can(base(r, "enable")) && (
            <button type="button" className="link" aria-label={`Enable ${r.server_id} ${r.revision}`} onClick={() => setAct({ kind: "enable", rev: r })}>
              Enable
            </button>
          )}
          {r.state === "enabled" && perm.can(base(r, "disable")) && (
            <button type="button" className="link" aria-label={`Suspend ${r.server_id} ${r.revision}`} onClick={() => setAct({ kind: "disable", rev: r })}>
              Suspend
            </button>
          )}
          {r.state !== "retired" && perm.can(base(r, "retire")) && (
            <button type="button" className="link" aria-label={`Retire ${r.server_id} ${r.revision}`} onClick={() => setAct({ kind: "retire", rev: r })}>
              Retire
            </button>
          )}
        </span>
      ),
    },
  ];
  return (
    <>
      {done && <Done>{done}</Done>}
      <Section
        title="Package revisions"
        actions={
          perm.can("POST /api/v1/packages/scan") && (
            <button type="button" disabled={scan.busy} onClick={() => void scan.run(() => post("/api/v1/packages/scan", {}), () => res.reload())}>
              {scan.busy ? "Scanning" : "Scan the library now"}
            </button>
          )
        }
      >
        {scan.error && <ErrorBlock error={scan.error} doing="the library scan" />}
        {scan.result && (
          <Done>
            Scan finished: {scan.result.imported.length} imported, {scan.result.rejected.length} rejected, {scan.result.revoked.length} revoked, {scan.result.suspended.length} suspended.
            {scan.result.rejected.map((r) => (
              <span key={r} className="mono small block">
                {r}
              </span>
            ))}
          </Done>
        )}
        <Loaded res={res} what="the package library" route="/api/v1/packages">
          {(d) => (
            <>
              <DataTable
                caption="Package revisions"
                columns={columns}
                rows={d.revisions}
                rowKey={(r) => r.server_id + "@" + r.revision}
                initialSort="id"
                rowClass={(r) => (r.state === "revoked" ? "row-bad" : undefined)}
                empty="No package is in the library. Build and sign one with smcpctl package build and smcpctl package sign, place it in the library and scan."
              />
              <h3 className="sub">Packaged servers</h3>
              <DataTable
                caption="Packaged servers"
                rows={d.servers}
                rowKey={(s) => s.alias}
                initialSort="alias"
                empty="No [[server]] entry names a package."
                columns={[
                  { key: "alias", label: "Alias", sort: (s) => s.alias, render: (s) => <Link to={`/servers/${encodeURIComponent(s.alias)}`}><Mono>{s.alias}</Mono></Link> },
                  { key: "pkg", label: "Package", sort: (s) => s.package, render: (s) => <Mono>{s.package}</Mono> },
                  { key: "rev", label: "Revision", render: (s) => <Mono>{s.revision ?? "none"}</Mono> },
                  { key: "status", label: "Status", sort: (s) => s.status, render: (s) => <StateLabel tone={stateTone(s.status)}>{s.status.replace("_", " ")}</StateLabel> },
                  { key: "why", label: "Reason (drift, expiry, revocation)", render: (s) => (s.reason_code ? <><Mono>{s.reason_code}</Mono> {s.reason}</> : <span className="muted">none</span>) },
                ]}
              />
              <h3 className="sub">Trust anchors</h3>
              <p className="small">
                Keys allowed to sign packages, each scoped to risk classes. A new anchor admits packages from the next library scan. The library is at{" "}
                <Mono>{d.library}</Mono>.
              </p>
              <DataTable
                caption="Trust anchors"
                rows={d.trust_anchors}
                rowKey={(a) => a.name}
                initialSort="name"
                empty="No trust anchor is enrolled, so no package can be imported."
                columns={[
                  { key: "name", label: "Anchor", sort: (a) => a.name, render: (a) => <Mono>{a.name}</Mono> },
                  { key: "key", label: "Key ID", sort: (a) => a.key_id, render: (a) => <Mono>{a.key_id}</Mono> },
                  { key: "classes", label: "Risk classes", render: (a) => a.classes.join(", ") },
                  { key: "exp", label: "Expires", sort: (a) => a.expires ?? "", render: (a) => <Time value={a.expires} /> },
                  {
                    key: "act",
                    label: "Action",
                    render: (a) =>
                      perm.can("DELETE /api/v1/packages/trust/{name}") ? (
                        <button type="button" className="link" onClick={() => void removeAnchor.run(() => del(`/api/v1/packages/trust/${encodeURIComponent(a.name)}`), () => res.reload())}>
                          Remove {a.name}
                        </button>
                      ) : (
                        <span className="muted">none</span>
                      ),
                  },
                ]}
              />
              {removeAnchor.error && <ErrorBlock error={removeAnchor.error} />}
              {perm.can("POST /api/v1/packages/trust") && <EnrollAnchor onDone={() => res.reload()} />}
            </>
          )}
        </Loaded>
      </Section>
      <Section title="Import receipts">
        <Loaded res={receipts} what="import receipts" route="/api/v1/packages/receipts">
          {(d) => (
            <DataTable
              caption="Import receipts"
              rows={d.receipts}
              rowKey={(r) => r.time + r.server_id + r.revision}
              initialSort="time"
              initialDir="desc"
              empty="No package has been imported yet."
              columns={[
                { key: "time", label: "Time", sort: (r) => r.time, render: (r) => <Time value={r.time} /> },
                { key: "pkg", label: "Package", sort: (r) => r.server_id, render: (r) => <Mono>{r.server_id} {r.revision}</Mono> },
                { key: "result", label: "Result", sort: (r) => r.result, render: (r) => <StateLabel tone={r.result === "accepted" ? "ok" : r.result === "rejected" ? "bad" : "neutral"}>{r.result}</StateLabel> },
                { key: "reason", label: "Reason", render: (r) => <Mono>{r.reason_code ?? ""}</Mono> },
                { key: "actor", label: "Actor", render: (r) => <Mono>{r.actor}</Mono> },
                { key: "checks", label: "Checks passed", render: (r) => <Mono>{r.checks?.length ?? 0}</Mono>, className: "num" },
              ]}
            />
          )}
        </Loaded>
      </Section>
      <ActionDialog act={act} onClose={() => setAct(null)} onDone={(m) => { setDone(m); res.reload(); }} />
    </>
  );
}

function EnrollAnchor({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [classes, setClasses] = useState<string[]>(["low", "moderate"]);
  const [expires, setExpires] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const a = useAction<Anchor>();
  // FR-7.10: the fingerprint is shown first and the key is enrolled only
  // after the administrator confirms it.
  const review = useAction<{ key_id: string; sha256: string }>();
  const body = { name: name.trim(), public_key: key, classes, ...(expires.trim() ? { expires: expires.trim() } : {}) };
  const edit = (f: (v: string) => void) => (v: string) => {
    f(v);
    review.reset();
    setConfirmed(false);
  };
  return (
    <details className="editor">
      <summary>Enroll a trust anchor</summary>
      <form
        className="editor-body"
        aria-label="Enroll a trust anchor"
        onSubmit={(e) => {
          e.preventDefault();
          if (!review.result) {
            void review.run(() => post("/api/v1/packages/trust", { ...body, preview: true }), () => setConfirmed(false));
            return;
          }
          void a.run(() => post("/api/v1/packages/trust", { ...body, confirm_key_id: review.result!.key_id }), () => {
            setName("");
            setKey("");
            setConfirmed(false);
            review.reset();
            onDone();
          });
        }}
      >
        <TextField label="Anchor name" value={name} onChange={edit(setName)} mono required />
        <div className="field field-wide">
          <label htmlFor="anchor-key">Minisign public key (the .pub file)</label>
          <textarea id="anchor-key" className="mono" rows={3} value={key} onChange={(e) => edit(setKey)(e.target.value)} required spellCheck={false} />
        </div>
        <CheckList legend="Risk classes it may admit" options={["low", "moderate", "high"]} value={classes} onChange={(v) => (setClasses(v), review.reset(), setConfirmed(false))} />
        <TextField label="Expires (date, default one year)" value={expires} onChange={edit(setExpires)} placeholder="2027-10-16" mono />
        {review.error && <ErrorBlock error={review.error} doing="reading the key" />}
        {review.result && (
          <div className="notice" role="status" aria-label="Key fingerprint">
            <p>Compare this fingerprint with the one the key's publisher gave you through another channel before you enroll it.</p>
            <KV
              rows={[
                ["Key ID", <Mono>{review.result.key_id}</Mono>],
                ["SHA-256", <Mono>{review.result.sha256}</Mono>],
                ["Risk classes", classes.join(", ")],
                ["Expires", expires.trim() || "one year from now"],
              ]}
            />
            <label className="check">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
              The key ID matches the publisher's
            </label>
          </div>
        )}
        {a.error && <ErrorBlock error={a.error} />}
        {a.result && <Done>Enrolled {a.result.name} (key {a.result.key_id}).</Done>}
        {review.result ? (
          <button type="submit" className="btn-primary" disabled={a.busy || !confirmed}>
            Enroll anchor
          </button>
        ) : (
          <button type="submit" className="btn-primary" disabled={review.busy || !name.trim() || !key.trim() || classes.length === 0}>
            Show fingerprint
          </button>
        )}
      </form>
    </details>
  );
}

export function PackageDetail({ id, rev }: { id: string; rev: string }) {
  const res = useResource<{ revision: PackageRevision; manifest: unknown; provenance: unknown }>(`/api/v1/packages/${encodeURIComponent(id)}/${encodeURIComponent(rev)}`, { live: false });
  const opt = (v?: string): ReactNode => (v ? <Mono>{v}</Mono> : <span className="muted">none</span>);
  return (
    <>
      <Crumbs items={[["Servers and library", "/library"], [`${id} ${rev}`, null]]} />
      <PageHeader code="G-10" title={`Package ${id}`}>
        <p>
          Revision <Mono>{rev}</Mono>: its state, attestation and the signed manifest as stored at import.
        </p>
      </PageHeader>
      <Loaded res={res} what="the package revision" route="/api/v1/packages/{id}/{rev}">
        {(d) => (
          <>
            <Section title="Revision">
              <KV
                rows={[
                  ["State", <StateLabel tone={stateTone(d.revision.state)}>{d.revision.state}</StateLabel>],
                  ["Why", opt(d.revision.state_reason)],
                  ["Changed", <>{<Time value={d.revision.state_changed_at} />} by {opt(d.revision.state_actor)}</>],
                  ["Alias", opt(d.revision.alias)],
                  ["Risk class", d.revision.risk_class],
                  ["Artifact", <>{d.revision.artifact_type} <Mono>{d.revision.artifact_sha256}</Mono></>],
                  ["Manifest digest", opt(d.revision.manifest_sha256)],
                  ["Enablement digest", opt(d.revision.enablement_sha256)],
                  ["Signer key", opt(d.revision.signer_key_id)],
                  ["Trust anchor", opt(d.revision.anchor)],
                  ["Imported", <Time value={d.revision.imported_at} />],
                  ["Expires", <Time value={d.revision.expires} />],
                  ["Tools", <Mono>{d.revision.tools.join(" ")}</Mono>],
                ]}
              />
            </Section>
            <RevisionPrivileges manifest={d.manifest} provenance={d.provenance} />
            <Section title="Signed manifest (publisher content, shown as text)">
              {/* SR-3.3-1: both blocks share one 256 KiB page budget. */}
              <JsonBlock value={d.manifest} label="Manifest" />
              <JsonBlock value={d.provenance} label="Provenance statement" limit={EVIDENCE_PAGE_BYTES - Math.min(EVIDENCE_PAGE_BYTES, utf8Length(blockText(d.manifest)))} />
            </Section>
          </>
        )}
      </Loaded>
    </>
  );
}

// SR-3.4-1: the revision's bill of materials and privileges, read from the
// signed manifest and provenance statement stored at import. Every value
// is publisher content and is shown as text.
type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "");
const none = (what: string): ReactNode => <span className="muted">{what}</span>;
const mono = (v: unknown, empty = "none"): ReactNode => (str(v) ? <Mono>{str(v)}</Mono> : none(empty));
const words = (v: unknown, empty: string): ReactNode => (arr(v).length ? <Mono>{arr(v).map(str).join(" ")}</Mono> : none(empty));

function RevisionPrivileges({ manifest, provenance }: { manifest: unknown; provenance: unknown }) {
  const m = obj(manifest);
  const p = obj(provenance);
  const art = obj(p["artifact"] ?? m["artifact"]);
  const src = obj(p["source"] ?? obj(m["provenance"])["source"]);
  const deps = obj(p["dependencies"]);
  const builder = obj(p["builder"]);
  const probe = obj(p["probe"]);
  const licenses = p["licenses"] ?? obj(m["provenance"])["licenses"];
  const launch = obj(m["launch"]);
  const caps = obj(m["capabilities"]);
  const res = obj(caps["resources"]);
  const mounts = arr(caps["filesystem"]).map(obj);
  const egress = arr(caps["egress"]).map(obj);
  const secrets = arr(m["secrets"]).map(obj);
  const env = Object.entries(obj(launch["env_fixed"]));
  const limit = (k: string, unit: string): ReactNode => (str(res[k]) && res[k] !== 0 ? <Mono>{`${str(res[k])}${unit}`}</Mono> : none("launcher default"));
  return (
    <>
      <Section title="Bill of materials (signed provenance statement)">
        <KV
          rows={[
            ["Artifact", <>{mono(art["type"])} {mono(art["reference"])} version {mono(art["version"])}</>],
            ["Artifact digest", mono(art["sha256"])],
            ["Source", <>{mono(src["kind"])} {mono(src["uri"])}</>],
            ["Source digest", mono(src["sha256"])],
            ["Licenses", words(licenses, "none declared")],
            ["Pinned dependencies", str(deps["kind"]) ? <>{mono(deps["kind"])} digest {mono(deps["sha256"])}</> : none("none: the artifact is self-contained")],
            ["Built by", <>{mono(builder["tool"])} {mono(builder["version"], "")} {str(builder["host"]) ? <>on {mono(builder["host"])}</> : null}</>],
            ["Built", str(p["built_at"]) ? <Time value={str(p["built_at"])} /> : none("not recorded")],
          ]}
        />
      </Section>
      <Section title="Launch and privileges">
        <KV
          rows={[
            ["Runtime", mono(launch["runtime"])],
            ["Launcher argument vector", words(launch["argv"], "none")],
            ["Environment passed through", words(launch["env_allowlist"], "none")],
            ["Fixed environment", env.length ? <Mono>{env.map(([k, v]) => `${k}=${str(v)}`).join(" ")}</Mono> : none("none")],
          ]}
        />
        <DataTable
          caption="Mounts"
          rows={mounts}
          rowKey={(r) => str(r["slot"])}
          empty="Mounts: none. The server gets no host directory."
          columns={[
            { key: "slot", label: "Mount slot", render: (r) => <Mono>{str(r["slot"])}</Mono> },
            { key: "mode", label: "Mode", render: (r) => (str(r["mode"]) === "rw" ? "read-write" : str(r["mode"]) === "ro" ? "read-only" : <Mono>{str(r["mode"])}</Mono>) },
            { key: "arg", label: "Argument placeholder", render: (r) => mono(r["argv_placeholder"]) },
          ]}
        />
        <DataTable
          caption="Egress destinations"
          rows={egress}
          rowKey={(r) => `${str(r["host"])}:${arr(r["ports"]).map(str).join(",")}`}
          empty="Egress destinations: none. The server has no network access."
          columns={[
            { key: "host", label: "Destination host", render: (r) => <Mono>{str(r["host"])}</Mono> },
            { key: "ports", label: "Ports", render: (r) => words(r["ports"], "any") },
            { key: "methods", label: "Methods", render: (r) => words(r["methods"], "any") },
          ]}
        />
        <DataTable
          caption="Secret slots"
          rows={secrets}
          rowKey={(r) => str(r["slot"])}
          empty="Secret slots: none. The server receives no secret."
          columns={[
            { key: "slot", label: "Secret slot", render: (r) => <Mono>{str(r["slot"])}</Mono> },
            { key: "purpose", label: "Purpose", render: (r) => str(r["purpose"]) },
            { key: "modes", label: "Delivery modes", render: (r) => words(r["modes"], "none") },
            { key: "dest", label: "Destination", render: (r) => mono(r["destination"]) },
            { key: "env", label: "Variable", render: (r) => mono(r["env_name"]) },
          ]}
        />
        <h3>Sandbox profile</h3>
        <KV
          rows={[
            ["Network", egress.length ? `egress only, through the Egress Broker, to the ${egress.length} destination${egress.length === 1 ? "" : "s"} above` : "none"],
            ["Child processes", caps["spawns_processes"] === true ? "may start child processes" : "may not start child processes"],
            ["Memory limit", limit("memory_mib", " MiB")],
            ["CPU limit", limit("cpus", " CPUs")],
            ["Process limit", limit("pids", " processes")],
            ["Wall-clock limit", limit("wall_seconds", " s")],
            ["Instance scope", words(m["instance_scope"], "not declared")],
            ["Tool-list probe at packaging", <>{mono(probe["launcher"], "not recorded")} {probe["confined"] === true ? "(confined)" : probe["confined"] === false ? "(unconfined)" : null}</>],
          ]}
        />
      </Section>
    </>
  );
}
