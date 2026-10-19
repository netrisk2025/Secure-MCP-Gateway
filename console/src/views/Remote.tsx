// Remote access and client registrations (FR-16, G-11): the Remote Access
// Profile state with enable and disable (Administrator), and the remote
// clients with approve, deny and revoke (Administrator and Session
// Approver, Appendix C). Routes: /api/v1/remote*, /api/v1/clients*.
import { useState, type ReactNode } from "react";
import { post } from "../api";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Link, match, useLocation } from "../router";
import type { Principals } from "../types";
import { Crumbs, DataTable, Dialog, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, StateLabel, TextField, Time, useAction, type Tone } from "../ui";

interface RemoteStatus {
  enabled: boolean;
  public_url?: string;
  provider?: string;
  changed_by?: string;
  changed_at?: string;
  listener: string;
  listening: boolean;
  resource_uri?: string;
  pending_registrations: number;
  remote_sessions: number;
}

interface Client {
  client_id: string;
  client_name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  token_endpoint_auth_method?: string;
  status: string;
  principal?: string;
  registered_at?: string;
  source_address?: string;
  source_address_source?: string;
  registration: string;
  software_id?: string;
  software_version?: string;
  decided_by?: string;
  decided_at?: string;
}

const statusTone = (s: string): Tone => (s === "approved" ? "ok" : s === "pending" ? "pending" : s === "denied" || s === "revoked" ? "bad" : "neutral");

function Profile() {
  const res = useResource<RemoteStatus>("/api/v1/remote");
  const perm = usePerm();
  const [url, setUrl] = useState("");
  const [provider, setProvider] = useState("manual");
  const enable = useAction<RemoteStatus>();
  const disable = useAction<RemoteStatus>();
  return (
    <Section title="Remote Access Profile">
      <Loaded res={res} what="the remote access state" route="/api/v1/remote">
        {(s) => (
          <>
            <KV
              rows={[
                ["State", s.enabled ? <StateLabel tone="warn">enabled: reachable from outside this machine</StateLabel> : <StateLabel tone="ok">disabled</StateLabel>],
                ["Public URL", s.public_url ? <Mono>{s.public_url}</Mono> : <span className="muted">none</span>],
                ["Resource URI", s.resource_uri ? <Mono>{s.resource_uri}</Mono> : <span className="muted">none</span>],
                ["Provider", s.provider ?? <span className="muted">none</span>],
                ["Remote listener", <><Mono>{s.listener}</Mono> {s.listening ? "(listening)" : "(closed)"}</>],
                ["Pending registrations", <Mono>{s.pending_registrations}</Mono>],
                ["Remote sessions", <Mono>{s.remote_sessions}</Mono>],
                ["Last changed", s.changed_at ? <><Time value={s.changed_at} /> by <Mono>{s.changed_by}</Mono></> : <span className="muted">never</span>],
              ]}
            />
            {enable.error && <ErrorBlock error={enable.error} doing="enabling" />}
            {disable.error && <ErrorBlock error={disable.error} doing="disabling" />}
            {s.enabled
              ? perm.can("POST /api/v1/remote/disable") && (
                  <div className="action-row">
                    <div>
                      <strong>Disable remote access</strong>
                      <p className="small">Closes the remote listener and ends every remote session.</p>
                    </div>
                    <button type="button" className="btn-danger" disabled={disable.busy} onClick={() => void disable.run(() => post("/api/v1/remote/disable", {}), res.reload)}>
                      Disable
                    </button>
                  </div>
                )
              : perm.can("POST /api/v1/remote/enable") && (
                  <form
                    className="inline-form"
                    aria-label="Enable remote access"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void enable.run(() => post("/api/v1/remote/enable", { ...(url.trim() ? { public_url: url.trim() } : {}), provider }), res.reload);
                    }}
                  >
                    <TextField label="Public URL (https://name, no path)" value={url} onChange={setUrl} placeholder="default remote.public_url" mono />
                    <SelectField label="Tunnel provider" value={provider} onChange={setProvider} options={["manual", "tailscale", "cloudflare", "vendor"]} />
                    <button type="submit" className="btn-primary" disabled={enable.busy}>
                      Enable remote access
                    </button>
                  </form>
                )}
          </>
        )}
      </Loaded>
    </Section>
  );
}

type Decision = { kind: "approve" | "deny" | "revoke"; client: Client } | null;

function DecideDialog({ d, onClose, onDone }: { d: Decision; onClose: () => void; onDone: (m: string) => void }) {
  const perm = usePerm();
  const principals = useResource<Principals>(d && perm.can("GET /api/v1/sessions/principals") ? "/api/v1/sessions/principals" : null, { live: false });
  const [principal, setPrincipal] = useState("");
  const [comment, setComment] = useState("");
  const a = useAction<Client>();
  if (!d) return null;
  const { kind, client } = d;
  const names = principals.status === "ok" ? principals.data.principals.filter((p) => p.enabled).map((p) => p.id) : [];
  return (
    <Dialog open onClose={onClose} title={`${kind === "approve" ? "Approve" : kind === "deny" ? "Deny" : "Revoke"} ${client.client_name || client.client_id}`}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const body: Record<string, string> = {};
          if (comment.trim()) body.comment = comment.trim();
          if (kind === "approve" && principal) body.principal = principal;
          void a.run(() => post(`/api/v1/clients/${encodeURIComponent(client.client_id)}/${kind}`, body), (r) => {
            onDone(`${r.client_name || r.client_id} is ${r.status}${r.principal ? ` and bound to ${r.principal}` : ""}.`);
            onClose();
          });
        }}
      >
        {kind === "approve" && (
          <>
            <p>
              The client may then sign in on the remote listener as the chosen principal. Its name and software ID are declared by the registrant and not verified;
              check the redirect URIs and the source address.
            </p>
            <KV
              rows={[
                ["Redirect URIs", <Mono>{(client.redirect_uris ?? []).join(" ")}</Mono>],
                ["Source address", <Mono>{client.source_address ?? "unknown"}</Mono>],
              ]}
            />
            {names.length > 0 ? (
              <SelectField label="Principal" value={principal} onChange={setPrincipal} options={[["", "default remote principal"], ...names.map((n) => [n, n] as [string, string])]} />
            ) : (
              <TextField label="Principal (empty: remote.default_principal)" value={principal} onChange={setPrincipal} mono />
            )}
          </>
        )}
        {kind === "revoke" && <p>The registration stops working and its remote sessions end.</p>}
        <TextField label="Comment (optional, recorded)" value={comment} onChange={setComment} />
        {a.error && <ErrorBlock error={a.error} />}
        <div className="dialog-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className={kind === "approve" ? "btn-primary" : "btn-danger"} disabled={a.busy}>
            {kind === "approve" ? "Approve" : kind === "deny" ? "Deny" : "Revoke"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

const states = ["all", "pending", "approved", "denied", "revoked"];

function Clients() {
  const { query } = useLocation();
  const st = states.includes(query.get("status") ?? "") ? query.get("status")! : "all";
  const res = useResource<{ clients: Client[] }>(st === "all" ? "/api/v1/clients" : `/api/v1/clients?status=${st}`);
  const perm = usePerm();
  const [d, setD] = useState<Decision>(null);
  const [done, setDone] = useState("");
  const actions = (c: Client): ReactNode => (
    <span className="row-actions">
      {c.status === "pending" && perm.can("POST /api/v1/clients/{id}/approve") && (
        <button type="button" className="link" onClick={() => setD({ kind: "approve", client: c })}>
          Approve
        </button>
      )}
      {c.status === "pending" && perm.can("POST /api/v1/clients/{id}/deny") && (
        <button type="button" className="link" onClick={() => setD({ kind: "deny", client: c })}>
          Deny
        </button>
      )}
      {c.status === "approved" && c.registration === "dynamic" && perm.can("POST /api/v1/clients/{id}/revoke") && (
        <button type="button" className="link" onClick={() => setD({ kind: "revoke", client: c })}>
          Revoke
        </button>
      )}
    </span>
  );
  return (
    <Section title="Client registrations">
      <nav aria-label="Registration states" className="tabs">
        {states.map((s) => (
          <Link key={s} to={s === "all" ? "/remote" : `/remote?status=${s}`} aria-current={st === s ? "page" : undefined}>
            {s}
          </Link>
        ))}
      </nav>
      {done && <Done>{done}</Done>}
      <Loaded res={res} what="client registrations" route="/api/v1/clients">
        {(r) => (
          <DataTable
            caption="Client registrations"
            rows={r.clients}
            rowKey={(c) => c.client_id}
            initialSort="registered"
            initialDir="desc"
            empty="No remote client is registered. Dynamic registrations appear here as pending when a remote client registers on the remote listener."
            columns={[
              { key: "name", label: "Client", sort: (c) => c.client_name ?? c.client_id, render: (c) => <Link to={`/remote/clients/${encodeURIComponent(c.client_id)}`}>{c.client_name || <Mono>{c.client_id}</Mono>}</Link> },
              { key: "status", label: "Status", sort: (c) => c.status, render: (c) => <StateLabel tone={statusTone(c.status)}>{c.status}</StateLabel> },
              { key: "reg", label: "Registration", sort: (c) => c.registration, render: (c) => c.registration },
              { key: "principal", label: "Principal", sort: (c) => c.principal ?? "", render: (c) => <Mono>{c.principal || ""}</Mono> },
              { key: "registered", label: "Registered", sort: (c) => c.registered_at ?? "", render: (c) => <Time value={c.registered_at} /> },
              { key: "src", label: "Source address", render: (c) => <Mono>{c.source_address ?? ""}</Mono> },
              { key: "act", label: "Actions", render: actions },
            ]}
          />
        )}
      </Loaded>
      <DecideDialog d={d} onClose={() => setD(null)} onDone={(m) => { setDone(m); res.reload(); }} />
    </Section>
  );
}

function ClientDetail({ id }: { id: string }) {
  const res = useResource<Client>(`/api/v1/clients/${encodeURIComponent(id)}`);
  const opt = (v?: string): ReactNode => (v ? <Mono>{v}</Mono> : <span className="muted">none</span>);
  return (
    <>
      <Crumbs items={[["Remote access", "/remote"], [id.length > 24 ? id.slice(0, 20) + "…" : id, null]]} />
      <PageHeader code="G-11" title="Remote client">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the client" route="/api/v1/clients/{id}">
        {(c) => (
          <Section title="Registration">
            <KV
              rows={[
                ["Status", <StateLabel tone={statusTone(c.status)}>{c.status}</StateLabel>],
                ["Declared name (unverified)", c.client_name || <span className="muted">none</span>],
                ["Registration", c.registration],
                ["Principal", opt(c.principal)],
                ["Redirect URIs", <Mono>{(c.redirect_uris ?? []).join(" ")}</Mono>],
                ["Grant types", <Mono>{(c.grant_types ?? []).join(" ")}</Mono>],
                ["Token endpoint authentication", opt(c.token_endpoint_auth_method)],
                ["Software (unverified)", opt([c.software_id, c.software_version].filter(Boolean).join(" "))],
                ["Source address", <>{opt(c.source_address)} {c.source_address_source && <span className="muted">({c.source_address_source})</span>}</>],
                ["Registered", <Time value={c.registered_at} />],
                ["Decided", c.decided_at ? <><Time value={c.decided_at} /> by <Mono>{c.decided_by}</Mono></> : <span className="muted">not yet</span>],
              ]}
            />
          </Section>
        )}
      </Loaded>
    </>
  );
}

export function Remote({ path }: { path: string }) {
  const m = match("/remote/clients/:id", path);
  const perm = usePerm();
  if (m?.id) return <ClientDetail id={m.id} />;
  return (
    <>
      <PageHeader code="G-11" title="Remote access">
        <p>The Remote Access Profile, which lets cloud agents reach this Gateway through a tunnel, and the OAuth clients registered on it.</p>
      </PageHeader>
      <Help>
        <p>
          Remote access is off by default. When it is on, a separate listener serves MCP behind a tunnel at the public URL. A client that registers itself stays
          <strong> pending</strong> until an Administrator or Session Approver approves it here and binds it to a principal. Revoking ends its sessions.
        </p>
      </Help>
      {perm.can("GET /api/v1/remote") && <Profile />}
      {perm.can("GET /api/v1/clients") && <Clients />}
    </>
  );
}
