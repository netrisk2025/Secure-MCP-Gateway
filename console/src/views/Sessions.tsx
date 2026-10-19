// G-11 Sessions and principals (FR-8.19): harness sessions with inspect,
// suspend, resume and terminate; principals of smcp.toml and of the
// principal directory with create, suspend and enable; OAuth client
// credentials with issue (the secret is shown once) and revoke; Session
// Approver accounts.
import { useState, type ReactNode } from "react";
import { post } from "../api";
import { useNow, useResource } from "../data";
import { usePerm } from "../perm";
import { Link, match } from "../router";
import type { PrincipalDirectory, Principals, SessionApprovers, SessionView } from "../types";
import { Crumbs, DataTable, Dialog, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, ShortId, StateLabel, TextField, Time, toneOf, useAction, type Column } from "../ui";

function SessionList() {
  const res = useResource<{ sessions: SessionView[] }>("/api/v1/sessions");
  const now = useNow(5000);
  const columns: Column<SessionView>[] = [
    { key: "id", label: "Session", sort: (s) => s.id, render: (s) => <Link to={`/sessions/${s.id}`}><ShortId id={s.id} /></Link> },
    { key: "state", label: "State", sort: (s) => s.state, render: (s) => <StateLabel tone={toneOf(s.state)}>{s.state}</StateLabel> },
    { key: "principal", label: "Principal", sort: (s) => s.principal_id, render: (s) => <Mono>{s.principal_id}</Mono> },
    { key: "client", label: "Client", sort: (s) => s.client_id ?? "", render: (s) => <Mono>{s.client_id}</Mono> },
    { key: "template", label: "Template", sort: (s) => s.template, render: (s) => <Mono>{s.template}</Mono> },
    { key: "approved", label: "Approved by", sort: (s) => s.approved_by ?? "", render: (s) => s.approved_by || <span className="muted">session API</span> },
    { key: "created", label: "Created", sort: (s) => s.created_at, render: (s) => <Time value={s.created_at} now={now} /> },
    { key: "idle", label: "Idle deadline", sort: (s) => s.idle_deadline ?? "", render: (s) => <Time value={s.idle_deadline} now={now} /> },
    { key: "rev", label: "Policy", sort: (s) => s.policy_revision ?? "", render: (s) => <Mono>{s.policy_revision}</Mono> },
  ];
  return (
    <Section title="Sessions">
      <Loaded res={res} what="sessions" route="/api/v1/sessions">
        {(d) => (
          <DataTable
            caption="Sessions"
            columns={columns}
            rows={d.sessions}
            rowKey={(s) => s.id}
            initialSort="created"
            initialDir="desc"
            empty="No harness is connected. A session appears here when a harness signs in through OAuth or the session API."
          />
        )}
      </Loaded>
    </Section>
  );
}

/** A confirmation dialog with a reason field that posts to one route. */
function ReasonDialog({
  open,
  title,
  text,
  action,
  danger,
  route,
  onClose,
  onDone,
}: {
  open: boolean;
  title: string;
  text: ReactNode;
  action: string;
  danger?: boolean;
  route: string;
  onClose: () => void;
  onDone: (r: unknown) => void;
}) {
  const [reason, setReason] = useState("");
  const act = useAction();
  return (
    <Dialog
      open={open}
      onClose={() => {
        act.reset();
        onClose();
      }}
      title={title}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void act.run(
            () => post(route, { reason: reason.trim() }),
            (r) => {
              setReason("");
              onDone(r);
            },
          );
        }}
      >
        <div>{text}</div>
        <label className="field">
          <span>Reason (recorded in the journal)</span>
          <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} autoFocus />
        </label>
        {act.error && <ErrorBlock error={act.error} />}
        <div className="dialog-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className={danger ? "btn-danger" : "btn-primary"} disabled={act.busy}>
            {action}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

type Row = PrincipalDirectory["principals"][number];
type Cred = Row["credentials"][number] & { principal: string };

function PrincipalDirectoryView() {
  const perm = usePerm();
  const res = useResource<PrincipalDirectory>("/api/v1/principals");
  const [dialog, setDialog] = useState<{ kind: "suspend" | "enable"; id: string } | { kind: "revoke"; id: string } | null>(null);
  const [done, setDone] = useState("");
  const did = encodeURIComponent(dialog?.id ?? "");
  const canCreate = perm.can("POST /api/v1/principals");
  const canSuspend = perm.can("POST /api/v1/principals/{id}/suspend");
  const canIssue = perm.can("POST /api/v1/principals/{id}/credentials");
  const canRevoke = perm.can("POST /api/v1/credentials/{client_id}/revoke");
  return (
    <Loaded res={res} what="principals" route="/api/v1/principals">
      {(d) => {
        const creds: Cred[] = d.principals.flatMap((p) => p.credentials.map((c) => ({ ...c, principal: p.id })));
        return (
          <>
            <Section title="Principals">
              {done && <Done>{done}</Done>}
              <DataTable
                caption="Principals"
                rows={d.principals}
                rowKey={(p) => p.id}
                initialSort="id"
                empty="No principal exists. Add one below or with a [[principal]] table in smcp.toml."
                columns={[
                  { key: "id", label: "Principal", sort: (p) => p.id, render: (p) => <Mono>{p.id}</Mono> },
                  { key: "name", label: "Display name", sort: (p) => p.display_name ?? "", render: (p) => p.display_name || <span className="muted">none</span> },
                  { key: "fw", label: "Framework", sort: (p) => p.framework, render: (p) => <Mono>{p.framework}</Mono> },
                  { key: "profile", label: "Framework profile", sort: (p) => p.profile, render: (p) => <Mono>{p.profile}</Mono> },
                  { key: "source", label: "Defined in", sort: (p) => p.source, render: (p) => (p.source === "file" ? "smcp.toml" : "console") },
                  {
                    key: "state",
                    label: "State",
                    sort: (p) => (p.enabled ? "enabled" : "suspended"),
                    render: (p) => (
                      <StateLabel tone={p.enabled ? "ok" : "bad"}>{p.enabled ? "enabled" : p.suspension ? "suspended" : "disabled in smcp.toml"}</StateLabel>
                    ),
                  },
                  { key: "active", label: "Active sessions", sort: (p) => p.active_sessions, render: (p) => <Mono>{p.active_sessions}</Mono>, className: "num" },
                  { key: "susp", label: "Suspended sessions", sort: (p) => p.suspended_sessions, render: (p) => <Mono>{p.suspended_sessions}</Mono>, className: "num" },
                  ...(canSuspend
                    ? [
                        {
                          key: "act",
                          label: "Action",
                          render: (p: Row) =>
                            p.suspension ? (
                              <button type="button" onClick={() => setDialog({ kind: "enable", id: p.id })}>
                                Enable {p.id}
                              </button>
                            ) : p.enabled ? (
                              <button type="button" className="btn-danger" onClick={() => setDialog({ kind: "suspend", id: p.id })}>
                                Suspend {p.id}
                              </button>
                            ) : null,
                        },
                      ]
                    : []),
                ]}
              />
            </Section>
            {canCreate && <AddPrincipal frameworks={d.frameworks} profiles={d.profiles} onDone={(id) => (setDone(`Created principal ${id}.`), res.reload())} />}
            <Section title="Credentials">
              <DataTable
                caption="Credentials"
                rows={creds}
                rowKey={(c) => c.client_id}
                initialSort="principal"
                empty="No OAuth client credential exists."
                columns={[
                  { key: "id", label: "Client ID", sort: (c) => c.client_id, render: (c) => <Mono>{c.client_id}</Mono> },
                  { key: "principal", label: "Principal", sort: (c) => c.principal, render: (c) => <Mono>{c.principal}</Mono> },
                  { key: "type", label: "Type", sort: (c) => String(c.confidential), render: (c) => (c.confidential ? "confidential" : "public") },
                  { key: "redirects", label: "Redirect URIs", render: (c) => <Mono>{c.redirect_uris.join(" ")}</Mono> },
                  { key: "source", label: "Defined in", sort: (c) => c.source, render: (c) => (c.source === "file" ? "smcp.toml" : "console") },
                  {
                    key: "state",
                    label: "State",
                    sort: (c) => (c.revoked_at ? "revoked" : "active"),
                    render: (c) => <StateLabel tone={c.revoked_at ? "bad" : "ok"}>{c.revoked_at ? "revoked" : "active"}</StateLabel>,
                  },
                  { key: "created", label: "Issued", sort: (c) => c.created_at ?? "", render: (c) => (c.created_at ? <Time value={c.created_at} /> : <span className="muted">file</span>) },
                  ...(canRevoke
                    ? [
                        {
                          key: "act",
                          label: "Action",
                          render: (c: Cred) =>
                            c.source === "console" && !c.revoked_at ? (
                              <button type="button" className="btn-danger" onClick={() => setDialog({ kind: "revoke", id: c.client_id })}>
                                Revoke {c.client_id}
                              </button>
                            ) : null,
                        },
                      ]
                    : []),
                ]}
              />
            </Section>
            {canIssue && <IssueCredential principals={d.principals.map((p) => p.id)} onDone={() => res.reload()} />}
            <ReasonDialog
              open={dialog?.kind === "suspend"}
              title={`Suspend principal ${dialog?.id ?? ""}`}
              text={<p>New sign-ins of this principal are refused and its active sessions are suspended. Enable it again to allow sign-ins.</p>}
              action="Suspend principal"
              danger
              route={`/api/v1/principals/${did}/suspend`}
              onClose={() => setDialog(null)}
              onDone={() => {
                setDone(`Suspended principal ${dialog?.id}.`);
                setDialog(null);
                res.reload();
              }}
            />
            <ReasonDialog
              open={dialog?.kind === "enable"}
              title={`Enable principal ${dialog?.id ?? ""}`}
              text={<p>The principal may sign in again. Its suspended sessions stay suspended until resumed one by one.</p>}
              action="Enable principal"
              route={`/api/v1/principals/${did}/enable`}
              onClose={() => setDialog(null)}
              onDone={() => {
                setDone(`Enabled principal ${dialog?.id}.`);
                setDialog(null);
                res.reload();
              }}
            />
            <ReasonDialog
              open={dialog?.kind === "revoke"}
              title={`Revoke credential ${dialog?.id ?? ""}`}
              text={<p>The client can no longer sign in or refresh, and every session it opened is terminated.</p>}
              action="Revoke credential"
              danger
              route={`/api/v1/credentials/${did}/revoke`}
              onClose={() => setDialog(null)}
              onDone={() => {
                setDone(`Revoked credential ${dialog?.id}.`);
                setDialog(null);
                res.reload();
              }}
            />
          </>
        );
      }}
    </Loaded>
  );
}

function AddPrincipal({ frameworks, profiles, onDone }: { frameworks: string[]; profiles: string[]; onDone: (id: string) => void }) {
  const [id, setId] = useState("");
  const [framework, setFramework] = useState(frameworks[0] ?? "other");
  const [name, setName] = useState("");
  const [profile, setProfile] = useState(profiles[0] ?? "");
  const act = useAction<{ id: string }>();
  return (
    <Section title="Add a principal">
      <form
        aria-label="Add a principal"
        onSubmit={(e) => {
          e.preventDefault();
          void act.run(
            () => post("/api/v1/principals", { id: id.trim(), framework, display_name: name.trim(), profile }),
            (p) => {
              setId("");
              setName("");
              onDone(p.id);
            },
          );
        }}
      >
        <p className="small">A principal is one framework instance. Its framework profile (from the active policy) decides which Session Allow templates it may use.</p>
        <div className="rule-grid">
          <TextField label="Principal ID" value={id} onChange={setId} required mono hint="lowercase letters, digits, dot, dash or underscore" />
          <SelectField label="Framework" value={framework} onChange={setFramework} options={frameworks} />
          <TextField label="Display name" value={name} onChange={setName} />
          <SelectField label="Framework profile" value={profile} onChange={setProfile} options={profiles} />
        </div>
        {act.error && <ErrorBlock error={act.error} doing="creating the principal" />}
        <button type="submit" className="btn-primary" disabled={act.busy || !profile}>
          Create principal
        </button>
      </form>
    </Section>
  );
}

function IssueCredential({ principals, onDone }: { principals: string[]; onDone: () => void }) {
  const [principal, setPrincipal] = useState(principals[0] ?? "");
  const [redirects, setRedirects] = useState("http://127.0.0.1:51234/callback");
  const [confidential, setConfidential] = useState(false);
  const act = useAction<{ client_id: string; client_secret?: string; principal: string }>();
  return (
    <Section title="Issue a credential">
      <form
        aria-label="Issue a credential"
        onSubmit={(e) => {
          e.preventDefault();
          void act.run(
            () =>
              post(`/api/v1/principals/${encodeURIComponent(principal)}/credentials`, {
                redirect_uris: redirects
                  .split(/\s+/)
                  .map((s) => s.trim())
                  .filter(Boolean),
                confidential,
              }),
            onDone,
          );
        }}
      >
        <p className="small">
          A credential is an OAuth client bound to one principal. Public clients (harnesses on this machine) prove possession with PKCE; a confidential client also
          gets a secret, shown once.
        </p>
        <div className="rule-grid">
          <SelectField label="Principal" value={principal} onChange={setPrincipal} options={principals} />
          <TextField label="Redirect URIs (separated by spaces)" value={redirects} onChange={setRedirects} required mono hint="https, or http on 127.0.0.1, ::1 or localhost" />
        </div>
        <label className="check">
          <input type="checkbox" checked={confidential} onChange={(e) => setConfidential(e.target.checked)} />
          Confidential client (issue a client secret)
        </label>
        {act.error && <ErrorBlock error={act.error} doing="issuing the credential" />}
        {act.result && (
          <div className="notice notice-ok" role="status">
            <p>
              Issued client <Mono>{act.result.client_id}</Mono> for <Mono>{act.result.principal}</Mono>.
            </p>
            {act.result.client_secret && (
              <p>
                Client secret, shown only now: <Mono>{act.result.client_secret}</Mono>
              </p>
            )}
          </div>
        )}
        <button type="submit" className="btn-primary" disabled={act.busy || !principal}>
          Issue credential
        </button>
      </form>
    </Section>
  );
}

/** FR-2.23: the Administrator creates and removes Session Approver accounts. */
function SessionApproverAccounts() {
  const res = useResource<SessionApprovers>("/api/v1/approvers");
  const [removing, setRemoving] = useState("");
  const [done, setDone] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const act = useAction<{ username: string }>();
  const mismatch = repeat !== "" && password !== repeat;
  return (
    <>
      <Loaded res={res} what="Session Approvers" route="/api/v1/approvers">
        {(d) => (
          <Section title="Session Approvers">
            {done && <Done>{done}</Done>}
            <DataTable
              caption="Session Approver accounts"
              rows={d.approvers}
              rowKey={(a) => a.username}
              initialSort="user"
              empty="No Session Approver account exists, so no harness can sign in through OAuth. Create one below."
              columns={[
                { key: "user", label: "Username", sort: (a) => a.username, render: (a) => <Mono>{a.username}</Mono> },
                { key: "source", label: "Defined in", sort: (a) => a.source, render: (a) => (a.source === "file" ? "smcp.toml" : "console") },
                { key: "created", label: "Created", sort: (a) => a.created_at ?? "", render: (a) => (a.created_at ? <Time value={a.created_at} /> : <span className="muted">file</span>) },
                { key: "by", label: "Created by", sort: (a) => a.created_by ?? "", render: (a) => (a.created_by ? <Mono>{a.created_by}</Mono> : <span className="muted">file</span>) },
                {
                  key: "act",
                  label: "Action",
                  render: (a) =>
                    a.source === "console" ? (
                      <button type="button" className="btn-danger" onClick={() => setRemoving(a.username)}>
                        Remove {a.username}
                      </button>
                    ) : null,
                },
              ]}
            />
          </Section>
        )}
      </Loaded>
      <Section title="Add a Session Approver">
        <form
          aria-label="Add a Session Approver"
          onSubmit={(e) => {
            e.preventDefault();
            if (mismatch) return;
            void act.run(
              () => post("/api/v1/approvers", { username: username.trim(), password }),
              (a) => {
                setUsername("");
                setPassword("");
                setRepeat("");
                setDone(`Created Session Approver ${a.username}.`);
                res.reload();
              },
            );
          }}
        >
          <p className="small">
            A Session Approver signs harnesses in at the Gateway's sign-in page and can use nothing else. Give it its own password: the Gateway refuses the
            Administrator's password.
          </p>
          <div className="rule-grid">
            <TextField label="Username" value={username} onChange={setUsername} required mono hint="lowercase letters, digits, dot, dash or underscore" />
            <TextField label="Password" type="password" autoComplete="new-password" value={password} onChange={setPassword} required hint="12 or more characters, not the Administrator's" />
            <TextField label="Repeat password" type="password" autoComplete="new-password" value={repeat} onChange={setRepeat} required />
          </div>
          {mismatch && (
            <p className="notice notice-bad" role="alert">
              The two passwords differ.
            </p>
          )}
          {act.error && <ErrorBlock error={act.error} doing="creating the Session Approver" />}
          <button type="submit" className="btn-primary" disabled={act.busy || mismatch || password.length < 12}>
            Create Session Approver
          </button>
        </form>
      </Section>
      <ReasonDialog
        open={removing !== ""}
        title={`Remove Session Approver ${removing}`}
        text={<p>The account can no longer sign harnesses in, and its console sessions end. Sessions it approved earlier are not affected.</p>}
        action="Remove Session Approver"
        danger
        route={`/api/v1/approvers/${encodeURIComponent(removing)}/remove`}
        onClose={() => setRemoving("")}
        onDone={() => {
          setDone(`Removed Session Approver ${removing}.`);
          setRemoving("");
          res.reload();
        }}
      />
    </>
  );
}

/** The read-only principal tables of builds without the principal directory. */
function PrincipalTables({ withPrincipals, withApprovers }: { withPrincipals: boolean; withApprovers: boolean }) {
  const res = useResource<Principals>("/api/v1/sessions/principals");
  return (
    <Loaded res={res} what="principals" route="/api/v1/sessions/principals">
      {(d) => (
        <>
          {withPrincipals && (
            <>
              <Section title="Principals">
                <DataTable
                  caption="Principals"
                  rows={d.principals}
                  rowKey={(p) => p.id}
                  initialSort="id"
                  empty="No principal is configured. Add a [[principal]] table to smcp.toml."
                  columns={[
                    { key: "id", label: "Principal", sort: (p) => p.id, render: (p) => <Mono>{p.id}</Mono> },
                    { key: "name", label: "Display name", sort: (p) => p.display_name ?? "", render: (p) => p.display_name || <span className="muted">none</span> },
                    { key: "fw", label: "Framework", sort: (p) => p.framework, render: (p) => <Mono>{p.framework}</Mono> },
                    { key: "profile", label: "Framework profile", sort: (p) => p.profile, render: (p) => <Mono>{p.profile}</Mono> },
                    { key: "enabled", label: "Enabled", sort: (p) => String(p.enabled), render: (p) => <StateLabel tone={p.enabled ? "ok" : "bad"}>{p.enabled ? "enabled" : "disabled"}</StateLabel> },
                    { key: "active", label: "Active sessions", sort: (p) => p.active_sessions, render: (p) => <Mono>{p.active_sessions}</Mono>, className: "num" },
                  ]}
                />
              </Section>
              <Section title="OAuth clients">
                <DataTable
                  caption="OAuth clients"
                  rows={d.clients}
                  rowKey={(c) => c.client_id}
                  initialSort="principal"
                  empty="No OAuth client is registered."
                  columns={[
                    { key: "id", label: "Client ID", sort: (c) => c.client_id, render: (c) => <Mono>{c.client_id}</Mono> },
                    { key: "principal", label: "Principal", sort: (c) => c.principal, render: (c) => <Mono>{c.principal}</Mono> },
                    { key: "type", label: "Type", sort: (c) => String(c.confidential), render: (c) => (c.confidential ? "confidential" : "public") },
                    { key: "redirects", label: "Redirect URIs", render: (c) => <Mono>{c.redirect_uris.join(" ")}</Mono> },
                  ]}
                />
              </Section>
            </>
          )}
          {withApprovers && (
            <Section title="Session Approvers">
              <DataTable
                caption="Session Approver accounts"
                rows={d.session_approvers}
                rowKey={(a) => a.username}
                initialSort="user"
                empty="No Session Approver account exists, so no harness can sign in through OAuth. The Administrator creates one in this view or with smcpctl approvers add."
                columns={[{ key: "user", label: "Username", sort: (a) => a.username, render: (a) => <Mono>{a.username}</Mono> }]}
              />
            </Section>
          )}
        </>
      )}
    </Loaded>
  );
}

function SessionDetail({ id }: { id: string }) {
  const perm = usePerm();
  const res = useResource<SessionView>(`/api/v1/sessions/${encodeURIComponent(id)}`);
  const [open, setOpen] = useState<"terminate" | "suspend" | "resume" | null>(null);
  const [done, setDone] = useState("");
  const base = `/api/v1/sessions/${encodeURIComponent(id)}`;
  const state = res.status === "ok" ? res.data.state : "";
  const live = state === "active" || state === "suspended";
  return (
    <>
      <Crumbs items={[["Sessions and principals", "/sessions"], [`Session ${id.slice(0, 8)}`, null]]} />
      <PageHeader
        code="G-11"
        title="Session"
        actions={
          live ? (
            <>
              {state === "active" && perm.can("POST /api/v1/sessions/{id}/suspend") && (
                <button type="button" onClick={() => setOpen("suspend")}>
                  Suspend session
                </button>
              )}
              {state === "suspended" && perm.can("POST /api/v1/sessions/{id}/resume") && (
                <button type="button" onClick={() => setOpen("resume")}>
                  Resume session
                </button>
              )}
              {perm.can("POST /api/v1/sessions/{id}/terminate") && (
                <button type="button" className="btn-danger" onClick={() => setOpen("terminate")}>
                  Terminate session
                </button>
              )}
            </>
          ) : undefined
        }
      >
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      {done && <Done>{done}</Done>}
      <Loaded res={res} what="the session" route="/api/v1/sessions/{id}">
        {(s) => (
          <Section title="Binding" actions={<Link to={`/audit?session_id=${encodeURIComponent(s.id)}`}>Journal events of this session</Link>}>
            <KV
              rows={[
                ["State", <StateLabel tone={toneOf(s.state)}>{s.state}</StateLabel>],
                ...(s.end_reason ? ([["End reason", <Mono>{s.end_reason}</Mono>]] as [string, ReactNode][]) : []),
                ["Principal", <Mono>{s.principal_id}</Mono>],
                ["Framework", <Mono>{s.framework}</Mono>],
                ["Framework profile", <Mono>{s.profile}</Mono>],
                ["Client", <Mono>{s.client_id}</Mono>],
                ["Template", <Mono>{s.template}</Mono>],
                ["Policy revision", <Mono>{s.policy_revision}</Mono>],
                ["Purpose", s.purpose || <span className="muted">none</span>],
                ["Project", s.project || <span className="muted">none</span>],
                ["End user", s.end_user || <span className="muted">none</span>],
                ["Approved by", s.approved_by || <span className="muted">session API</span>],
                ["Harness version", s.harness_version || <span className="muted">not reported</span>],
                ["Listener", <Mono>{s.listener}</Mono>],
                ["Created", <Time value={s.created_at} />],
                ["Idle deadline", <Time value={s.idle_deadline} />],
                ["Maximum lifetime", <Time value={s.max_deadline} />],
                ...(s.ended_at ? ([["Ended", <Time value={s.ended_at} />]] as [string, ReactNode][]) : []),
              ]}
            />
          </Section>
        )}
      </Loaded>
      <ReasonDialog
        open={open === "terminate"}
        title="Terminate this session"
        text={<p>The harness loses access at once: its calls in flight are cancelled and its tokens stop working. It has to sign in again to continue.</p>}
        action="Terminate session"
        danger
        route={`${base}/terminate`}
        onClose={() => setOpen(null)}
        onDone={() => {
          setOpen(null);
          setDone("Terminated.");
          res.reload();
        }}
      />
      <ReasonDialog
        open={open === "suspend"}
        title="Suspend this session"
        text={<p>The harness's tokens are refused and its calls in flight are refused, until you resume the session. The session keeps its deadlines and expires as usual.</p>}
        action="Suspend session"
        route={`${base}/suspend`}
        onClose={() => setOpen(null)}
        onDone={() => {
          setOpen(null);
          setDone("Suspended.");
          res.reload();
        }}
      />
      <ReasonDialog
        open={open === "resume"}
        title="Resume this session"
        text={<p>The harness may use the session again with its current tokens.</p>}
        action="Resume session"
        route={`${base}/resume`}
        onClose={() => setOpen(null)}
        onDone={() => {
          setOpen(null);
          setDone("Resumed.");
          res.reload();
        }}
      />
    </>
  );
}

export function Sessions({ path }: { path: string }) {
  const perm = usePerm();
  const m = match("/sessions/:id", path);
  if (m?.id) return <SessionDetail id={m.id} />;
  const directory = perm.can("GET /api/v1/principals");
  const approvers = perm.can("POST /api/v1/approvers");
  return (
    <>
      <PageHeader code="G-11" title="Sessions and principals">
        <p>Harness sessions, the framework instances (principals) that may open them, their OAuth client credentials and the Session Approvers.</p>
      </PageHeader>
      <Help>
        <p>
          A session binds one principal to one Session Allow template for a bounded time. Suspending a session refuses its tokens and calls until it is resumed;
          terminating it cancels its calls and revokes its tokens, and the harness must sign in again. Principals and credentials created here are kept in the
          state directory and take effect at once; those in smcp.toml are edited there and can be suspended here. Session Approver accounts sign harnesses
          in and do nothing else; the Administrator creates and removes them here, each with its own password.
        </p>
      </Help>
      <SessionList />
      {directory && <PrincipalDirectoryView />}
      {approvers && <SessionApproverAccounts />}
      {(!directory || !approvers) && <PrincipalTables withPrincipals={!directory} withApprovers={!approvers} />}
    </>
  );
}
