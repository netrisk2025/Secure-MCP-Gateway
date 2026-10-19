// Runtime monitor (E-15, E-17): launcher summary, the enforced-profile
// prerequisite checks, the instance table with resource use and runtime
// observations, an instance's launch specification and stderr tail, and
// the kill action. Routes: /api/v1/runtime*.
import { useState, type ReactNode } from "react";
import { post } from "../api";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Link, match } from "../router";
import { Crumbs, DataTable, Dialog, Done, ErrorBlock, Help, JsonBlock, KV, Loaded, Mono, PageHeader, Section, ShortId, StateLabel, TextField, Time, bytes, useAction, type Tone } from "../ui";

interface Usage {
  at: string;
  memory_current_bytes: number;
  memory_peak_bytes: number;
  cpu_usage_usec: number;
  pids: number;
  pids_peak: number;
  oom_events: number;
  oom_kills: number;
}

interface Instance {
  instance_id: string;
  alias: string;
  container: string;
  state: string;
  removed: boolean;
  scope: string;
  started: string;
  ended?: string;
  exit_code?: number;
  kill_reason?: string;
  oom_killed: boolean;
  deviations: number;
  usage?: Usage;
  launch_spec?: unknown;
  observations?: { at: string; kind: string; detail?: unknown }[];
}

const tone = (s: string): Tone => (s === "running" ? "ok" : s === "starting" ? "pending" : s === "killed" ? "bad" : "neutral");

function Summary() {
  const res = useResource<{ sandbox: string; launcher: string; confined: boolean; podman?: string; gateway_id?: string; defaults?: Record<string, unknown>; instances: number | Record<string, number> }>("/api/v1/runtime");
  const doctor = useResource<{ ready: boolean; checks: { id: string; name: string; status: string; detail?: string; remedy?: string }[] }>("/api/v1/runtime/doctor", { live: false });
  return (
    <>
      <Section title="Launcher">
        <Loaded res={res} what="the launcher" route="/api/v1/runtime">
          {(s) => (
            <KV
              rows={[
                ["Sandbox", s.sandbox === "none" ? <StateLabel tone="warn">none: servers run as your user</StateLabel> : <Mono>{s.sandbox}</Mono>],
                ["Launcher", <Mono>{s.launcher}</Mono>],
                ["Confined", s.confined ? <StateLabel tone="ok">confined</StateLabel> : <StateLabel tone="warn">unconfined</StateLabel>],
                ...(s.podman ? ([["Podman", <Mono>{s.podman}</Mono>]] as [string, ReactNode][]) : []),
                ["Instances", <Mono>{typeof s.instances === "number" ? s.instances : Object.entries(s.instances).map(([k, v]) => `${k} ${v}`).join(", ")}</Mono>],
                ...Object.entries(s.defaults ?? {}).map(([k, v]) => [`Default ${k.replace(/_/g, " ")}`, <Mono>{k.endsWith("bytes") && typeof v === "number" ? bytes(v) : String(v)}</Mono>] as [string, ReactNode]),
              ]}
            />
          )}
        </Loaded>
      </Section>
      <Section title="Enforced-profile prerequisites">
        <Loaded res={doctor} what="the prerequisite checks" route="/api/v1/runtime/doctor">
          {(d) => (
            <>
              <p>{d.ready ? <StateLabel tone="ok">this host can run the Enforced profile</StateLabel> : <StateLabel tone="warn">this host cannot run the Enforced profile yet</StateLabel>}</p>
              <DataTable
                caption="Prerequisite checks"
                rows={d.checks}
                rowKey={(c) => c.id}
                empty="No check ran. Run the prerequisite checks with smcpctl runtime doctor."
                columns={[
                  { key: "name", label: "Check", render: (c) => c.name },
                  { key: "status", label: "Result", sort: (c) => c.status, render: (c) => <StateLabel tone={c.status === "pass" ? "ok" : c.status === "warn" ? "warn" : "bad"}>{c.status}</StateLabel> },
                  { key: "detail", label: "Detail", render: (c) => <Mono>{c.detail ?? ""}</Mono> },
                  { key: "remedy", label: "Remedy", render: (c) => <Mono>{c.remedy ?? ""}</Mono> },
                ]}
              />
            </>
          )}
        </Loaded>
      </Section>
    </>
  );
}

function Instances() {
  const res = useResource<{ instances: Instance[] }>("/api/v1/runtime/instances");
  return (
    <Section title="Instances">
      <Loaded res={res} what="server instances" route="/api/v1/runtime/instances">
        {(d) => (
          <DataTable
            caption="Server instances"
            rows={d.instances}
            rowKey={(i) => i.instance_id}
            initialSort="started"
            initialDir="desc"
            rowClass={(i) => (i.deviations > 0 || i.oom_killed ? "row-bad" : undefined)}
            empty="No sandboxed instance exists. In the Standalone profile servers run without the sandbox and do not appear here."
            columns={[
              { key: "id", label: "Instance", render: (i) => <Link to={`/runtime/instances/${encodeURIComponent(i.instance_id)}`}><ShortId id={i.instance_id} /></Link> },
              { key: "alias", label: "Server", sort: (i) => i.alias, render: (i) => <Mono>{i.alias}</Mono> },
              { key: "state", label: "State", sort: (i) => i.state, render: (i) => <StateLabel tone={tone(i.state)}>{i.state}</StateLabel> },
              { key: "started", label: "Started", sort: (i) => i.started, render: (i) => <Time value={i.started} /> },
              { key: "mem", label: "Memory", sort: (i) => i.usage?.memory_current_bytes ?? 0, render: (i) => <Mono>{bytes(i.usage?.memory_current_bytes)}</Mono>, className: "num" },
              { key: "pids", label: "Processes", sort: (i) => i.usage?.pids ?? 0, render: (i) => <Mono>{i.usage?.pids ?? 0}</Mono>, className: "num" },
              { key: "dev", label: "Deviations", sort: (i) => i.deviations, render: (i) => <Mono>{i.deviations}</Mono>, className: "num" },
            ]}
          />
        )}
      </Loaded>
    </Section>
  );
}

function InstanceDetail({ id }: { id: string }) {
  const res = useResource<{ instance: Instance; stderr_tail: string }>(`/api/v1/runtime/instances/${encodeURIComponent(id)}`);
  const perm = usePerm();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const kill = useAction<{ state: string }>();
  return (
    <>
      <Crumbs items={[["Runtime", "/runtime"], [`Instance ${id.slice(0, 8)}`, null]]} />
      <PageHeader title="Server instance">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the instance" route="/api/v1/runtime/instances/{id}">
        {({ instance: i, stderr_tail }) => (
          <>
            <Section
              title="Instance"
              actions={
                i.state === "running" &&
                perm.can("POST /api/v1/runtime/instances/{id}/kill") && (
                  <button type="button" className="btn-danger" onClick={() => setOpen(true)}>
                    Kill this instance
                  </button>
                )
              }
            >
              {kill.result && <Done>The instance was killed.</Done>}
              <KV
                rows={[
                  ["State", <StateLabel tone={tone(i.state)}>{i.state}</StateLabel>],
                  ["Server", <Mono>{i.alias}</Mono>],
                  ["Container", <Mono>{i.container}</Mono>],
                  ["Scope", i.scope],
                  ["Started", <Time value={i.started} />],
                  ["Ended", <Time value={i.ended} />],
                  ["Exit code", i.exit_code === undefined ? <span className="muted">none</span> : <Mono>{i.exit_code}</Mono>],
                  ["Kill reason", i.kill_reason ?? <span className="muted">none</span>],
                  ["Out of memory", i.oom_killed ? <StateLabel tone="bad">killed</StateLabel> : "no"],
                  ["Memory now / peak", <Mono>{bytes(i.usage?.memory_current_bytes)} / {bytes(i.usage?.memory_peak_bytes)}</Mono>],
                  ["CPU time", <Mono>{((i.usage?.cpu_usage_usec ?? 0) / 1e6).toFixed(2)} s</Mono>],
                  ["Processes now / peak", <Mono>{i.usage?.pids ?? 0} / {i.usage?.pids_peak ?? 0}</Mono>],
                  ["Deviations", <Mono>{i.deviations}</Mono>],
                ]}
              />
            </Section>
            <Section title="Runtime observations">
              <DataTable
                caption="Runtime observations"
                rows={(i.observations ?? []).map((o, n) => ({ ...o, n }))}
                rowKey={(o) => String(o.n)}
                initialSort="at"
                initialDir="desc"
                rowClass={(o) => (o.kind === "deviation" ? "row-bad" : undefined)}
                empty="The Runtime Monitor has observed nothing for this instance."
                columns={[
                  { key: "at", label: "Time", sort: (o) => o.at, render: (o) => <Time value={o.at} /> },
                  { key: "kind", label: "Kind", sort: (o) => o.kind, render: (o) => <Mono>{o.kind}</Mono> },
                  { key: "detail", label: "Detail", render: (o) => <Mono>{JSON.stringify(o.detail ?? {})}</Mono> },
                ]}
              />
            </Section>
            <Section title="Launch specification and diagnostics">
              <JsonBlock value={i.launch_spec ?? {}} label="Launch specification" />
              <JsonBlock value={stderr_tail || "(empty)"} label="Standard error, last 64 KiB (server output, shown as text)" />
            </Section>
          </>
        )}
      </Loaded>
      <Dialog open={open} onClose={() => setOpen(false)} title="Kill this instance">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void kill.run(() => post(`/api/v1/runtime/instances/${encodeURIComponent(id)}/kill`, { reason: reason.trim() }), () => {
              setOpen(false);
              res.reload();
            });
          }}
        >
          <p>The container is killed at once. Calls in flight to it fail. The kill is recorded with your account and the reason.</p>
          <TextField label="Reason" value={reason} onChange={setReason} required />
          {kill.error && <ErrorBlock error={kill.error} />}
          <div className="dialog-actions">
            <button type="button" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn-danger" disabled={kill.busy || !reason.trim()}>
              Kill
            </button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

export function Runtime({ path }: { path: string }) {
  const m = match("/runtime/instances/:id", path);
  if (m?.id) return <InstanceDetail id={m.id} />;
  return (
    <>
      <PageHeader title="Runtime">
        <p>Server instances in the execution sandbox, their resource use and what the Runtime Monitor observed.</p>
      </PageHeader>
      <Help>
        <p>
          With <Mono>[runtime] sandbox = "podman"</Mono> each server runs in a rootless container with a read-only root, no capabilities and resource limits. A{" "}
          <strong>deviation</strong> is a process or exec the server's profile does not allow. The prerequisite checks say what this host lacks for the Enforced
          profile.
        </p>
      </Help>
      <Summary />
      <Instances />
    </>
  );
}
