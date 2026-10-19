// Egress (E-18): broker limits, attached instances, effective grants and
// the connection log with filters. Routes: /api/v1/egress* (read-only).
import { useState } from "react";
import { useResource } from "../data";
import { DataTable, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, ShortId, StateLabel, TextField, Time, bytes } from "../ui";

interface EgressStatus {
  enabled: boolean;
  enforced_instances: number;
  advisory_instances: number;
  instances: { id: string; server: string; enforced: boolean; proxy: string; endpoints?: Record<string, string>; attached_at: string }[];
  limits: Record<string, number | string>;
}

interface Grant {
  server: string;
  host: string;
  ports: number[];
  methods: string[];
  class: string;
  addresses?: string[];
  endpoint_env?: string;
  request_bytes: number;
  response_bytes: number;
  timeout: string;
}

interface Conn {
  id: string;
  time: string;
  server: string;
  mode: string;
  method: string;
  host: string;
  port: number;
  path?: string;
  address?: string;
  address_class?: string;
  decision: string;
  reason?: string;
  detail?: string;
  bytes_up: number;
  bytes_down: number;
  duration_ms: number;
}

function ConnectionLog() {
  const [form, setForm] = useState({ server: "", decision: "", since: "", limit: "100" });
  const [q, setQ] = useState(form);
  const qs = new URLSearchParams(Object.entries(q).filter(([, v]) => v.trim()) as [string, string][]).toString();
  const res = useResource<{ connections: Conn[] }>(`/api/v1/egress/connections${qs ? `?${qs}` : ""}`);
  return (
    <Section title="Connection log">
      <form
        className="filters"
        aria-label="Connection filter"
        onSubmit={(e) => {
          e.preventDefault();
          setQ(form);
        }}
      >
        <TextField label="Server alias" value={form.server} onChange={(v) => setForm({ ...form, server: v })} mono />
        <SelectField label="Decision" value={form.decision} onChange={(v) => setForm({ ...form, decision: v })} options={[["", "any"], "allowed", "denied"]} />
        <TextField label="Since (RFC 3339)" value={form.since} onChange={(v) => setForm({ ...form, since: v })} mono />
        <TextField label="Limit (1 to 10000)" value={form.limit} onChange={(v) => setForm({ ...form, limit: v })} type="number" />
        <div className="filter-actions">
          <button type="submit" className="btn-primary">
            Apply filter
          </button>
        </div>
      </form>
      <Loaded res={res} what="egress connections" route="/api/v1/egress/connections">
        {(d) => (
          <DataTable
            caption="Egress connections"
            rows={d.connections}
            rowKey={(c) => c.id}
            initialSort="time"
            initialDir="desc"
            rowClass={(c) => (c.decision === "denied" ? "row-bad" : undefined)}
            empty="No egress operation matches. Operations appear when a server instance uses its proxy or endpoints."
            columns={[
              { key: "time", label: "Time", sort: (c) => c.time, render: (c) => <Time value={c.time} /> },
              { key: "server", label: "Server", sort: (c) => c.server, render: (c) => <Mono>{c.server}</Mono> },
              { key: "dest", label: "Destination", sort: (c) => c.host, render: (c) => <Mono>{c.method} {c.host}:{c.port}{c.path ?? ""}</Mono> },
              { key: "addr", label: "Address", render: (c) => <Mono>{c.address ?? ""} {c.address_class ?? ""}</Mono> },
              { key: "decision", label: "Decision", sort: (c) => c.decision, render: (c) => <StateLabel tone={c.decision === "allowed" ? "ok" : "bad"}>{c.decision}</StateLabel> },
              { key: "reason", label: "Reason", render: (c) => <Mono>{c.reason ?? ""}</Mono> },
              { key: "up", label: "Sent", sort: (c) => c.bytes_up, render: (c) => <Mono>{bytes(c.bytes_up)}</Mono>, className: "num" },
              { key: "down", label: "Received", sort: (c) => c.bytes_down, render: (c) => <Mono>{bytes(c.bytes_down)}</Mono>, className: "num" },
              { key: "ms", label: "ms", sort: (c) => c.duration_ms, render: (c) => <Mono>{c.duration_ms}</Mono>, className: "num" },
            ]}
          />
        )}
      </Loaded>
    </Section>
  );
}

export function Egress() {
  const status = useResource<EgressStatus>("/api/v1/egress");
  const grants = useResource<{ grants: Grant[] }>("/api/v1/egress/grants");
  return (
    <>
      <PageHeader title="Egress">
        <p>Network destinations that server instances may reach through the Egress Broker (E-18), and what they reached.</p>
      </PageHeader>
      <Help>
        <p>
          Each grant names a server, a host, ports and methods. An instance reaches the network only through its broker proxy or endpoints; in the Enforced
          profile nftables drops everything else, in the Standalone profile the proxy variables are advisory. Every operation is journaled; this log shows the
          most recent ones held in memory.
        </p>
      </Help>
      <Section title="Broker">
        <Loaded res={status} what="the egress broker" route="/api/v1/egress">
          {(s) => (
            <>
              <KV
                rows={[
                  ["Enforced instances", <Mono>{s.enforced_instances}</Mono>],
                  ["Advisory instances", <Mono>{s.advisory_instances}</Mono>],
                  ...Object.entries(s.limits).map(([k, v]) => [k.replace(/_/g, " "), <Mono>{typeof v === "number" && k.endsWith("bytes") ? bytes(v) : String(v)}</Mono>] as [string, React.ReactNode]),
                ]}
              />
              <h3 className="sub">Attached instances</h3>
              <DataTable
                caption="Attached instances"
                rows={s.instances}
                rowKey={(i) => i.id}
                empty="No server instance is attached to the broker. An instance appears here when a server with an egress grant starts."
                columns={[
                  { key: "id", label: "Instance", render: (i) => <ShortId id={i.id} /> },
                  { key: "server", label: "Server", sort: (i) => i.server, render: (i) => <Mono>{i.server}</Mono> },
                  { key: "enf", label: "Confinement", sort: (i) => String(i.enforced), render: (i) => (i.enforced ? <StateLabel tone="ok">enforced</StateLabel> : <StateLabel tone="warn">advisory</StateLabel>) },
                  { key: "proxy", label: "Proxy", render: (i) => <Mono>{i.proxy}</Mono> },
                  { key: "at", label: "Attached", render: (i) => <Time value={i.attached_at} /> },
                ]}
              />
            </>
          )}
        </Loaded>
      </Section>
      <Section title="Grants">
        <Loaded res={grants} what="egress grants" route="/api/v1/egress/grants">
          {(d) => (
            <DataTable
              caption="Egress grants"
              rows={d.grants}
              rowKey={(g) => g.server + g.host + g.ports.join(",")}
              initialSort="server"
              empty="No server has an egress grant, so no instance can reach the network. A grant appears here when a server whose manifest declares egress destinations is enabled."
              columns={[
                { key: "server", label: "Server", sort: (g) => g.server, render: (g) => <Mono>{g.server}</Mono> },
                { key: "host", label: "Host", sort: (g) => g.host, render: (g) => <Mono>{g.host}</Mono> },
                { key: "ports", label: "Ports", render: (g) => <Mono>{g.ports.join(" ")}</Mono> },
                { key: "methods", label: "Methods", render: (g) => <Mono>{g.methods.join(" ")}</Mono> },
                { key: "class", label: "Class", sort: (g) => g.class, render: (g) => g.class },
                { key: "limits", label: "Limits", render: (g) => <Mono>{bytes(g.request_bytes)} / {bytes(g.response_bytes)} / {g.timeout}</Mono> },
              ]}
            />
          )}
        </Loaded>
      </Section>
      <ConnectionLog />
    </>
  );
}
