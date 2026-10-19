// G-10 Servers and library: configured servers with their state, revision
// and manifest source, the tools each offers, the public catalog per
// Session Allow template, and signed packages when E-13 is installed.
import { useState } from "react";
import { useResource } from "../data";
import { Link, match } from "../router";
import type { Catalog, ServerView, ToolView } from "../types";
import { Crumbs, DataTable, Help, JsonBlock, KV, Loaded, Mono, PageHeader, Section, ShortId, StateLabel, toneOf, type Column } from "../ui";
import { LibrarySections, PackageDetail } from "./Library";

function Tabs({ current }: { current: "servers" | "library" | "catalog" }) {
  return (
    <nav aria-label="Servers and library sections" className="tabs">
      <Link to="/servers" aria-current={current === "servers" ? "page" : undefined}>
        Servers
      </Link>
      <Link to="/library" aria-current={current === "library" ? "page" : undefined}>
        Library and trust anchors
      </Link>
      <Link to="/catalog" aria-current={current === "catalog" ? "page" : undefined}>
        Tool catalog
      </Link>
    </nav>
  );
}

function ServerList() {
  const res = useResource<{ servers: ServerView[] }>("/api/v1/servers");
  const columns: Column<ServerView>[] = [
    { key: "alias", label: "Alias", sort: (s) => s.alias, render: (s) => <Link to={`/servers/${encodeURIComponent(s.alias)}`}><Mono>{s.alias}</Mono></Link> },
    { key: "state", label: "State", sort: (s) => s.state, render: (s) => <StateLabel tone={toneOf(s.state)}>{s.state.replace("_", " ")}</StateLabel> },
    {
      key: "manifest",
      label: "Manifest",
      sort: (s) => String(s.verified),
      render: (s) => (s.verified ? <StateLabel tone="ok">verified</StateLabel> : <StateLabel tone="warn">unverified ({s.manifest_source || "live"})</StateLabel>),
    },
    { key: "revision", label: "Revision", sort: (s) => s.revision ?? "", render: (s) => <ShortId id={s.revision ?? ""} /> },
    { key: "tools", label: "Tools", sort: (s) => s.tool_count, render: (s) => <Mono>{s.tool_count}</Mono>, className: "num" },
    { key: "era", label: "Protocol", sort: (s) => s.era ?? "", render: (s) => <Mono>{s.era}</Mono> },
    { key: "launcher", label: "Launcher", sort: (s) => s.launcher, render: (s) => <>{s.launcher}{s.confined ? "" : <span className="muted"> (unconfined)</span>}</> },
  ];
  return (
    <Section title="Servers">
      <Loaded res={res} what="servers" route="/api/v1/servers">
        {(d) => (
          <DataTable
            caption="Servers"
            columns={columns}
            rows={d.servers}
            rowKey={(s) => s.alias}
            initialSort="alias"
            empty="No server is configured. Add a [[server]] table to smcp.toml, or package one with smcpctl package, then restart smcpd."
          />
        )}
      </Loaded>
    </Section>
  );
}

function ServerDetail({ alias }: { alias: string }) {
  const res = useResource<{ server: ServerView; tools: ToolView[] }>(`/api/v1/servers/${encodeURIComponent(alias)}`);
  const [schema, setSchema] = useState<string | null>(null);
  return (
    <>
      <Crumbs items={[["Servers and library", "/servers"], [alias, null]]} />
      <PageHeader code="G-10" title={`Server ${alias}`}>
        <p>Launch specification, recorded revision and tools of this server.</p>
      </PageHeader>
      <Loaded res={res} what="the server" route="/api/v1/servers/{alias}">
        {({ server: s, tools }) => (
          <>
            <Section title="Launch">
              <KV
                rows={[
                  ["State", <StateLabel tone={toneOf(s.state)}>{s.state.replace("_", " ")}</StateLabel>],
                  ["Revision", <Mono>{s.revision || "none"}</Mono>],
                  ["Manifest", s.verified ? "verified package manifest" : `unverified: tool list read from the running server (${s.manifest_source || "live"})`],
                  ["Protocol version", <Mono>{s.era || "unknown"}</Mono>],
                  ["Argument vector", <Mono>{[s.command, ...s.args].join(" ")}</Mono>],
                  ["Working directory", s.dir ? <Mono>{s.dir}</Mono> : <span className="muted">default</span>],
                  ["Environment keys", s.env_keys.length ? <Mono>{s.env_keys.join(" ")}</Mono> : <span className="muted">none</span>],
                  ["Secret slots", s.secret_slots.length ? <Mono>{s.secret_slots.join(" ")}</Mono> : <span className="muted">none</span>],
                  ["Risk classes", s.risk_classes.length ? <Mono>{s.risk_classes.join(" ")}</Mono> : <span className="muted">none declared</span>],
                  ["Launcher", <>{s.launcher} {s.confined ? "(confined)" : "(unconfined: runs as your user without a sandbox)"}</>],
                  ["Oversized frames dropped", <Mono>{s.oversized_frames}</Mono>],
                ]}
              />
            </Section>
            <Section title="Tools">
              <DataTable
                caption={`Tools of ${alias}`}
                rows={tools}
                rowKey={(t) => t.name}
                initialSort="name"
                empty="This server offers no tools. Its tools appear here when it lists them at start or a package manifest names them."
                columns={[
                  { key: "name", label: "Tool", sort: (t) => t.name, render: (t) => <Mono>{t.name}</Mono> },
                  { key: "public", label: "Public name", sort: (t) => t.public_name, render: (t) => <Mono>{t.public_name}</Mono> },
                  { key: "desc", label: "Description", render: (t) => <span className="clamp">{t.description || t.title || ""}</span> },
                  {
                    key: "schema",
                    label: "Input schema",
                    render: (t) => (
                      <button type="button" className="link" aria-expanded={schema === t.name} onClick={() => setSchema(schema === t.name ? null : t.name)}>
                        {schema === t.name ? "Hide" : "Show"}
                      </button>
                    ),
                  },
                ]}
              />
              {schema && <JsonBlock value={tools.find((t) => t.name === schema)?.input_schema ?? {}} label={`Input schema of ${schema}`} />}
            </Section>
          </>
        )}
      </Loaded>
    </>
  );
}

function CatalogView() {
  const res = useResource<Catalog>("/api/v1/catalog");
  return (
    <>
      <PageHeader code="G-10" title="Tool catalog">
        <p>The public tools a session is offered, per Session Allow template of the active policy.</p>
      </PageHeader>
      <Help>
        <p>
          Each table lists the tools one template grants: the public name a harness sees, the server and rule behind it, whether calls need approval and which
          optional filters run. A tool marked as not offered is named by a rule but no running server provides it. Change the grants in the Policy studio (G-02).
        </p>
      </Help>
      <Tabs current="catalog" />
      <Loaded res={res} what="the catalog" route="/api/v1/catalog">
        {(c) => (
          <>
            <p className="small">
              Policy revision <Mono>{c.policy_revision || "none"}</Mono>. A tool is offered only when a rule of the session's template names it and a running
              server provides it.
            </p>
            {c.templates.length === 0 && <p className="empty">The active policy defines no template. Add one to policy.json and reload the policy.</p>}
            {c.templates.map((t) => (
              <Section key={t.name} title={`Template ${t.name}`} actions={<span className="small muted">profiles: {t.profiles.join(", ") || "none"}{t.default_for.length ? `; default for ${t.default_for.join(", ")}` : ""}</span>}>
                <DataTable
                  caption={`Tools of template ${t.name}`}
                  rows={t.tools}
                  rowKey={(g) => g.public_name}
                  initialSort="public"
                  empty="This template grants no tools."
                  columns={[
                    { key: "public", label: "Public name", sort: (g) => g.public_name, render: (g) => <Mono>{g.public_name}</Mono> },
                    { key: "server", label: "Server", sort: (g) => g.server, render: (g) => <Link to={`/servers/${encodeURIComponent(g.server)}`}><Mono>{g.server}</Mono></Link> },
                    { key: "rule", label: "Rule", sort: (g) => g.rule_id, render: (g) => <Mono>{g.rule_id}</Mono> },
                    { key: "approval", label: "Approval", sort: (g) => String(g.approval), render: (g) => (g.approval ? <StateLabel tone="pending">required</StateLabel> : "no") },
                    { key: "filters", label: "Filters", render: (g) => (g.filters.length ? <Mono>{g.filters.join(" ")}</Mono> : <span className="muted">mandatory only</span>) },
                    { key: "avail", label: "Offered", sort: (g) => String(g.available), render: (g) => (g.available ? "yes" : <StateLabel tone="warn">no server provides it</StateLabel>) },
                  ]}
                />
              </Section>
            ))}
          </>
        )}
      </Loaded>
    </>
  );
}

export function Servers({ path }: { path: string }) {
  const m = match("/servers/:alias", path);
  if (m?.alias) return <ServerDetail alias={m.alias} />;
  const pk = match("/library/:id/:rev", path);
  if (pk?.id && pk.rev) return <PackageDetail id={pk.id} rev={pk.rev} />;
  if (path === "/catalog") return <CatalogView />;
  if (path === "/library")
    return (
      <>
        <PageHeader code="G-10" title="Library and trust anchors">
          <p>Signed package revisions, their state and attestation, the actions that change it, and the keys allowed to sign packages.</p>
        </PageHeader>
        <Help>
          <p>
            A revision is <strong>enabled</strong> (it runs under its alias), <strong>verified-disabled</strong> (suspended; it can be enabled again),{" "}
            <strong>retired</strong> (final) or <strong>revoked</strong> (by a signed revocation entry). A running server that drifts from its signed manifest or
            whose manifest expires is suspended; the reason is shown under packaged servers. Enabling usually needs a restart of smcpd. A trust anchor is
            enrolled in two steps: the console first shows the key's fingerprint, and enrolls it only after you confirm that the key ID matches the one the
            publisher gave you.
          </p>
        </Help>
        <Tabs current="library" />
        <LibrarySections />
      </>
    );
  return (
    <>
      <PageHeader code="G-10" title="Servers and library">
        <p>Backend MCP servers this Gateway launches, how they were verified and what they offer.</p>
      </PageHeader>
      <Help>
        <p>
          A server is enabled by a [[server]] table in smcp.toml. Until signed packages (E-13) are installed, tool definitions are read from the running
          server and the server is marked unverified, which also puts the Gateway in the degraded state. The catalog shows which tools each policy template
          offers.
        </p>
      </Help>
      <Tabs current="servers" />
      <ServerList />
    </>
  );
}
