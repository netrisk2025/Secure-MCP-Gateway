import Link from "next/link";
import { DocHead, Note, ReqBadge, SampleNotice, Sec } from "@/components/Sheet";
import { docExists } from "@/lib/content";
import { docPath, loadMatrix, resultFor, type MatrixClient } from "@/lib/matrix";
import { loadStatus, type AgentResult } from "@/lib/status";
import { buildCommit, chapter, plural, shortSha } from "@/lib/site";

export const metadata = { title: "Agents" };

const CH = chapter("/clients/");

type Row = { c: MatrixClient; r?: AgentResult; result: "pass" | "fail" | "not-run" };

function Mark({ result }: { result: Row["result"] }) {
  if (result === "pass") return <ReqBadge status="verified" text="pass" />;
  if (result === "fail") return <ReqBadge status="failing" text="fail" />;
  return <ReqBadge status="unverified" text="not run" />;
}

function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function Mech({ m }: { m: { mechanism: string | null; confirm: boolean } }) {
  if (!m.mechanism) return <span className="nil">none documented</span>;
  return (
    <>
      {m.mechanism}
      {m.confirm ? " (from vendor documentation, not yet confirmed at a pinned version)" : ""}
    </>
  );
}

export default function AgentsPage() {
  const matrix = loadMatrix();
  const snap = loadStatus();
  const s = snap.status;
  const rows: Row[] = matrix.clients.map((c) => {
    const r = resultFor(c, s.agents);
    const raw = r?.result ?? (c.runsOn === "local" ? "not-run" : (c.lastResult as Row["result"]));
    return { c, r, result: raw === "pass" || raw === "fail" ? raw : "not-run" };
  });
  const local = rows.filter((x) => x.c.runsOn === "local");
  const cloud = rows.filter((x) => x.c.runsOn !== "local");
  const count = (rs: Row[], k: Row["result"]) => rs.filter((x) => x.result === k).length;

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Agents"
        left={["Secure MCP Gateway", "Real-agent conformance", `Client matrix updated ${matrix.updated}`]}
        right={[
          snap.source === "remote" ? `results at ${shortSha(s.commit)}` : "results: sample data",
          `${count(local, "pass")} of ${local.length} local clients pass`,
          `site build ${buildCommit()}`,
        ]}
      >
        <p>
          Shipping agent CLIs signed in to a running Gateway and driven through six scenarios: sign-in, catalog, an
          allowed call, a denied call, an approval-obligated call and an ungranted tool. Every verdict comes from the
          evidence journal, never from what the model says. Cloud agents reach the Gateway only through the Remote
          Access Profile.
        </p>
      </DocHead>

      <SampleNotice snap={snap} />

      <Sec no={`${CH.n}.1`} id="results" title="Results">
        <Note label="Totals">
          <p>
            Local: {count(local, "pass")} pass, {count(local, "fail")} fail, {count(local, "not-run")} not run. Cloud:{" "}
            {count(cloud, "pass")} pass, {count(cloud, "not-run")} not run, of {plural(cloud.length, "agent")}.
          </p>
        </Note>
        <p>
          Local clients: the latest run of the &quot;Real agents&quot; workflow from the status data. Cloud agents: the
          dated manual record of <code>docs/clients/matrix.json</code> (FR-15.9). The method is in{" "}
          <Link href="/docs/agents-conformance/">the conformance suite</Link>.
        </p>
        <div className="table-wrap wide">
          <table>
            <caption>Every client of SRS Appendix K, in matrix order.</caption>
            <thead>
              <tr>
                <th scope="col">Client</th>
                <th scope="col">Runs on</th>
                <th scope="col">Version</th>
                <th scope="col">Result</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ c, r, result }) => (
                <tr key={c.client}>
                  <th scope="row">
                    <a href={`#agent-${slug(c.client)}`}>{c.client}</a>
                    <span className="pkgs">{c.vendor}</span>
                  </th>
                  <td>{c.runsOn === "local" ? "local" : "vendor cloud"}</td>
                  <td className="id">{r?.version && r.version !== "-" ? r.version : (c.pinnedVersion ?? "not pinned")}</td>
                  <td>
                    <Mark result={result} />
                  </td>
                  <td>{r?.detail ?? (c.runsOn === "local" ? "No result in the status data." : `No dated run recorded${c.lastRun ? ` since ${c.lastRun}` : ""}.`)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${CH.n}.2`} id="notes" title="Per-agent notes">
        <p>
          How each client connects, how it trusts the Gateway&apos;s CA, how it can be locked to the Gateway, and why a
          client is not run. Mechanisms marked &quot;not yet confirmed&quot; come from vendor documentation.
        </p>
        {rows.map(({ c, r, result }) => (
          <section key={c.client} className="agent" aria-labelledby={`agent-${slug(c.client)}`}>
            <h3 id={`agent-${slug(c.client)}`}>
              {c.client} <Mark result={result} />
            </h3>
            {c.notes && <p>{c.notes}</p>}
            <dl className="facts">
              <dt>Connection</dt>
              <dd>{c.connectionMode ?? <span className="nil">to be confirmed</span>}</dd>
              <dt>Fallback</dt>
              <dd>{c.fallbackMode ?? <span className="nil">none</span>}</dd>
              <dt>Session</dt>
              <dd>{c.session ?? <span className="nil">to be confirmed</span>}</dd>
              <dt>CA trust</dt>
              <dd>
                <Mech m={c.caTrust} />
              </dd>
              <dt>Lockdown</dt>
              <dd>
                <Mech m={c.lockdown} />
              </dd>
              <dt>Last result</dt>
              <dd>{r ? `${r.result}, ${r.mode}, version ${r.version}` : c.lastRun ? `${c.lastResult}, ${c.lastRun}` : "not run"}</dd>
              <dt>Quick start</dt>
              <dd>{docExists(c.quickStart) ? <Link href={docPath(c.quickStart)}>{c.quickStart}</Link> : c.quickStart}</dd>
            </dl>
          </section>
        ))}
      </Sec>

      <Sec no={`${CH.n}.3`} id="remote" title="Cloud agents and the Remote Access Profile">
        <Note label="Status">
          <p>
            Tested against a local test tunnel in the Go tests. No cloud agent has been connected in a dated run, so
            every cloud agent is &quot;not run&quot;.
          </p>
        </Note>
        <p>
          Grok Bot, the ChatGPT agent and Meta Muse run on their vendors&apos; computers and cannot reach{" "}
          <code>127.0.0.1</code>. The Remote Access Profile (FR-16) publishes the Gateway&apos;s MCP endpoint through a
          tunnel (Tailscale Funnel, a Cloudflare quick tunnel, or one the operator runs) on a separate remote listener
          with its own bounds and per-client limits. An agent registers itself with RFC 7591 dynamic registration, which
          waits for the operator&apos;s approval (<code>smcpctl clients approve</code>), and then signs in through a
          Session Approver; an agent that can only run a command uses <code>smcp-connect</code> and the device grant.{" "}
          <code>smcpctl remote disable</code> ends every remote session and stops the tunnel.
        </p>
        <p>
          What the Gateway does not control: the agent&apos;s own browser, terminal and connector tools, and the tunnel
          provider, which can read the traffic. See <Link href="/docs/remote-access/">the Remote Access Profile</Link>,{" "}
          <Link href="/docs/clients/cloud-agents/">the cloud agent quick start</Link>,{" "}
          <Link href="/flows/cloud-agent-tunnel/">the cloud agent flow</Link> and{" "}
          <Link href="/docs/security-limitations/">security limitations</Link>.
        </p>
      </Sec>

      <Sec no={`${CH.n}.4`} id="background" title="Background">
        <p>
          What the harnesses expect from an MCP server, checked against their primary documentation, and where the
          specification changes to meet them, is in <Link href="/docs/client-compatibility/">the client compatibility
          brief</Link>. The matrix itself is <code>{"docs/clients/matrix.json"}</code>; quick starts per client are under{" "}
          <Link href="/docs/clients/">client quick starts</Link>.
        </p>
      </Sec>
    </article>
  );
}
