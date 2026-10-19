import Link from "next/link";
import { DocHead, Note, SampleNotice } from "@/components/Sheet";
import { allDocs, readDoc } from "@/lib/content";
import { Inline } from "@/lib/inline";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements } from "@/lib/parse-reqs";
import { loadSecurity } from "@/lib/parse-sec";
import { loadFlows } from "@/lib/flows";
import { loadStatus } from "@/lib/status";
import { loadMatrix } from "@/lib/matrix";
import { loadOpenApi } from "@/lib/openapi";
import { loadReleases } from "@/lib/release";
import { CHAPTERS, buildCommit, fmtDateTime, fmtPct, shortSha } from "@/lib/site";
import { SYSTEM_MAP_HREF, loadSystemMap } from "@/lib/system-map";

/** The README's opening paragraph: what the system is. */
function readmeIntro(): string {
  const md = readDoc("README.md");
  const body = md.replace(/^# .*\n+/, "");
  const para = body.split(/\n\s*\n/).find((p) => p.trim() && !p.startsWith("#") && !p.startsWith("**"));
  if (!para) throw new Error("README.md: no opening paragraph after the title.");
  return para.replace(/\s*\n\s*/g, " ").trim();
}

export default function Home() {
  const arch = loadArch();
  const { reqs } = loadRequirements();
  const { controls } = loadSecurity();
  const flows = loadFlows();
  const snap = loadStatus();
  const s = snap.status;
  const implemented = s.elements.filter((e) => e.implementation === "implemented").length;
  const partialEl = s.elements.filter((e) => e.implementation === "partial").length;
  const r = s.requirements;
  const matrix = loadMatrix();
  const api = loadOpenApi();
  const releases = loadReleases();
  const map = loadSystemMap();
  const acc = s.acceptance;
  const perf = s.performance;
  const agentRows = s.agents.filter((a) => !a.mode.includes("+"));
  const agentsPassing = agentRows.filter((a) => a.result === "pass").length;

  const counts: Record<string, string> = {
    "/status/": `${s.tests.passed} of ${s.tests.total} tests passing`,
    "/flows/": `${flows.length} flows, ${flows.reduce((a, f) => a + f.diagrams.length, 0)} diagrams`,
    "/architecture/": `revision ${arch.revision.split(/\s/)[0]}, ${arch.date}`,
    "/elements/": `${arch.elements.length} elements in ${arch.subsystems.length} subsystems`,
    "/interfaces/": `${arch.external.length} external, ${arch.internal.length} internal, ${arch.stores.length} stores`,
    "/requirements/": `${reqs.length} requirements`,
    "/security/": `${controls.length} controls`,
    "/clients/": `${matrix.clients.length} clients, ${agentsPassing} passing`,
    "/docs/": `${allDocs().length} documents`,
    "/control-api/": `${api.operations.length} operations`,
    "/install/": releases.releases[0] ? `latest ${releases.releases[0].tag}` : releases.source === "remote" ? "no release yet" : "release list unavailable",
  };

  return (
    <article className="sheet">
      <DocHead
        title="Secure MCP Gateway"
        left={["Technical reference", "Built from the repository on each push to main"]}
        right={[
          `build ${buildCommit()}`,
          snap.source === "remote" ? `status ${shortSha(s.commit)}` : "status: sample data",
          fmtDateTime(s.generatedAt),
        ]}
      >
        <p>
          <Inline text={readmeIntro()} linkIds={false} />
        </p>
      </DocHead>

      <SampleNotice snap={snap} />

      <section aria-labelledby="now-h">
        <h2 id="now-h" className="visually-hidden">
          Current status
        </h2>
        <Note label="Source">
          <p>
            {snap.source === "remote" ? (
              <>
                From the CI run at <a href={s.commitUrl}>{shortSha(s.commit)}</a>
                {s.runUrl && (
                  <>
                    {" "}
                    (<a href={s.runUrl}>run</a>)
                  </>
                )}
                .
              </>
            ) : (
              <>From site/data/status.sample.json.</>
            )}
          </p>
        </Note>
        <p className="statusline">
          {snap.source === "sample" ? "Sample figures. " : `At ${shortSha(s.commit)}, ${fmtDateTime(s.generatedAt)}: `}
          {implemented} of {arch.elements.length} elements implemented and {partialEl} partly implemented.{" "}
          {r.verified} of {r.total} requirements verified by test, {r.partial} partly verified, {r.failing}{" "}
          failing. {s.tests.passed} of {s.tests.total} tests passed
          {s.tests.failed ? `, ${s.tests.failed} failed` : ""}; statement coverage {fmtPct(s.coverage.totalPct)}.
        </p>
        <p className="statusline">
          {acc ? (
            <>
              <Link href="/status/#acceptance">Acceptance</Link>: {acc.enforcedPassed} of {acc.total} scenarios pass
              in the Enforced profile and {acc.standalonePassed} in the Standalone profile; release label &quot;
              {acc.label}&quot;.{" "}
            </>
          ) : (
            <>No acceptance results in this run. </>
          )}
          {perf ? (
            <>
              <Link href="/status/#performance">Performance</Link>: {perf.measurements.filter((m) => m.pass).length} of{" "}
              {perf.measurements.length} measurements within budget
              {perf.referenceHardware ? " on reference hardware" : " on a CI runner, not reference hardware"}.{" "}
            </>
          ) : null}
          <Link href="/clients/">Agents</Link>: {agentsPassing} of {agentRows.length} agent CLIs pass through the
          Gateway.{" "}
          <Link href="/install/#verify">Releases</Link>: {releases.releases[0] ? `latest ${releases.releases[0].tag}` : "none listed"}.
        </p>
      </section>

      <p className="sysmap-callout">
        <Link href={SYSTEM_MAP_HREF}>
          <strong>System map</strong>
        </Link>
        : the whole Gateway in one flowchart, from installation and start-up through a tool call to the evidence it
        leaves and day-2 operations, in {map.stages.length} stages with element IDs, pan and zoom.
      </p>

      <section aria-labelledby="contents-h">
        <h2 id="contents-h">Contents</h2>
        <div className="table-wrap wide">
          <table className="contents">
            <thead>
              <tr>
                <th scope="col" className="num">
                  No.
                </th>
                <th scope="col">Chapter</th>
                <th scope="col">What it holds</th>
                <th scope="col" className="num">
                  Extent
                </th>
              </tr>
            </thead>
            <tbody>
              {CHAPTERS.map((c) => (
                <tr key={c.href}>
                  <td className="num">{c.n}</td>
                  <td>
                    <Link href={c.href}>{c.label}</Link>
                  </td>
                  <td>{c.about}</td>
                  <td className="num">{counts[c.href]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </article>
  );
}
