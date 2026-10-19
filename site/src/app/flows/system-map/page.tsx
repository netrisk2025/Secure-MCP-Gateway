import Link from "next/link";
import SystemMap from "@/components/SystemMap";
import { DocHead } from "@/components/Sheet";
import { renderMarkdown, stepTableHtml } from "@/lib/markdown";
import { REPO_URL, buildCommit, chapter, plural } from "@/lib/site";
import { SYSTEM_MAP_FILE, SYSTEM_MAP_SVG, loadSystemMap } from "@/lib/system-map";

const CH = chapter("/flows/");

export const metadata = { title: "System map, flows" };

export default async function SystemMapPage() {
  const m = loadSystemMap();
  const intro = await renderMarkdown(m.intro, { file: SYSTEM_MAP_FILE });
  const rest = await renderMarkdown(m.rest, { file: SYSTEM_MAP_FILE });
  const label = `${m.title}: flowchart of the whole Gateway in ${m.stages.length} stages with ${m.diagram.steps.length} edges. The table after the chart lists every edge.`;
  return (
    <>
      <article className="sheet">
        <DocHead
          chapter={CH.n}
          title={m.title}
          left={[
            <Link key="c" href="/flows/">
              {CH.n} Flows
            </Link>,
            "Flowchart of the whole product",
            <a key="s" href={`${REPO_URL}/blob/main/${SYSTEM_MAP_FILE}`}>
              {SYSTEM_MAP_FILE}
            </a>,
          ]}
          right={[plural(m.stages.length, "stage"), plural(m.diagram.steps.length, "edge"), `site build ${buildCommit()}`]}
        />
        <div className="prose flow-body" dangerouslySetInnerHTML={{ __html: intro }} />
        <p className="sysmap-download">
          <a href={SYSTEM_MAP_SVG} download="secure-mcp-gateway-system-map.svg">
            Download the chart as SVG
          </a>{" "}
          (static copy in light colors, drawn from the same source).
        </p>
      </article>
      <section className="sysmap-wrap" aria-label="System map chart">
        <SystemMap source={Buffer.from(m.source, "utf8").toString("base64")} stages={m.stages} label={label} />
      </section>
      <article className="sheet">
        <div className="prose flow-body" dangerouslySetInnerHTML={{ __html: rest }} />
        <details className="sysmap-edges">
          <summary>Every edge of the chart, in source order ({m.diagram.steps.length})</summary>
          <div dangerouslySetInnerHTML={{ __html: stepTableHtml(m.diagram, "Edges of the system map in the order they are written in the source.") }} />
        </details>
        <nav className="pager meta" aria-label="Other flows">
          <p>
            All flows: <Link href="/flows/">Flows</Link>
          </p>
        </nav>
      </article>
    </>
  );
}
