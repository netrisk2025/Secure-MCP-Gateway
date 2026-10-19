import Link from "next/link";
import { DocHead, Note, Sec } from "@/components/Sheet";
import { loadFlows, flowSourceDir, type Flow } from "@/lib/flows";
import { buildCommit, chapter, plural } from "@/lib/site";
import { SYSTEM_MAP_HREF, SYSTEM_MAP_SLUG, loadSystemMap } from "@/lib/system-map";

export const metadata = { title: "Flows" };

const CH = chapter("/flows/");

function FlowTable({ flows, caption }: { flows: Flow[]; caption: string }) {
  return (
    <div className="table-wrap wide">
      <table>
        <caption>{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Flow</th>
            <th scope="col">Diagrams</th>
            <th scope="col" className="num">
              Steps
            </th>
            <th scope="col">Source</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((f) => (
            <tr key={f.slug}>
              <td>
                <Link href={`/flows/${f.slug}/`}>{f.title}</Link>
              </td>
              <td>
                {f.diagrams.length === 0
                  ? "none"
                  : f.diagrams.map((d) => (d.kind === "sequence" ? "sequence" : d.kind === "flowchart" ? "flowchart" : "other")).join(", ")}
              </td>
              <td className="num">{f.diagrams.reduce((a, d) => a + d.steps.length, 0)}</td>
              <td className="id">{f.file}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function FlowsIndex() {
  const flows = loadFlows();
  const docs = flows.filter((f) => f.origin === "flow" && f.slug !== SYSTEM_MAP_SLUG);
  const map = loadSystemMap();
  const arch = flows.filter((f) => f.origin === "architecture");
  const diagrams = flows.reduce((a, f) => a + f.diagrams.length, 0);
  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Flows"
        left={["Secure MCP Gateway", "Sequence and flow diagrams", `Sources: ${flowSourceDir()}/*.md, ArchitectureV2.md`]}
        right={[`${plural(flows.length, "flow")}`, `${plural(diagrams, "diagram")}`, `site build ${buildCommit()}`]}
      >
        <p>
          How a request, a session or a server moves through the Gateway. Every diagram is drawn from its Mermaid source
          and followed by a numbered table of its steps, read from the same source, so the table and the drawing cannot
          disagree.
        </p>
      </DocHead>

      <p className="sysmap-callout">
        <Link href={SYSTEM_MAP_HREF}>
          <strong>System map</strong>
        </Link>
        : the whole product in one flowchart, from installation to a tool call and its evidence, in {map.stages.length}{" "}
        stages with pan and zoom. Each stage links to the detailed flows below.
      </p>

      <Sec no={`${CH.n}.1`} id="flow-docs" title="Flow documents">
        <Note label="Source">
          <p>Each Markdown file in {flowSourceDir()} becomes one page here at the next build.</p>
        </Note>
        {docs.length === 0 ? (
          <p className="empty-state">
            No flow documents yet. Add a Markdown file with a Mermaid diagram to {flowSourceDir()} and it appears here.
          </p>
        ) : (
          <FlowTable flows={docs} caption={`Files in ${flowSourceDir()}, by file name.`} />
        )}
      </Sec>

      <Sec no={`${CH.n}.2`} id="architecture-diagrams" title="Architecture diagrams">
        <p>The diagrams in the architecture document, each with the section text that introduces it.</p>
        <FlowTable flows={arch} caption="Diagrams in ArchitectureV2.md, in document order." />
      </Sec>
    </article>
  );
}
