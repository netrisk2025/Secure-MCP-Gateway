import Mermaid from "@/components/Mermaid";
import { readDoc } from "@/lib/content";
import { renderMarkdown, toc } from "@/lib/markdown";

export const metadata = { title: "Architecture V2, Secure MCP Gateway" };

export default async function ArchitecturePage() {
  const md = readDoc("ArchitectureV2.md");
  const html = await renderMarkdown(md, { dropTitle: true });
  const entries = toc(md, 3);
  return (
    <div className="doc-layout">
      <aside className="toc" aria-label="Sections">
        <ol>
          {entries.map((e) => (
            <li key={e.id} className={`d${e.depth}`}>
              <a href={`#${e.id}`}>{e.text}</a>
            </li>
          ))}
        </ol>
      </aside>
      <article className="prose">
        <div className="page-head">
          <h1>Architecture V2</h1>
          <p className="lede">
            The logical decomposition of the Gateway: ten subsystems, their elements, functions, interfaces and data,
            rendered directly from the architecture document.
          </p>
        </div>
        <div dangerouslySetInnerHTML={{ __html: html }} />
      </article>
      <Mermaid />
    </div>
  );
}
