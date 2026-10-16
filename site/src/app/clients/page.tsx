import { readDoc } from "@/lib/content";
import { renderMarkdown, toc } from "@/lib/markdown";

export const metadata = { title: "Client compatibility, Secure MCP Gateway" };

export default async function ClientsPage() {
  const md = readDoc("Client-Compatibility-Brief.md");
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
          <h1>Client compatibility</h1>
          <p className="lede">
            What the frameworks in front of the Gateway expect today, checked against primary documentation, and the
            places where the specification must bend to meet them.
          </p>
        </div>
        <div dangerouslySetInnerHTML={{ __html: html }} />
      </article>
    </div>
  );
}
