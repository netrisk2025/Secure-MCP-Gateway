import { notFound } from "next/navigation";
import Mermaid from "@/components/Mermaid";
import { DOCS, docExists, readDoc } from "@/lib/content";
import { renderMarkdown, toc } from "@/lib/markdown";

export function generateStaticParams() {
  return DOCS.filter((d) => docExists(d.file)).map((d) => ({ slug: d.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const d = DOCS.find((x) => x.slug === slug);
  return { title: d ? `${d.title}, Secure MCP Gateway` : "Document" };
}

export default async function DocPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const d = DOCS.find((x) => x.slug === slug);
  if (!d || !docExists(d.file)) notFound();
  const md = readDoc(d.file);
  const title = (md.match(/^# (.*)$/m) ?? ["", d.title])[1];
  const html = await renderMarkdown(md, { dropTitle: true });
  const entries = toc(md, 2);
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
          <h1>{title}</h1>
          <p className="meta">{d.file}</p>
        </div>
        <div dangerouslySetInnerHTML={{ __html: html }} />
      </article>
      <Mermaid />
    </div>
  );
}
