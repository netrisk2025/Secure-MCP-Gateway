import type { ReactNode } from "react";
import Link from "next/link";
import Mermaid from "@/components/Mermaid";
import { DocHead } from "@/components/Sheet";
import { docMtime } from "@/lib/content";
import { renderMarkdown, toc } from "@/lib/markdown";
import { REPO_URL, buildCommit } from "@/lib/site";

type PageLink = { href: string; title: string };

/** A long-form document rendered as written, with a rail of sibling documents and sections. */
export default async function DocPage({
  file,
  md,
  title,
  chapter,
  tocDepth = 3,
  left,
  siblings,
  pager,
  children,
}: {
  file: string;
  md: string;
  title: string;
  chapter?: number;
  tocDepth?: number;
  left?: ReactNode[];
  /** Other documents of the same group, listed above the sections. */
  siblings?: { label: string; items: (PageLink & { current: boolean })[] };
  /** Previous and next document in reading order. */
  pager?: { prev?: PageLink; next?: PageLink };
  children?: ReactNode;
}) {
  const html = await renderMarkdown(md, { dropTitle: true, file });
  const entries = toc(md, tocDepth);
  const hasDiagrams = md.includes("```mermaid");
  return (
    <div className="doc-layout">
      <div className="rail">
        {siblings && siblings.items.length > 1 && (
          <nav className="toc siblings" aria-label={`Documents in ${siblings.label}`}>
            <p className="rail-label">{siblings.label}</p>
            <ol>
              {siblings.items.map((s) => (
                <li key={s.href}>
                  <Link href={s.href} aria-current={s.current ? "page" : undefined}>
                    {s.title}
                  </Link>
                </li>
              ))}
            </ol>
          </nav>
        )}
        {entries.length > 0 && (
          <nav className="toc" aria-label="Sections of this document">
            {siblings && <p className="rail-label">On this page</p>}
            <ol>
              {entries.map((e) => (
                <li key={e.id} className={`d${e.depth}`}>
                  <a href={`#${e.id}`}>{e.text}</a>
                </li>
              ))}
            </ol>
          </nav>
        )}
      </div>
      <article className="prose">
        <DocHead
          chapter={chapter}
          title={title}
          left={[
            ...(left ?? []),
            <a key="f" href={`${REPO_URL}/blob/main/${file}`}>
              {file}
            </a>,
          ]}
          right={[`last changed ${docMtime(file)}`, `site build ${buildCommit()}`]}
        >
          {children}
        </DocHead>
        <div dangerouslySetInnerHTML={{ __html: html }} />
        {pager && (pager.prev || pager.next) && (
          <nav className="pager" aria-label="Previous and next document">
            {pager.prev ? (
              <Link href={pager.prev.href} rel="prev">
                <span className="pager-dir">Previous</span>
                {pager.prev.title}
              </Link>
            ) : (
              <span />
            )}
            {pager.next ? (
              <Link href={pager.next.href} rel="next" className="pager-next">
                <span className="pager-dir">Next</span>
                {pager.next.title}
              </Link>
            ) : (
              <span />
            )}
          </nav>
        )}
      </article>
      {hasDiagrams && <Mermaid />}
    </div>
  );
}
