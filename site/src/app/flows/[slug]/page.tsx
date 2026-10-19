import Link from "next/link";
import { notFound } from "next/navigation";
import Mermaid from "@/components/Mermaid";
import { DocHead } from "@/components/Sheet";
import { loadFlows } from "@/lib/flows";
import { renderMarkdown } from "@/lib/markdown";
import { REPO_URL, buildCommit, chapter, plural } from "@/lib/site";
import { SYSTEM_MAP_SLUG } from "@/lib/system-map";

const CH = chapter("/flows/");

export function generateStaticParams() {
  // The system map has its own page (flows/system-map/page.tsx) with pan and zoom.
  return loadFlows()
    .filter((f) => f.slug !== SYSTEM_MAP_SLUG)
    .map((f) => ({ slug: f.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const f = loadFlows().find((x) => x.slug === slug);
  return { title: f ? `${f.title}, flows` : "Flow" };
}

export default async function FlowPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const flows = loadFlows();
  const idx = flows.findIndex((x) => x.slug === slug);
  const f = flows[idx];
  if (!f) notFound();
  const html = await renderMarkdown(f.markdown, { dropTitle: true, steps: true, file: f.file });
  const steps = f.diagrams.reduce((a, d) => a + d.steps.length, 0);
  const prev = flows[idx - 1];
  const next = flows[idx + 1];
  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title={f.title}
        left={[
          <Link key="c" href="/flows/">
            {CH.n} Flows
          </Link>,
          f.origin === "flow" ? "Flow document" : "Architecture diagram",
          <a key="s" href={`${REPO_URL}/blob/main/${f.file}`}>
            {f.file}
          </a>,
        ]}
        right={[plural(f.diagrams.length, "diagram"), plural(steps, "step"), `site build ${buildCommit()}`]}
      />
      <div className="prose flow-body" dangerouslySetInnerHTML={{ __html: html }} />
      <nav className="pager meta" aria-label="Other flows">
        {prev && (
          <p>
            Previous: <Link href={`/flows/${prev.slug}/`}>{prev.title}</Link>
          </p>
        )}
        {next && (
          <p>
            Next: <Link href={`/flows/${next.slug}/`}>{next.title}</Link>
          </p>
        )}
      </nav>
      <Mermaid />
    </article>
  );
}
