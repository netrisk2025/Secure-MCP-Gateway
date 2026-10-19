import Link from "next/link";
import { notFound } from "next/navigation";
import DocPage from "@/components/DocPage";
import { allDocs, docBySlug, docHref, groupAnchor, readDoc } from "@/lib/content";
import { chapter } from "@/lib/site";

const CH = chapter("/docs/");

export function generateStaticParams() {
  return allDocs().map((d) => ({ slug: d.slug.split("/") }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await params;
  const d = docBySlug(slug.join("/"));
  return { title: d ? d.title : "Document" };
}

export default async function Doc({ params }: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await params;
  const docs = allDocs();
  const d = docBySlug(slug.join("/"));
  if (!d) notFound();
  const md = readDoc(d.file);
  const title = (md.match(/^# (.*)$/m) ?? ["", d.title])[1];
  const group = docs.filter((x) => x.group === d.group);
  const at = docs.indexOf(d);
  const prev = at > 0 ? docs[at - 1] : undefined;
  const next = at < docs.length - 1 ? docs[at + 1] : undefined;
  return (
    <DocPage
      file={d.file}
      md={md}
      title={title}
      tocDepth={2}
      left={[
        <Link key="c" href="/docs/">
          {CH.n} Documents
        </Link>,
        <Link key="g" href={`/docs/#${groupAnchor(d.group)}`}>
          {d.group}
        </Link>,
      ]}
      siblings={{
        label: d.group,
        items: group.map((x) => ({ href: docHref(x), title: x.title, current: x === d })),
      }}
      pager={{
        prev: prev && { href: docHref(prev), title: prev.title },
        next: next && { href: docHref(next), title: next.title },
      }}
    />
  );
}
