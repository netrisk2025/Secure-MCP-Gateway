import Link from "next/link";
import { DOCS, docExists, docMtime } from "@/lib/content";

export const metadata = { title: "Documents, Secure MCP Gateway" };

export default function DocsIndex() {
  return (
    <>
      <div className="page-head">
        <h1>Documents</h1>
        <p className="lede">
          The full documents, rendered as written. The structured pages elsewhere on this site are derived from these.
        </p>
      </div>
      <ul className="read-list" style={{ maxWidth: "var(--wide)" }}>
        {DOCS.filter((d) => docExists(d.file)).map((d) => (
          <li key={d.slug}>
            <Link href={`/docs/${d.slug}/`}>{d.title}</Link>
            <p>{d.blurb}</p>
            <p className="meta">
              {d.file}, last changed {docMtime(d.file)}
            </p>
          </li>
        ))}
      </ul>
    </>
  );
}
