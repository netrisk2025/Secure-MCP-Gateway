import Link from "next/link";
import { DocHead, Note, Sec } from "@/components/Sheet";
import { Inline } from "@/lib/inline";
import { INDEX_FILE, ROOT_GROUP, allDocs, docGroups, docHref, docMtime, groupAnchor, readDoc } from "@/lib/content";
import { loadFlows } from "@/lib/flows";
import { REPO_URL, buildCommit, chapter, plural } from "@/lib/site";

export const metadata = { title: "Documents" };

const CH = chapter("/docs/");

const GROUP_ABOUT: Record<string, string> = {
  "Start here": "Installing, the first run, day-2 operation, what is not protected, and every error code.",
  Reference: "One document per element group: policy, packaging, approvals, filters, secrets, sandbox, egress, the console, the graph mirror, observation, remote access, adapters and the conformance suites.",
  "Client quick starts": "One page per client of SRS Appendix K: connection, sign-in, CA trust, lockdown and doctor.",
  Runbooks: "Procedures for incidents and scheduled maintenance.",
  "Control API": "Routes of the loopback admin listener, per element. A running Gateway also serves the full route table as GET /api/v1/openapi.json; the Control API chapter renders it.",
  Operations: "Health, logs, metrics, reload, keys, backup, upgrade and removal.",
  Verification: "The verification record format.",
  [ROOT_GROUP]: "The specification documents, background research and the repository's own records.",
};

export default function DocsIndex() {
  const docs = allDocs().map((d) => {
    const md = readDoc(d.file);
    return { ...d, words: md.split(/\s+/).filter(Boolean).length, mtime: docMtime(d.file) };
  });
  const groups = docGroups();
  const flows = loadFlows().filter((f) => f.origin === "flow");
  let n = 0;
  return (
    <article className="sheet doc-groups">
      <DocHead
        chapter={CH.n}
        title="Documents"
        left={["Secure MCP Gateway", "User, operator and specification documents"]}
        right={[plural(docs.length, "document"), `site build ${buildCommit()}`]}
      >
        <p>
          Every Markdown file under <code>docs/</code> and the specification documents at the repository root, rendered as
          written. The list is built from the repository tree on each build; order and grouping follow{" "}
          <Link href="/docs/documentation/">the documentation index</Link> (<code>{INDEX_FILE}</code>).
        </p>
      </DocHead>

      <nav aria-label="Document groups" className="group-nav">
        <ol>
          {groups.map((g) => (
            <li key={g}>
              <a href={`#${groupAnchor(g)}`}>{g}</a>{" "}
              <span className="nil">{docs.filter((d) => d.group === g).length}</span>
            </li>
          ))}
          {flows.length > 0 && (
            <li>
              <a href="#g-flows">Flows</a> <span className="nil">{flows.length}</span>
            </li>
          )}
        </ol>
      </nav>

      {groups.map((g) => {
        const mine = docs.filter((d) => d.group === g);
        n++;
        return (
          <Sec key={g} no={`${CH.n}.${n}`} id={groupAnchor(g)} title={g}>
            {GROUP_ABOUT[g] && <p className="group-about">{GROUP_ABOUT[g]}</p>}
            <div className="table-wrap wide">
              <table>
                <caption className="visually-hidden">{g}: {plural(mine.length, "document")}</caption>
                <thead>
                  <tr>
                    <th scope="col">Document</th>
                    <th scope="col">About</th>
                    <th scope="col">File</th>
                    <th scope="col" className="num">
                      Words
                    </th>
                    <th scope="col" className="num">
                      Changed
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {mine.map((d) => (
                    <tr key={d.slug}>
                      <td>
                        <Link href={docHref(d)}>{d.title}</Link>
                      </td>
                      <td>{d.blurb ? <Inline text={d.blurb} linkIds={false} /> : <span className="nil">none</span>}</td>
                      <td className="id">{d.file}</td>
                      <td className="num">{d.words.toLocaleString("en-US")}</td>
                      <td className="num">{d.mtime}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Sec>
        );
      })}

      {flows.length > 0 && (
        <Sec no={`${CH.n}.${n + 1}`} id="g-flows" title="Flows">
          <Note label="Where">
            <p>
              Rendered in <Link href="/flows/">chapter 2</Link> with a numbered table of each diagram&apos;s steps.
            </p>
          </Note>
          <p className="group-about">
            Sequence diagrams in <a href={`${REPO_URL}/tree/main/docs/flows`}>docs/flows/</a>, each with the differences of
            the current implementation.
          </p>
          <ul className="flow-list">
            {flows.map((f) => (
              <li key={f.slug}>
                <Link href={`/flows/${f.slug}/`}>{f.title}</Link> <span className="id">{f.file}</span>
              </li>
            ))}
          </ul>
        </Sec>
      )}
    </article>
  );
}
