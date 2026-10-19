import Link from "next/link";
import { DocHead, Note, Sec } from "@/components/Sheet";
import { loadSecurity } from "@/lib/parse-sec";
import { loadRequirements } from "@/lib/parse-reqs";
import { Inline } from "@/lib/inline";
import { buildCommit, chapter } from "@/lib/site";

export const metadata = { title: "Security controls" };

const CH = chapter("/security/");

export default function SecurityPage() {
  const { controls, groups } = loadSecurity();
  const { reqs, disps } = loadRequirements();
  const srByParent = new Map<string, string[]>();
  for (const r of reqs) {
    if (r.kind !== "SR") continue;
    const pid = r.parent.replace("SEC-", "");
    srByParent.set(pid, [...(srByParent.get(pid) ?? []), r.id]);
  }
  const dispBy = new Map(disps.map((d) => [d.secId, d.text]));
  const musts = controls.filter((c) => c.imperative === "MUST");
  const realized = musts.filter((c) => (srByParent.get(c.id) ?? []).length > 0).length;
  const disposed = musts.filter((c) => !(srByParent.get(c.id) ?? []).length && dispBy.has(c.id)).length;

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Security controls"
        left={["Secure MCP Gateway", "Security-control SRS", "Source: MCP_Gateway_Security_SRS.md"]}
        right={[`${controls.length} controls`, `${groups.length} groups, ${musts.length} MUST`, `site build ${buildCommit()}`]}
      >
        <p>
          Each MUST is realized by one or more SHALL requirements in the implementation SRS, or carries a disposition
          that says where outside the Gateway it is met.
        </p>
      </DocHead>
      <Note label="Coverage">
        <p>
          {realized} of {musts.length} MUST controls are realized by security requirements; {disposed} carry a
          disposition; the rest are decomposed into child controls.
        </p>
      </Note>

      {groups.map((g) => {
        const root = controls.find((c) => c.id === g.id);
        const children = controls.filter((c) => c.group === g.id && c.id !== g.id);
        return (
          <Sec key={g.id} no={`${CH.n}.${g.id}`} id={`sec-${g.id}`} title={g.title}>
            {root && (
              <p>
                <span className={`badge badge-${root.imperative}`}>{root.imperative}</span>{" "}
                <Inline text={root.statement.replace(/\bMUST\b/, "must")} linkIds={false} />
              </p>
            )}
            <div className="controls wide">
              {children.map((c) => {
                const srs = srByParent.get(c.id) ?? [];
                const disp = dispBy.get(c.id);
                const cov =
                  c.imperative === "MUST"
                    ? srs.length
                      ? `${srs.length} SR`
                      : disp
                        ? "disposition"
                        : "decomposed"
                    : "SHALL";
                return (
                  <details key={c.id} className="control" id={`sec-${c.id}`}>
                    <summary>
                      <span className="cid">{c.id}</span>
                      <span className="cname">{c.name}</span>
                      <span className="ccov">{cov}</span>
                    </summary>
                    <div className="body">
                      <p>
                        <span className={`badge badge-${c.imperative}`}>{c.imperative}</span>{" "}
                        <Inline text={c.statement.replace(/\b(MUST|SHALL)\b/, (m) => m.toLowerCase())} linkIds={false} />
                      </p>
                      <dl className="facts">
                        <dt>Verification</dt>
                        <dd>
                          <strong>{c.method}.</strong> {c.verification}
                        </dd>
                        <dt>Source</dt>
                        <dd>{c.source}</dd>
                        <dt>Rationale</dt>
                        <dd>{c.rationale}</dd>
                        {srs.length > 0 && (
                          <>
                            <dt>Realized by</dt>
                            <dd>
                              {srs.map((id, i) => (
                                <span key={id}>
                                  {i > 0 && ", "}
                                  <Link className="idref" href={`/requirements/#${id}`}>
                                    {id}
                                  </Link>
                                </span>
                              ))}
                            </dd>
                          </>
                        )}
                        {disp && (
                          <>
                            <dt>Disposition</dt>
                            <dd>
                              <Inline text={disp} />
                            </dd>
                          </>
                        )}
                      </dl>
                    </div>
                  </details>
                );
              })}
            </div>
          </Sec>
        );
      })}
    </article>
  );
}
