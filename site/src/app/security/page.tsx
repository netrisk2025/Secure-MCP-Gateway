import Link from "next/link";
import { loadSecurity } from "@/lib/parse-sec";
import { loadRequirements } from "@/lib/parse-reqs";
import { Inline } from "@/lib/inline";

export const metadata = { title: "Security controls, Secure MCP Gateway" };

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
  const musts = controls.filter((c) => c.imperative === "MUST").length;

  return (
    <>
      <div className="page-head">
        <h1>Security controls</h1>
        <p className="lede">
          The security-control SRS states {controls.length} controls in {groups.length} groups, {musts} of them as
          MUST. Each MUST is realized by one or more SHALL requirements in the implementation SRS, or carries a
          disposition explaining where outside the Gateway it is met.
        </p>
      </div>

      <div className="controls">
        {groups.map((g) => {
          const root = controls.find((c) => c.id === g.id);
          const children = controls.filter((c) => c.group === g.id && c.id !== g.id);
          return (
            <section key={g.id} className="control-group" id={`sec-${g.id}`}>
              <div className="control-root">
                <h2>
                  {g.id}. {g.title}
                </h2>
                {root && (
                  <p>
                    <span className={`badge badge-${root.imperative}`}>{root.imperative}</span>{" "}
                    <Inline text={root.statement.replace(/\bMUST\b/, "must")} linkIds={false} />
                  </p>
                )}
              </div>
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
                      <dl>
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
            </section>
          );
        })}
      </div>
    </>
  );
}
