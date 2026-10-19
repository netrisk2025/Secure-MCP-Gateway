import { Fragment } from "react";
import Link from "next/link";
import { DocHead, ImplBadge, SampleNotice, Sec } from "@/components/Sheet";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements } from "@/lib/parse-reqs";
import { loadStatus } from "@/lib/status";
import { buildCommit, chapter, dataSourceLine, elementStatusMap, reqStatusMap, reqStatusOf } from "@/lib/site";

export const metadata = { title: "Elements" };

const CH = chapter("/elements/");

export default function ElementsPage() {
  const arch = loadArch();
  const { reqs } = loadRequirements();
  const snap = loadStatus();
  const els = elementStatusMap(snap.status);
  const rs = reqStatusMap(snap.status);

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Elements"
        left={["Secure MCP Gateway", `Architecture revision ${arch.revision}`, `Status: ${dataSourceLine(snap)}`]}
        right={[`${arch.elements.length} elements`, `${arch.subsystems.length} subsystems`, `site build ${buildCommit()}`]}
      >
        <p>
          Each element owns its functions and is the allocation target for the requirements that name it. The trust level
          says what a compromise of the element would defeat.
        </p>
      </DocHead>
      <SampleNotice snap={snap} />
      <dl className="facts">
        {(["T0", "T1", "T2", "U"] as const).map((t) => (
          <Fragment key={t}>
            <dt>
              <span className={`badge badge-${t}`}>{t}</span>
            </dt>
            <dd>{arch.trustLevels[t]}</dd>
          </Fragment>
        ))}
      </dl>

      {arch.subsystems.map((ss, i) => {
        const mine = arch.elements.filter((e) => e.subsystemId === ss.id);
        return (
          <Sec key={ss.id} no={`${CH.n}.${i + 1}`} id={ss.id} title={`${ss.id} ${ss.name}`}>
            <div className="table-wrap wide">
              <table className="eltable">
                <thead>
                  <tr>
                    <th scope="col">ID</th>
                    <th scope="col">Element</th>
                    <th scope="col">Trust</th>
                    <th scope="col">Implementation</th>
                    <th scope="col" className="num">
                      Verified / allocated
                    </th>
                    <th scope="col">Packages</th>
                  </tr>
                </thead>
                <tbody>
                  {mine.map((e) => {
                    const alloc = reqs.filter((r) => r.alloc.includes(e.id));
                    const verified = alloc.filter((r) => reqStatusOf(rs, r.id) === "verified").length;
                    const st = els.get(e.id);
                    return (
                      <tr key={e.id}>
                        <td className="id">{e.id}</td>
                        <td>
                          <Link href={`/elements/${e.id}/`}>{e.name}</Link>
                        </td>
                        <td>
                          <span className={`badge badge-${e.trust}`}>{e.trust}</span>
                          {e.trustNote && (
                            <>
                              {" "}
                              <span className="badge badge-U" title={e.trustNote}>
                                U
                              </span>
                            </>
                          )}
                        </td>
                        <td>
                          <ImplBadge impl={st?.implementation} />
                        </td>
                        <td className="num">
                          {verified} / {alloc.length}
                        </td>
                        <td className="id">{st?.packages.length ? st.packages.join(", ") : <span className="nil">none</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Sec>
        );
      })}
    </article>
  );
}
