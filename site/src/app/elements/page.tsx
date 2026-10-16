import Link from "next/link";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements } from "@/lib/parse-reqs";

export const metadata = { title: "Elements, Secure MCP Gateway" };

export default function ElementsPage() {
  const arch = loadArch();
  const { reqs } = loadRequirements();
  const countFor = (id: string) => reqs.filter((r) => r.alloc.includes(id)).length;

  return (
    <>
      <div className="page-head">
        <h1>Elements</h1>
        <p className="lede">
          The Gateway decomposes into {arch.elements.length} elements across {arch.subsystems.length} subsystems. Each
          element owns its functions and is the allocation target for the requirements that name it.
        </p>
        <ul className="trust-key">
          {(["T0", "T1", "T2", "U"] as const).map((t) => (
            <li key={t}>
              <span className={`badge badge-${t}`}>{t}</span> {arch.trustLevels[t]}
            </li>
          ))}
        </ul>
      </div>

      {arch.subsystems.map((ss) => (
        <section key={ss.id} className="subsystem" id={ss.id}>
          <h2>
            {ss.id} {ss.name}
          </h2>
          <ul className="element-rows">
            {arch.elements
              .filter((e) => e.subsystemId === ss.id)
              .map((e) => (
                <li key={e.id}>
                  <span className="eid">{e.id}</span>
                  <div>
                    <Link href={`/elements/${e.id}/`} className="ename">
                      {e.name}
                    </Link>
                    <span className={`badge badge-${e.trust}`}>{e.trust}</span>
                    {e.trustNote && (
                      <>
                        {" "}
                        <span className="badge badge-U">U</span> <span className="meta">{e.trustNote}</span>
                      </>
                    )}
                    <p>{e.purpose}</p>
                    <div className="trail meta">
                      {e.functions.length} functions, {e.interfaces.length} interfaces, {countFor(e.id)} requirements
                    </div>
                  </div>
                </li>
              ))}
          </ul>
        </section>
      ))}
    </>
  );
}
