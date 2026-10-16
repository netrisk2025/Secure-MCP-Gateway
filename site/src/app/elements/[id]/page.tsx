import Link from "next/link";
import { notFound } from "next/navigation";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements } from "@/lib/parse-reqs";
import { Inline } from "@/lib/inline";

export function generateStaticParams() {
  return loadArch().elements.map((e) => ({ id: e.id }));
}

export function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return params.then(({ id }) => {
    const e = loadArch().elements.find((x) => x.id === id);
    return { title: e ? `${e.id} ${e.name}, Secure MCP Gateway` : "Element" };
  });
}

export default async function ElementPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const arch = loadArch();
  const el = arch.elements.find((e) => e.id === id);
  if (!el) notFound();
  const { reqs } = loadRequirements();
  const mine = reqs.filter((r) => r.alloc.includes(el.id));
  const fns = arch.functions.filter((f) => el.functions.includes(f.id));
  const ext = arch.external.filter((x) => el.interfaces.includes(x.id));
  const int = arch.internal.filter((x) => el.interfaces.includes(x.id));
  const stores = arch.stores.filter((d) => d.owner.includes(el.id) || d.host.includes(el.id));
  const idx = arch.elements.findIndex((e) => e.id === el.id);
  const prev = arch.elements[idx - 1];
  const next = arch.elements[idx + 1];

  return (
    <article className="element-detail">
      <div className="page-head">
        <p className="meta">
          <Link href="/elements/">Elements</Link> / {el.subsystemId} {el.subsystem}
        </p>
        <h1>
          {el.id} {el.name}
        </h1>
        <p>
          <span className={`badge badge-${el.trust}`}>{el.trust}</span> {arch.trustLevels[el.trust]}
          {el.trustNote && <> The {el.trustNote}.</>}
        </p>
        <p className="lede">{el.purpose}</p>
      </div>

      <dl>
        <dt>Owned data</dt>
        <dd>
          <Inline text={el.ownedData || "None recorded."} />
        </dd>
        <dt>Allocation targets</dt>
        <dd>
          <Inline text={el.allocationTargets || "None recorded."} />
        </dd>
        <dt>Functions</dt>
        <dd>
          {fns.length === 0 && "None."}
          {fns.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Function</th>
                    <th>Phase</th>
                    <th>Required behaviour</th>
                  </tr>
                </thead>
                <tbody>
                  {fns.map((f) => (
                    <tr key={f.id} id={f.id}>
                      <td>{f.id}</td>
                      <td>{f.name}</td>
                      <td>{f.phase}</td>
                      <td>{f.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </dd>
        <dt>Interfaces</dt>
        <dd>
          {ext.map((x) => (
            <div key={x.id}>
              <Link className="idref" href={`/interfaces/#${x.id}`}>
                {x.id}
              </Link>{" "}
              {x.name}. {x.between}.
            </div>
          ))}
          {int.map((x) => (
            <div key={x.id}>
              <Link className="idref" href={`/interfaces/#${x.id}`}>
                {x.id}
              </Link>{" "}
              {x.fromTo}. {x.purpose}.
            </div>
          ))}
        </dd>
        {stores.length > 0 && (
          <>
            <dt>Data stores</dt>
            <dd>
              {stores.map((d) => (
                <div key={d.id}>
                  <Link className="idref" href={`/interfaces/#${d.id}`}>
                    {d.id}
                  </Link>{" "}
                  {d.name}. {d.contents}
                </div>
              ))}
            </dd>
          </>
        )}
      </dl>

      <h2>
        Requirements allocated to {el.id} ({mine.length})
      </h2>
      <p className="meta">
        Open any requirement in the <Link href={`/requirements/#${el.id}`}>explorer</Link> to see its verification,
        source and rationale.
      </p>
      <ol className="req-list">
        {mine.map((r) => (
          <li key={r.id} className={`req ${r.kind === "SR" ? "req-sr" : "req-fr"}`}>
            <div className="req-head" style={{ cursor: "default" }}>
              <Link className="req-id" href={`/requirements/#${r.id}`}>
                {r.id}
              </Link>
              <span className="req-title">{r.title}</span>
              <span className="req-method">{r.method}</span>
            </div>
            <p className="req-stmt">
              <Inline text={r.stmt} />
            </p>
          </li>
        ))}
      </ol>

      <p className="meta" style={{ marginTop: "2rem" }}>
        {prev && (
          <>
            Previous: <Link href={`/elements/${prev.id}/`}>{prev.id} {prev.name}</Link>.{" "}
          </>
        )}
        {next && (
          <>
            Next: <Link href={`/elements/${next.id}/`}>{next.id} {next.name}</Link>.
          </>
        )}
      </p>
    </article>
  );
}
