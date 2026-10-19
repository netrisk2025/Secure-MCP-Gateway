import Link from "next/link";
import { notFound } from "next/navigation";
import { DocHead, ImplBadge, Note, ReqBadge, SampleNotice, Sec } from "@/components/Sheet";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements } from "@/lib/parse-reqs";
import { loadStatus } from "@/lib/status";
import { Inline } from "@/lib/inline";
import {
  REPO_URL,
  REQ_STATUSES,
  buildCommit,
  chapter,
  dataSourceLine,
  elementStatusMap,
  reqStatusMap,
  reqStatusOf,
} from "@/lib/site";

const CH = chapter("/elements/");

export function generateStaticParams() {
  return loadArch().elements.map((e) => ({ id: e.id }));
}

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const e = loadArch().elements.find((x) => x.id === id);
  return { title: e ? `${e.id} ${e.name}` : "Element" };
}

export default async function ElementPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const arch = loadArch();
  const el = arch.elements.find((e) => e.id === id);
  if (!el) notFound();
  const { reqs } = loadRequirements();
  const snap = loadStatus();
  const st = elementStatusMap(snap.status).get(el.id);
  const rs = reqStatusMap(snap.status);
  const mine = reqs.filter((r) => r.alloc.includes(el.id));
  const tally = Object.fromEntries(REQ_STATUSES.map((s) => [s, mine.filter((r) => reqStatusOf(rs, r.id) === s).length]));
  const fns = arch.functions.filter((f) => el.functions.includes(f.id));
  const ext = arch.external.filter((x) => el.interfaces.includes(x.id));
  const int = arch.internal.filter((x) => el.interfaces.includes(x.id));
  const stores = arch.stores.filter((d) => d.owner.includes(el.id) || d.host.includes(el.id));
  const idx = arch.elements.findIndex((e) => e.id === el.id);
  const prev = arch.elements[idx - 1];
  const next = arch.elements[idx + 1];
  const n = CH.n;

  return (
    <article className="sheet">
      <DocHead
        title={`${el.id} ${el.name}`}
        left={[
          <Link key="c" href="/elements/">
            {n} Elements
          </Link>,
          <Link key="s" href={`/elements/#${el.subsystemId}`}>
            {el.subsystemId} {el.subsystem}
          </Link>,
          `Status: ${dataSourceLine(snap)}`,
        ]}
        right={[`trust ${el.trust}`, `${mine.length} requirements`, `site build ${buildCommit()}`]}
      >
        <p>{el.purpose}</p>
      </DocHead>
      <SampleNotice snap={snap} />

      <Sec no={`${el.id}.1`} id="status" title="Status">
        {st?.note && (
          <Note label="Status note">
            <p>{st.note}</p>
          </Note>
        )}
        <dl className="facts">
          <dt>Implementation</dt>
          <dd>
            <ImplBadge impl={st?.implementation} />
          </dd>
          <dt>Packages</dt>
          <dd>
            {st?.packages.length
              ? st.packages.map((p, i) => (
                  <span key={p}>
                    {i > 0 && ", "}
                    <a className="idref" href={`${REPO_URL}/tree/main/${p}`}>
                      {p}
                    </a>
                  </span>
                ))
              : "None recorded."}
          </dd>
          <dt>Requirements</dt>
          <dd>
            {REQ_STATUSES.map((s, i) => (
              <span key={s}>
                {i > 0 && ", "}
                {tally[s]} {s}
              </span>
            ))}{" "}
            of {mine.length} allocated.
          </dd>
          <dt>Trust</dt>
          <dd>
            <span className={`badge badge-${el.trust}`}>{el.trust}</span> {arch.trustLevels[el.trust]}
            {el.trustNote && <> The {el.trustNote}.</>}
          </dd>
          <dt>Owned data</dt>
          <dd>
            <Inline text={el.ownedData || "None recorded."} />
          </dd>
          <dt>Allocation targets</dt>
          <dd>
            <Inline text={el.allocationTargets || "None recorded."} />
          </dd>
        </dl>
      </Sec>

      <Sec no={`${el.id}.2`} id="requirements" title={`Requirements (${mine.length})`}>
        <p>
          Status comes from the tests that claim each requirement. The{" "}
          <Link href={`/requirements/?element=${el.id}`}>requirements explorer</Link> shows the full statement, verification
          method, source and rationale.
        </p>
        {mine.length === 0 ? (
          <p className="empty-state">No requirement is allocated to {el.id}.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <thead>
                <tr>
                  <th scope="col">ID</th>
                  <th scope="col">Requirement</th>
                  <th scope="col">Status</th>
                  <th scope="col">Tests</th>
                </tr>
              </thead>
              <tbody>
                {mine.map((r) => {
                  const entry = rs.get(r.id);
                  return (
                    <tr key={r.id}>
                      <td className="id">
                        <Link href={`/requirements/#${r.id}`}>{r.id}</Link>
                      </td>
                      <td>
                        {r.title}
                        <br />
                        <span className="meta">{r.method}</span>
                      </td>
                      <td>
                        <ReqBadge status={reqStatusOf(rs, r.id)} />
                      </td>
                      <td className="id">
                        {entry?.tests.length ? (
                          entry.tests.map((t) => (
                            <span key={t}>
                              {t.split(".").pop()}
                              <br />
                            </span>
                          ))
                        ) : (
                          <span className="nil">none</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Sec>

      <Sec no={`${el.id}.3`} id="interfaces" title="Interfaces">
        {ext.length + int.length === 0 ? (
          <p className="empty-state">No interface names {el.id}.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <thead>
                <tr>
                  <th scope="col">ID</th>
                  <th scope="col">Interface</th>
                  <th scope="col">Between or from and to</th>
                  <th scope="col">Purpose or content</th>
                </tr>
              </thead>
              <tbody>
                {ext.map((x) => (
                  <tr key={x.id}>
                    <td className="id">
                      <Link href={`/interfaces/#${x.id}`}>{x.id}</Link>
                    </td>
                    <td>{x.name}</td>
                    <td>
                      <Inline text={x.between} />
                    </td>
                    <td>
                      <Inline text={x.content} />
                    </td>
                  </tr>
                ))}
                {int.map((x) => (
                  <tr key={x.id}>
                    <td className="id">
                      <Link href={`/interfaces/#${x.id}`}>{x.id}</Link>
                    </td>
                    <td>internal</td>
                    <td>
                      <Inline text={x.fromTo} />
                    </td>
                    <td>
                      <Inline text={x.purpose} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {stores.length > 0 && (
          <>
            <h3>Data stores</h3>
            <div className="table-wrap wide">
              <table>
                <thead>
                  <tr>
                    <th scope="col">ID</th>
                    <th scope="col">Store</th>
                    <th scope="col">Contents</th>
                  </tr>
                </thead>
                <tbody>
                  {stores.map((d) => (
                    <tr key={d.id}>
                      <td className="id">
                        <Link href={`/interfaces/#${d.id}`}>{d.id}</Link>
                      </td>
                      <td>{d.name}</td>
                      <td>
                        <Inline text={d.contents} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Sec>

      <Sec no={`${el.id}.4`} id="functions" title={`Functions (${fns.length})`}>
        {fns.length === 0 ? (
          <p className="empty-state">No function is owned by {el.id}.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <thead>
                <tr>
                  <th scope="col">ID</th>
                  <th scope="col">Function</th>
                  <th scope="col">Phase</th>
                  <th scope="col">Required behaviour</th>
                </tr>
              </thead>
              <tbody>
                {fns.map((f) => (
                  <tr key={f.id} id={f.id}>
                    <td className="id">{f.id}</td>
                    <td>{f.name}</td>
                    <td>{f.phase}</td>
                    <td>{f.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Sec>

      <nav className="pager meta" aria-label="Adjacent elements">
        {prev && (
          <p>
            Previous: <Link href={`/elements/${prev.id}/`}>{prev.id} {prev.name}</Link>
          </p>
        )}
        {next && (
          <p>
            Next: <Link href={`/elements/${next.id}/`}>{next.id} {next.name}</Link>
          </p>
        )}
      </nav>
    </article>
  );
}
