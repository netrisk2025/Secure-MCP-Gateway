import { DocHead, Note, Sec } from "@/components/Sheet";
import { loadArch } from "@/lib/parse-arch";
import { Inline } from "@/lib/inline";
import { buildCommit, chapter } from "@/lib/site";

export const metadata = { title: "Interfaces and data" };

const CH = chapter("/interfaces/");

export default function InterfacesPage() {
  const arch = loadArch();
  const n = CH.n;
  return (
    <article className="sheet">
      <DocHead
        chapter={n}
        title="Interfaces and data"
        left={["Secure MCP Gateway", `Architecture revision ${arch.revision}`, "Source: ArchitectureV2.md sections 6, 13, 19"]}
        right={[
          `${arch.external.length} external, ${arch.internal.length} internal`,
          `${arch.stores.length} data stores`,
          `site build ${buildCommit()}`,
        ]}
      >
        <p>
          What crosses each boundary, in which direction, and who trusts whom. External interfaces are candidates for
          their own interface control documents. Internal interfaces are the contracts between elements.
        </p>
      </DocHead>

      <Sec no={`${n}.1`} id="external" title="External interfaces">
        <div className="table-wrap wide">
          <table>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Interface</th>
                <th scope="col">Between</th>
                <th scope="col">Direction and trust</th>
                <th scope="col">Content</th>
                <th scope="col">Requirement topics</th>
              </tr>
            </thead>
            <tbody>
              {arch.external.map((x) => (
                <tr key={x.id} id={x.id}>
                  <td className="id">{x.id}</td>
                  <td>{x.name}</td>
                  <td>
                    <Inline text={x.between} />
                  </td>
                  <td>
                    <Inline text={x.direction} />
                  </td>
                  <td>
                    <Inline text={x.content} />
                  </td>
                  <td>
                    <Inline text={x.topics} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${n}.2`} id="internal" title="Internal interfaces">
        <div className="table-wrap wide">
          <table>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">From and to</th>
                <th scope="col">Purpose</th>
                <th scope="col">Key content</th>
              </tr>
            </thead>
            <tbody>
              {arch.internal.map((x) => (
                <tr key={x.id} id={x.id}>
                  <td className="id">{x.id}</td>
                  <td>
                    <Inline text={x.fromTo} />
                  </td>
                  <td>
                    <Inline text={x.purpose} />
                  </td>
                  <td>
                    <Inline text={x.content} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${n}.3`} id="stores" title="Data stores">
        <div className="table-wrap wide">
          <table>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Store</th>
                <th scope="col">Host</th>
                <th scope="col">Owner</th>
                <th scope="col">Contents</th>
                <th scope="col">Protection</th>
              </tr>
            </thead>
            <tbody>
              {arch.stores.map((d) => (
                <tr key={d.id} id={d.id}>
                  <td className="id">{d.id}</td>
                  <td>{d.name}</td>
                  <td>
                    <Inline text={d.host} />
                  </td>
                  <td>
                    <Inline text={d.owner} />
                  </td>
                  <td>
                    <Inline text={d.contents} />
                  </td>
                  <td>
                    <Inline text={d.protection} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${n}.4`} id="gui" title="Management console view modules">
        <Note label="Allocation">
          <p>Each view module is the subject of its own usability and role-separation requirements.</p>
        </Note>
        <p>The console (E-24) is one GUI with separately allocatable view modules, each serving named roles.</p>
        <div className="table-wrap wide">
          <table>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">View module</th>
                <th scope="col">Primary users</th>
                <th scope="col">Purpose</th>
              </tr>
            </thead>
            <tbody>
              {arch.gui.map((g) => (
                <tr key={g.id} id={g.id}>
                  <td className="id">{g.id}</td>
                  <td>{g.name}</td>
                  <td>{g.users}</td>
                  <td>
                    <Inline text={g.purpose} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${n}.5`} id="decisions" title="Open decisions">
        {arch.decisions.length === 0 ? (
          <p className="empty-state">The architecture document lists no open decisions.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <thead>
                <tr>
                  <th scope="col">ID</th>
                  <th scope="col">Decision</th>
                  <th scope="col">Options</th>
                  <th scope="col">Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {arch.decisions.map((d) => (
                  <tr key={d.id} id={d.id}>
                    <td className="id">{d.id}</td>
                    <td>{d.decision}</td>
                    <td>{d.options}</td>
                    <td>
                      <Inline text={d.recommendation} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Sec>

      <Sec no={`${n}.6`} id="functions" title="Function catalog">
        <p>
          Every function of the architecture&apos;s function catalog with its owning element. Function references elsewhere
          on the site link here.
        </p>
        <div className="table-wrap wide">
          <table>
            <caption>{arch.functions.length} functions, in catalog order.</caption>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Function</th>
                <th scope="col">Owner</th>
                <th scope="col">Phase</th>
                <th scope="col">Summary</th>
              </tr>
            </thead>
            <tbody>
              {arch.functions.map((f) => (
                <tr key={f.id} id={f.id}>
                  <td className="id">{f.id}</td>
                  <td>{f.name}</td>
                  <td>
                    <Inline text={f.owner} />
                  </td>
                  <td>{f.phase}</td>
                  <td>
                    <Inline text={f.summary} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Sec>
    </article>
  );
}
