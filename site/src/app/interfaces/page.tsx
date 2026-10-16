import { loadArch } from "@/lib/parse-arch";
import { Inline } from "@/lib/inline";

export const metadata = { title: "Interfaces and data, Secure MCP Gateway" };

export default function InterfacesPage() {
  const arch = loadArch();
  return (
    <>
      <div className="page-head">
        <h1>Interfaces and data</h1>
        <p className="lede">
          What crosses each boundary, in which direction, and who trusts whom. External interfaces are candidates for
          their own interface control documents. Internal interfaces are the contracts between elements.
        </p>
      </div>

      <section className="iface-section" id="external">
        <h2>External interfaces</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Interface</th>
                <th>Between</th>
                <th>Direction and trust</th>
                <th>Content</th>
                <th>Requirement topics</th>
              </tr>
            </thead>
            <tbody>
              {arch.external.map((x) => (
                <tr key={x.id} id={x.id}>
                  <td>{x.id}</td>
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
      </section>

      <section className="iface-section" id="internal">
        <h2>Internal interfaces</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>From and to</th>
                <th>Purpose</th>
                <th>Key content</th>
              </tr>
            </thead>
            <tbody>
              {arch.internal.map((x) => (
                <tr key={x.id} id={x.id}>
                  <td>{x.id}</td>
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
      </section>

      <section className="iface-section" id="stores">
        <h2>Data stores</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Store</th>
                <th>Host</th>
                <th>Owner</th>
                <th>Contents</th>
                <th>Protection</th>
              </tr>
            </thead>
            <tbody>
              {arch.stores.map((d) => (
                <tr key={d.id} id={d.id}>
                  <td>{d.id}</td>
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
      </section>

      <section className="iface-section" id="gui">
        <h2>Management console view modules</h2>
        <p className="measure">
          The console (E-24) is one GUI with separately allocatable view modules. Each serves named roles and is the
          subject of its own usability and role-separation requirements.
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>View module</th>
                <th>Primary users</th>
                <th>Purpose</th>
              </tr>
            </thead>
            <tbody>
              {arch.gui.map((g) => (
                <tr key={g.id} id={g.id}>
                  <td>{g.id}</td>
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
      </section>

      <section className="iface-section" id="decisions">
        <h2>Open decisions</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Decision</th>
                <th>Options</th>
                <th>Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {arch.decisions.map((d) => (
                <tr key={d.id} id={d.id}>
                  <td>{d.id}</td>
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
      </section>
    </>
  );
}
