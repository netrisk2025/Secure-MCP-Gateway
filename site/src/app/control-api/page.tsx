import Link from "next/link";
import { DocHead, Note, Sec } from "@/components/Sheet";
import { ROLE_NAMES, ROLE_ORDER, apiDocHref, loadOpenApi, type ApiOperation } from "@/lib/openapi";
import { buildCommit, chapter, plural } from "@/lib/site";

export const metadata = { title: "Control API" };

const CH = chapter("/control-api/");

function Roles({ op }: { op: ApiOperation }) {
  if (op.public) return <span className="api-public">public, no token</span>;
  return (
    <>
      {op.roles.map((r, i) => (
        <span key={r}>
          {i > 0 && ", "}
          {ROLE_NAMES[r] ?? r}
        </span>
      ))}
      {op.refined && <span className="api-refined"> (part of the operation only for some roles)</span>}
    </>
  );
}

function Params({ op }: { op: ApiOperation }) {
  const query = op.params.filter((p) => p.in === "query");
  const bits: string[] = [];
  if (op.hasBody) bits.push("JSON body");
  if (op.response === "stream") bits.push("answers text/event-stream");
  if (op.response === "file") bits.push("answers a file");
  if (bits.length === 0 && query.length === 0) return null;
  return (
    <p className="api-params">
      {bits.join("; ")}
      {bits.length > 0 && query.length > 0 && "; "}
      {query.length > 0 && (
        <>
          query{" "}
          {query.map((q, i) => (
            <span key={q.name}>
              {i > 0 && " "}
              <code>{q.name}</code>
            </span>
          ))}
        </>
      )}
    </p>
  );
}

export default function ControlApiPage() {
  const api = loadOpenApi();
  const ops = api.operations;
  const publicOps = ops.filter((o) => o.public).length;
  const roleCount = (role: string) => ops.filter((o) => o.roles.includes(role)).length;
  const methods = Array.from(new Set(ops.map((o) => o.method)));

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Control API"
        left={["Secure MCP Gateway", api.title, `OpenAPI ${api.openapi}, document version ${api.version}`]}
        right={[plural(ops.length, "operation"), plural(api.tags.length, "group"), `site build ${buildCommit()}`]}
      >
        <p>
          Every route of the loopback admin listener (default <code>https://127.0.0.1:8444</code>) with the Appendix C
          roles that may use it. The document is generated from the Go sources at build time; a running Gateway serves
          the same operations at <code>GET /api/v1/openapi.json</code>.
        </p>
      </DocHead>

      <Sec no={`${CH.n}.1`} id="document" title="Document">
        <Note label="Source">
          <p>
            <code>go run ./tools/openapi</code> writes <code>site/data/openapi.json</code> from{" "}
            <code>internal/openapi</code> and the route registrations. A Go test fails when the committed file is stale.
          </p>
        </Note>
        <dl className="facts">
          <dt>Download</dt>
          <dd>
            <a href="/openapi.json" download>
              openapi.json
            </a>{" "}
            (OpenAPI {api.openapi})
          </dd>
          <dt>Authentication</dt>
          <dd>
            Bearer token from a sign-in route, or a browser session cookie with <code>X-CSRF-Token</code>.{" "}
            {plural(publicOps, "operation")} need no token.
          </dd>
          <dt>Methods</dt>
          <dd>{methods.join(", ")}</dd>
          <dt>Description</dt>
          <dd>{api.description}</dd>
        </dl>
      </Sec>

      <Sec no={`${CH.n}.2`} id="roles" title="Operations per role">
        <p>
          The Administrator may use every authenticated operation. The other roles reach only the operations listed for
          them; a refused role gets HTTP 403 <code>role_refused</code>.
        </p>
        <div className="table-wrap">
          <table>
            <caption>Number of operations each role may use, of {ops.length - publicOps} authenticated operations.</caption>
            <thead>
              <tr>
                <th scope="col">Role</th>
                <th scope="col" className="num">
                  operations
                </th>
              </tr>
            </thead>
            <tbody>
              {ROLE_ORDER.map((r) => (
                <tr key={r}>
                  <th scope="row">{ROLE_NAMES[r]}</th>
                  <td className="num">{roleCount(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <nav aria-label="Operation groups">
          <p>
            Groups:{" "}
            {api.tags.map((t, i) => (
              <span key={t}>
                {i > 0 && ", "}
                <a href={`#group-${t}`}>{t}</a>
              </span>
            ))}
            .
          </p>
        </nav>
      </Sec>

      {api.tags.map((tag, i) => {
        const mine = ops.filter((o) => o.tag === tag);
        const docs = Array.from(new Set(mine.map((o) => o.doc).filter(Boolean)));
        return (
          <Sec key={tag} no={`${CH.n}.${i + 3}`} id={`group-${tag}`} title={tag}>
            <p>
              {plural(mine.length, "operation")}. Reference:{" "}
              {docs.map((d, j) => (
                <span key={d}>
                  {j > 0 && ", "}
                  <Link href={apiDocHref(d)}>docs/api/{d}</Link>
                </span>
              ))}
              .
            </p>
            <div className="table-wrap wide">
              <table className="api">
                <caption>Operations in the {tag} group.</caption>
                <thead>
                  <tr>
                    <th scope="col">Operation</th>
                    <th scope="col">What it does</th>
                    <th scope="col">Roles</th>
                  </tr>
                </thead>
                <tbody>
                  {mine.map((o) => (
                    <tr key={o.operationId} id={o.operationId}>
                      <th scope="row" className="api-op">
                        <span className="api-method">{o.method}</span> <code>{o.path}</code>
                      </th>
                      <td>
                        {o.summary}
                        <Params op={o} />
                      </td>
                      <td>
                        <Roles op={o} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Sec>
        );
      })}
    </article>
  );
}
