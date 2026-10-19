/**
 * The control API's OpenAPI 3.1 document, read at build time.
 *
 * site/data/openapi.json is written by `go run ./tools/openapi` (`make openapi`)
 * from the operation table smcpd serves at GET /api/v1/openapi.json and the
 * route registrations in the Go sources. A Go test fails when the committed
 * file is stale, and the regenerate workflow rewrites it on pull requests.
 */
import fs from "node:fs";
import path from "node:path";

export const OPENAPI_FILE = path.join(process.cwd(), "data", "openapi.json");

export type ApiParam = { name: string; in: "path" | "query"; required: boolean };

export type ApiOperation = {
  method: string;
  path: string;
  operationId: string;
  tag: string;
  summary: string;
  /** docs/api/<file>.md, from the operation's "Reference:" description. */
  doc: string;
  params: ApiParam[];
  hasBody: boolean;
  response: "json" | "stream" | "file";
  public: boolean;
  roles: string[];
  refined: boolean;
};

export type ApiDocument = {
  title: string;
  version: string;
  description: string;
  openapi: string;
  tags: string[];
  operations: ApiOperation[];
  raw: unknown;
};

const METHOD_ORDER = ["get", "post", "put", "patch", "delete"];

type RawOp = {
  operationId?: string;
  tags?: string[];
  summary?: string;
  description?: string;
  parameters?: { name: string; in: string; required?: boolean }[];
  requestBody?: unknown;
  responses?: Record<string, { content?: Record<string, unknown> }>;
  "x-smcp-public"?: boolean;
  "x-smcp-roles"?: string[];
  "x-smcp-refined"?: boolean;
};

type RawDoc = {
  openapi?: string;
  info?: { title?: string; version?: string; description?: string };
  tags?: { name: string }[];
  paths?: Record<string, Record<string, RawOp>>;
};

/** Parses the document; throws with the field that is missing. */
export function parseOpenApi(text: string, file = OPENAPI_FILE): ApiDocument {
  const raw = JSON.parse(text) as RawDoc;
  if (!raw.openapi || !raw.info?.title || !raw.paths) {
    throw new Error(`${file}: not an OpenAPI document (openapi, info.title or paths missing)`);
  }
  const operations: ApiOperation[] = [];
  for (const [p, item] of Object.entries(raw.paths)) {
    for (const [method, op] of Object.entries(item)) {
      if (!METHOD_ORDER.includes(method)) continue;
      const content = op.responses?.["200"]?.content ?? {};
      const doc = /Reference: docs\/api\/([\w.-]+\.md)/.exec(op.description ?? "")?.[1] ?? "";
      operations.push({
        method: method.toUpperCase(),
        path: p,
        operationId: op.operationId ?? `${method}${p}`,
        tag: op.tags?.[0] ?? "other",
        summary: op.summary ?? "",
        doc,
        params: (op.parameters ?? []).map((x) => ({
          name: x.name,
          in: x.in === "path" ? "path" : "query",
          required: Boolean(x.required),
        })),
        hasBody: op.requestBody !== undefined,
        response: "text/event-stream" in content ? "stream" : "application/octet-stream" in content ? "file" : "json",
        public: op["x-smcp-public"] === true,
        roles: op["x-smcp-roles"] ?? [],
        refined: op["x-smcp-refined"] === true,
      });
    }
  }
  operations.sort(
    (a, b) =>
      a.tag.localeCompare(b.tag) ||
      a.path.localeCompare(b.path) ||
      METHOD_ORDER.indexOf(a.method.toLowerCase()) - METHOD_ORDER.indexOf(b.method.toLowerCase()),
  );
  const tags = Array.from(new Set([...(raw.tags ?? []).map((t) => t.name), ...operations.map((o) => o.tag)])).filter(
    (t) => operations.some((o) => o.tag === t),
  );
  tags.sort();
  return {
    title: raw.info.title,
    version: raw.info.version ?? "",
    description: raw.info.description ?? "",
    openapi: raw.openapi,
    tags,
    operations,
    raw,
  };
}

let cached: ApiDocument | null = null;

export function loadOpenApi(): ApiDocument {
  if (!cached) cached = parseOpenApi(fs.readFileSync(OPENAPI_FILE, "utf8"));
  return cached;
}

/** Appendix C role identifiers as the document writes them, with display names. */
export const ROLE_NAMES: Record<string, string> = {
  administrator: "Administrator",
  operator: "Operator",
  policy_author: "Policy Author",
  approver: "Approver",
  session_approver: "Session Approver",
  auditor: "Auditor",
  researcher: "Researcher",
};

export const ROLE_ORDER = Object.keys(ROLE_NAMES);

/** Site path of the reference page for docs/api/<file>.md. */
export function apiDocHref(doc: string): string {
  return doc ? `/docs/api/${doc.replace(/\.md$/, "").toLowerCase()}/` : "";
}
