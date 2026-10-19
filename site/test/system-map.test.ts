// Tests of the system map (docs/flows/system-map.md) and its static SVG
// (public/system-map.svg). Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseDiagram } from "../src/lib/diagram.ts";

const SITE = path.resolve(import.meta.dirname, "..");
const md = fs.readFileSync(path.join(SITE, "..", "docs/flows/system-map.md"), "utf8");
const source = md.match(/```mermaid\n([\s\S]*?)```/)?.[1] ?? "";

test("the static SVG was rendered from the current source", () => {
  const svg = fs.readFileSync(path.join(SITE, "public/system-map.svg"), "utf8");
  const want = crypto.createHash("sha256").update(source).digest("hex");
  const got = svg.match(/sha256 ([0-9a-f]{64})/)?.[1];
  assert.equal(got, want, "public/system-map.svg is stale: run npm run render-system-map in site/");
});

test("every stage in the Stages table names a top-level subgraph, in order", () => {
  const table = md.slice(md.search(/^## Stages\s*$/m)).split("\n").filter((l) => l.startsWith("|")).slice(2);
  const ids = table.map((r) => r.split("|")[3].trim().replace(/`/g, ""));
  assert.ok(ids.length >= 8, "too few stages");
  // Top-level subgraphs are indented by two spaces; nested rows by four.
  const top = Array.from(source.matchAll(/^ {2}subgraph (\S+?)\[/gm), (m) => m[1]);
  assert.deepEqual(ids, top);
});

test("the chart cites every architecture element E-01 to E-33 and no other", () => {
  const cited = new Set(Array.from(source.matchAll(/E-(\d\d)\b/g), (m) => Number(m[1])));
  for (let n = 1; n <= 33; n++) assert.ok(cited.has(n), `E-${String(n).padStart(2, "0")} is not in the chart`);
  for (const n of cited) assert.ok(n >= 1 && n <= 33, `E-${n} is not an element`);
});

test("the edge table reads every edge", () => {
  const d = parseDiagram(source);
  assert.equal(d.kind, "flowchart");
  const arrows = source.split("\n").filter((l) => /-->|==>|-\.->/.test(l)).length;
  assert.ok(d.steps.length >= arrows, `${d.steps.length} edges parsed for ${arrows} edge lines`);
});
