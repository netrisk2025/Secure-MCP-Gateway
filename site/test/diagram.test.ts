// Unit tests of the diagram step parser and of split diagrams. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { parseDiagram, withAutonumber } from "../src/lib/diagram.ts";

test("sequence steps start at the autonumber start value", () => {
  const d = parseDiagram(
    ["sequenceDiagram", "  autonumber 13", "  participant A as Alpha", "  A->>B: one", "  B-->>A: two"].join("\n"),
  );
  assert.equal(d.kind, "sequence");
  assert.deepEqual(
    d.steps.map((s) => [s.n, s.from, s.to, s.label, s.style]),
    [
      [13, "Alpha", "B", "one", "solid"],
      [14, "B", "Alpha", "two", "dashed"],
    ],
  );
  assert.deepEqual(
    parseDiagram("sequenceDiagram\n  autonumber\n  A->>B: x").steps.map((s) => s.n),
    [1],
  );
});

test("withAutonumber keeps an explicit start value", () => {
  const src = "sequenceDiagram\n  autonumber 7\n  A->>B: x";
  assert.equal(withAutonumber(src), src);
  assert.match(withAutonumber("sequenceDiagram\n  A->>B: x"), /^sequenceDiagram\n  autonumber\n/);
});

// A sequence drawn in parts numbers its steps once across the parts: within
// a flow document, or a section of the architecture document, the steps of
// the sequence diagrams run 1, 2, 3 ... without gaps or repeats.
const ROOT = path.resolve(import.meta.dirname, "../..");
const MERMAID = /```mermaid\n([\s\S]*?)```/g;

function assertContinuous(md: string, where: string) {
  const ns = Array.from(md.matchAll(MERMAID), (m) => parseDiagram(m[1]))
    .filter((d) => d.kind === "sequence")
    .flatMap((d) => d.steps.map((s) => s.n));
  assert.deepEqual(ns, ns.map((_, i) => i + 1), `${where}: step numbers ${ns.join(",")}`);
}

test("split sequence diagrams continue their step numbers", () => {
  const flows = path.join(ROOT, "docs/flows");
  for (const f of fs.readdirSync(flows).filter((f) => f.endsWith(".md"))) {
    assertContinuous(fs.readFileSync(path.join(flows, f), "utf8"), `docs/flows/${f}`);
  }
  const arch = fs.readFileSync(path.join(ROOT, "ArchitectureV2.md"), "utf8");
  for (const section of arch.split(/^#{2,4} /m)) assertContinuous(section, `ArchitectureV2.md "${section.split("\n")[0]}"`);
});
