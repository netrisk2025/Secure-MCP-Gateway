// Unit tests of the document list. Run with `npm test` (node --test with type stripping).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  FLOWS_DIR,
  INDEX_FILE,
  REPO_ROOT,
  ROOT_GROUP,
  allDocs,
  docGroups,
  docSlug,
  firstSentence,
  flowSlug,
  groupAnchor,
  indexPlacement,
} from "../src/lib/content.ts";

function markdownUnder(rel: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(path.join(REPO_ROOT, rel), { withFileTypes: true })) {
    const r = `${rel}/${e.name}`;
    if (e.isDirectory()) out.push(...markdownUnder(r));
    else if (e.name.endsWith(".md")) out.push(r);
  }
  return out;
}

test("every Markdown file under docs/ except the flows is a document page", () => {
  const files = new Set(allDocs().map((d) => d.file));
  const expected = markdownUnder("docs").filter((f) => !f.startsWith(`${FLOWS_DIR}/`));
  assert.ok(expected.length > 40, `found only ${expected.length} documents under docs/`);
  for (const f of expected) assert.ok(files.has(f), `${f} has no page`);
  for (const f of files) assert.ok(!f.startsWith(`${FLOWS_DIR}/`), `${f} belongs to the Flows chapter`);
});

test("document slugs are unique and the named pages exist", () => {
  const slugs = allDocs().map((d) => d.slug);
  assert.equal(new Set(slugs).size, slugs.length);
  const want = ["install", "quickstart", "operator-guide", "policy-reference", "packaging-guide", "security-limitations",
    "hostile-fixtures", "agents-conformance", "clients", "clients/claude-code", "runbooks/emergency-stop", "api/policy",
    "documentation", "architecture-v2", "changelog"];
  for (const s of want) assert.ok(slugs.includes(s), `no /docs/${s}/`);
});

test("groups follow the documentation index and the root documents come last", () => {
  const groups = docGroups();
  assert.equal(groups[0], "Start here");
  assert.equal(groups[groups.length - 1], ROOT_GROUP);
  for (const g of ["Reference", "Client quick starts", "Runbooks", "Control API", "Operations"]) assert.ok(groups.includes(g), g);
  assert.ok(groups.indexOf("Client quick starts") < groups.indexOf("Operations"), "index sections come before directory groups");
  const first = allDocs()[0];
  assert.equal(first.file, INDEX_FILE);
  for (const d of allDocs()) assert.ok(groups.includes(d.group));
  // A group's documents are contiguous, so the previous and next links read through one group at a time.
  const seq = allDocs().map((d) => d.group);
  for (const g of groups) {
    const idx = seq.flatMap((x, i) => (x === g ? [i] : []));
    assert.equal(idx[idx.length - 1] - idx[0] + 1, idx.length, `group ${g} is split`);
  }
});

test("docSlug maps paths under docs/", () => {
  assert.equal(docSlug("docs/README.md"), "documentation");
  assert.equal(docSlug("docs/install.md"), "install");
  assert.equal(docSlug("docs/api/policy.md"), "api/policy");
  assert.equal(docSlug("docs/clients/README.md"), "clients");
  assert.equal(docSlug("docs/operations/logging-metrics-reload.md"), "operations/logging-metrics-reload");
  assert.equal(flowSlug("docs/flows/Tool_Call.md"), "tool-call");
  assert.equal(groupAnchor("Client quick starts"), "g-client-quick-starts");
});

test("indexPlacement records the first linking section and skips external links", () => {
  const md = [
    "# Docs",
    "",
    "## Start here",
    "[Install](install.md) and [site](https://example.com/x.md)",
    "## Runbooks (FR-18.8)",
    "| [Stop](runbooks/stop.md#a) | [Install again](install.md) |",
    "[Clients](clients/)",
  ].join("\n");
  const p = indexPlacement(md);
  assert.deepEqual(p.get("docs/install.md"), { pos: 0, heading: "Start here" });
  assert.deepEqual(p.get("docs/runbooks/stop.md"), { pos: 1, heading: "Runbooks" });
  assert.deepEqual(p.get("docs/clients/README.md"), { pos: 2, heading: "Runbooks" });
  assert.equal(p.size, 3);
});

test("firstSentence takes the opening sentence, or the section headings", () => {
  assert.equal(
    firstSentence("\nThe broker is off by default. Enable it with `[egress] enabled = true`.\n\n## Use\n"),
    "The broker is off by default.",
  );
  assert.equal(firstSentence("\nSee [the guide](g.md), e.g. `a. B` here. Next.\n"), "See the guide, e.g. `a. B` here.");
  assert.equal(firstSentence("\nReference: [x](x.md).\n\n## Back up\n\ntext\n\n## Restore (FR-1)\n"), "Sections: Back up, Restore.");
  assert.equal(firstSentence("\n```\ncode. Not prose.\n```\n\nProse here\n"), "Prose here");
  assert.equal(firstSentence(""), "");
});
