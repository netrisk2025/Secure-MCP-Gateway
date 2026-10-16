import { readDoc } from "./content";

export type Control = {
  id: string;
  name: string;
  parent: string;
  imperative: "MUST" | "SHALL";
  statement: string;
  method: string;
  verification: string;
  source: string;
  rationale: string;
  group: string;
};

export type SecData = {
  controls: Control[];
  groups: { id: string; title: string }[];
};

export function loadSecurity(): SecData {
  const md = readDoc("MCP_Gateway_Security_SRS.md");
  const lines = md.split("\n");
  const controls: Control[] = [];
  const groups: { id: string; title: string }[] = [];
  let group = "";
  for (let i = 0; i < lines.length; i++) {
    const g = lines[i].match(/^## (\d+)\. (.*)$/);
    if (g) {
      group = g[1];
      groups.push({ id: g[1], title: g[2].trim() });
      continue;
    }
    const h = lines[i].match(/^### ([\d.]+) — (.*)$/);
    if (!h) continue;
    const fields: Record<string, string> = {};
    for (let j = i + 1; j < lines.length && !lines[j].startsWith("#"); j++) {
      const row = lines[j].match(/^\| (.*?) \| (.*) \|$/);
      if (row && row[1] !== "Field") fields[row[1].trim()] = row[2].trim();
    }
    const statement = fields["Statement"] ?? "";
    controls.push({
      id: h[1],
      name: h[2].trim(),
      parent: fields["Parent ID"] ?? "",
      imperative: statement.includes("**MUST**") ? "MUST" : "SHALL",
      statement: statement.replace(/\*\*/g, ""),
      method: fields["Verification Method"] ?? "",
      verification: fields["Verification Statement"] ?? "",
      source: fields["Source"] ?? "",
      rationale: fields["Rationale"] ?? "",
      group,
    });
  }
  return { controls, groups };
}
