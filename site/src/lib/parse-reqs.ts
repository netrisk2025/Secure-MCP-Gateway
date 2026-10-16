import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "./content";

export type Requirement = {
  id: string;
  title: string;
  kind: "FR" | "SR";
  parent: string;
  /** Root of the hierarchy: FR-n for functional, the SEC id (e.g. "1.18") for security. */
  root: string;
  section: string;
  stmt: string;
  alloc: string[];
  method: string;
  vstmt: string;
  src: string;
  rat: string;
};

export type Disposition = { secId: string; text: string };

export type ReqData = {
  reqs: Requirement[];
  disps: Disposition[];
  sections: { id: string; title: string }[];
};

const KEYMAP: Record<string, keyof Requirement | "ver"> = {
  P: "parent",
  S: "stmt",
  A: "alloc" as never,
  V: "ver",
  SRC: "src",
  R: "rat",
};

export function loadRequirements(): ReqData {
  const dir = path.join(REPO_ROOT, "srs_build");
  const files = fs
    .readdirSync(dir)
    .filter((f) => /^req\d+\.txt$/.test(f))
    .sort();
  const reqs: Requirement[] = [];
  const disps: Disposition[] = [];
  const sections: { id: string; title: string }[] = [];
  let section = "";
  for (const fn of files) {
    const lines = fs.readFileSync(path.join(dir, fn), "utf8").split("\n");
    lines.push("");
    let cur: Partial<Requirement> & { ver?: string } | null = null;
    for (const raw of lines) {
      const line = raw.replace(/\s+$/, "");
      if (line.startsWith("@DISP ")) {
        const [sid, txt] = line.slice(6).split(" | ");
        disps.push({ secId: sid.replace("SEC-", ""), text: txt });
        continue;
      }
      if (line.startsWith("@")) {
        const [rid, title] = line.slice(1).split(" | ");
        cur = { id: rid.trim(), title: (title ?? "").trim() };
        continue;
      }
      if (cur) {
        if (!line) {
          const r = cur;
          const [method, vstmt] = (r.ver ?? "").split(" | ");
          const id = r.id!;
          const kind: "FR" | "SR" = id.startsWith("FR-") ? "FR" : "SR";
          let root: string;
          if (kind === "FR") root = id.split(".")[0];
          else {
            const m = id.match(/^SR-([\d.]+)-\d+$/);
            root = m ? m[1].split(".")[0] : "";
          }
          reqs.push({
            id,
            title: r.title ?? "",
            kind,
            parent: r.parent ?? "",
            root,
            section,
            stmt: r.stmt ?? "",
            alloc: ((r.alloc as unknown as string) ?? "")
              .split(";")
              .map((s) => s.trim())
              .filter(Boolean),
            method: (method ?? "").trim(),
            vstmt: (vstmt ?? "").trim(),
            src: r.src ?? "",
            rat: r.rat ?? "",
          });
          cur = null;
          continue;
        }
        const idx = line.indexOf(": ");
        if (idx > 0) {
          const key = line.slice(0, idx);
          const val = line.slice(idx + 2).trim();
          const mapped = KEYMAP[key];
          if (mapped) (cur as Record<string, string>)[mapped] = val;
        }
        continue;
      }
      if (line.startsWith("### ")) {
        section = line.slice(4).trim();
        const m = section.match(/^(FR-\d+)\s+(.*)$/);
        if (m) sections.push({ id: m[1], title: m[2] });
        else sections.push({ id: section, title: section });
      }
    }
  }
  return { reqs, disps, sections };
}

/** Requirements that name an architecture ID (E-xx, F-xx, X-xx, I-xx, D-xx, G-xx) in their allocation. */
export function reqsFor(reqs: Requirement[], archId: string): Requirement[] {
  return reqs.filter((r) => r.alloc.includes(archId));
}

export function methodCounts(reqs: Requirement[]) {
  const out: Record<string, number> = {};
  for (const r of reqs) out[r.method] = (out[r.method] ?? 0) + 1;
  return out;
}
