/**
 * Console Playwright results from the status data.
 *
 * The console job runs every spec on Chromium, Firefox and WebKit against a
 * real smcpd. Its counts arrive as test packages named console/e2e/<engine>,
 * and each test that claims requirements appears in the requirement items as
 * "console/e2e/<engine>.<spec> > <title>". A claimed requirement is failing
 * when any test claiming it failed, so a listed test whose requirements are
 * all not failing did not fail.
 */
import type { PackageTests, ReqStatus, Status } from "./status";

export const CONSOLE_PREFIX = "console/e2e/";

export type ConsoleEngine = PackageTests & { engine: string };

export type ConsoleTest = {
  spec: string;
  title: string;
  /** Engine to outcome: "pass" when none of its claimed requirements is failing. */
  engines: Record<string, "pass" | "failing-claim">;
  requirements: string[];
};

export type ConsoleResults = { engines: ConsoleEngine[]; tests: ConsoleTest[]; wrappers: PackageTests[] };

export function consoleResults(s: Status): ConsoleResults {
  const engines: ConsoleEngine[] = [];
  const wrappers: PackageTests[] = [];
  for (const p of s.tests.packages) {
    if (!p.name.startsWith(CONSOLE_PREFIX)) continue;
    const engine = p.name.slice(CONSOLE_PREFIX.length);
    if (engine === "browsers") wrappers.push(p);
    else engines.push({ ...p, engine });
  }
  engines.sort((a, b) => a.engine.localeCompare(b.engine));
  const known = new Set(engines.map((e) => e.engine));

  const byKey = new Map<string, ConsoleTest>();
  for (const item of s.requirements.items) {
    for (const t of item.tests ?? []) {
      if (!t.startsWith(CONSOLE_PREFIX)) continue;
      const rest = t.slice(CONSOLE_PREFIX.length);
      const dot = rest.indexOf(".");
      if (dot < 0) continue;
      const engine = rest.slice(0, dot);
      if (!known.has(engine)) continue;
      const [spec, ...title] = rest.slice(dot + 1).split(" > ");
      if (!spec || title.length === 0) continue;
      const key = `${spec} > ${title.join(" > ")}`;
      let ct = byKey.get(key);
      if (!ct) {
        ct = { spec, title: title.join(" > "), engines: {}, requirements: [] };
        byKey.set(key, ct);
      }
      if (!ct.requirements.includes(item.id)) ct.requirements.push(item.id);
      const failing = (item.status as ReqStatus) === "failing";
      if (failing) ct.engines[engine] = "failing-claim";
      else if (!ct.engines[engine]) ct.engines[engine] = "pass";
    }
  }
  const tests = Array.from(byKey.values());
  for (const t of tests) t.requirements.sort(compareReq);
  tests.sort((a, b) => a.spec.localeCompare(b.spec) || a.title.localeCompare(b.title));
  return { engines, tests, wrappers };
}

function compareReq(a: string, b: string): number {
  return a.localeCompare(b, "en", { numeric: true });
}
