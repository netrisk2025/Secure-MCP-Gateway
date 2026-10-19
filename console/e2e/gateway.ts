// Starts a real Gateway for the Playwright acceptance tests: builds smcpd,
// smcpctl, the reference server and the test MCP client, bootstraps a new
// instance in console/.e2e, adds an Approver account and an account for
// every other Appendix C role, enables the Secret Vault (passphrase key
// source) and the Egress Broker, turns desktop notifications off, moves
// the listeners to free ports and runs smcpd until teardown.
//
// With SMCP_E2E_PROFILE=enforced (Linux with rootless Podman, the CI job
// console-enforced) the instance runs the Enforced profile: the reference
// server, which must then be statically linked, runs in the sandbox. The
// profile the Gateway reports is recorded in GatewayInfo.profile, and
// start fails when the Enforced profile was asked for and not obtained.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { request } from "node:https";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const consoleDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const repoRoot = resolve(consoleDir, "..");
export const work = join(consoleDir, ".e2e");
export const bin = join(work, "bin");
export const inst = join(work, "instance");
export const infoFile = join(work, "gateway.json");

export interface GatewayInfo {
  adminURL: string;
  publicURL: string;
  ca: string;
  config: string;
  adminPassword: string;
  approverUser: string;
  approverPassword: string;
  sessionApproverPassword: string;
  /** Console accounts by role (Operator, Policy Author, Auditor, Researcher); all use rolePassword. */
  roleUsers: Record<string, string>;
  rolePassword: string;
  marker: string;
  pid: number;
  /** The profile the running Gateway reports (health info.profile): "standalone" or "enforced". */
  profile: string;
}

/** The profile the suite is asked to run in (SMCP_E2E_PROFILE). */
export const requestedProfile = process.env.SMCP_E2E_PROFILE === "enforced" ? "enforced" : "standalone";

// reportedProfile reads info.profile from the control API health report.
function reportedProfile(adminURL: string, ca: string, token: string): Promise<string> {
  return new Promise((ok, fail) => {
    const req = request(`${adminURL}/api/v1/health/status`, { ca: readFileSync(ca), headers: { Authorization: `Bearer ${token}` } }, (res) => {
      let body = "";
      res.on("data", (d: Buffer) => (body += d.toString()));
      res.on("end", () => {
        try {
          const p = (JSON.parse(body) as { info?: { profile?: string } }).info?.profile;
          ok(p === "enforced" ? "enforced" : "standalone");
        } catch (e) {
          fail(e);
        }
      });
    });
    req.on("error", fail);
    req.end();
  });
}

export function info(): GatewayInfo {
  return JSON.parse(readFileSync(infoFile, "utf8")) as GatewayInfo;
}

// Ports handed out by freePort in this run.
const issued = new Set<number>();

function bindable(port: number): Promise<boolean> {
  return new Promise((ok) => {
    const s = createServer();
    s.once("error", () => ok(false));
    s.listen(port, "127.0.0.1", () => s.close(() => ok(true)));
  });
}

// freePort returns a bindable loopback port below the ephemeral range
// (20000-32767) for a listener written into the configuration. A port from
// listen(0) is in the ephemeral range, where smcpd's own port-0 listeners
// (the egress proxy) can take it before the configured listener binds it,
// which made smcpd exit at startup with "address already in use".
async function freePort(): Promise<number> {
  for (let i = 0; i < 500; i++) {
    const p = 20000 + Math.floor(Math.random() * 12768);
    if (issued.has(p)) continue;
    issued.add(p);
    if (await bindable(p)) return p;
  }
  throw new Error("no free loopback port below the ephemeral range");
}

function secretFile(name: string, value: string): string {
  const p = join(work, name);
  writeFileSync(p, value, { mode: 0o600 });
  chmodSync(p, 0o600);
  return p;
}

let proc: ChildProcess | null = null;

export async function start(): Promise<GatewayInfo> {
  rmSync(work, { recursive: true, force: true });
  mkdirSync(bin, { recursive: true });
  if (process.env.SMCP_E2E_BIN) {
    for (const b of ["smcpd", "smcpctl", "smcp-refserver", "itest-client"]) execFileSync("cp", [join(process.env.SMCP_E2E_BIN, b), bin]);
    // Test tooling that only some jobs build (console/e2e/exports.spec.ts).
    for (const b of ["evidence-fixture"]) if (existsSync(join(process.env.SMCP_E2E_BIN, b))) execFileSync("cp", [join(process.env.SMCP_E2E_BIN, b), bin]);
  } else {
    execFileSync("go", ["build", "-o", bin + "/", "./cmd/smcpd", "./cmd/smcpctl", "./cmd/smcp-refserver", "./scripts/itest-client", "./scripts/evidence-fixture"], {
      cwd: repoRoot,
      stdio: "inherit",
    });
  }
  const adminPassword = "console-e2e-admin-pw";
  const sessionApproverPassword = "console-e2e-session-approver";
  const approverPassword = "console-e2e-approver-pw";
  const adminPw = secretFile("admin.pw", adminPassword);
  const saPw = secretFile("approver.pw", sessionApproverPassword);
  const apPw = secretFile("tool-approver.pw", approverPassword);
  const ctl = join(bin, "smcpctl");
  execFileSync(ctl, ["bootstrap", "--dir", inst, "--admin-password-file", adminPw, "--approver-password-file", saPw], { stdio: "inherit" });
  const config = join(inst, "smcp.toml");
  const harness = await freePort();
  const admin = await freePort();
  const metrics = await freePort();
  let toml = readFileSync(config, "utf8");
  toml = toml
    .replaceAll("127.0.0.1:8443", `127.0.0.1:${harness}`)
    .replaceAll("127.0.0.1:8444", `127.0.0.1:${admin}`)
    .replaceAll("127.0.0.1:8445", `127.0.0.1:${metrics}`);
  // Bootstrap may write an [approvals] table; desktop notifications stay off.
  const hasApprovals = /^\[approvals\]$/m.test(toml);
  toml = toml.replace(/^notify = ".*"$/m, 'notify = "off"');
  writeFileSync(config, toml);
  const remotePort = await freePort();
  const hash = execFileSync(ctl, ["hash-password", "--password-file", apPw], { encoding: "utf8" }).trim();
  const rolePassword = "console-e2e-role-password";
  const roleHash = execFileSync(ctl, ["hash-password", "--password-file", secretFile("role.pw", rolePassword)], { encoding: "utf8" }).trim();
  const roleUsers: Record<string, string> = { operator: "olga", policy_author: "pat", auditor: "aud", researcher: "rita" };
  const vaultPw = secretFile("vault.pw", "console-e2e-vault-passphrase");
  const sandboxDir = join(inst, "sandbox");
  const enforced = requestedProfile === "enforced";
  if (enforced) {
    // Server instances run under subordinate UIDs: the instance and sandbox
    // directories must be searchable by them.
    for (const d of [work, inst, sandboxDir]) chmodSync(d, 0o755);
  }
  const cgroupManager = process.env.SMCP_ENFORCED_CGROUP_MANAGER;
  // Tables go before the arrays of tables so no key lands in the wrong table.
  appendFileSync(
    config,
    [
      ...(enforced ? ["", "[profile]", 'mode = "enforced"', "", "[runtime]", 'sandbox = "podman"', ...(cgroupManager ? [`cgroup_manager = "${cgroupManager}"`] : [])] : []),
      ...(hasApprovals ? [] : ["", "[approvals]", 'notify = "off"']),
      // Every mcpCall signs in anew and leaves its session open, all as
      // the bootstrap principal; with Playwright's retry the suite opens
      // more than the CP-18 default of 8 concurrent sessions, and a refused
      // sign-in then looks like a missing approval or call (G-13).
      ...(/^\[limits\]$/m.test(toml) ? [] : ["", "[limits]", "sessions_per_principal = 64"]),
      "",
      "[egress]",
      "enabled = true",
      "",
      "[remote]",
      `address = "127.0.0.1:${remotePort}"`,
      "",
      "[secrets]",
      'key_source = "passphrase"',
      `passphrase_file = "${vaultPw}"`,
      // The G-02 Secret Use Policy editor publishes to this file.
      'use_policy_file = "secret-use.json"',
      "",
      "[[approvals.account]]",
      'username = "alice"',
      `password_hash = "${hash}"`,
      ...Object.entries(roleUsers).flatMap(([role, user]) => ["", "[[console.account]]", `username = "${user}"`, `password_hash = "${roleHash}"`, `role = "${role}"`]),
      ...(enforced ? ["", "[[runtime.server]]", 'alias = "ref"', "[[runtime.server.mount]]", `source = "${sandboxDir}"`] : []),
      "",
    ].join("\n"),
  );
  writeFileSync(join(dirname(config), "secret-use.json"), '{"revision": "u0"}\n', { mode: 0o600 });
  execFileSync(ctl, ["secrets", "init", "--config", config, "--passphrase-file", vaultPw], { stdio: "inherit" });
  const marker = `console-e2e-${Date.now()}`;
  writeFileSync(join(sandboxDir, "hello.txt"), marker + "\n");
  if (enforced) chmodSync(join(sandboxDir, "hello.txt"), 0o644);
  proc = spawn(join(bin, "smcpd"), ["--config", config], { stdio: ["ignore", "pipe", "pipe"], detached: false });
  const log: string[] = [];
  proc.stdout?.on("data", (d: Buffer) => log.push(d.toString()));
  proc.stderr?.on("data", (d: Buffer) => log.push(d.toString()));
  const g: GatewayInfo = {
    adminURL: `https://127.0.0.1:${admin}`,
    publicURL: `https://127.0.0.1:${harness}`,
    ca: join(inst, "state", "tls", "ca.crt"),
    config,
    adminPassword,
    approverUser: "alice",
    approverPassword,
    sessionApproverPassword,
    roleUsers,
    rolePassword,
    marker,
    pid: proc.pid ?? 0,
    profile: "",
  };
  for (let i = 0; i < 120; i++) {
    if (proc.exitCode !== null) throw new Error("smcpd exited during startup:\n" + log.join(""));
    try {
      execFileSync(ctl, ["health", "--config", config], { stdio: "ignore" });
    } catch {
      await new Promise((r) => setTimeout(r, 500));
      continue;
    }
    g.profile = await reportedProfile(g.adminURL, g.ca, readFileSync(join(inst, "state", "keys", "admin.token"), "utf8").trim());
    if (g.profile !== requestedProfile) throw new Error(`SMCP_E2E_PROFILE=${requestedProfile} but the Gateway reports the ${g.profile} profile:\n` + log.join(""));
    writeFileSync(infoFile, JSON.stringify(g, null, 2));
    writeFileSync(join(work, "smcpd.pid"), String(proc.pid));
    proc.stdout?.removeAllListeners("data");
    proc.stderr?.removeAllListeners("data");
    proc.stdout?.resume();
    proc.stderr?.resume();
    return g;
  }
  throw new Error("smcpd did not become healthy within 60 s:\n" + log.join(""));
}

export function stop(): void {
  const pidFile = join(work, "smcpd.pid");
  if (proc && proc.exitCode === null) proc.kill("SIGTERM");
  else if (existsSync(pidFile)) {
    try {
      process.kill(Number(readFileSync(pidFile, "utf8")), "SIGTERM");
    } catch {
      // already gone
    }
  }
}

/** A second Gateway for tests that change state the shared one must keep (a suspended server, a fail-closed cause). */
export interface Dedicated extends GatewayInfo {
  dir: string;
  /** Stops smcpd and starts it again on the same instance; resolves once it answers. */
  restart(between?: () => void | Promise<void>): Promise<void>;
  stop(): void;
}

/**
 * Bootstraps and starts a dedicated Gateway in console/.e2e/<name> with the
 * binaries the global setup built, on free ports, with notifications off.
 * Sign in with a fresh browser context: the session cookie is per host, not
 * per port, so it would replace the shared Gateway's.
 */
/** The Neo4j database for the graph mirror (SMCP_NEO4J_URL, SMCP_NEO4J_USER, SMCP_NEO4J_PASSWORD), or null. */
export const neo4j = process.env.SMCP_NEO4J_URL
  ? { url: process.env.SMCP_NEO4J_URL, user: process.env.SMCP_NEO4J_USER || "neo4j", password: process.env.SMCP_NEO4J_PASSWORD ?? "" }
  : null;

export async function startDedicated(
  name: string,
  opts: { secrets?: boolean; egress?: boolean; graph?: boolean; edit?: (toml: string) => string } = {},
): Promise<Dedicated> {
  const dir = join(work, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const adminPassword = "console-e2e-dedicated-admin";
  const sessionApproverPassword = "console-e2e-dedicated-approver";
  const adminPw = secretFile(`${name}-admin.pw`, adminPassword);
  const saPw = secretFile(`${name}-approver.pw`, sessionApproverPassword);
  const ctl = join(bin, "smcpctl");
  const harness = await freePort();
  const admin = await freePort();
  const metrics = await freePort();
  const instDir = join(dir, "instance");
  execFileSync(
    ctl,
    ["bootstrap", "--dir", instDir, "--port", String(harness), "--admin-port", String(admin), "--metrics-port", String(metrics), "--notify", "off", "--admin-password-file", adminPw, "--approver-password-file", saPw],
    { stdio: "ignore" },
  );
  const config = join(instDir, "smcp.toml");
  if (opts.edit) writeFileSync(config, opts.edit(readFileSync(config, "utf8")));
  // Optional elements, configured as on the shared Gateway.
  if (opts.egress) appendFileSync(config, "\n[egress]\nenabled = true\n");
  if (opts.graph) {
    if (!neo4j) throw new Error("the graph mirror needs SMCP_NEO4J_URL");
    const pw = secretFile(`${name}-neo4j.pw`, neo4j.password + "\n");
    appendFileSync(config, `\n[graph]\nenabled = true\nuri = "${neo4j.url}"\nusername = "${neo4j.user}"\npassword_file = "${pw}"\ncatchup_interval = "1s"\n`);
  }
  if (opts.secrets) {
    const vaultPw = secretFile(`${name}-vault.pw`, "console-e2e-dedicated-vault");
    appendFileSync(config, `\n[secrets]\nkey_source = "passphrase"\npassphrase_file = "${vaultPw}"\n`);
    execFileSync(ctl, ["secrets", "init", "--config", config, "--passphrase-file", vaultPw], { stdio: "ignore" });
  }
  const marker = `console-e2e-${name}-${Date.now()}`;
  writeFileSync(join(instDir, "sandbox", "hello.txt"), marker + "\n");
  let p: ChildProcess | null = null;
  const launch = async () => {
    p = spawn(join(bin, "smcpd"), ["--config", config], { stdio: ["ignore", "ignore", "ignore"], detached: false });
    for (let i = 0; i < 120; i++) {
      if (p.exitCode !== null) throw new Error(`dedicated smcpd ${name} exited during startup`);
      try {
        execFileSync(ctl, ["health", "--config", config], { stdio: "ignore" });
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    throw new Error(`dedicated smcpd ${name} did not answer within 60 s`);
  };
  const halt = async () => {
    const q = p;
    if (!q || q.exitCode !== null) return;
    const gone = new Promise((ok) => q.once("exit", ok));
    q.kill("SIGTERM");
    await gone;
  };
  await launch();
  return {
    adminURL: `https://127.0.0.1:${admin}`,
    publicURL: `https://127.0.0.1:${harness}`,
    ca: join(instDir, "state", "tls", "ca.crt"),
    config,
    adminPassword,
    approverUser: "",
    approverPassword: "",
    sessionApproverPassword,
    roleUsers: {},
    rolePassword: "",
    marker,
    pid: (p as ChildProcess | null)?.pid ?? 0,
    profile: await reportedProfile(`https://127.0.0.1:${admin}`, join(instDir, "state", "tls", "ca.crt"), readFileSync(join(instDir, "state", "keys", "admin.token"), "utf8").trim()),
    dir: instDir,
    restart: async (between?: () => void | Promise<void>) => {
      await halt();
      await between?.();
      await launch();
    },
    stop: () => {
      if (p && p.exitCode === null) p.kill("SIGTERM");
    },
  };
}

/** Runs the test MCP client: OAuth sign-in as the Session Approver, then one tool call. */
export function mcpCall(g: GatewayInfo, tool: string, args: object, opts: { scope?: string; expect?: string; timeout?: string; clientID?: string; repeat?: number } = {}) {
  const a = ["-url", g.publicURL, "-ca", g.ca, "-call", tool, "-args", JSON.stringify(args), "-timeout", opts.timeout ?? "150s"];
  if (opts.repeat) a.push("-repeat", String(opts.repeat));
  if (opts.scope) a.push("-scope", opts.scope);
  if (opts.clientID) a.push("-client-id", opts.clientID);
  if (opts.expect) a.push("-expect", opts.expect);
  const p = spawn(join(bin, "itest-client"), a, { env: { ...process.env, SMCP_SIGNIN_PASSWORD: g.sessionApproverPassword }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  p.stdout?.on("data", (d: Buffer) => (out += d.toString()));
  p.stderr?.on("data", (d: Buffer) => (out += d.toString()));
  const done = new Promise<{ code: number | null; out: string }>((ok) => p.on("exit", (code) => ok({ code, out })));
  return { done, kill: () => p.kill() };
}
