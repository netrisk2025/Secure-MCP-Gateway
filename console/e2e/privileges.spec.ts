// SR-3.4-1 dependency visibility: a package revision opened in G-10 shows
// its bill of materials (the signed provenance statement: artifact and
// source with digests, licenses, the pinned dependency lock, the builder),
// its launcher argument vector, mounts, egress destinations, secret slots
// and sandbox profile. A revision is built and signed here with one of
// each (an egress destination, a secret slot, a read-only and a read-write
// mount, resource limits) and installed through the running Gateway; the
// bootstrap reference package shows the empty forms. This test is the
// SRS demonstration (open a revision in G-10; confirm each item).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { expect, test, type APIRequestContext } from "@playwright/test";
import { bin, work } from "./gateway";
import { claims, g, signIn } from "./helpers";

const operatorToken = () => readFileSync(join(dirname(g.config), "state", "keys", "admin.token"), "utf8").trim();
const auth = () => ({ Authorization: `Bearer ${operatorToken()}` });

async function enroll(request: APIRequestContext, name: string, pub: string) {
  const preview = await request.post(g.adminURL + "/api/v1/packages/trust", {
    headers: auth(),
    data: { name, public_key: pub, classes: ["low"], preview: true },
  });
  expect(preview.status(), await preview.text()).toBe(200);
  const { key_id } = (await preview.json()) as { key_id: string };
  const r = await request.post(g.adminURL + "/api/v1/packages/trust", {
    headers: auth(),
    data: { name, public_key: pub, classes: ["low"], confirm_key_id: key_id },
  });
  expect(r.status(), await r.text()).toBeLessThan(300);
}

test("G-10 shows a revision's bill of materials, argument vector, mounts, egress destinations, secret slots and sandbox profile", async ({ page, request }) => {
  claims("FR-8.18");
  test.info().annotations.push({ type: "requirement", description: "SR-3.4-1" });
  test.setTimeout(300_000);
  const ctl = join(bin, "smcpctl");
  const prefix = join(work, `privs-${Date.now()}`);
  execFileSync(ctl, ["package", "keygen", "--out", prefix, "--unencrypted"]);
  const refserver = join(bin, "smcp-refserver");
  const sha = createHash("sha256").update(readFileSync(refserver)).digest("hex");
  const id = "smcp-e2e-privileges";
  const rev = "1.0.0-e2e";
  const recipe = {
    recipe_version: 1,
    server: {
      id,
      alias: "privs",
      publisher: "Secure MCP Gateway project",
      description: "Package with one of each privilege for the G-10 dependency view.",
      revision: rev,
    },
    artifact: { type: "binary", reference: refserver, version: rev, sha256: sha },
    launch: { runtime: "native", argv: ["smcp-refserver", "--root", "{root}"], env_allowlist: ["TZ"] },
    risk_class: "low",
    instance_scope: ["shared"],
    tools: { default: { side_effect: "read", source_trust: "trusted" }, expect: ["echo", "time_now", "list_files", "read_file"] },
    capabilities: {
      filesystem: [
        { slot: "root", mode: "ro", argv_placeholder: "{root}" },
        { slot: "scratch", mode: "rw" },
      ],
      egress: [{ host: "api.example.com", ports: [443], methods: ["GET", "POST"] }],
      spawns_processes: false,
      resources: { memory_mib: 256, cpus: 0.5, pids: 64, wall_seconds: 3600 },
    },
    secrets: [{ slot: "api_token", purpose: "Token for the example API", destination: "api.example.com", modes: ["S1"] }],
    licenses: ["Apache-2.0"],
    operator_note: "Acceptance test package (SR-3.4-1).",
    source: { kind: "archive", uri: "file://" + refserver, sha256: sha },
  };
  const recipeFile = prefix + "-recipe.json";
  writeFileSync(recipeFile, JSON.stringify(recipe));
  const pkg = prefix + "-pkg";
  execFileSync(ctl, ["package", "build", "--recipe", recipeFile, "--out", pkg]);
  execFileSync(ctl, ["package", "sign", pkg, "--key", prefix + ".key"]);
  await enroll(request, "e2e-privs", readFileSync(prefix + ".pub", "utf8"));
  try {
    execFileSync(ctl, ["package", "install", pkg, "--config", g.config]);

    // Open the revision from the library list.
    await signIn(page, "/library");
    const revs = page.getByRole("table", { name: "Package revisions" });
    const row = revs.getByRole("row").filter({ hasText: rev });
    await expect(row).toContainText("verified-disabled", { timeout: 20_000 });
    await row.getByRole("link", { name: id }).click();
    await expect(page.getByRole("heading", { level: 1, name: `Package ${id}` })).toBeVisible();

    // Bill of materials.
    const bom = page
      .getByRole("region", { name: "Bill of materials (signed provenance statement)" })
      .or(page.locator("section").filter({ has: page.getByRole("heading", { name: "Bill of materials (signed provenance statement)" }) }));
    await expect(bom).toContainText(sha);
    await expect(bom).toContainText("file://" + refserver);
    await expect(bom).toContainText("Apache-2.0");
    await expect(bom).toContainText("smcpctl package");
    await expect(bom).toContainText("none: the artifact is self-contained");
    await expect(bom).toContainText(`version ${rev}`);
    // Launcher argument vector.
    const launch = page.locator("section").filter({ has: page.getByRole("heading", { name: "Launch and privileges" }) });
    await expect(launch.getByRole("definition").filter({ hasText: /^smcp-refserver --root \{root\}$/ })).toBeVisible();
    await expect(launch.getByRole("definition").filter({ hasText: /^TZ$/ })).toBeVisible();
    // Mounts.
    const mounts = page.getByRole("table", { name: "Mounts" });
    await expect(mounts.getByRole("row").filter({ hasText: "root" })).toContainText("read-only");
    await expect(mounts.getByRole("row").filter({ hasText: "root" })).toContainText("{root}");
    await expect(mounts.getByRole("row").filter({ hasText: "scratch" })).toContainText("read-write");
    // Egress destinations.
    const egress = page.getByRole("table", { name: "Egress destinations" });
    await expect(egress.getByRole("row").filter({ hasText: "api.example.com" })).toContainText("443");
    await expect(egress.getByRole("row").filter({ hasText: "api.example.com" })).toContainText("GET POST");
    // Secret slots.
    const secrets = page.getByRole("table", { name: "Secret slots" });
    await expect(secrets.getByRole("row").filter({ hasText: "api_token" })).toContainText("Token for the example API");
    await expect(secrets.getByRole("row").filter({ hasText: "api_token" })).toContainText("S1");
    await expect(secrets.getByRole("row").filter({ hasText: "api_token" })).toContainText("api.example.com");
    // Sandbox profile.
    const sandbox = launch;
    await expect(page.getByRole("heading", { name: "Sandbox profile" })).toBeVisible();
    for (const t of [
      "egress only, through the Egress Broker, to the 1 destination above",
      "may not start child processes",
      "256 MiB",
      "0.5 CPUs",
      "64 processes",
      "3600 s",
      "shared",
    ])
      await expect(sandbox.getByRole("definition").filter({ hasText: t }).first(), t).toBeVisible();

    // The bootstrap reference package: the empty forms say so.
    await page.goto(g.adminURL + "/library");
    await revs
      .getByRole("row")
      .filter({ hasText: "enabled" })
      .filter({ hasText: "smcp-ref-filesystem" })
      .getByRole("link", { name: "smcp-ref-filesystem" })
      .click();
    await expect(page.getByRole("heading", { level: 1, name: "Package smcp-ref-filesystem" })).toBeVisible();
    await expect(page.getByText("Egress destinations: none. The server has no network access.")).toBeVisible();
    await expect(page.getByText("Secret slots: none. The server receives no secret.")).toBeVisible();
    await expect(page.getByRole("table", { name: "Mounts" }).getByRole("row").filter({ hasText: "root" })).toBeVisible();
    await expect(
      page
        .locator("section")
        .filter({ has: page.getByRole("heading", { name: "Launch and privileges" }) })
        .getByRole("definition")
        .filter({ hasText: /^none$/ })
        .first(),
    ).toBeVisible();
  } finally {
    await request
      .post(g.adminURL + `/api/v1/packages/${id}/${rev}/retire`, { headers: auth(), data: { reason: "SR-3.4-1 test cleanup" } })
      .catch(() => undefined);
    await request.delete(g.adminURL + "/api/v1/packages/trust/e2e-privs", { headers: auth() }).catch(() => undefined);
  }
});
