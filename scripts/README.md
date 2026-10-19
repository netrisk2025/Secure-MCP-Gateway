# scripts

Automation for CI, releases and merging many parallel branches. Every script
prints what it does and exits non-zero on failure. Run them from any
directory inside the repository.

| Script | Used by | Purpose |
|---|---|---|
| `merge-queue.sh` | merge-steward agent, maintainers | Rebase, regenerate, check, push and squash-merge ready PRs one at a time |
| `ci-integration.sh` | CI job `linux-integration`, `make integration` | Bootstrap an instance, run smcpd, drive an MCP client, verify the journal, check Podman and nftables |
| `itest-client/` | `ci-integration.sh` | Go MCP client: OAuth 2.1 with PKCE through the sign-in form, `tools/list`, `tools/call` |
| `evidence-fixture/` | console job (`console/e2e/exports.spec.ts`) | Writes hostile journal events and observation records (formula, HTML, script and remote-media payloads) into a stopped instance, for the inert-rendering and CSV export test (SR-6.17-1) |
| `ci-offline.sh` | CI job `offline` | Run the acceptance suite in a network namespace with loopback only (FR-12.2, AT-17), after building the reference filesystem and git packages |
| `agents/` | workflow `agents` ("Real agents"), developers | Real-agent conformance suite: drives Claude Code, Codex CLI, Hermes, OpenCode, Gemini CLI and Goose against a fresh Gateway and judges each scenario from the journal; `install-clis.sh` installs the pinned CLIs, `publish.sh` puts `agents.json` on `site-data`. See `docs/agents-conformance.md` |
| `publish-status.sh` | CI job `status` | Commit `status.json` and `history.json` to the orphan branch `site-data` |
| `trigger-site-deploy.sh` | CI job `status` | Wait for the new `status.json` to be served, then call the Vercel deploy hook |
| `auto-update-prs.sh` | workflow `auto-update` | Label auto-merge PRs that conflict with main `needs-rebase` (does not push) |
| `npm-audit-gate.sh` | CI job `security`, `make vuln` | `npm audit` at high severity with the reviewed allowlist in `.github/npm-audit-allowlist.json` |
| `render-brew-formula.sh` | release maintainers | Render `packaging/homebrew/smcp.rb.tmpl` for a release |
| `release-sbom.sh` | GoReleaser before hook | Write `build/sbom/sbom.spdx.json`, the SBOM placed in every release archive (FR-13.1) |
| `ci-systemd.sh` | `ci-integration.sh` (enforced section) | `smcpctl install --profile enforced` twice, then smcpd.service under systemd with servers as `smcp-srv` |
| `ci-install-standalone.sh` | CI job `install-standalone` | `smcpctl install` with the runner's systemd user manager or launchd, a second install, uninstall |

## Merge queue

Many agents open PRs against main at the same time. Most conflicts between
them are in files that are generated from other files, or in CHANGELOG.md
where both sides added entries. `merge-queue.sh` resolves those mechanically
and stops on anything else.

```
scripts/merge-queue.sh              # all open PRs labeled "ready", oldest first
scripts/merge-queue.sh 12 15 14     # these PRs, in this order
scripts/merge-queue.sh --dry-run 12 # rebase and check only; no push, no merge
```

For each PR it:

1. Fetches `main` and the PR branch. Draft PRs and PRs from forks are skipped.
2. Rebases the branch onto `origin/main` in a temporary worktree, so the
   working copy you run it from is not touched. Conflicts are resolved as
   follows; any other conflicted file aborts the rebase for that PR and is
   reported with the kept worktree path:

   | File | Resolution |
   |---|---|
   | `Secure_MCP_Gateway_SRS.md` | regenerate with `python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md` |
   | `go.sum` (any module) | union of both sides, then `go mod tidy` |
   | `site/package-lock.json` | main's version, then `npm install --package-lock-only` |
   | `CHANGELOG.md` | union of both sides (also set by `.gitattributes`, `merge=union`) |

3. Regenerates the SRS and runs `go mod tidy` again (and the npm lock when
   `site/package.json` changed), because a clean textual rebase can still
   leave generated files stale. Differences are committed as "Regenerate
   generated files after rebase onto main".
4. Runs `make check`. A failure is reported with the log path and the PR is
   left unchanged on GitHub.
5. Pushes with `--force-with-lease` against the head it started from, so a
   push someone made in the meantime is never overwritten.
6. Waits for the PR's required checks (`gh pr checks --watch --required`).
7. Merges with `gh pr merge --squash --delete-branch --match-head-commit`,
   then fetches main before the next PR.

The final report lists merged, failed (with the reason) and skipped PRs. The
exit status is 1 when any PR failed.

Requirements: `git`, `gh` (authenticated with push access), `jq`,
`python3`, Go and Node.js (for `make check`).

### What resolves conflicts without the merge queue

- `.gitattributes` marks `CHANGELOG.md` `merge=union`, so local merges and
  rebases keep both sides' entries.
- The `regenerate` workflow regenerates the SRS and runs `go mod tidy` on
  same-repository PRs and pushes the result to the PR branch.
- The `auto-update` workflow checks PRs that have auto-merge enabled after
  every push to main and labels conflicting PRs `needs-rebase`. It does not
  push: a CI run started by a `github-actions[bot]` push waits for approval
  and blocks the merge. Update branches with `gh pr update-branch <n>
  --rebase` (a user token) or `merge-queue.sh`.
- For the same reason, commit regenerated files yourself. When the
  `regenerate` workflow has to push a fix, re-run the held CI run with
  `gh run rerun <id>` or push any commit to the branch.

## Integration run

`ci-integration.sh` uses the built binaries the way an operator would:
`smcpctl bootstrap` in a temporary directory with password files, `smcpd
--config`, a full OAuth sign-in as the Session Approver and MCP session from
`itest-client` against the bundled `smcp-refserver`, `smcpctl stop` (the next
call must be refused) and `smcpctl resume`, and `smcpctl journal verify` after
a clean stop. On Linux it also checks `podman --version` and
`sudo nft list ruleset`; set `SMCP_REQUIRE_PREREQS=1` to make missing
prerequisites fail the run. Features not in the current build (backup,
restore and the enforced profile) are listed under "Skipped" at the end
instead of failing.

```
make integration
SMCP_ITEST_DIR=/tmp/itest scripts/ci-integration.sh   # keep the work directory
```

## Status data for the website

On every push to main the CI `status` job takes `build/status.json` from the
`go` job (written by `tools/reqreport`), records the overall CI conclusion,
and `publish-status.sh` commits it with an updated `history.json` (at most
200 entries, newest last) to the orphan branch `site-data`. The branch carries
a `vercel.json` that disables Vercel deployments for it, and no workflow runs
on pushes to it. `trigger-site-deploy.sh` then waits until
`https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/site-data/status.json`
serves the new commit and calls the deploy hook in the `VERCEL_DEPLOY_HOOK`
secret; without the secret it does nothing.

To produce the same files locally:

```
make status                                   # build/reqreport.{json,md}, build/status.json
SITE_DATA_DRY_RUN=1 scripts/publish-status.sh build/status.json
```
