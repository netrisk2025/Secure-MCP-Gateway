# Release checklist

The procedure for publishing a Secure MCP Gateway release, starting with v1.0.0. Each step names the command and what to check. A release is made only from `main` with every required CI job green.

## What a release contains

| Asset | Made by | Requirement |
|---|---|---|
| `smcp_<version>_<os>_<arch>.tar.gz` for darwin-arm64, darwin-amd64, linux-amd64, linux-arm64, each with `smcpd`, `smcpctl`, `smcp-refserver`, `smcp-session`, `smcp-stdio`, `smcp-connect`, `README.md`, `CHANGELOG.md`, `LICENSE` and `sbom.spdx.json`; since v1.1.0 also `PROVENANCE.md`, `THIRD_PARTY_NOTICES.txt`, the build recipe (`.goreleaser.yaml`, `scripts/release-sbom.sh`) and the lockfiles (`go.mod`, `go.sum`, `console/package-lock.json`) | GoReleaser (`.goreleaser.yaml`); the SBOM from `scripts/release-sbom.sh` (syft over `go.mod`, `go.sum` and `console/package-lock.json`, with the modules' license files); `PROVENANCE.md` and the notices from `tools/provenance` | FR-13.1, FR-12.8 |
| `smcp_<version>_checksums.txt` (SHA-256 of every archive) | GoReleaser | FR-13.1 |
| `smcp_<version>_checksums.txt.minisig` | GoReleaser `signs` with the release key (secrets `MINISIGN_SECRET_KEY`, `MINISIGN_PASSWORD`) | FR-13.1, FR-13.2 |
| `smcp_<version>_checksums.txt.sigstore.json` | cosign keyless step in `release.yml` | security review RR-01 |
| `*.tar.gz.sbom.json` per archive (syft over the archive, so it lists the Go modules compiled into each binary) | syft through GoReleaser | FR-12.1 |
| `Formula/smcp.rb` in [ethan03805/homebrew-tap](https://github.com/ethan03805/homebrew-tap) | GoReleaser `brews` (secret `HOMEBREW_TAP_TOKEN`); not for a pre-release unless the variable `SMCP_TAP_PRERELEASE` is `true` | FR-13.3 |

The console is embedded in `smcpd` from the committed `console/dist`. The release workflow fails when an archive lacks one of the files above, when one of the six linux-amd64 binaries does not print the tag's version (`--version`, `smcpctl version --short`), or when an SBOM entry has a license that is neither OSI-approved, public domain nor reviewed in `packaging/sbom-review.json` (`tools/sbomcheck`, FR-12.1); GoReleaser has published the release by then, so a failure there means deleting the release (below). After a release whose formula was pushed, the release workflow starts the `tap` workflow (FR-13.3).

The release public key, published in `SECURITY.md`, `docs/install.md` and embedded in `install.sh`:

```
untrusted comment: minisign public key 064FAC0C64ACCED0
RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
```

## Rehearsal results (2026-10-17, 2026-10-18)

- `v1.0.0-rc.1` (main `200719d`): published on the first run; no SBOM inside the archives yet, `smcpd --version` unsupported, no formula pushed (pre-release).
- `v1.0.0-rc.2` (main `4ba2189`, release run 39032406916): archives with `sbom.spdx.json`, every binary reports `1.0.0-rc.2`, minisign and cosign verify, `install.sh` installs on macOS arm64. With `SMCP_TAP_PRERELEASE=true` the formula was pushed (so `HOMEBREW_TAP_TOKEN` works) and the `tap` workflow passed on macOS and Ubuntu (run 39032895870). The variable was deleted afterwards; the tap holds the rc.2 formula until v1.0.0 replaces it.
- `v1.0.0-rc.3` and `v1.0.0` (both main `17b84ba`, 2026-10-18): v1.0.0 published as the latest release. The `tap` workflow passed for v1.0.0 on macOS and Ubuntu (run 39096814323) and `reference-packages` built, signed, imported and called the four reference packages on the tag (run 39096364892); both results are in `site-data/workflows.json`. The inspection of the v1.0.0 SBOMs and bundle found entries without licenses and no build recipe, lockfiles or third-party notices (FR-12.1, FR-12.8; `docs/verification/gap-list.md`); the release workflow now checks both, so the next release needs the Inspection records.
- `v1.1.0-rc.1` (main `a5e9b14`, release run 39172409546): GoReleaser published the pre-release, then the SBOM license check refused the per-archive SBOMs. For the Gateway's own module, syft reads the tagged module zip from the Go proxy and reports every file whose name looks like a license file, and that included the review file itself (then `packaging/license-review.json`, whose hash changes with every edit). The file was renamed to `packaging/sbom-review.json` (PR #121). A local snapshot cannot catch this, because a snapshot's module version is not on the proxy. The rc.1 pre-release was kept without its Sigstore bundle and label.
- `v1.1.0-rc.2` and `v1.1.0` (both main `935dc4d`, 2026-10-18; release runs 39177522965 and 39178207151): all checks passed, both labelled "enforced" (21 of 21 scenarios in the Enforced profile). For rc.2: minisign and cosign verify, `install.sh --version v1.1.0-rc.2` installs on macOS arm64, the smoke test passes (bootstrap, `smcpd` start, health, `servers list`, console HTTP 200, journal verify), every binary prints `1.1.0-rc.2` (`smcp-refserver --version` included), and `smcpctl upgrade` from v1.0.0 to rc.2 reports `release verified` and `upgrade complete`. v1.1.0 is the latest release, the tap formula is 1.1.0, the `tap` workflow passed on macOS and Ubuntu (run 39178720966), `reference-packages` passed on the tag (run 39178206965), and `install.sh` without `--version` installs 1.1.0. The SBOMs and the bundle passed the FR-12.1, FR-12.8 and FR-13.1 inspections (`docs/verification/inspections.md`).
- `smcpctl upgrade` cannot upgrade from v1.0.0-rc.1 to a later release: rc.1's `smcpctl` expects the old unsigned `SHA256SUMS` layout. Upgrades from rc.2 onward use the signed release files.

## Repository settings (once)

- [ ] Secrets `MINISIGN_SECRET_KEY` (the minisign secret key file, both lines) and `MINISIGN_PASSWORD` exist: `gh secret list -R ethan03805/Secure-MCP-Gateway`. The release job fails when the key is missing.
- [ ] Secret `HOMEBREW_TAP_TOKEN` holds a token with write access to `ethan03805/homebrew-tap` (contents: read and write). Without it GoReleaser skips the tap upload; the release still completes.
- [ ] The repository variable `SMCP_COSIGN` is unset or `true` (cosign keyless signing on).
- [ ] The repository variable `SMCP_TAP_PRERELEASE` is unset for a final release (`gh variable list -R ethan03805/Secure-MCP-Gateway`). Set it to `true` only while rehearsing the tap with a release candidate, and delete it afterwards (`gh variable delete SMCP_TAP_PRERELEASE -R ethan03805/Secure-MCP-Gateway`): while it is set, a pre-release replaces the formula of the final release.
- [ ] The maintainer's offline copy of the secret key and its password is in place (the copy used to create the secrets).

## Before tagging

- [ ] Every pull request intended for the release is merged; `main` is green on all required jobs (srs, go, lint, site, security, linux-integration, console).
- [ ] `make check` passes on a clean checkout of `main`.
- [ ] `make status` and `build/reqreport.md` reviewed: no requirement newly failing; `docs/verification/gap-list.md` matches the report.
- [ ] Runbook records (FR-18.8): `docs/verification/runbooks/` holds an execution record of each runbook in `docs/runbooks/`. When code that a runbook uses (`smcpctl stop`/`resume`, `keys`, `backup`/`restore`, `upgrade`, `package revoke`, `policy rollback`) changed after the recorded commit, execute the runbook again on the release candidate's commit and add a new dated record.
- [ ] `CHANGELOG.md` has a `## v<version>` section at the top that lists what the release contains and its known limitations, dated with the release day.
- [ ] Release label: the release is labelled "not enforced" unless AT-01 to AT-21 evidence for the release commit is complete and passing in the Enforced profile (FR-19.3). Tag a commit whose CI run on main has finished, so that the status data is for that commit: the release workflow's "Release label" step reads it with `go run ./tools/reqreport label` and appends the label, the scenario table and the reasons to the release notes (see `docs/acceptance.md`).
- [ ] Local snapshot with signing proves the configuration:

  ```sh
  MINISIGN_KEY_FILE=~/.config/smcp-dev/minisign.key MINISIGN_PASSWORD="$(cat ~/.config/smcp-dev/minisign.password)" make release-snapshot
  minisign -Vm build/dist/smcp_*_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
  tar -tzf build/dist/smcp_*_darwin_arm64.tar.gz
  rm -rf build/dist
  ```

  Check that the four archives exist, that each lists the six binaries, that the signature verifies, and that `build/dist/homebrew/Formula/smcp.rb` names the four archives with their checksums. Without `MINISIGN_KEY_FILE` the snapshot skips signing; without syft installed the archives carry no `sbom.spdx.json` (GoReleaser prints `no files matched glob=build/sbom/*.spdx.json`), which the release workflow does not allow. The snapshot builds 24 binaries in about two minutes and takes about 500 MB in `build/dist`.

- [ ] Rehearse with a release candidate on the same commit: tag `v<version>-rc.<n>` as below. GoReleaser marks a tag with a `-` suffix as a pre-release and does not push the Homebrew formula for it. Check the pre-release as in "After publishing" (install.sh needs `--version`, because `releases/latest` never resolves to a pre-release), and `smcpctl upgrade` from the previous release to it. Fix any failure through a pull request, then tag the next candidate (`-rc.<n+1>`) at the new `main` commit rather than moving a published tag.

## Tag and publish

- [ ] Tag the release commit on `main` and push the tag:

  ```sh
  git fetch origin && git checkout origin/main
  git tag -a v1.0.0 -m "Secure MCP Gateway v1.0.0"
  git push origin v1.0.0
  ```

- [ ] Watch the `release` workflow: `gh run watch -R ethan03805/Secure-MCP-Gateway $(gh run list -R ethan03805/Secure-MCP-Gateway -w release -L 1 --json databaseId -q '.[0].databaseId')`. It runs the tests (about four minutes), GoReleaser (archives with the SBOM, checksums, minisign signature, SBOM assets, release, Homebrew formula; about two minutes), checks the archive contents and versions, checks the minisign signature against the key in `install.sh` and `SECURITY.md`, signs the checksum file with cosign and uploads the bundle, then dispatches the `tap` workflow when the formula was pushed. v1.0.0-rc.1 took seven minutes. The release page exists from the end of the GoReleaser step; the Sigstore bundle is added a few seconds later.

## After publishing

- [ ] The release page lists the four archives, the checksum file, `.minisig`, `.sigstore.json` and the SBOMs: `gh release view v1.0.0 -R ethan03805/Secure-MCP-Gateway`.
- [ ] Verify the release from a clean directory:

  ```sh
  gh release download v1.0.0 -R ethan03805/Secure-MCP-Gateway -D /tmp/smcp-rel
  cd /tmp/smcp-rel
  minisign -Vm smcp_1.0.0_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
  cosign verify-blob --bundle smcp_1.0.0_checksums.txt.sigstore.json \
    --certificate-identity-regexp '^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com smcp_1.0.0_checksums.txt
  sha256sum --check smcp_1.0.0_checksums.txt   # macOS: shasum -a 256 -c
  ```

- [ ] `install.sh` installs it on macOS and on Linux: `curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh -s -- --version v1.0.0 --dir /tmp/smcp-bin`; the output reports the signature verified and, with cosign installed, the Sigstore bundle verified.
- [ ] Homebrew: the `tap` workflow (dispatched by the release workflow) passes on macOS and Ubuntu: it installs `ethan03805/tap/smcp`, runs `brew test`, fetches the archive with `install.sh` and compares every binary's SHA-256 (FR-13.3): `gh run list -R ethan03805/Secure-MCP-Gateway -w tap -L 2`. A release published with `GITHUB_TOKEN` starts no `release: published` workflow, which is why the release workflow dispatches it; to rerun it, `gh workflow run tap.yml -R ethan03805/Secure-MCP-Gateway -f tag=v1.0.0`. Locally: `brew install ethan03805/tap/smcp`, `smcpctl version`, `brew test smcp`.
- [ ] `smcpctl upgrade` from the previous release (or a source build) to the new one: download the checksum file, its `.minisig` and the host archive into a directory (`gh release download v1.0.0 -R ethan03805/Secure-MCP-Gateway -D <dir> -p 'smcp_1.0.0_checksums.txt*' -p 'smcp_1.0.0_darwin_arm64.tar.gz'`) and run `smcpctl upgrade --release <dir>`; it reports `release verified`, the backup, `upgrade complete` and the new version (FR-13.7).
- [ ] `smcpctl install` on a macOS host and on a Linux host reports every step and `health: degraded`; a second run reports `present` throughout; `smcpctl uninstall` removes the unit and binaries and keeps the journal.
- [ ] Inspect the release for FR-13.1 and record the result (date, release, inspector) in `docs/verification/inspections.md` so that `tools/reqreport` counts it; update `docs/verification/gap-list.md` for FR-13.1 and FR-13.3 (the `tap` run is the FR-13.3 evidence).
- [ ] Announce: the release notes are the `CHANGELOG.md` section; link them from the site's status page.

## If something goes wrong

- A failed workflow before GoReleaser publishes leaves no release; fix on `main`, delete the tag (`git push origin :refs/tags/v1.0.0`, `git tag -d v1.0.0`) and tag again. For a release candidate, tag the next `-rc.<n>` instead.
- A failure after GoReleaser (archive contents, signature check, cosign) leaves a published release: delete it and its tag (`gh release delete v1.0.0 -R ethan03805/Secure-MCP-Gateway --cleanup-tag --yes`), fix on `main` and tag again.
- A published release with a defect is not edited in place. Publish the fix as the next patch version; mark the bad release as a pre-release or delete it with `gh release delete`, and say so in `CHANGELOG.md`.
- A suspected compromise of the minisign key: follow [runbooks/key-compromise.md](runbooks/key-compromise.md) for the release key as well: generate a new key, sign the new public key with the old one if the old one is still trusted, replace it in `install.sh`, `SECURITY.md` and this file, rotate the two secrets, and publish a release signed with the new key.
