# Packaging guide

How an operator admits a local MCP server: write a recipe that pins the artifact, build a package (which probes the server and writes its manifest), sign it, enroll the signing key, install and enable the package, and reference it from `smcp.toml`. This guide is required by SRS FR-18.6 and covers FR-14, FR-5.1 to FR-5.8, FR-5.39 and SEC-3. The sequence diagram is in [flows/server-packaging.md](flows/server-packaging.md); the control API routes are in [api/packages.md](api/packages.md).

The packaging step (`smcpctl package build`) is the only step that contacts a package registry. The Gateway never resolves or installs packages when it starts a server (SR-3.6-1).

## Terms

| Term | Meaning |
|---|---|
| Recipe | JSON file the operator writes: the pinned artifact reference, the launch vector and the classification (risk class, side effects, source trust, capability ceiling) |
| Package | Directory produced by `package build`: `index.json`, `index.json.minisig`, `manifest.json`, `provenance.json` and `artifact/<file>` |
| Manifest | `manifest.json`, validated against [schemas/manifest.schema.json](schemas/manifest.schema.json) (SRS Appendix J). It holds the tool definitions read from the live server at packaging time |
| Package index | `index.json`: the SHA-256 of the artifact, manifest and provenance statement, and the signer key ID. The minisign signature covers this file |
| Trust anchor | An enrolled minisign public key, limited to risk classes and an expiry (FR-14.8) |
| Library | Directory the Gateway scans for packages and revocation entries; default `<state>/library` |
| Revision | One imported package (`<server-id>@<revision>`), immutable, with a registry state |

## Worked example: the reference filesystem server

The repository ships recipes for four reference servers in `packaging/reference/`: `filesystem`, `memory` (npm), `git` and `fetch` (PyPI). Each is pinned to an exact version and digest, and its transitive dependencies are pinned by a lock file (`package-lock.json`, or `requirements.txt` with `--hash` lines).

```sh
# 1. A signing key. The secret key is encrypted with a passphrase you type
#    (or read with --passphrase-file); --unencrypted writes it without one.
smcpctl package keygen --out ~/keys/smcp-packages

# 2. Enroll the public key after comparing its key ID (printed by keygen and
#    by trust add) with the one you expect; --key-id confirms it (FR-7.10).
#    Without --classes it may admit low and moderate.
smcpctl trust add ~/keys/smcp-packages.pub --name operator --key-id 7B3357B76507695D --expires 365d

# 3. Build: fetch the pinned artifact, verify its digest, install the locked
#    dependencies, start the server once in a throwaway directory and read
#    its tools/list into the manifest.
smcpctl package build --recipe packaging/reference/filesystem/recipe.json --out pkg-fs

# 4. Review pkg-fs/manifest.json (tools, descriptions, schemas), then sign.
smcpctl package sign pkg-fs --key ~/keys/smcp-packages.key

# 5. Verify offline against the enrolled anchors (or --pubkey <file>).
smcpctl package verify pkg-fs

# 6. Copy into the library, import as verified-disabled, and enable.
smcpctl package install pkg-fs --enable
```

Then reference the package in `smcp.toml` and bind its filesystem slot, grant its tools in `policy.json`, and restart `smcpd`:

```toml
[[server]]
alias = "fs"
package = "mcp-filesystem"
# Optional: refuse to start unless the enabled revision has this artifact.
package_sha256 = "<artifact sha256 printed by package build>"
slots = { root = "/Users/me/projects/notes" }

[packages]
node = "/opt/homebrew/bin/node"   # optional; default: node on PATH at start
```

Public tool names are `<alias>_<tool>`, for example `fs_read_text_file`.

`scripts/build-reference-packages.sh` does all of this for the four reference servers in a fresh instance and calls one tool of each through the Gateway. It needs network access, npm, node, git and Python 3.10 or later (`SMCP_PYTHON`). The `reference-packages` workflow runs it on release tags and on demand.

## The bootstrap package

`smcpctl bootstrap` packages the bundled `smcp-refserver` as `smcp-ref-filesystem` (alias `ref`, risk class `low`), signs it with a key generated for this one package and then discarded, enrolls that key as the anchor `bootstrap-<key id>` for the `low` class only, imports and enables the revision, and writes the only `[[server]]` entry of the example configuration with `package`, `package_sha256` and `slots`. The revision is `<version>+<first 12 hex digits of the artifact digest>`, so a rebuilt binary is a new revision. Its source evidence is the binary itself (`file://` URI and digest), because the release checksums cover it.

## Recipe format

Paths in a recipe are relative to the recipe file.

| Member | Required | Meaning |
|---|---|---|
| `recipe_version` | yes | `1` |
| `server.id` | yes | Stable server ID: `^[a-z0-9][a-z0-9-]{0,62}$` |
| `server.revision` | no | Revision; default the artifact version without a leading `v` |
| `server.alias` | yes | Default alias: 1 to 16 characters of `a-z 0-9` (CP-42) |
| `server.publisher` | yes | Who publishes the server |
| `server.description`, `server.homepage` | no | Shown in listings; `homepage` must be `https://` |
| `artifact.type` | yes | `npm`, `pypi`, `oci` or `binary` |
| `artifact.reference` | yes | npm package name, PyPI project, OCI repository (`registry/path`), or a local path or `https://` URL for `binary` |
| `artifact.version` | yes | Exact version. Ranges (`^1`, `~1.2`, `1.x`, `>=1`), `*` and dist-tags (`latest`, `next`, ...) are refused |
| `artifact.integrity` | npm or oci | npm `sha512-...` registry integrity, or the OCI image manifest digest `sha256:...` |
| `artifact.sha256` | npm (if no integrity), pypi, binary | SHA-256 of the npm tarball, the PyPI distribution file (a wheel) or the binary |
| `dependencies.npm_package_json`, `dependencies.npm_lockfile` | no | Install the dependency closure with `npm ci --omit=dev --ignore-scripts --no-bin-links`. The lock file must pin the artifact with the same integrity |
| `dependencies.pip_requirements` | no | Install with `pip install --no-deps --require-hashes --only-binary=:all: --target site`. The file must contain `--hash=sha256:<artifact.sha256>` |
| `launch.runtime` | yes | `node`, `python`, `oci` or `native`; must match the artifact type (npm, pypi, oci, binary) |
| `launch.argv` | yes | Exact argument vector, run without a shell. `node` and `python3` are the release runtime; relative paths are inside the artifact. Package runners and shells (`npx`, `uvx`, `pip`, `sh`, ...) are refused |
| `launch.env_allowlist` | no | Variable names an operator may set in the server's `env` |
| `launch.env_fixed` | no | Non-secret variables; values may use slot placeholders |
| `risk_class` | yes | `low`, `moderate` or `high`. `high` cannot be enabled in the Standalone profile (SR-4-1) |
| `instance_scope` | yes | Any of `per-call`, `per-session`, `per-principal`, `shared` |
| `tools.default` | yes | `side_effect` (`read`, `write`, `external`, `execute`) and `source_trust` (`trusted`, `untrusted`) for every tool |
| `tools.overrides` | no | Per-tool `side_effect`, `source_trust` and `risk_class` (which may only raise the server class). An override naming a tool the server does not list fails the build |
| `tools.expect` | no | Tools the probe must find |
| `capabilities` | yes | `filesystem` slots (`slot`, `mode` `ro`/`rw`, optional `argv_placeholder` such as `{root}`), `egress`, `spawns_processes`, `resources` |
| `secrets` | no | Secret slots (Appendix J) |
| `source` | binary, oci | `kind`, `uri` and either `sha256` or `path` to a local copy of the source archive. npm uses the registry tarball and PyPI the sdist when present |
| `licenses` | yes | SPDX identifiers |
| `expires`, `attestations.recuration_due` | no | Dates after which the revision is suspended (FR-5.8) |
| `probe.repo_init` | no | Slots initialized as empty Git repositories before the probe (for servers that refuse a plain directory) |
| `operator_note` | no | Free text recorded in the manifest |

## What `package build` does

1. Refuses an unpinned reference (`UNPINNED_REFERENCE`).
2. Fetches the artifact and verifies the pinned digest (`DIGEST_MISMATCH`): npm tarballs from `--npm-registry` (default `https://registry.npmjs.org`), PyPI files through the JSON API of `--pypi-index` (default `https://pypi.org`), OCI images from the registry by manifest digest (anonymous token authentication; for an index, the `linux/<host architecture>` image), binaries from a path or `https://`.
3. Assembles the artifact. A binary or OCI image layout tar is stored as fetched. npm and PyPI artifacts are a deterministic `.tar.gz` of the installed tree (`node_modules/...` or `site/...`), so the stored artifact is the exact code that runs.
4. Unpacks the artifact and starts the server once. The probe environment is `PATH=/usr/bin:/bin`, `HOME` set to an empty throwaway directory, the recipe's `env_fixed`, and for Python `PYTHONPATH`, `PYTHONDONTWRITEBYTECODE` and `PYTHONNOUSERSITE`; every filesystem slot is an empty throwaway directory; no secrets are given. With `--sandbox podman`, or with `--config` naming a configuration in the Enforced profile, the probe runs in the rootless Podman sandbox (SR-3.5-1): no network, the candidate executable and its empty slot directories as the only mounts, and the `[runtime]` limits of that configuration (or the CP-24 defaults); a node or python candidate then needs `--image name@sha256:...`. The slot directories are mounted at their own paths, so `TMPDIR` must not be at or below `/tmp`. Otherwise (`--sandbox none`, the default in the Standalone profile) the probe is a plain subprocess with the host's network; `provenance.json` records which (`probe.launcher`, `probe.network`).
5. Negotiates the protocol era (`2026-07-28` or `2025-11-25`, otherwise `ERA_UNSUPPORTED`) and reads the complete `tools/list`.
6. Writes `provenance.json` (source reference, licenses, dependency lock digest, builder, probe conditions, bound to the artifact digest), `manifest.json` (validated before it is written) and an unsigned `index.json`.

Packages built from npm or PyPI artifacts that contain compiled code run only on the platform and, for Python, the Python minor version they were built with.

## Signing and verifying

- `smcpctl package sign <dir> --key <file> [--passphrase-file <file>]` writes the signer key ID into `index.json` and the minisign signature into `index.json.minisig`. An encrypted key's passphrase is read from the file or prompted. `--secret-key` and `--passphrase` exist only to refuse a secret on the command line (`KEY_ON_COMMAND_LINE`).
- `smcpctl package verify <dir> [--pubkey <file>]` checks, without network access: every component present, the signature under the key or an enrolled anchor, the anchor's expiry and risk-class scope, every listed digest, the manifest schema and the provenance binding. It exits 0 only when every check passes and otherwise names the first failed check.

## Trust anchors

```sh
smcpctl trust add <pubkey-file> --name <name> --key-id <ID> [--classes low,moderate,high] [--expires 2027-10-16|365d]
smcpctl trust list
smcpctl trust remove <name-or-key-id>
```

`trust add` prints the key ID (the minisign key ID) and the SHA-256 of the key line and enrolls the key only when `--key-id` names that key ID, or, on a terminal, when the key ID is typed at the prompt (FR-7.10): the administrator compares it with the value the publisher gave out of band. Anchors are stored in `<state>/keys/trust-anchors.json` (mode 0600). Without `--classes` an anchor admits `low` and `moderate`; a package is accepted only when its highest risk class (server or any tool) is in the anchor's classes and the anchor has not expired (SR-3-1). An anchor can sign revocation entries even after it expires.

## Importing, enabling and states

`smcpctl package install <dir>` verifies the package, copies it to `<library>/<server-id>/<revision>/` and imports it. When `smcpd` is running it holds the registry lock, so `install` asks it to scan instead (`POST /api/v1/packages/scan`). The Gateway also scans the library at start and every `[packages] scan_interval` (default 300 s).

Import writes a receipt for every attempt to `<state>/packages/receipts/` and, when `smcpd` performs it, an evidence event (class `package`, outcomes `imported`, `import_rejected`, `import_unchanged`). On success the artifact is stored under `<state>/packages/artifacts/sha256/<digest>` and unpacked read-only under `<state>/packages/unpacked/<digest>/`; the signed metadata is copied read-only to `<state>/packages/revisions/<id>/<revision>/`. A revision is never changed after import: importing a different package with the same ID and revision is refused (`REVISION_CONFLICT`). A revision lower than an installed one of the same server is refused unless the administrator authorizes it (`--allow-downgrade`, SR-3-5).

| State | Meaning | Changed by |
|---|---|---|
| `verified-disabled` | Imported and verified; not launched | import; `package disable` |
| `enabled` | Launched by a `[[server]]` entry that names its server ID | `package enable` (Administrator) |
| `suspended` | Stopped: drift, changed artifact, expiry or an administrator action | the Gateway; `enable` restores it |
| `revoked` | Withdrawn by a signed revocation entry; final | `package revoke` and a scan |
| `retired` | Removed from use; final. The cached artifact is deleted when no non-retired revision uses it | `package retire` |

`smcpctl package enable|disable|retire <id>@<revision>` use the control API when `smcpd` is running (the bearer token authenticates the Administrator) and the state directory otherwise. Enabling a revision returns any other enabled revision of the same server to `verified-disabled`. The backend registry starts servers once, so a revision enabled while `smcpd` runs is launched at the next start; disabling, retiring, revoking or suspending a running revision tears its instance down at once.

Enabling is refused when: the revision is high risk and instances run unconfined (`PROFILE_UNCONFINED`); another enabled server uses the alias (`ALIAS_CONFLICT`; pass `--alias`); the manifest declares stateful tools, for which the manifest format has no handle contract yet (`STATEFUL_UNCONTRACTED`); or its expiry or re-curation date has passed (`MANIFEST_EXPIRED`). Each enablement records `enablement_sha256`, the digest of the manifest tool definitions, capabilities, secret slots and launch vector (SR-3.7-1).

## At run time

For a `[[server]]` entry with `package`:

1. The enabled revision of that server ID is resolved; the entry is skipped with an evidence event `server_not_started` when there is none (`PACKAGE_NOT_ENABLED`), when `package_sha256` differs from its artifact (`PACKAGE_PIN_MISMATCH`), when a configured `[[egress.grant]]` of the alias exceeds the manifest's `capabilities.egress` in host, port or method (`EGRESS_EXCEEDS_MANIFEST`, with `[egress] enabled`), or when it is high risk and the launcher is unconfined.
2. The launch vector is built from the manifest: the unpacked tree, slot placeholders replaced by the `slots` paths, `env` limited to `env_allowlist`, `PATH=/usr/bin:/bin` unless `env_fixed` sets it, `HOME` set to `<state>/packages/work/<alias>`. `node`, `python3` and `podman` come from `[packages]` or are looked up once on PATH and used as absolute paths. OCI images run with `podman run --rm -i --pull=never --network=none --read-only --cap-drop=all oci-archive:<artifact>`, slots mounted at `/slots/<slot>`.
3. Before every launch the artifact file and the unpacked tree are hashed and compared with the import digests; a difference suspends the revision (`ARTIFACT_TAMPERED`, SR-3-2).
4. After the handshake the live `tools/list` is compared with the manifest (names, titles, descriptions, input and output schemas, annotations). A difference suspends the revision and writes the observed list to `<state>/packages/evidence/` with an evidence event (`MANIFEST_DRIFT`, SR-3.8-1). The same check runs on every `notifications/tools/list_changed`; the instance is then torn down and its tools leave the catalog.
5. The Gateway presents the manifest's definitions, flagged as verified; health reports no `unverified_manifests` for the server.

A `[[server]]` entry with `command` instead of `package` still runs with its live tool list, flagged unverified, unless `[packages] require_signed = true`, which refuses such entries at start (`UNSIGNED_SERVER_REFUSED`).

## Revoking

```sh
smcpctl package revoke <id>@<revision> --key <file> --reason "<text>"
```

writes `<library>/revocations/<id>@<revision>.json` and its signature. Any enrolled anchor may sign one. The next scan (immediately when run offline or through the control API, otherwise within `scan_interval`) marks the revision `revoked` and tears down its instance; a revoked revision can never be imported again.

## Configuration keys

| Key | Default | Meaning |
|---|---|---|
| `[[server]] package` | none | Server ID of a package; exclusive with `command` |
| `[[server]] package_sha256` | none | Required artifact digest of the enabled revision |
| `[[server]] slots` | none | Filesystem slot name to host directory (absolute, or relative to `smcp.toml`) |
| `[packages] library` | `<state>/library` | Directory library |
| `[packages] scan_interval` | `300s` | Library polling interval (FR-5.3) |
| `[packages] require_signed` | `false` | Refuse `[[server]]` entries that are not packages |
| `[packages] node`, `python`, `podman` | PATH lookup | Absolute paths of the runtimes |

## Reason codes

| Reason code | Where | Meaning |
|---|---|---|
| `UNPINNED_REFERENCE` | build | The artifact reference has no exact version or digest |
| `DIGEST_MISMATCH` | build, verify, import | A fetched file, listed file or lock entry does not match its digest |
| `FETCH_FAILED` | build | The registry or file could not be read |
| `PROBE_FAILED` | build | The server did not start, did not answer or listed no tools |
| `ERA_UNSUPPORTED` | build | The server negotiated a protocol version a manifest cannot declare |
| `PACKAGE_INDEX_MISSING`, `PACKAGE_SIGNATURE_MISSING`, `PACKAGE_MANIFEST_MISSING`, `PACKAGE_PROVENANCE_MISSING`, `PACKAGE_ARTIFACT_MISSING`, `SIGNER_KEY_ID_MISSING` | verify, import | A package component is missing (FR-5.2) |
| `PACKAGE_INDEX_INVALID` | verify, import | The index is malformed or names another package than the manifest |
| `SIGNATURE_INVALID` | verify, import | The signature does not verify, or names another key than the index |
| `SIGNER_UNKNOWN` | verify, import | The signer is not the given key or an enrolled anchor |
| `ANCHOR_EXPIRED` | verify, import | The signing anchor has expired |
| `ANCHOR_SCOPE` | verify, import | The package's risk class is outside the anchor's classes |
| `MANIFEST_SCHEMA` | verify, import | The manifest violates Appendix J or a rule the schema cannot express (description digests, tool-list digest, slot placeholders, runtime and type) |
| `MANIFEST_VERSION_UNSUPPORTED` | verify, import | `manifest_version` is not 1 |
| `SOURCE_EVIDENCE_MISSING` | verify, import | The provenance statement lacks a source digest or licenses (SR-3.1-1) |
| `PROVENANCE_BINDING` | verify, import | The statement names another artifact, source or package (SR-3.2-1) |
| `REMOTE_BACKEND_UNSUPPORTED` | verify, import | The entrypoint is a network URL (FR-14.4) |
| `UNPINNED_LAUNCH` | verify, import, start | The launch vector runs a package runner, installer or shell (SR-3.6-1) |
| `KEY_ON_COMMAND_LINE` | sign, keygen, revoke | A secret key or passphrase was given as an argument |
| `REVOCATION_INVALID` | scan | A revocation entry is malformed or unsigned |
| `REVOKED` | import | The revision has been revoked |
| `REVOCATION_FEED_STALE` | import, health | The revocation feed (`<library>/revocations` and the trust anchors) has not been read successfully for more than 24 h (CP-34); imports are refused and health shows `revocation_feed_stale` until it can be read (SR-3-4) |
| `CLASSIFICATION_OVERRIDDEN` | classification | An operator tightened a tool's side-effect class, source trust or risk class (SR-3.11-1) |
| `CLASSIFICATION_LOOSENING_REFUSED` | classification | The override would make a classification less restrictive than the signed manifest's |
| `CLASSIFICATION_TOOL_UNKNOWN` | classification | The revision has no such tool |
| `DOWNGRADE_REFUSED` | import | A higher revision of the server is installed |
| `REVISION_CONFLICT` | import | The revision exists with a different package index |
| `PROFILE_UNCONFINED` | enable, start | High risk class while instances run unconfined |
| `ALIAS_CONFLICT` | enable | The alias is invalid or used by another enabled server |
| `PUBLIC_NAME_COLLISION` | enable | Two tools map to one public name or a name exceeds 64 characters |
| `STATEFUL_UNCONTRACTED` | enable | Stateful tools without a handle contract |
| `MANIFEST_EXPIRED` | enable, scan | The expiry or re-curation date has passed |
| `STATE_TRANSITION_REFUSED` | enable, disable, retire | The change is not allowed from the current state |
| `PACKAGE_UNKNOWN` | API, CLI | No such revision |
| `PACKAGE_NOT_ENABLED` | start | The `[[server]]` entry names a server with no enabled revision |
| `PACKAGE_PIN_MISMATCH` | start | `package_sha256` differs from the enabled artifact |
| `MANIFEST_DRIFT` | start, list_changed | The live tool list differs from the manifest |
| `ARTIFACT_TAMPERED` | launch | The stored artifact or unpacked tree changed after import |
| `UNSIGNED_SERVER_REFUSED` | start | `require_signed` is set and an entry uses `command` |

## Limitations

- The library is a directory (FR-5.1); release 1.0 has no OCI registry library. An OCI image can still be the artifact inside a package.
- The probe has the host network in the Standalone profile; `--sandbox podman` (Linux with rootless Podman) removes it.
- OCI packages need `podman`; they are fetched and verified on any host but were not probed or launched in the automated tests.
- Imports are refused with `REVOCATION_FEED_STALE` while the revocation feed has been unreadable for longer than CP-34 (SR-3-4), and operators can override a revision's classification after import (SR-3.11-1). The metadata rule set runs at import, but SR-5.9-2 is only partly verified; era consistency at start (FR-5.17) is deferred from release 1.0 (SRS Appendix N). The console view G-10 enables, suspends and retires revisions.
- A revision enabled while `smcpd` runs starts at the next Gateway start.
- Catalogs built for sessions before a suspension keep listing the suspended tools until they are rebuilt; calls to them are refused.
