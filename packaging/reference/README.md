# Reference packages

Packaging recipes for the four reference MCP servers (SRS FR-14.9). Each recipe pins the artifact to an exact version and digest, and pins its transitive dependencies with a lock file. The procedure and the recipe format are in [docs/packaging-guide.md](../../docs/packaging-guide.md).

| Directory | Server ID | Alias | Artifact | Risk class | Dependency lock |
|---|---|---|---|---|---|
| `filesystem` | `mcp-filesystem` | `fs` | npm `@modelcontextprotocol/server-filesystem` 2026.8.31 | moderate | `package-lock.json` |
| `memory` | `mcp-memory` | `mem` | npm `@modelcontextprotocol/server-memory` 2026.8.31 | low | `package-lock.json` |
| `git` | `mcp-git` | `git` | PyPI `mcp-server-git` 2026.8.18 (wheel) | moderate | `requirements.txt` (hashes) |
| `fetch` | `mcp-fetch` | `fetch` | PyPI `mcp-server-fetch` 2026.8.18 (wheel) | moderate | `requirements.txt` (hashes) |

Build, sign, import, enable and call one tool of each in a fresh instance:

```sh
SMCP_PYTHON=$(command -v python3.11) scripts/build-reference-packages.sh
```

Build one by hand:

```sh
smcpctl package build --recipe packaging/reference/git/recipe.json --out pkg-git --python /usr/bin/python3
smcpctl package sign pkg-git --key <secret key file>
smcpctl package install pkg-git --enable
```

## Updating a pin

1. Choose a version published at least two weeks ago and note its registry digest (npm `dist.integrity`, or the PyPI wheel's `sha256`).
2. npm: set the version in `package.json` and run `npm install --package-lock-only --ignore-scripts` in the directory. PyPI: set the version in `requirements.in` and run `uv pip compile requirements.in --generate-hashes --python-version 3.11 --universal --no-header --exclude-newer <date two weeks ago> -o requirements.txt`.
3. Update `artifact.version` and `artifact.integrity` or `artifact.sha256` in `recipe.json`.
4. Run the build: it fails if the lock file does not pin the artifact with the same digest, or if a tool named in `tools.overrides` or `tools.expect` is gone. Review the new manifest's tool descriptions before signing.

The CI test `TestReferenceRecipesArePinned` checks that each recipe is pinned and that its lock file names the same digest; it does not fetch anything. The packaged `smcp-refserver` fixture used by the other tests and by `smcpctl bootstrap` needs no network.
