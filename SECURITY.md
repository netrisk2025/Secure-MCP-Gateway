# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a vulnerability.

Include the commit or release, the platform profile (Enforced or Standalone), the steps to reproduce, and what you observed. If the report involves evidence journal entries or diagnostic logs, remove secret values and personal data first.

You will receive an acknowledgment within five days. Fixes are released as soon as they are ready; the release notes and `CHANGELOG.md` credit the reporter unless you ask otherwise.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| Latest GitHub Release | Yes |
| Older releases | No; upgrade with `smcpctl upgrade` |

## Scope

In scope: the Gateway daemon `smcpd`, the CLI `smcpctl`, the adapters `smcp-session`, `smcp-stdio` and `smcp-connect`, the management console, the installer `install.sh`, the Homebrew formula and the packaging format.

Known limitations are documented in [`docs/security-limitations.md`](docs/security-limitations.md) and are not vulnerabilities in themselves. A report showing that a documented control does not work as specified, or that a limitation is broader than documented, is in scope. Examples: a tool call dispatched without a permit decision, a launch without a flushed journal intent record, a server running outside its sandbox in the Enforced profile, a secret value reaching a harness, or an "enforced" release label without passing acceptance evidence.

Out of scope: vulnerabilities in third-party MCP servers, agent harnesses or tunnel providers, unless the Gateway makes them worse; and findings that require administrator access to the host (SRS ARCH A-4).

## Release signing key

Each release's checksum file `smcp_<version>_checksums.txt` is signed with minisign (SRS FR-13.1) as `smcp_<version>_checksums.txt.minisig`. The release public key is:

```
untrusted comment: minisign public key 064FAC0C64ACCED0
RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
```

`install.sh` embeds the same key and refuses to install when the signature does not verify. The checksum file is also signed with Sigstore cosign (keyless, the release workflow's GitHub OIDC identity); `install.sh` checks that bundle when `cosign` is installed. To verify by hand:

```sh
minisign -Vm smcp_<version>_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
sha256sum --check --ignore-missing smcp_<version>_checksums.txt
```

The secret key is held only as GitHub Actions secrets of this repository (used by `.github/workflows/release.yml`) and in an offline copy kept by the maintainer. A key rotation is announced here and in the release notes, and the new key is signed by the old one. No signed release exists yet; the first is v1.0.0.
