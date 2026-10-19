# Install guide

How to install, upgrade, roll back and remove the Secure MCP Gateway on each platform and profile (SRS FR-18.1). For a first run after installing, go to the [quick start](quickstart.md).

**Release status.** v1.1.0 is the latest release (2026-10-18, main `935dc4d`, rehearsed with v1.1.0-rc.1 and rc.2; rc.2 and v1.1.0 are the same commit). v1.0.0 was the first final release, rehearsed with v1.0.0-rc.1 to rc.3 (rc.3 and v1.0.0 are the same commit, `17b84ba`). GitHub's latest-release link skips pre-releases, so `install.sh` without `--version` installs the latest final release and a pre-release needs `--version`. The release workflow writes each final release's formula to the Homebrew tap (rehearsed with v1.0.0-rc.2, [verification/FR-13.3.md](verification/FR-13.3.md)). For v1.1.0 the `tap` workflow installed the formula and the archive on macOS and Ubuntu and found every binary equal to the release archive (run 39178720966; for v1.0.0, run 39096814323). Building from source (below) needs no release. The sections on release archives describe what the release workflow (`.github/workflows/release.yml`) publishes. Since v1.1.0 the archives also carry the build recipe, the lockfiles, `PROVENANCE.md` and `THIRD_PARTY_NOTICES.txt`, and their SBOMs pass the license check (FR-12.8, FR-12.1). [release-checklist.md](release-checklist.md) is the release procedure.

The short path on macOS or Linux, once a release exists:

```sh
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh   # or: brew install ethan03805/tap/smcp
smcpctl install          # Standalone: CP-46 directories, keys, smcp.toml, launchd agent or systemd user unit, health check
```

## What gets installed

| Binary | Purpose |
|---|---|
| `smcpd` | The Gateway daemon |
| `smcpctl` | Command-line tool: bootstrap, configuration, policy, approvals, packages, operations |
| `smcp-refserver` | Read-only reference MCP server that `smcpctl bootstrap` packages as the example backend |
| `smcp-stdio`, `smcp-session` | Harness adapters for local clients ([adapters.md](adapters.md)) |
| `smcp-connect` | Relay for cloud agents through the Remote Access Profile ([remote-access.md](remote-access.md)); also published as the npm package `smcp-connect` |

## Platforms and profiles

| Host | Profile | What runs |
|---|---|---|
| Linux x86_64 or arm64 with rootless Podman (crun), nftables, cgroup v2, systemd and AppArmor or SELinux | **Enforced** | Every backend in a rootless Podman sandbox; health can be `healthy`; release label "enforced" only for a build that passed AT-01 to AT-21 |
| macOS arm64 or x86_64 | **Standalone** | Backends as plain subprocesses; health always `degraded: unconfined`; high-risk servers refused; label "not enforced" |
| Linux without the enforced prerequisites | **Standalone** | As macOS |

The profile is chosen by `[profile] mode`: `auto` (default) picks enforced when every prerequisite is present, `enforced` refuses to start without them, `standalone` never sandboxes. `smcpctl runtime doctor` lists what is missing on a Linux host. See [sandbox.md](sandbox.md).

## Option 1: install.sh (Linux and macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh
# or a fixed version and directory
sh install.sh --version v1.1.0 --dir "$HOME/.local/bin"
```

The script detects the OS and architecture and downloads `smcp_<version>_<os>_<arch>.tar.gz`, `smcp_<version>_checksums.txt` and `smcp_<version>_checksums.txt.minisig` from the GitHub release. It then, in order:

1. verifies the minisign signature of the checksum file with the release public key embedded in the script, and checks that the signed trusted comment names that checksum file (SRS FR-13.2);
2. when `cosign` is installed, downloads `smcp_<version>_checksums.txt.sigstore.json` and verifies it with `cosign verify-blob` against the release workflow identity (security review RR-01); when `cosign` is not installed it says so;
3. checks the archive's SHA-256 against the verified checksum file.

If any check fails it installs nothing and removes its temporary directory. Otherwise it installs the binaries into `~/.local/bin` (or `--dir`). It never runs `sudo`; when the directory is not writable it stops and prints the command to run.

The signature check uses `minisign` when it is installed and otherwise OpenSSL 3 (`openssl pkeyutl`, Ed25519 over the BLAKE2b-512 digest). macOS ships LibreSSL as `/usr/bin/openssl`, which cannot do this; install `minisign` first (`brew install minisign`), or use Homebrew for the whole install. Debian 12, Ubuntu 22.04 and later have OpenSSL 3.

Options: `--version <tag>`, `--dir <path>`, `--repo <owner/name>`, `--base-url <url>` (a mirror holding the same files), `--pubkey <key>` (the release key of a fork), `--no-cosign` (skip the cosign check even when cosign is installed), `--help`.

### Release signing key

```
untrusted comment: minisign public key 064FAC0C64ACCED0
RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
```

The same key is in `SECURITY.md` and embedded in `install.sh`. To check a release by hand:

```sh
minisign -Vm smcp_<version>_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
cosign verify-blob --bundle smcp_<version>_checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  smcp_<version>_checksums.txt
sha256sum --check --ignore-missing smcp_<version>_checksums.txt
```

## Option 2: Homebrew (macOS and Linux)

```sh
brew install ethan03805/tap/smcp
smcpctl install
```

The release workflow writes `Formula/smcp.rb` to the tap repository [ethan03805/homebrew-tap](https://github.com/ethan03805/homebrew-tap) with GoReleaser (`brews` in `.goreleaser.yaml`); its URLs and SHA-256 values are those of the release archives for darwin and linux. Homebrew checks the archive's SHA-256 from the formula; it does not check the minisign signature. The formula installs the same binaries as `install.sh`. `packaging/homebrew/smcp.rb.tmpl` with `scripts/render-brew-formula.sh` renders an equivalent formula by hand.

## Option 3: from source

Needs Go (the version in `go.mod`) and git. Node.js is not needed: the console is committed prebuilt in `console/dist` and embedded with `go:embed`.

```sh
git clone https://github.com/ethan03805/Secure-MCP-Gateway.git
cd Secure-MCP-Gateway
make build                       # smcpd and smcpctl into build/bin
go build -o build/bin/ ./cmd/... # all six binaries
export PATH="$PWD/build/bin:$PATH"
```

Builds with cgo (the default when a C compiler is present) use DuckDB for the Observation Store and can export Parquet. Release archives are built with `CGO_ENABLED=0` and use the JSON Lines store instead ([observation.md](observation.md)).

## Install as a service: smcpctl install

`smcpctl install` sets up a complete installation in one idempotent command (SRS FR-13.4 to FR-13.6). It reports every step as `created` or `present` (`updated` when a unit file it wrote earlier has changed); a second run reports `present` throughout and leaves configuration, keys, policy and the journal byte-for-byte unchanged.

**Standalone (macOS and Linux, as your user):**

```sh
smcpctl install                         # prompts for the administrator and Session Approver passwords
smcpctl install --admin-password-file a.pw --approver-password-file b.pw --port 8443 --admin-port 8444
```

| Step | macOS | Linux |
|---|---|---|
| CP-46 directories (0700) | `~/Library/Application Support/smcp-gateway/{config,state}`, `~/Library/Logs/smcp-gateway` | `$XDG_CONFIG_HOME/smcp-gateway`, `$XDG_STATE_HOME/smcp-gateway` with `log/`, `$XDG_RUNTIME_DIR/smcp-gateway` |
| Keys, local CA, reference package | in the state directory (as `smcpctl bootstrap`) | same |
| `smcp.toml` and `policy.json` | in `config/`, with `[profile] mode = "standalone"` and `[log] file` in the log directory | in the configuration directory, same values |
| Service | launchd user agent `~/Library/LaunchAgents/com.smcp.gateway.plist`, loaded with `launchctl bootstrap gui/<uid>` | systemd user unit `~/.config/systemd/user/smcpd.service`, enabled and started with `systemctl --user` |
| Health | waits up to `--health-timeout` (60 s) for the control API; fails on `fail-closed` | same |

It ends by printing that the installation is not enforced. The unit runs the `smcpd` next to `smcpctl` (`--bin-dir` to choose another directory). `--no-start` writes the unit without loading it and skips the health check. Other flags are those of `bootstrap`: `--port`, `--admin-port`, `--metrics-port`, `--notify`, `--sandbox`, `--bootstrap-token`. On Linux a user unit stops at logout unless lingering is on: `loginctl enable-linger "$USER"`. An existing configuration is never rewritten; if it selects another profile, install says so.

**Enforced (Linux, as root):**

```sh
sudo smcpctl install --profile enforced --admin-password-file a.pw --approver-password-file b.pw
```

It runs the copy of `packaging/linux/install-enforced.sh` embedded in `smcpctl` with `--bin-dir` set to the directory of `smcpctl` (which must also hold `smcpd` and `smcp-refserver`). That script checks every Section 1.5.1 prerequisite before changing the host and stops naming the missing ones; then it creates the CP-46 service identities and subordinate ranges, the directories, the nftables table, the AppArmor profile (when AppArmor is enabled) and the systemd units, and installs the binaries into `/usr/local/bin`. `smcpctl install` then bootstraps the state into `/var/lib/smcp/state` and the policy into `/var/lib/smcp/policy` (owned by `smcp-core`), writes `/etc/smcp/smcp.toml` (root:smcp 0640) with `[profile] mode = "enforced"`, `[runtime] sandbox = "podman"`, `cgroup_manager = "cgroupfs"`, a mount of `/srv/smcp/sandbox` for the reference server and `[log] file = "/var/log/smcp/smcpd.log"`, starts `smcp-nftables.service` and `smcpd.service`, and checks health.

Remove either installation with `smcpctl uninstall` (below); without `--config` it finds the configuration that install wrote.

## Create an instance by hand

```sh
smcpctl bootstrap --dir ~/smcp
```

This writes `~/smcp/smcp.toml`, `~/smcp/policy.json` and `~/smcp/state/` (keys, local CA, journal, the packaged reference server). Ports default to `127.0.0.1:8443` (harness) and `127.0.0.1:8444` (control API and console); change them with `--port` and `--admin-port`. The [quick start](quickstart.md) explains the prompts and what to do next.

CP-46 names standard locations (`~/Library/Application Support/smcp-gateway/` on macOS, `$XDG_CONFIG_HOME/smcp-gateway` and `$XDG_STATE_HOME/smcp-gateway` on Linux, `/etc/smcp` and `/var/lib/smcp` for the Enforced profile). `bootstrap` uses the directory you give it; pass one of those paths to follow CP-46.

## Run as a service

`smcpctl install` (above) is the supported way. For an instance made with `bootstrap`, run `smcpd --config ~/smcp/smcp.toml` in a terminal, or write a launchd user agent with the label `com.smcp.gateway` (`~/Library/LaunchAgents/com.smcp.gateway.plist`). `smcpctl upgrade` and `smcpctl uninstall` find and use that label, or the systemd unit `smcpd.service`, when present.

On Linux for the Enforced profile, `smcpctl install --profile enforced` runs the following script for you; it can also be run directly from a checkout to prepare the host as root:

```sh
sudo packaging/linux/install-enforced.sh --check            # prerequisites only; changes nothing
sudo packaging/linux/install-enforced.sh --bin-dir ./build/bin
```

It checks every prerequisite before changing anything, then creates the CP-46 service identities, subordinate ID ranges, directories, the nftables table `inet smcp` and the systemd units `smcpd.service` and `smcp-nftables.service`. It is idempotent. `--bin-dir` installs `smcpd`, `smcpctl` and `smcp-refserver` into `/usr/local/bin`.

The unit runs `/usr/local/bin/smcpd --config /etc/smcp/smcp.toml` as `smcp-core` with `/var/lib/smcp`, `/run/smcp` and `/var/log/smcp` writable. The configuration it starts needs, in addition to what `bootstrap` writes:

```toml
[state]
dir = "/var/lib/smcp/state"

[profile]
mode = "enforced"          # refuse to start when a prerequisite is missing

[runtime]
sandbox = "podman"
cgroup_manager = "cgroupfs"

[[runtime.server]]         # one per backend that needs host paths
alias = "ref"
[[runtime.server.mount]]
source = "/srv/smcp-share" # readable by other users: instances run under subordinate UIDs
```

Then `sudo packaging/linux/install-enforced.sh --start`. The enforced profile is exercised in CI (linux-integration job): `scripts/ci-integration.sh` with smcpd started directly, and `scripts/ci-systemd.sh`, which installs with `smcpctl install --profile enforced` and runs `smcpd.service` under systemd. Every `[runtime]` key, the mount rules and the startup refusal are in [sandbox.md](sandbox.md#installing-on-a-linux-host).

## Upgrade and rollback

```sh
smcpctl upgrade --config ~/smcp/smcp.toml --release <dir with the downloaded release files> \
  --passphrase-file <backup passphrase file>
```

Download the release's checksum file, its `.minisig` and the archive for the host into one directory (`gh release download v1.1.0 -R ethan03805/Secure-MCP-Gateway -D <dir> -p 'smcp_1.1.0_checksums.txt*' -p 'smcp_1.1.0_<os>_<arch>.tar.gz'`). The upgrade verifies the minisign signature of the checksum file with the release key and the archive's SHA-256 against it, as `install.sh` does (FR-13.2), and changes nothing when either fails. It then takes an encrypted pre-upgrade backup, stops dispatch, swaps the binaries (keeping `<name>.prev`), migrates the configuration's `schema_version`, starts the Gateway and waits up to 60 s (CP-47) for it to leave fail-closed. If any step after the backup fails it restores the backup and the previous binaries and records `upgrade_rolled_back`. Pass `--start-cmd` and `--stop-cmd` when the Gateway is not run by launchd or systemd. See [operations/upgrade-uninstall.md](operations/upgrade-uninstall.md) and the [upgrade rollback runbook](runbooks/upgrade-rollback.md).

Homebrew users run `brew upgrade smcp` and then restart the Gateway; that path has no automatic backup, so run `smcpctl backup` first.

## Uninstall

```sh
smcpctl uninstall --config ~/smcp/smcp.toml           # services and binaries; keeps evidence
smcpctl uninstall --config ~/smcp/smcp.toml --purge   # also configuration, state, keys, journal
```

Without `--purge` the configuration, the state directory and the evidence journal stay, so `smcpctl journal verify` still works afterwards. `--purge` asks for the installation ID (`smcpctl keys status` shows it) before deleting. On the Enforced profile it also removes the service identities. Homebrew installs are removed with `brew uninstall smcp` after `smcpctl uninstall`.

## Verify an installation

```sh
smcpctl version --config ~/smcp/smcp.toml   # with a running Gateway, also its profile and label
smcpctl health --config ~/smcp/smcp.toml
smcpctl journal verify --config ~/smcp/smcp.toml
smcpctl doctor --config ~/smcp/smcp.toml    # client configuration and CA trust
```
