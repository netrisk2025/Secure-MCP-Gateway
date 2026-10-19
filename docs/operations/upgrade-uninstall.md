# Upgrade, rollback and uninstall

## Upgrade (FR-13.7, FR-13.8)

```
smcpctl upgrade --release DIR \
  (--passphrase-file FILE | --recipient age1... --identity-file FILE) \
  [--bin-dir DIR] [--start-cmd CMD --stop-cmd CMD] [--health-timeout 60s] [--pubkey KEY]
```

`DIR` holds the downloaded GitHub release files, unchanged: `smcp_<version>_checksums.txt`, `smcp_<version>_checksums.txt.minisig` and the archive for this host, `smcp_<version>_<os>_<arch>.tar.gz`. For example:

```
gh release download v1.0.0 -R ethan03805/Secure-MCP-Gateway -D ~/smcp-v1.0.0 \
  -p 'smcp_1.0.0_checksums.txt*' -p 'smcp_1.0.0_darwin_arm64.tar.gz'
```

`--bin-dir` is where the installed binaries are (default: the directory of the running `smcpctl`). `--pubkey` replaces the minisign release key from `SECURITY.md` (for a fork that signs its own releases).

The Gateway is started and stopped through the installed service unit (launchd agent `com.smcp.gateway` on macOS, systemd units `smcpd.service` on Linux (system units from `packaging/linux/install-enforced.sh`, or a user unit)), or through `--start-cmd` and `--stop-cmd`, which are run with `sh -c` and get `SMCP_CONFIG` set to the absolute configuration path.

Steps:

1. Verify the release as `install.sh` does (FR-13.2): the minisign signature of the checksum file with the release key embedded in `smcpctl` (the key in `SECURITY.md`), the signed trusted comment naming that file, and the archive's SHA-256 against the verified checksum file. Only then is the archive extracted into a temporary directory; it must contain `smcpd` and `smcpctl`. Any failure stops the upgrade with `release verification failed, nothing changed`.
2. Take an encrypted backup (online when the Gateway runs; see [backup.md](backup.md)).
3. Stop dispatch (`POST /admin/v1/stop`, reason `upgrade`) and stop the Gateway.
4. Install the new binaries (`smcpd`, `smcpctl`, `smcp-refserver`, `smcp-connect`, `smcp-stdio`, `smcp-session`, those the archive has); each replaced binary is kept as `<name>.prev`.
5. Run the new release's `smcpctl config migrate`, limited to 120 s (CP-47).
6. Start the Gateway and wait up to 60 s (CP-47, `--health-timeout`) for it to answer with a state other than `fail-closed` and the new version.

If step 4, 5 or 6 fails, the upgrade rolls back: it stops the new Gateway, restores the `.prev` binaries, restores the pre-upgrade backup (the state of the failed attempt is kept as `<state>.pre-restore-<time>`), writes `state/upgrade-event.json`, and starts the previous version, which records an `upgrade_rolled_back` event (reason `UPGRADE_ROLLED_BACK`, with both versions and the reason) in the journal when it starts. `smcpctl upgrade` then exits with status 1 and `upgrade rolled back: <reason>; the previous version is running`.

Upgrading to a release older than the running one is not refused; use the backup and `.prev` binaries for a manual downgrade instead.

## Uninstall (FR-13.11)

```
smcpctl uninstall [--bin-dir DIR] [--stop-cmd CMD]
```

Without `--config`, and with no `smcp.toml` in the working directory, it uses the configuration that `smcpctl install` wrote (`/etc/smcp/smcp.toml`, then the Standalone CP-46 path).

1. Stops the Gateway (service unit or `--stop-cmd`) and waits until the control API stops answering.
2. Unloads the launchd agent or disables the systemd units, then removes the launchd plist or the systemd units (`smcpd.service`, `smcp-nftables.service`) and `/etc/smcp/smcp.nft`, the nftables table `inet smcp` (Linux, with `sudo -n` when not root), the AppArmor profiles `/etc/apparmor.d/smcpd` and `/etc/apparmor.d/smcp-*` (Linux), and the binaries `smcpd`, `smcpctl`, `smcp-refserver`, `smcp-connect` and their `.prev` copies in `--bin-dir`.
3. Keeps the evidence journal, the evidence public keys, the backup archives, the configuration and the state directory, and prints how to verify the kept journal later:

```
smcpctl journal verify --dir <state>/journal --key <state>/keys/evidence-genesis.pub
```

## Purge (FR-13.12)

```
smcpctl uninstall --purge
```

Prints the installation ID and asks the operator to type it; any other input stops the purge before anything is removed. Then it performs the uninstall steps, prints the name and SHA-256 of the last journal segment (record it), and deletes the configuration file, the policy file, the state directory (keys, journal, TLS material), the diagnostic log files, and on Linux the CP-46 service identities (`smcp-core`, `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data`, `smcp-console`, `smcp-srv`) that exist. Backup archives are kept; delete them separately.

## Errors

| Message | Meaning |
|---|---|
| `release verification failed, nothing changed` | The checksum file's minisign signature does not verify with the release key, its trusted comment names another file, the archive does not match the checksum file, the directory lacks a file, or the archive lacks `smcpd` or `smcpctl` |
| `pre-upgrade backup failed, nothing changed` | See [backup.md](backup.md) |
| `no service manager unit is installed for the Gateway; pass --start-cmd and --stop-cmd` | No unit was found |
| `--recipient needs --identity-file` | A rollback must be able to decrypt the pre-upgrade backup |
| `upgrade rolled back: ...` | The upgrade failed and the previous version runs |
| `upgrade failed (...) and the rollback had errors: ...` | Manual recovery needed: restore the `.prev` binaries and the named backup |
| `installation ID does not match; nothing was removed` | Purge refused |
