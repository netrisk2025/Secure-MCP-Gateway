# Linux enforced-profile packaging

| File | Installed as | Purpose |
|---|---|---|
| `install-enforced.sh` | (run from here as root) | Checks prerequisites, then creates service identities, subordinate ID ranges, directories, the nftables table, the AppArmor profiles and the systemd units; idempotent |
| `setup-server-identity.sh` | (called by `install-enforced.sh`) | Prepares `smcp-srv` for `runtime.run_as`: own group and home, lingering, `/var/lib/smcp/srv`, `/etc/sudoers.d/smcp-srv`, `/etc/systemd/system/smcpd.service.d/smcp-srv.conf` |
| `systemd/smcpd.service` | `/etc/systemd/system/smcpd.service` | smcpd as `smcp-core` with a delegated cgroup for rootless Podman |
| `systemd/smcp-nftables.service` | `/etc/systemd/system/smcp-nftables.service` | Loads the nftables table at boot |
| `nftables/smcp.nft` | `/etc/smcp/smcp.nft` | Table `inet smcp` |
| `apparmor/smcpd` | `/etc/apparmor.d/smcpd` | AppArmor profile of smcpd, loaded in enforce mode when AppArmor is enabled |
| `apparmor/smcp-server` | `/etc/apparmor.d/smcp-server` | AppArmor profile of server processes, attached by path to `/smcp/bin/**` inside containers |

See [docs/enforced-profile.md](../../docs/enforced-profile.md) for the installation walk-through and [docs/sandbox.md](../../docs/sandbox.md) for what each object is for and for the `[runtime]` configuration.
