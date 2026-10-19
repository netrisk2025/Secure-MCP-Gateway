# Server sandbox (enforced profile)

In the enforced profile the Gateway starts every backend MCP server in a rootless Podman container. Three architecture elements do this:

| Element | Package | What it does |
|---|---|---|
| E-15 Server Runtime Manager | `internal/sandbox` (`Launcher`) | Builds the launch specification of each instance, starts it with an argument vector, keeps the instance table, runs the shutdown sequence, removes containers |
| E-16 Execution Sandbox | `internal/sandbox` (`LaunchSpec.PodmanArgs`) | The container profile: read-only root, no capabilities, no network, cgroup limits, granted mounts only |
| E-17 Runtime Monitor | `internal/sandbox` (`Monitor`) | Samples each instance's cgroup, follows the Podman event stream, records runtime evidence and kills an instance that breaches a limit or matches a kill rule |

On macOS, and on Linux without the prerequisites below, the Gateway runs servers as ordinary child processes (standalone profile, "not enforced"). See [Security Limitations](security-limitations.md).

## Prerequisites

`smcpctl runtime doctor` checks each of these on the current host and prints a remedy for each one that fails. It changes nothing.

| Check ID | Prerequisite |
|---|---|
| `os`, `arch` | Linux on x86_64 or arm64 |
| `kernel` | Kernel 6.8 or later |
| `rootless` | smcpd runs as a non-root user (the service identity `smcp-core`) |
| `cgroup-v2` | cgroup v2 unified hierarchy |
| `userns` | Unprivileged user namespaces enabled |
| `userns-apparmor` | Warning only: `kernel.apparmor_restrict_unprivileged_userns=1` is set; Podman then needs an AppArmor profile that allows user namespaces. If the `podman` check passes, nothing more is needed |
| `subid-subuid`, `subid-subgid` | At least 65,536 subordinate UIDs and GIDs for the user in `/etc/subuid` and `/etc/subgid` |
| `uidmap` | `newuidmap` and `newgidmap` |
| `nftables` | `nft` |
| `systemd` | systemd is the running service manager |
| `lsm` | AppArmor or SELinux is enabled |
| `podman` | `podman info` succeeds as this user |
| `podman-rootless` | Podman runs rootless |
| `crun` | The OCI runtime is `crun` |
| `podman-cgroup-v2` | Podman uses cgroup v2 |
| `cgroup-delegation` | The `memory`, `pids` and `cpu` controllers are delegated to this user |
| `seccomp` | Podman has seccomp |
| `run-as` | Only with `runtime.run_as`: the server identity exists and is not root. The Podman checks then run as that identity through sudo, and the `subid` checks read its ranges |
| `apparmor-server` | Warning only, on AppArmor hosts: the server profile `smcp-server` is loaded in enforce mode (see "AppArmor") |

```
smcpctl runtime doctor [--json] [--podman PATH] [--config FILE]
```

Exit status 0 when every check passes, 1 otherwise. `--json` prints `{"ready": bool, "checks": [{"id", "name", "status", "detail", "remedy"}]}`. `status` is `pass`, `warn` or `fail`. The Go function behind it is `sandbox.Doctor(ctx, sandbox.DoctorOptions{})`; `smcpctl doctor` can call it.

### Startup refusal

When `[runtime] sandbox = "podman"`, smcpd runs the same checks before it launches anything:

- With `[profile] mode = "enforced"`, any failed check stops startup with `enforced-profile prerequisites missing: <each failed check>; run smcpctl runtime doctor for remedies` (FR-13.9).
- With `mode = "auto"`, only the checks the container itself needs stop startup (`os`, `arch`, `kernel`, `rootless`, `cgroup-v2`, `userns`, the two `subid` checks, `uidmap`, every `podman*` check, `crun`, `cgroup-delegation`, `seccomp`). A missing `systemd`, `nftables` or LSM is logged; servers are still sandboxed, but the profile resolves to standalone and the release label is "not enforced".

## Installing on a Linux host

`packaging/linux/install-enforced.sh` prepares the host. Run it as root:

```
sudo packaging/linux/install-enforced.sh --check          # prerequisites only
sudo packaging/linux/install-enforced.sh [--bin-dir DIR] [--start]
```

It verifies every prerequisite first and exits with status 2, listing each missing one, before it changes anything. It then creates, when absent:

| Object | Detail |
|---|---|
| Groups | `smcp`; `smcp-srv` |
| Users | `smcp-core`, `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data`, `smcp-console` (group `smcp`) and `smcp-srv` (group `smcp-srv`, so it cannot read `/etc/smcp`); system users, no login shell |
| Subordinate IDs | 65,536 UIDs and GIDs each for `smcp-core` (runs smcpd) and `smcp-srv` (runs the server containers with `runtime.run_as`), in non-overlapping ranges starting at 100000 or after the highest existing range |
| Directories | `/etc/smcp` (root:smcp 0750); `/var/lib/smcp/{policy,registry,artifacts}` (smcp-core 0700); `/var/lib/smcp/journal` (smcp-evidence 0700); `/var/lib/smcp/keys` (smcp-keys 0700); `/var/lib/smcp/vault` (smcp-vault 0700); `/var/lib/smcp/exports` (smcp-core 0750); `/var/lib/smcp/state` and `/var/lib/smcp/home/smcp-core` (smcp-core 0700); `/var/lib/smcp/home` (root 0755); `/var/lib/smcp/home/smcp-srv` (smcp-srv 0711; rootless Podman needs others to traverse it); `/var/lib/smcp/srv` (smcp-core:smcp-srv 0751, `runtime.shared_dir`); `/var/log/smcp` (0750) |
| Server identity | Lingering for `smcp-srv` (its systemd user manager owns `/run/user/<uid>`), `/etc/sudoers.d/smcp-srv` (smcp-core may run Podman, and nothing else, as smcp-srv) and the drop-in `/etc/systemd/system/smcpd.service.d/smcp-srv.conf` (`packaging/linux/setup-server-identity.sh`; see "Server identity") |
| AppArmor | `/etc/apparmor.d/smcpd` and `/etc/apparmor.d/smcp-server`, loaded in enforce mode when AppArmor is enabled |
| nftables | `/etc/smcp/smcp.nft`, loaded as table `inet smcp` |
| systemd units | `/etc/systemd/system/smcp-nftables.service` and `smcpd.service`, enabled |
| Binaries | With `--bin-dir DIR`: `smcpd`, `smcpctl` and `smcp-refserver` from DIR into `/usr/local/bin` |

Each step prints `present`, `created` or `updated`. A second run prints only `present` lines. It never touches configuration, keys, policy or the journal. `--start` starts both units and needs `/etc/smcp/smcp.toml`.

The Gateway currently keeps keys and the journal in one state directory owned by `smcp-core` (`/var/lib/smcp/state`). The per-identity directories of CP-46 are created for the elements that will use them.

### smcpd.service

The unit runs `/usr/local/bin/smcpd --config /etc/smcp/smcp.toml` as `smcp-core:smcp` with `Delegate=yes` and `DelegateSubgroup=supervisor`, so that container cgroups are created below the service's own cgroup, and with `XDG_RUNTIME_DIR=/run/smcp`. With this unit set `runtime.cgroup_manager = "cgroupfs"`. It applies `ProtectSystem=strict` (writable: `/var/lib/smcp`, `/run/smcp`, `/var/log/smcp`), `ProtectHome=read-only`, `PrivateTmp`, `ProtectKernelModules`, `ProtectClock`, `LockPersonality`, `RestrictRealtime`, `RestrictAddressFamilies` and `SystemCallArchitectures=native`. The unit file lists the options it does not set and why (rootless Podman needs setuid `newuidmap`, its own namespaces and capabilities inside them). A writable mount grant outside `/var/lib/smcp` needs a drop-in with `ReadWritePaths=` as well as the grant in `smcp.toml`.

### nftables table `inet smcp`

| Object | Purpose |
|---|---|
| set `gateway_ports` | The harness and control listener ports (8443, 8444 by default; edit `/etc/smcp/smcp.nft` if you change them) |
| chain `input` | Drops TCP connections to `gateway_ports` that do not arrive on loopback |
| chain `egress` | Empty; jumped to from `output`. The Egress Broker (E-18) adds its rules here |

Sandboxed instances have no network interface but loopback (network `none`), so they cannot reach anything whatever this table contains.

## Configuration

The `[runtime]` table of `smcp.toml`. All keys are optional.

| Key | Default | Meaning |
|---|---|---|
| `sandbox` | `"podman"` when `[profile] mode = "enforced"`, else `"none"` | `"podman"` runs servers in containers; `"none"` runs them as child processes. `"podman"` with `mode = "standalone"` is a configuration error |
| `podman` | `podman` on `PATH` | Absolute path of the Podman binary |
| `image` | none | Default image for every server, by digest (`name@sha256:<64 hex>`). Without an image the Gateway uses an empty root directory and mounts the server executable read-only |
| `memory_bytes` | 536870912 (512 MiB, CP-24) | Memory limit; swap is disabled (`--memory-swap` equals the limit). Minimum 16 MiB |
| `cpus` | 1 (CP-24) | CPU limit |
| `pids` | 128 (CP-24) | PID limit (threads count). Minimum 8 |
| `tmpfs_bytes` | 67108864 (64 MiB) | Size of each of the `/work` and `/tmp` tmpfs mounts |
| `nofile` | 1024 | Open-file limit |
| `userns_size` | 2048 | UIDs in each instance's user namespace (1024 to 65536) |
| `user` | `"1000:1000"` | UID:GID inside the container; must be below `userns_size` |
| `apparmor_profile` | none | Passed as `--security-opt apparmor=<name>`. Rootless Podman refuses this option ("Apparmor is not enabled"), so it only works with a rootful Podman, which the Enforced profile does not use; see "AppArmor" for the profile that applies |
| `selinux_type` | none | Passed as `--security-opt label=type:<type>` |
| `cgroup_manager` | Podman's default | `"systemd"` or `"cgroupfs"`; use `"cgroupfs"` under `smcpd.service` |
| `monitor_interval` | `"500ms"` | How often the Runtime Monitor samples each cgroup (50ms to 10s) |
| `run_as` | none | The server identity (CP-46 `smcp-srv`): every Podman command runs as this user through `sudo -n -E -u <run_as>`, so containers belong to its rootless Podman and subordinate range. Needs `shared_dir`, and `cgroup_manager` unset or `"systemd"`. See "Server identity" |
| `sudo` | `/usr/bin/sudo` | Absolute path of sudo; only with `run_as` |
| `shared_dir` | none | Only with `run_as`, and required then: a directory the Gateway writes and `run_as` can read, outside the state directory (`/var/lib/smcp/srv`). It holds the Gateway-built root directory of servers without an image |

Per-server settings, matched by alias. Every `alias` must name a configured `[[server]]`.

```toml
[[runtime.server]]
alias = "fs"
memory_bytes = 268435456   # overrides [runtime]
pids = 64
network = "none"           # or "egress"
scope = "shared"
userns = "auto"            # or "keep-id"
allow_spawn = false
on_deviation = "alert"     # or "kill-instance"

[[runtime.server.mount]]
source = "/srv/projects"   # host path; relative paths are resolved against the config directory
target = "/data"           # path in the container; default: the source path
write = false              # read-only unless true
```

| Key | Default | Meaning |
|---|---|---|
| `image` | `[runtime] image` | Image for this server, by digest. The `[[server]] command` is then a path inside the image |
| `memory_bytes`, `cpus`, `pids` | `[runtime]` values | Resource limits for this server |
| `network` | `"none"` | `"none"`: loopback only. `"egress"`: attached to the Egress Broker and confined to its listeners (see "Egress"); needs `[egress] enabled = true` |
| `scope` | `"shared"` | Instance scope (FR-5.10). Only `"shared"` (one instance per server) is implemented; `"session"` and `"call"` are refused at load |
| `userns` | `"auto"` | `"auto"` gives each instance its own range of subordinate UIDs. `"keep-id"` maps the identity that runs Podman (the Gateway user, or `run_as`) into the container so that writable grants on directories that user owns work; instances of that server then share one mapping |
| `allow_spawn` | `false` | Declares that the server may start processes. When false, and the server's signed manifest does not declare `spawns_processes`, every process besides the first is a deviation |
| `on_deviation` | `"alert"` | Containment action for a deviation: record it (`alert`) or also kill the instance (`kill-instance`). Resource-limit breaches always kill |
| `mount` | none | Host paths granted to this server |

### Mount grants

A mount source must be an existing, clean absolute path (after resolving relative paths), must not contain `,` `=` or a newline, must not be a socket, and must not be, contain or lie inside the Gateway state directory, `/`, `/proc`, `/sys`, `/dev`, `/boot`, `/etc`, `/root`, `/run`, `/var/run`, `/var/lib/containers`, `/var/lib/docker`, `/var/lib/smcp`, `/etc/smcp` or `/run/smcp`. Names containing `docker.sock`, `podman.sock`, `containerd.sock`, `crio.sock`, `dbus` or `systemd` are refused. A target must not be at or below `/`, `/work`, `/tmp`, `/var/tmp`, `/smcp`, `/proc`, `/sys`, `/dev`, `/run` or `/etc`; choose another path such as `/data`.

For a packaged server (a `[[server]]` entry with `package`), the grants are cut down to the filesystem slots its signed manifest declares, bound by the entry's `slots` (SR-4.6-1): a grant inside a declared slot is mounted as granted; a grant that contains slots mounts each slot alone, at the matching path under the grant's target; a mount is writable only when the grant sets `write = true` and the manifest declares the slot `rw`. A grant that meets no declared slot refuses the launch (`mount refused: ... outside every filesystem slot its manifest declares`). A server configured by `command` has no manifest, and its grants apply as written.

With `userns = "auto"` the instance runs under a subordinate UID, not the Gateway user. It can read a granted directory only if the files are readable by others (for example mode 0755 for directories and 0644 for files), and write only to a directory that is writable by others. Files it creates belong to that subordinate UID on the host. Use a dedicated directory for writable grants, or `userns = "keep-id"` for the server. With `run_as`, the mount source must also be reachable by the server identity (its Podman resolves it), and `keep-id` maps the server identity, not the Gateway user.

### Environment

The instance environment is the server's `env` and its resolved `secret_env`. `PATH` and `HOME` of the Gateway are not passed. Values travel in the Podman process environment and are named on the command line (`--env=NAME`), never written there. Names that would configure Podman itself are refused: those starting with `CONTAINERS_`, `PODMAN_`, `BUILDAH_`, `XDG_`, `DBUS_`, `DOCKER_`, `LD_`, `STORAGE_`, `REGISTRY_`, `CONTAINER_`, and `NOTIFY_SOCKET`, `TMPDIR`, `SSL_CERT_*`, the proxy variables, `GODEBUG` and `GOTRACEBACK`.

Secret files (delivery modes S2 and S3, see [secrets.md](secrets.md)) are written by the Secret Broker into a per-instance directory on the host. The sandbox mounts that directory read-only at `/smcp/secrets` and rewrites the file-path variables to match. The files are mode 0600 and belong to the Gateway user. When the instance runs under any other UID (`userns = "auto"`, or `run_as`), the launcher creates the container, reads the host UID that the container user maps to from the created container's `uid_map` (`/proc/<pid>/uid_map` after `podman init`), and adds POSIX ACL entries for exactly that UID: search on the directory and read on each file. Only then does the server start. The broker copies the directory's named-user entries to every file it writes later (per-call S2 files, rotated S3 values). With `run_as` the server identity also gets search on the directory and on its ancestors that the Gateway owns, so that its Podman can resolve the mount source. The owning group and others get nothing, and the directory is scrubbed and removed at teardown as before. The secret runtime directory must be on a file system with POSIX ACLs (tmpfs, ext4, xfs); otherwise the launch fails with a message naming it. With `keep-id` under the Gateway's own identity nothing changes.

## Server identity (`run_as`)

CP-46 names a separate identity, `smcp-srv`, for the server runtime. With

```toml
[runtime]
sandbox = "podman"
run_as = "smcp-srv"
shared_dir = "/var/lib/smcp/srv"
```

smcpd (as `smcp-core`) runs every Podman command as `sudo -n -E -u smcp-srv -- <podman> ...`. Rootless Podman runs as the user that starts it, so the containers, their storage (`/var/lib/smcp/home/smcp-srv`), their `conmon` monitors and their subordinate UIDs all belong to `smcp-srv`. A server that escapes its container lands in `smcp-srv`'s range: it cannot read the Gateway's state, keys, journal or configuration (`smcp-srv` is not in group `smcp`), and it cannot signal or trace smcpd.

What the launcher does differently:

- The Podman environment is built for `smcp-srv`: `HOME`, `USER`, `LOGNAME`, `XDG_RUNTIME_DIR=/run/user/<uid>` and `DBUS_SESSION_BUS_ADDRESS` of its user manager. `-E` passes them and the instance values that Podman reads by name (`--env=NAME`); values never appear on a command line.
- Containers get their cgroups from `smcp-srv`'s systemd user manager (lingering), so `cgroup_manager` must be unset or `"systemd"`; `"cgroupfs"` is refused because the cgroup subtree of `smcpd.service` belongs to `smcp-core`. The Runtime Monitor reads the cgroup files, which are world-readable, as before.
- The root directory of image-less servers lives in `shared_dir/rootfs`, because the state directory is closed to `smcp-srv`. Their executable (packaged servers are unpacked into the state directory) is copied to `shared_dir/bin/<sha256>/<name>` (mode 0755), checked against the digest of the launch specification, and mounted from there.
- The egress confinement step (`podman unshare nsenter ... nft`) runs as `smcp-srv`, the owner of the container's user and network namespaces.
- Secret files get ACL entries for the instance's UID (see "Environment").

Host setup (`packaging/linux/setup-server-identity.sh`, run by `install-enforced.sh`): `smcp-srv` in its own group with home `/var/lib/smcp/home/smcp-srv`; `loginctl enable-linger smcp-srv`; `/var/lib/smcp/srv` (smcp-core:smcp-srv 0751); `/etc/sudoers.d/smcp-srv`:

```
smcp-core ALL=(smcp-srv) NOPASSWD:SETENV: /usr/bin/podman
```

and `/etc/systemd/system/smcpd.service.d/smcp-srv.conf`, which orders smcpd after `user@<uid>.service` and adds `ReadWritePaths=-/run/user/<uid>` (Podman's runtime directory; `ProtectSystem=strict` makes `/run` read-only otherwise). The rule lets `smcp-core` run any Podman command as `smcp-srv`, so `smcp-core` controls `smcp-srv`'s containers; the separation protects the Gateway from the servers, not the servers from the Gateway. `smcpctl runtime doctor --config /etc/smcp/smcp.toml` checks the identity and runs `podman info` through the same sudo rule.

Without `run_as`, Podman runs as the Gateway's own identity, as before.

## AppArmor

Rootless Podman cannot apply an AppArmor profile to a container: it refuses `--security-opt apparmor=` without root, and its own default profile is not applied either. The packaged profile `packaging/linux/apparmor/smcp-server` therefore attaches by path: `profile smcp-server /smcp/bin/**`. The Gateway mounts the executable of every server that runs without an image at `/smcp/bin/<name>`, and when the runtime executes that path inside the container's mount namespace, the process enters the profile. No host program lives at `/smcp/bin`. `install-enforced.sh` installs it as `/etc/apparmor.d/smcp-server` and loads it in enforce mode.

The profile adds to the container profile above: it denies reading any process environment in `/proc` (S4 secret values live there, so a helper process the server starts cannot read them), writes below `/smcp`, writes to `/proc` and `/sys` settings, mounts, `pivot_root`, tracing other processes and every capability, following Podman's `containers-default` profile. `cat /proc/<container pid>/attr/current` prints `smcp-server (enforce)`; denials appear in `journalctl -k -g 'profile="smcp-server"'`. Site rules go into `/etc/apparmor.d/local/smcp-server`.

Servers that run from an image execute other paths and are not confined by this profile; Podman's seccomp profile, the dropped capabilities, the user namespace and the read-only root still apply. `smcpctl runtime doctor` warns (`apparmor-server`) while the profile is not loaded.

## The sandbox profile

Every instance is started as (with `run_as`, prefixed by `sudo -n -E -u <run_as> --`):

```
podman run --interactive --name smcp-<alias>-<id> --label smcp.managed=1 --label smcp.gateway=<gateway id>
  --label smcp.alias=<alias> --label smcp.instance=<instance id>
  --pull=never --log-driver=none --read-only --read-only-tmpfs=false
  --cap-drop=all --security-opt=no-new-privileges --userns=auto:size=<userns_size>
  --network=none --pid=private --ipc=private --uts=private --hostname=<name> --no-hosts --passwd=false
  --memory=<bytes> --memory-swap=<bytes> --cpus=<n> --pids-limit=<n>
  --ulimit=nofile=<n>:<n> --ulimit=core=0:0
  --tmpfs=/work:rw,nosuid,nodev,size=<bytes>,mode=1777
  --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=<bytes>,mode=1777
  --workdir=/work --user=<uid:gid>
  [--security-opt=apparmor=<profile>] [--security-opt=label=type:<type>] [--cgroup-manager=<manager>]
  --mount=type=bind,src=<source>,dst=<target>,ro|rw,bind-propagation=rprivate ...
  --env=<NAME> ...
  (<image> | --rootfs <state>/runtime/rootfs)  <argv>
```

Podman's default seccomp profile applies (it is never disabled). No device is added and no host namespace is shared. The working directory is `/work` unless the server's `dir` equals a mount target. Without an image, the root directory is `<state>/runtime/rootfs`: empty mount points, a two-line `/etc/passwd`, and the server executable bind-mounted read-only at `/smcp/bin/<name>`. Such a server must be a statically linked executable (for Go: `CGO_ENABLED=0`); servers that need an interpreter need an image. A packaged node or python server (manifest launch runtime `node` or `python`) runs on the interpreter of its image, found on the image's `PATH` (`node`, `python3`), with its verified, unpacked artifact tree mounted read-only at its own path; without an image its launch is refused. The image must provide what the package needs at run time, for example the Python minor version its compiled wheels were built for, or a `git` binary for a git server.

`smcpctl runtime spec --config FILE` prints, without starting anything, the launch specification and the Podman argument vector of every configured server (FR-5.9). Environment values are not printed. For a server with `network = "egress"` while `[egress] enabled = true`, `egress_env` lists the Egress Broker variables the instance receives (FR-5.37): the proxy variables unless `[egress] proxy_env = false`, and the `endpoint_env` variable of each of its grants; the broker picks the listener ports at launch, so the values read `http://10.0.2.2:<port>`.

The launch specification records: alias, instance ID, container name, the artifact (command, `sha256:` digest of the executable or the image digest), argument vector, environment variable names, mounts, network, working directory, limits, sandbox profile and scope.

## Lifecycle

- **Start.** The Gateway removes containers labelled `smcp.managed=1` that belong to an earlier Gateway process, then launches each configured server at startup. It waits until the container runs and its cgroup is known before the first MCP message, so the monitor sees the instance from the start.
- **Shutdown (FR-5.27).** Close stdin, wait 5 seconds, `podman kill --signal TERM`, wait 5 seconds, `podman kill --signal KILL`, then `podman rm --force`. If the Gateway process dies, the attached Podman client is killed with it (parent-death signal), so the instance loses its stdin.
- **Unexpected exit.** Recorded as `instance_exited` with reason `INSTANCE_EXITED_UNEXPECTEDLY` (or `MEMORY_LIMIT`). The next call to the server fails and the instance is then relaunched; later calls reach the new instance. An instance that does not answer a call within `upstream_timeout` is also relaunched (the call ends with `-31009`). A relaunch that fails, or whose tool list differs from the enabled revision, suspends the server.

## Runtime Monitor

For each instance the monitor reads, every `monitor_interval` and on each kernel change notification of `memory.events` and `pids.events` (inotify), the cgroup files `memory.current`, `memory.peak`, `memory.events`, `pids.current`, `pids.peak`, `pids.events`, `cpu.stat` and `cgroup.procs` (including child cgroups). It follows `podman events` for the Gateway's containers.

| Observation | Rule | Action |
|---|---|---|
| `oom_kill` in `memory.events` increased, or a Podman `oom` event | Memory limit breach | Kill the instance |
| Unrequested exit 137 after the cgroup reached 90% of its memory limit or recorded an OOM event | Memory limit breach (rootless Podman does not always report `OOMKilled`) | Recorded at exit |
| `max` in `pids.events` increased | PID limit breach | Kill the instance |
| A new PID in the cgroup | `process_created` observation; a deviation when `allow_spawn = false` and it is not the first process | `on_deviation` |
| Podman `exec` event | Someone ran a command inside the instance | `on_deviation` |

The kill is `podman kill --signal KILL`. The evidence records `latency_ms` from the decision to the kill. CPU is throttled by the kernel at the `cpus` limit and is not a breach.

## Evidence

All runtime events have class `runtime` and `policy_status` `not_evaluated`.

| Outcome | Origin | Reason code | Durable | Detail |
|---|---|---|---|---|
| `instance_launched` | E-15 | | yes | `alias`, `instance_id`, `container`, `launch_spec` (names, no values) |
| `process_created` | E-17 | | no | `alias`, `instance_id`, `pid`, `comm` |
| `deviation` | E-17 | `UNDECLARED_PROCESS`, `EXEC_INTO_INSTANCE` | yes | `action` (`alert` or `kill-instance`), `latency_ms` when killed |
| `limit_breach` | E-17 | `MEMORY_LIMIT`, `PIDS_LIMIT` | yes | `action` `kill-instance`, counters, limit, `latency_ms` |
| `instance_killed` | E-17 | `OPERATOR_KILL` | yes | `actor`, `reason` |
| `instance_exited` | E-15 | none (requested), `INSTANCE_EXITED_UNEXPECTEDLY`, `MEMORY_LIMIT` | yes | `expected`, `exit_code`, `oom_killed`, `memory_peak_bytes`, `cpu_usage_usec`, `pids_peak`, `kill_reason`, `stderr_bytes` |
| `monitor_degraded` | E-17 | `MONITOR_UNAVAILABLE` | no | The monitor could not find the instance's cgroup after 20 tries |
| `evidence_dropped` | E-15 | | yes | `events`: runtime events dropped because more than 1,024 were produced before the journal was attached |

Stderr content never enters harness traffic. It is kept in a 1 MiB ring per instance (CP-37) and the control API returns its last 64 KiB.

Text a server asserts is recorded as evidence of class `server_asserted` (SR-6.18-1), origin E-15, `policy_status` `not_evaluated`, attributed to the server revision and the instance. The outcome is `stderr` (output written since the last record), `error` (the message and code of a JSON-RPC error the server returned; the harness sees only `BACKEND_ERROR` and the code) or `notification` (any notification the server sent, with its method and parameters). Detail: `server`, `instance` (`<alias>#<n>`), `text`, and `method`, `code`, `truncated_bytes`, `skipped_bytes` (stderr overwritten in the ring before it was read) and `dropped` when they apply. Records are written once a second per instance, at most 16 per second; each `text` holds at most 4 KiB, and every secret value delivered to the instance is replaced with `[REDACTED]`. These events are labelled origin `backend`; their claims are not facts about a call and are not linked to one.

## Commands

| Command | What it does |
|---|---|
| `smcpctl runtime doctor [--json] [--podman PATH] [--config FILE]` | Check the enforced-profile prerequisites (offline) |
| `smcpctl runtime spec [--config FILE]` | Print the launch specification of every server (offline) |
| `smcpctl runtime status [--config FILE]` | Launcher, defaults and instance counts by state |
| `smcpctl runtime instances [--config FILE]` | The instance table |
| `smcpctl runtime show <id> [--config FILE]` | One instance with its observations and stderr tail |
| `smcpctl runtime kill <id> [--reason TEXT] [--config FILE]` | Kill an instance now; recorded as `instance_killed` with your identity |

The control routes are documented in [api/runtime.md](api/runtime.md).

## Egress

A server whose `[[runtime.server]]` entry sets `network = "egress"` is attached to the Egress Broker (E-18, [egress.md](egress.md)); `[egress] enabled = true` is required. The launcher, not the broker, confines the network, because only the rootless user namespace that owns the container's network namespace holds `CAP_NET_ADMIN` over it:

1. The broker opens the instance's listeners on 127.0.0.1 and returns their addresses as the instance sees them (`10.0.2.2:<port>`) in `HTTP_PROXY`, `HTTPS_PROXY` and the grant endpoint variables.
2. `podman create` with `--network=slirp4netns:allow_host_loopback=true`, `--http-proxy=false` and the broker variables (addresses only, so they are passed on the Podman command line; every other value still goes through the Podman process environment).
3. `podman init`: the network namespace and the mounts exist; the server process has not started.
4. `podman unshare nsenter --net=<namespace> nft -f -` installs table `inet smcp_egress`: output policy drop, loopback and established traffic accepted, TCP to each broker listener accepted, everything else rejected; input policy drop. `nft list table` reads it back, and the launch fails unless the drop policy and every listener port are present.
5. `podman start --attach --interactive` starts the server.

Any failure removes the container and closes the broker attachment, so a server is never started on an unconfined network. The instance has every capability dropped and cannot change the table. The `instance_launched` evidence names the attachment, the namespace and the allowed endpoints; the broker's `attached` evidence has `"confined_by": "launcher"`.

Host requirements: `slirp4netns`, `nsenter` (util-linux) and `nft`. `scripts/ci-integration.sh` and `TestIntegrationEgressBroker` check on real Podman that direct connections (to the granted server itself, to other loopback services, to the slirp4netns DNS forwarder 10.0.2.3 and to the Internet) are refused and that a proxied request to a granted local HTTP server succeeds.

## Errors

| Message | Cause |
|---|---|
| `enforced-profile prerequisites missing: ...` | A doctor check failed at startup (see above) |
| `sandbox: podman not found on PATH; install rootless Podman or set runtime.podman` | No Podman binary |
| `mount refused: ...` | A mount grant broke a rule in "Mount grants" |
| `server artifact unavailable: <path> is not a regular file` | The server command does not exist (no image configured) |
| `environment variable X is reserved: it would configure Podman itself` | A reserved name in `env` or `secret_env` |
| `runtime.server "x" requests egress but no Egress Broker is enabled ([egress] enabled = true)` | `network = "egress"` without `[egress] enabled = true` |
| `runtime.server "x": egress confinement: podman create: ... slirp4netns ...` | `network = "egress"` needs `slirp4netns` (`apt-get install slirp4netns`) |
| `runtime.server "x": egress confinement: install the egress rules in ...` | `podman unshare nsenter --net=<namespace> nft -f -` failed: `nft` or `nsenter` missing, or nftables unavailable in the namespace. The container is removed before it starts |
| `runtime.server "x": scope "session" is not supported yet` | Only shared instances exist |
| `runtime.image must be referenced by digest` | An image without `@sha256:` (SR-3.6-1) |

Errors that Podman reports when it starts a container appear in the server's stderr and in the `launch:` or `connect` startup error. Common ones:

| Podman or crun error | Fix |
|---|---|
| `container uses ID mappings ... but doesn't map UID 1000` | `user` is not below `userns_size` |
| `not enough unused IDs in user namespace` | The user's subordinate range is too small for the number of instances times `userns_size` |
| `crun: chown ...: Invalid argument` | A mount target below a tmpfs path; choose another target |
| `cannot set memory limit` or missing controllers | Delegate the `memory`, `pids` and `cpu` controllers (see `cgroup-delegation`) |

## Limits of this implementation

- Egress for sandboxed servers uses slirp4netns with host loopback (see "Egress" below). Only TCP to the instance's own broker listeners leaves the namespace; UDP, ICMP and every other destination are dropped. The broker's listeners are bound on the host's 127.0.0.1, so a host process could also use an instance's listener as that server; the broker's grants still apply.
- Instance scope is shared (one instance per server, started with the Gateway). An instance that times out or exits is relaunched, and later calls wait for the new one; a relaunch that fails or reports another revision suspends the server. The third unexpected exit within five minutes suspends the server revision (FR-5.12). Per-session and per-call instances (FR-5.10) and reuse and idle teardown (FR-5.11) are deferred from release 1.0 (SRS Appendix N).
- The containment actions are `alert` and `kill-instance` (FR-5.35). `suspend-revision` and `suspend-session` are not part of release 1.0: an instance that keeps ending is suspended after three unexpected exits within five minutes (FR-5.12), and the operator suspends a revision or ends a session from the console.
- Declared behavior rules: process creation is declared by the signed manifest's `capabilities.spawns_processes` or by `allow_spawn` in `[[runtime.server]]` (FR-5.34); the containment action comes from `on_deviation`.
- File opens outside mounts and network connection attempts are prevented (read-only root, no network) but not observed (FR-5.33 leaves them out): observing them needs eBPF or a seccomp notifier.
- Mount grants come from the operator's configuration. For a packaged server they are cut to the filesystem slots its signed manifest declares (SR-4.6-1, see "Mount grants" above); a server configured by `command` has no manifest, so its grants are mounted as configured.
- Without `run_as`, the Gateway and rootless Podman run as one identity. With `run_as`, `smcp-core` can run any Podman command as `smcp-srv` (the sudoers rule names the Podman binary, not its arguments), and the `conmon` processes and the Podman client of each instance run as `smcp-srv`: smcpd cannot signal them directly and stops instances through `podman kill`.
- The `smcp-server` AppArmor profile confines servers started from `/smcp/bin` (image-less servers) only. No SELinux policy module is shipped for servers or smcpd; `selinux_type` passes a type to Podman.
