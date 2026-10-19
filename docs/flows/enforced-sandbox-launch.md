# Enforced sandbox launch

How `smcpd` starts one backend server in a rootless Podman container when `[runtime] sandbox = "podman"` (FR-5.27, FR-13.9, SR-3-2, SR-4-1, SR-4.5-1 to SR-4.7-2, SR-2.14-1; ARCH §18.1). The operator procedure and every option are in the [server sandbox guide](../sandbox.md).

The flow is drawn in three parts. Step numbers run on from one part to the next.

## 1. Start-up (steps 1–7)

```mermaid
sequenceDiagram
  autonumber
  participant D as smcpd start-up
  participant DR as sandbox.Doctor
  participant E15 as E-15 Runtime Manager (sandbox.Launcher)
  participant P as Podman (rootless, crun)
  participant E10 as E-10 Server registry (backend.Start)

  D->>DR: prerequisite checks (kernel, rootless, cgroup v2, user namespaces, subids, Podman, crun, delegation, seccomp, nftables, systemd, LSM)
  DR-->>D: failed checks
  Note over D,DR: mode enforced refuses start-up on any failed check. mode auto refuses only on the checks the container needs and resolves to standalone otherwise
  D->>E15: Start
  E15->>P: podman ps, rm --force each smcp.managed container of an earlier Gateway
  E15->>P: podman events (monitor stream)
  D->>D: profile.Resolve with the launcher (confined)
  D->>E10: start each configured server
```

## 2. Secrets and artifact check (steps 8–15, for each server)

```mermaid
sequenceDiagram
  autonumber 8
  participant E10 as E-10 Server registry (backend.Start)
  participant E20 as E-20 Secret Broker
  participant E21 as E-21 Journal
  participant E13 as E-13 Library re-verification
  participant E15 as E-15 Runtime Manager (sandbox.Launcher)

  E10->>E10: refuse a high-risk server when the launcher is not confined (SR-4-1), check the launch spec is pinned
  E10->>E20: resolve secret_env and launch-time bindings (S1, S3, S4)
  E20->>E21: secret_use delivered or denied
  E20-->>E10: environment values, S3 file paths
  E10->>E10: instance environment from the allowlist plus configured and secret variables (SR-2.14-1)
  E10->>E13: Launch (packaged server)
  E13->>E13: artifact SHA-256 and unpacked tree digest against the import record (SR-3-2)
  E13->>E15: Launch
```

## 3. Container launch and tool check (steps 16–26)

```mermaid
sequenceDiagram
  autonumber 16
  participant E15 as E-15 Runtime Manager (sandbox.Launcher)
  participant P as Podman (rootless, crun)
  participant S as Server instance (E-16 container)
  participant E17 as E-17 Runtime Monitor
  participant E21 as E-21 Journal
  participant E10 as E-10 Server registry (backend.Start)
  participant E13 as E-13 Library re-verification

  E15->>E15: network = egress: attach to the E-18 Egress Broker (refused when none is enabled)
  E15->>E15: Build launch spec: limits, read-only root, cap-drop all, no-new-privileges, user namespace, network none (egress: slirp4netns confined by nftables), artifact digest, granted mounts, reserved variable check
  E15->>P: podman run --interactive with an argument vector, values passed in the Podman process environment
  P->>S: create and start the container
  E15->>E17: locate the cgroup before the first MCP message
  E15->>E21: instance_launched with the launch spec (names, no values), committed
  E15->>E17: watch the instance (cgroup files, inotify, events)
  E10->>S: MCP initialize, tools/list over stdin and stdout
  S-->>E10: tools
  E10->>E13: compare with the signed manifest
  Note over E10,E13: a changed tool list suspends the revision and the instance is not started
  E17->>E21: process_created, deviation, limit_breach, instance_exited
```

## Implementation

`internal/sandbox` (`FromConfig`, `Launcher`, `Build`, `PodmanArgs`, `Monitor`), wired in `cmd/smcpd/main.go`. The launcher chain from outside in is the library's verifying launcher (`internal/library/runtime.go`), the Secret Broker's wrapper (`internal/secrets/launcher.go`, which withdraws an instance's deliveries when it closes or fails to start) and `sandbox.Launcher`. The Egress Broker hands its attacher to the sandbox launcher (`SetEgress`) instead of wrapping it. Differences from the specification:

- A sandboxed server with `network = "egress"` is attached to the Egress Broker on slirp4netns and confined by nftables in its namespace before it starts ([sandbox.md](../sandbox.md#egress)); with `network = "none"` it has loopback only.
- Instances are shared across sessions; per-session and per-call scopes (FR-5.10) and idle teardown (FR-5.11) are deferred from release 1.0 (SRS Appendix N). An instance that times out or exits is relaunched; a failed relaunch suspends the server.
- When the artifact check in step 14 fails, the revision is suspended, the server is skipped and the registry withdraws the launch-time secret deliveries of step 9 (`withdrawn`, reason `LAUNCH_FAILED`; security review SR-14).
- `packaging/linux` ships and loads the AppArmor profiles `smcpd` and `smcp-server`; the latter attaches by path to the executables of image-less servers, so servers run from an image are covered by the container profile only. No SELinux module ships. With `[runtime] run_as`, Podman runs as the CP-46 server identity `smcp-srv` ([enforced-profile.md](../enforced-profile.md)).
- `scripts/ci-integration.sh` runs a second instance with `[runtime] sandbox = "podman"` on the linux-integration CI job, where a probe server must fail to open network sockets; the Linux-only tests in `internal/sandbox/integration_linux_test.go` exercise the launcher against Podman. macOS never reaches this flow and always runs the standalone profile.
