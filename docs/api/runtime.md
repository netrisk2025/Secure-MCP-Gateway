# Control API: runtime (`/api/v1/runtime*`)

Routes of the Server Runtime Manager (E-15) and Runtime Monitor (E-17) on the loopback control listener. They use the control API's authentication (operator token or administrator session as `Authorization: Bearer`), host, origin and content-type checks; a failed authentication is recorded as `ADMIN_AUTH_FAILED`. Errors have the control API's shape:

```json
{ "error": { "code": "no_instance", "message": "no instance with that ID" } }
```

When the Gateway runs without a sandbox (`[runtime] sandbox = "none"`) the routes exist and report that.

## GET /api/v1/runtime

Launcher summary.

```json
{
  "sandbox": "podman",
  "launcher": "podman",
  "confined": true,
  "gateway_id": "01a14729-ea1e-793a-bb6e-468ebea6bdbf",
  "podman": "/usr/bin/podman",
  "defaults": {
    "memory_bytes": 536870912, "cpus": 1, "pids": 128, "tmpfs_bytes": 67108864,
    "nofile": 1024, "userns_size": 2048, "user": "1000:1000", "image": "", "monitor_interval": "500ms"
  },
  "instances": { "running": 2, "killed": 1 }
}
```

Without a sandbox: `{"sandbox": "none", "launcher": "subprocess", "confined": false, "instances": 0}`.

## GET /api/v1/runtime/instances

The instance table, oldest first.

```json
{
  "instances": [
    {
      "instance_id": "01a14729-c295-721f-a82c-05236e076e75",
      "alias": "fs",
      "container": "smcp-fs-05236e076e75",
      "state": "running",
      "removed": false,
      "scope": "shared",
      "started": "2026-10-17T00:01:31.689Z",
      "oom_killed": false,
      "deviations": 0,
      "usage": {
        "at": "2026-10-17T00:05:02.112Z",
        "memory_current_bytes": 7340032, "memory_peak_bytes": 9437184, "cpu_usage_usec": 81234,
        "pids": 7, "pids_peak": 8, "oom_events": 0, "oom_kills": 0, "pids_max_events": 0
      },
      "launch_spec": { "alias": "fs", "artifact": { "command": "/usr/local/bin/smcp-refserver", "digest": "sha256:...", "rootfs": "/var/lib/smcp/state/runtime/rootfs" },
        "argv": ["/smcp/bin/smcp-refserver", "--root", "/data"], "env_names": [], "mounts": [ { "source": "/srv/data", "target": "/data", "write": false } ],
        "network": "none", "workdir": "/work", "limits": { "memory_bytes": 536870912, "cpus": 1, "pids": 128, "tmpfs_bytes": 67108864, "nofile": 1024 },
        "profile": { "read_only_root": true, "no_new_privileges": true, "cap_drop": "ALL", "seccomp": "default", "userns": "auto:size=2048",
          "user": "1000:1000", "allow_spawn": false, "on_deviation": "alert" }, "scope": "shared" },
      "observations": [ { "at": "2026-10-17T00:01:31.749Z", "kind": "process_created", "detail": { "pid": 11094, "comm": "smcp-refserver" } } ]
    }
  ]
}
```

`state` is `starting`, `running`, `exited` or `killed`; `removed` is true once the container is deleted. `ended`, `exit_code` and `kill_reason` appear once known. `observations` keeps the last 64 runtime events of the instance (`process_created`, `deviation`, `exec`, `exited`); the evidence journal has all of them.

## GET /api/v1/runtime/instances/{id}

One instance and the last 64 KiB of its stderr (diagnostic output; it may contain anything the server printed).

```json
{ "instance": { "instance_id": "...", "alias": "fs", "...": "as above" }, "stderr_tail": "listening on stdio" }
```

`404 no_instance` for an unknown ID.

## POST /api/v1/runtime/instances/{id}/kill

Kill a running instance at once (`podman kill --signal KILL`). The body must be `application/json`:

```json
{ "reason": "investigating unexpected output" }
```

Response `200`:

```json
{ "instance_id": "01a14729-c295-721f-a82c-05236e076e75", "state": "killed" }
```

The kill is recorded as evidence: outcome `instance_killed`, reason code `OPERATOR_KILL`, detail `actor` (`operator-token` or `admin:<user>`) and `reason`. Errors: `400 bad_request` (body is not `{reason}`), `404 no_instance` (unknown ID or instance not running).

## GET /api/v1/runtime/doctor

The enforced-profile prerequisite checks of the host, as seen by the Gateway's own user (the same as `smcpctl runtime doctor --json`).

```json
{
  "ready": false,
  "checks": [
    { "id": "os", "name": "Linux", "status": "pass", "detail": "linux" },
    { "id": "nftables", "name": "nftables (nft)", "status": "fail", "remedy": "apt-get install nftables" }
  ]
}
```
