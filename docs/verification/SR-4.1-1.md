# SR-4.1-1 Service identities of the running processes

| Field | Content |
|---|---|
| Requirement or scenario | SR-4.1-1 |
| Commit | `b51a8252c6a75d352a960981413dfe9b9b9360dc` |
| Profile and platform | Enforced; ubuntu-24.04 GitHub-hosted runner (image 20261012.334.1), linux/amd64 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (release-ops partials task); CI run 39100503279, job linux-integration |
| Method | Inspection |
| Result | pass |

The statement is the narrowed one of 2026-10-18 (`srs_build/req5.txt:698`). `smcpd` runs as the CP-46 identity `smcp-core`, and every MCP server process runs under `smcp-srv` (as `smcp-srv` or a UID of its subordinate range). Neither identity is root or the operator's account.

Steps: the CI job linux-integration of https://github.com/ethan03805/Secure-MCP-Gateway/actions/runs/39100503279 (pull request #104, head commit above) ran `scripts/ci-systemd.sh`. That script installed the Enforced profile with `smcpctl install --profile enforced`, started `smcpd.service` with the reference server and the sandbox probe, made a tool call through the Gateway, and then inspected the running processes (`scripts/ci-systemd.sh:238`, `scripts/ci-systemd.sh:246`, `scripts/ci-systemd.sh:260`). I read the job log.

Observations (from the job log):

- `smcp-srv: uid 987, group smcp-srv, subuid smcp-srv:296608:65536`. The runner account (the operator) is UID 1001.
- `smcpd runs as smcp-core`: `ps` of the unit's main PID printed `smcp-co+ 999 15525 smcpd`, so UID 999 is `smcp-core`. The unit sets `User=smcp-core` (`packaging/linux/systemd/smcpd.service:20`). The script checks that this UID equals `id -u smcp-core` and is neither 0 nor the runner's UID.
- The reference server container `smcp-ref-d7ce8d821b8a` has main PID 15645 at host UID 297608. The probe container `smcp-probe-70d992d83833` has main PID 15687 at host UID 299656. Both UIDs are inside smcp-srv's subordinate range (296608 to 362143), and both containers run under the AppArmor label `smcp-server (enforce)`.
- `conmon processes run as: smcp-srv`. No container process or monitor runs as `smcp-core`, root or the runner.

Deviation: none for the narrowed statement. As its rationale states, the Data Access Service, vault and secret broker, evidence exporter, key manager and console run inside `smcpd` as `smcp-core`, not as separate identities.
