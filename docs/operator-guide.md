# Operator guide

Day-2 operation of a running Gateway (SRS FR-18.4): accounts and roles, approvals, sessions, policy publication, servers and packages, secrets, emergency stop, backups, keys, configuration reload, logs and metrics, upgrades and remote access. Each section gives the commands and links to the reference document with every option, configuration key and error.

Every `smcpctl` command takes `--config <file>` (default `smcp.toml` in the current directory). Commands that talk to the running Gateway authenticate to the control API with the operator token in `<state>/keys/admin.token`, which acts as the Administrator; keep that file readable only by you.

The console serves the same functions in a browser at the control API address (default `https://127.0.0.1:8444/`). Sign in as the Administrator or as an Approver. See [console.md](console.md).

## Accounts and roles

| Role | Account | Configured in | Can |
|---|---|---|---|
| Administrator | `admin` (password) or the operator token | `[admin]`, `<state>/keys/admin.token` | Everything on the control API and console |
| Approver | `[[approvals.account]]` | `smcp.toml` | Decide tool-call approvals; nothing else |
| Session Approver | `[[approver]]` | `smcp.toml` | Approve harness sign-ins in the browser; nothing on the control API |
| Harness principal | `[[principal]]` with `[[client]]` registrations | `smcp.toml` | Open sessions and call the tools its template permits; no control-plane access |

The roles follow SRS Appendix C. Operator, Policy Author, Auditor and Researcher accounts are configured in `[[console.account]]` and sign in to the console and the control API; each route admits the roles of the Appendix C matrix (`internal/adminapi/rolematrix.go`, listed per operation in `GET /api/v1/openapi.json`). See [console.md](console.md).

Add an Approver or Session Approver by hashing a password and adding the entry:

```sh
smcpctl hash-password --password-file alice.pw
```

```toml
[[approvals.account]]          # an Approver
username = "alice"
password_hash = "$argon2id$..."

[[approver]]                   # a Session Approver
username = "bob"
password_hash = "$argon2id$..."
```

Restart `smcpd` after changing accounts. Set the Administrator password after a `--bootstrap-token` bootstrap with `smcpctl admin redeem`.

## Approvals

A policy rule with `"approval": true` (or a taint or anomaly obligation) holds the call for up to `limits.approval_hold` (default 120 s) while an Approver decides. Approval is bound to the exact session, tool revision, arguments and policy revision, and is used once.

```sh
smcpctl approvals                          # pending approvals
smcpctl approvals show <id>                # the bound request: tool, revisions, rules, arguments
smcpctl approvals approve <id> [--comment text] [--yes]
smcpctl approvals deny <id> [--comment text] [--yes]
smcpctl approvals watch                    # follow new approvals
smcpctl approvals --user alice --password-file alice.pw   # as an Approver instead of the token
```

The console's Approvals view (`/approvals`) does the same, and an OS desktop notification names the tool, server, approval ID and console link (`[approvals] notify`, `off` to disable). Reference: [approvals.md](approvals.md).

## Sessions and clients

Sessions are listed and terminated in the console (Sessions view, `/sessions`) or through `GET /api/v1/sessions` and `POST /api/v1/sessions/{id}/terminate` ([api/console.md](api/console.md)). Terminating a session refuses its token at once. Sessions are held in memory and end when `smcpd` restarts.

Local harness clients are `[[client]]` entries bound to a `[[principal]]`; a principal's `profile` names a framework profile in the policy, which lists the templates its sessions may use. Configure a client's own files with `smcpctl clients setup <client>` and check them with `smcpctl doctor` ([harness.md](harness.md), [clients/](clients/README.md)).

A client that identifies itself by a Client ID Metadata Document URL can be allowed without listing its redirect URIs: add the exact HTTPS URL to the CP-52 allowlist with the principal it binds to.

```toml
[[client_metadata]]
url = "https://agent.example/oauth/client.json"
principal = "cc"
```

The Gateway fetches the document when the client first authorizes and caches it for 24 hours. The fetch has a 5 s timeout and a 64 KiB limit, follows redirects only on the same host, and connects only to public addresses. The document's `client_id` must equal the URL, it must list `redirect_uris`, and its `token_endpoint_auth_method` must be `none` or absent. A metadata URL that is not on the allowlist is refused without a fetch. A client ID is bound to one principal; the same ID in `[[client]]` and `[[client_metadata]]` is a configuration error.

The harness listener closes connections beyond 128 at accept and answers `429` with `-31005` `QUEUE_FULL` when 32 requests are already being read or authenticated (CP-09). Requests whose headers or body do not arrive within 5 s or 15 s are closed (CP-06, CP-07).

## Policy

The active policy is a signed revision in the Policy Store, not the file. Edit `policy.json` (with a new `revision` ID), then:

```sh
smcpctl policy validate policy.json         # offline schema check
smcpctl policy diff policy.json             # against the active revision
smcpctl policy simulate policy.json         # replay recent journal calls; prints a simulation ID
smcpctl policy publish policy.json --parent <active rev> --simulation <id>
smcpctl policy history
smcpctl policy rollback <rev>               # publishes <rev>'s content as a new revision
```

`smcpctl policy reload` publishes the configured `[policy] file` in one step. Activation is atomic and sends `notifications/tools/list_changed` to clients with an open listen stream. Reference: [policy-reference.md](policy-reference.md); runbook: [runbooks/policy-rollback.md](runbooks/policy-rollback.md).

## Servers and packages

Backends are signed packages. To admit a server: build it from a recipe, sign it, enroll the signing key as a trust anchor, install it into the library and enable it.

```sh
smcpctl package keygen --out mykey
smcpctl trust add mykey.pub --name mykey --key-id <ID printed by keygen> --classes low,moderate
smcpctl package build --recipe recipe.json --out pkg
smcpctl package sign pkg --key mykey.key
smcpctl package install pkg --enable --alias fs
smcpctl package list
```

Then reference it from a `[[server]]` entry (`package = "<server id>"`) and restart `smcpd`; a revision enabled while the Gateway runs is launched at the next start. Suspend or withdraw a revision with `smcpctl package disable|retire <id>@<rev>`, or with a signed revocation (`smcpctl package revoke <id>@<rev> --key <file>`), which tears the instance down at once. The Gateway itself suspends a revision whose live tool list drifts from its manifest or whose artifact changed. Reference: [packaging-guide.md](packaging-guide.md); runbook: [runbooks/revocation.md](runbooks/revocation.md).

A `[[server]]` entry may name a `command` instead of a package (unless `[packages] require_signed` is set). The command must be an absolute path and may not be a package runner or installer (`npx`, `uvx`, `pip`, ...; SR-3.6-1). At its first launch the Gateway records the SHA-256 of the command file and of every argument that names a file by absolute path (`artifact_recorded` in the journal), and refuses a relaunch after any of them changed, suspending the server instead. `command_sha256 = "<hex>"` pins the command file in the configuration, so a different file is refused even at the first launch. Modules an interpreter loads from its search path are not covered; package such servers.

`smcpctl servers list|show <alias>` shows each server's registry state, and `smcpctl servers suspended-tools` lists the tools the import-time metadata scan suspended, with the blocking rules (SR-5.9-2).

On the Enforced profile each instance runs in a rootless Podman sandbox: `smcpctl runtime status|instances|show <id>|kill <id>` ([sandbox.md](sandbox.md)). Network access goes only through the Egress Broker's grants: `smcpctl egress status|grants|connections` ([egress.md](egress.md)).

## Secrets

Secrets live in an age-encrypted vault whose master key is in the macOS Keychain or wrapped by a passphrase. Values are never accepted on the command line.

```sh
smcpctl secrets init                        # once, offline
smcpctl secrets set github-token --value-file token.txt
smcpctl secrets rotate github-token --value-file new.txt   # old version stays valid for the overlap
smcpctl secrets list
smcpctl secrets impact github-token         # which servers and slots use it
smcpctl secrets resume github-token         # after reviewing a leak suspension
smcpctl secrets reload                      # activate a changed Secret Use Policy file
```

Enable the vault with the `[secrets]` table; the Secret Use Policy file binds each secret to a server slot and delivery mode. Reference: [secrets.md](secrets.md).

## Emergency stop

```sh
smcpctl stop --reason "<why>"
smcpctl resume
```

Stop refuses every tool call with `-31004 EMERGENCY_STOP` until resumed, records who stopped and why, and withdraws S1 and S2 secret deliveries. The console has Stop and Resume in its status bar. Runbook: [runbooks/emergency-stop.md](runbooks/emergency-stop.md).

## Health

```sh
smcpctl health                         # state, causes, profile, release label
smcpctl health ack <cause>             # acknowledge a latched integrity cause
```

States are `healthy`, `degraded` and `fail-closed`. The Standalone profile is always at least `degraded: unconfined`. A critical cause refuses calls with `FAIL_CLOSED` until it has been clear for 10 s and, for integrity causes, acknowledged. Reference: [operations/health.md](operations/health.md).

## Backups and restore

```sh
smcpctl backup --passphrase-file backup.pass        # or --recipient age1...
smcpctl backup --list
smcpctl restore --archive <file> --passphrase-file backup.pass --verify-only
smcpctl restore --archive <file> --passphrase-file backup.pass   # Gateway stopped
```

A backup holds the configuration, the policy file and the state directory (journal, keys, CA, Policy Store, package library, vault), encrypted with age, with a manifest of checksums; `smcpctl backup` against a running Gateway pauses dispatch briefly to take a consistent copy. The archive contains private keys: keep the passphrase or age identity apart from it. Copy archives off the machine, and set `[evidence] export_dir` to storage off the machine so journal segments leave it within 60 s. Reference: [operations/backup.md](operations/backup.md); runbook: [runbooks/backup-restore.md](runbooks/backup-restore.md).

## Keys and certificates

```sh
smcpctl keys status
smcpctl keys rotate tls                         # listener certificate (90-day lifetime)
smcpctl keys rotate ca --overlap 168h           # server CA, with a period where both are trusted
smcpctl keys rotate evidence                    # evidence-signing key, with a signed transition
```

Keep `<state>/keys/evidence-genesis.pub` off the machine: it is the trust root for every later `smcpctl journal verify`. Reference: [operations/keys.md](operations/keys.md); runbooks: [key rotation](runbooks/key-rotation.md), [key compromise](runbooks/key-compromise.md).

## Configuration reload, logs and metrics

```sh
smcpctl config validate                 # offline
smcpctl reload                          # or kill -HUP <smcpd pid>
```

An invalid file is refused and the running configuration stays. `log.level` and `limits.principal_calls_per_minute` apply at once; other keys are reported as needing a restart. The diagnostic log is `<state>/log/smcpd.log` (JSON Lines, rotated at 10 MiB, 5 files, sensitive attribute names redacted); it is not evidence. `[metrics] enabled = true` serves Prometheus metrics on `127.0.0.1:9464/metrics`. Reference: [operations/logging-metrics-reload.md](operations/logging-metrics-reload.md).

## Evidence

```sh
smcpctl journal verify [--strict]       # hash chain, signatures, key transitions, anchor
smcpctl journal export --to <dir>       # copy closed segments and the anchor
```

The console's Audit view (`/audit`) browses, filters, exports (CSV, JSON Lines) and verifies the journal. With `[graph] enabled` the journal is mirrored into Neo4j for investigation queries (`smcpctl graph status|query|neighborhood|rebuild`, [graph.md](graph.md)). Observation records, baselines and anomaly scores are under `smcpctl observe` ([observation.md](observation.md)).

## Upgrade and removal

```sh
smcpctl upgrade --release <dir with the downloaded release files> --passphrase-file backup.pass
smcpctl uninstall [--purge]
```

The upgrade verifies the release's minisign signature and archive checksum, takes a backup, swaps binaries, migrates the configuration, waits for health and rolls back automatically on failure. Reference: [install.md](install.md#upgrade-and-rollback), [operations/upgrade-uninstall.md](operations/upgrade-uninstall.md); runbook: [runbooks/upgrade-rollback.md](runbooks/upgrade-rollback.md).

## Remote access for cloud agents

Cloud agents (Grok Bot, ChatGPT agent, Meta Muse) reach the Gateway through an authenticated tunnel to a second loopback listener:

```sh
smcpctl remote enable --provider tailscale      # or cloudflare, or manual --public-url
smcpctl remote check
smcpctl clients list --status pending           # registrations waiting for approval
smcpctl clients approve <client-id> --principal <id>
smcpctl clients revoke <client-id>              # ends its sessions
smcpctl remote disable
```

Remote sessions are limited to the templates in `[remote] templates`, last at most 2 h, and are rate limited per client. The tunnel provider can read the traffic. Reference: [remote-access.md](remote-access.md), [clients/cloud-agents.md](clients/cloud-agents.md).

## Runbooks

| Situation | Runbook |
|---|---|
| Stop all tool execution now | [runbooks/emergency-stop.md](runbooks/emergency-stop.md) |
| A server package must be withdrawn | [runbooks/revocation.md](runbooks/revocation.md) |
| A published policy is wrong | [runbooks/policy-rollback.md](runbooks/policy-rollback.md) |
| A key or the operator token may be exposed | [runbooks/key-compromise.md](runbooks/key-compromise.md) |
| Back up or restore | [runbooks/backup-restore.md](runbooks/backup-restore.md) |
| Rotate keys on schedule | [runbooks/key-rotation.md](runbooks/key-rotation.md) |
| An upgrade failed | [runbooks/upgrade-rollback.md](runbooks/upgrade-rollback.md) |
