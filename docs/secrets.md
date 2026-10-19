# Secrets: vault and broker

The Secret Vault (E-19) stores the credentials that backend servers need. The Secret Broker (E-20) hands a secret to a server instance only when a Secret Use Policy binds that secret to one of the server's slots, in the delivery mode the policy selects. Harnesses and models never see a secret value: results and arguments that contain a delivered value are refused.

This page covers configuration, the `smcpctl secrets` commands, the Secret Use Policy file, the delivery modes, evidence, reason codes and the current limits. The control API routes are in [api/secrets.md](api/secrets.md).

## How it fits together

1. `smcpctl secrets init` creates the vault: an age X25519 master key and an empty store. The master key is kept in the macOS Keychain or, encrypted under a passphrase, in `<vault>/master.age`. It is never written to disk in plaintext.
2. `smcpctl secrets set` sends a value to the running Gateway over the loopback control API. The vault encrypts it with age to the master key and stores only the ciphertext.
3. The Secret Use Policy file binds a secret to a server slot and selects the delivery mode.
4. When the Gateway launches a server, the broker decides each launch-time binding (S1, S3, S4), delivers the value, records the delivery in the evidence journal and registers leak fingerprints of the value. Per-call bindings (S2) are delivered before each permitted call and deleted when it ends.
5. Every result and every argument list is scanned for the fingerprints of delivered values. A match withholds the result or blocks the call.

## Configuration

Secrets are enabled by a `[secrets]` table in the Gateway configuration. Without the table the Gateway runs without a vault and refuses to start a server that has `secret_env` entries.

```toml
[secrets]
key_source       = "auto"            # auto, keychain or passphrase
passphrase_file  = "vault-pass"      # passphrase key source only; mode 0600 or stricter
use_policy_file  = "secret-use.json" # Secret Use Policy; absent means no bindings
# vault_dir      = "state/vault"     # default <state>/vault
# runtime_dir    = ...               # default: Linux tmpfs, see below
# rotation_overlap = "24h"           # CP-15 default and ceiling
```

| Key | Default | Meaning |
|---|---|---|
| `vault_dir` | `<state.dir>/vault` | Directory of `secrets.json` (the store) and, for the passphrase source, `master.age`. Created with mode 0700; the Gateway refuses to open a store or directory readable by group or others. |
| `key_source` | `auto` | Where `smcpctl secrets init` keeps the master key. `keychain`: a generic password item in the login Keychain (macOS only). `passphrase`: `master.age`, encrypted with age to an scrypt passphrase. `auto` picks `keychain` on macOS and `passphrase` elsewhere. After init the store records the source and the Gateway uses it. |
| `passphrase_file` | none | File holding the vault passphrase, read by `smcpd` to unlock a passphrase vault. Must be mode 0600 or stricter. `smcpctl secrets init` prompts for the passphrase when this key and `--passphrase-file` are both absent. |
| `use_policy_file` | none | The Secret Use Policy file (below). Relative paths are resolved against the configuration directory. |
| `runtime_dir` | Linux: `$XDG_RUNTIME_DIR/smcp-secrets` when it is a tmpfs, else `/dev/shm/smcp-secrets-<uid>`, else `<state.dir>/run/secrets`; macOS: `<state.dir>/run/secrets` | Parent of the instance-private directories that hold S2 and S3 files. Created with mode 0700 and emptied when the Gateway starts. The Gateway logs a warning when it is not a tmpfs. |
| `rotation_overlap` | `24h` | How long the previous version stays deliverable after a rotation. At most `24h` (CP-15). `0` selects the default; use `--overlap 0s` on a rotation to retire the previous version at once. |

The Linux kernel keyring is not used as a key source: its keys do not survive a reboot, so it cannot hold the only copy of the master key. TPM sealing is not implemented.

## Commands

All commands take `--config <file>` (default `smcp.toml`). Every command except `init` talks to the running Gateway's control API with the local operator token. Secret values are read from `--value-file` (mode 0600 or stricter; `-` for standard input), from standard input when it is not a terminal, or from a prompt with confirmation. A value given as `--value` is refused with `secret values are never accepted on the command line`. One trailing newline is removed from a value read from a file or standard input.

| Command | What it does |
|---|---|
| `smcpctl secrets init [--key-source auto\|keychain\|passphrase] [--passphrase-file F]` | Offline. Creates the vault and its master key. Refuses an existing vault. The passphrase must have 12 or more characters. |
| `smcpctl secrets list` | Vault status (vault ID, key source, runtime directory and whether it is a tmpfs, rotation overlap, number of registered fingerprints, suspended secrets), the active Secret Use Policy and the metadata of every secret. |
| `smcpctl secrets show NAME` | Metadata and versions of one secret, and whether it is suspended. |
| `smcpctl secrets set NAME [--type T] [--owner O] [--description D] [--expires RFC3339] [--value-file F]` | Creates a secret as version 1. Types: `api_key`, `token`, `password`, `certificate`, `connection_string`, `generic` (default). Owner defaults to the authenticated actor. Values must have 8 to 32768 bytes. |
| `smcpctl secrets rotate NAME [--overlap D] [--value-file F]` | Stores a new current version. The previous version stays deliverable for `--overlap` (default `rotation_overlap`, at most 24h) and is then retired. |
| `smcpctl secrets rm NAME` | Retires every version (deletes the ciphertext) and deletes the record. |
| `smcpctl secrets impact NAME` | Every Secret Use Policy, server, server revision and slot that references the secret, and whether it is delivered to a running instance (FR-6.12). |
| `smcpctl secrets resume NAME` | Lifts a leak suspension after review. |
| `smcpctl secrets reload` | Validates the Secret Use Policy file and activates it. New S2 deliveries follow it at once; launch-time deliveries change when the server is next launched. |

Names match `^[a-z0-9][a-z0-9._-]{0,63}$`.

## Secret Use Policy

The Secret Use Policy file is JSON, validated against the schema embedded in `internal/secrets/usepolicy.schema.json`. It has a `revision`, the `slots` servers declare and the `policies` that bind secrets to slots.

```json
{
  "revision": "2026-10-16a",
  "slots": [
    {"server": "gh", "name": "token", "modes": ["S1", "S3"], "header": "Authorization", "header_template": "Bearer {secret}",
     "destination": "api.github.com", "file_env": "GITHUB_TOKEN_FILE"},
    {"server": "db", "name": "password", "modes": ["S3"], "file_env": "PGPASSFILE"},
    {"server": "sign", "name": "key", "modes": ["S2"], "file_env": "SIGNING_KEY_FILE"}
  ],
  "policies": [
    {"id": "db-password", "secret": "db-password", "server": "db", "slot": "password", "mode": "S3", "tools": ["*"], "purpose": "database session"},
    {"id": "sign-key", "secret": "signing-key", "server": "sign", "slot": "key", "mode": "S2", "tools": ["sign_release"],
     "purpose": "release signing", "calls_per_minute": 10, "hours": {"start": "08:00", "end": "18:00"}, "approval": true},
    {"id": "legacy", "secret": "legacy-token", "server": "old", "slot": "LEGACY_TOKEN", "mode": "S4", "tools": ["*"], "purpose": "legacy client",
     "s4_waiver": {"approved_by": "admin:alice", "reason": "the server reads only its environment", "expires": "2026-12-31T00:00:00Z"}}
  ]
}
```

### Slots

A slot is what a server declares it can receive. Until signed package manifests (E-13) declare slots, they are declared here. Each `secret_env` entry of a `[[server]]` declares an S4-only slot named after the variable, unless the file declares that slot itself; the policy for such a slot must name the same secret as the `secret_env` entry.

| Field | Meaning |
|---|---|
| `server`, `name` | Server alias and slot name. |
| `modes` | Delivery modes the server supports. A policy may select only one of these. |
| `env` | S4: the environment variable that carries the value. |
| `file_env` | S2 and S3: the environment variable that carries the path of the secret file. |
| `header`, `header_template`, `destination` | S1: the header the Egress Broker inserts, its template (must contain `{secret}`; default `{secret}`) and the only destination it is inserted for. |

### Policies

| Field | Meaning |
|---|---|
| `id` | Unique policy ID, recorded in every secret-use event. |
| `secret` | Secret name in the vault. |
| `version` | Optional pinned version; 0 or absent delivers the current version. A pinned version stops being deliverable when it is retired. |
| `server`, `slot`, `mode` | The binding. One policy per slot. |
| `tools` | Tools the secret is delivered for. Launch-time modes (S1, S3, S4) are bound for the instance lifetime and must use `["*"]`. |
| `destination` | S1 only; must equal the slot's destination. |
| `purpose` | Declared purpose, recorded in events. |
| `session_purpose` | S2 only: deliver only when the session's purpose equals this text. |
| `calls_per_minute` | S2 only: deliveries per minute for this policy. |
| `not_before`, `not_after` | RFC 3339 times outside which nothing is delivered. |
| `hours` | Daily window in the Gateway's local time: `start` and `end` as `HH:MM`; an end before the start spans midnight. |
| `approval` | S2 only: deliver only for calls whose policy decision carries an approval obligation. |
| `s4_waiver` | Required for S4: `approved_by`, `reason` and optional `expires`. |

The file is refused when a policy names an undeclared slot or an unknown server, selects a mode the slot does not support, selects S4 without a waiver or for a slot that supports any other mode (FR-6.9), gives an S1 destination other than the slot's, restricts a launch-time mode to some tools, or binds one slot twice.

## Delivery modes

| Mode | What the server gets | When | Withdrawn |
|---|---|---|---|
| S1 header injection | Nothing. The broker passes the value to the Egress Broker (E-18) through `pipeline.SecretHeaderInjector`, which inserts it on requests to the slot's destination. | At launch | At instance teardown and on emergency stop; rebound on resume |
| S2 per call | The path in `file_env` at launch. The file exists only while a permitted call runs. | Before each call of a bound tool, after request inspection | When the result arrives, and in every case when the call ends |
| S3 per instance | The path in `file_env`; the file holds the value. | At launch | At instance teardown |
| S4 environment | The value in `env`. | At launch | Not possible: the value stays in the process environment until the instance exits |

Secret files are created with mode 0600 inside a per-instance directory with mode 0700 under `runtime_dir`, and are overwritten with zeros before they are deleted. When the sandboxed instance runs under another UID (an auto user namespace, or `[runtime] run_as`), the launcher adds a POSIX ACL entry for exactly that UID to the directory and its files, and later files inherit it ([sandbox.md](sandbox.md), "Environment"); `runtime_dir` then needs a file system with POSIX ACLs, which tmpfs has. When several calls to one server run at once, they share the S2 file; the last one to finish deletes it.

When a version is retired at the end of its rotation overlap, S3 files holding it are rewritten with the current version and S1 grants are rebound, so a rotated secret stops being deliverable at the overlap limit. S4 values cannot be replaced in a running process.

S1 needs the Egress Broker: set `[egress] enabled = true` and give the server a grant with `endpoint_env` for the slot's destination; the server sends its requests to that endpoint and the broker inserts the header (see [egress.md](egress.md)). Without `[egress]`, an S1 binding is denied with `SECRET_MODE_UNAVAILABLE` and the server does not start.

## Leak detection

For every delivered version the broker registers keyed HMAC-SHA-256 fingerprints of the full value and of every 12-byte window of its raw, Base64 (standard and URL-safe, at all three byte alignments), hex (lower and upper case), and URL query- and path-escaped forms (FR-6.10). The HMAC key is random per Gateway process and never stored; the set holds no plaintext. The set implements `pipeline.SecretFingerprints` (`Scan`, `Redact`, `Len`) for other filters and the Observation Collector; `Broker.Fingerprints()` returns it. Each delivered version is also registered with the E-09/E-11 inspector's fingerprint set, so the built-in `secret-fingerprint` request and response filters detect it as well. smcpd registers the set with the Observation Collector (E-29) too: the `observe-request` and `observe-response` probes scan the arguments and the result's text parts (at most 4 MiB), and the observation record's `secret_fingerprint_matches` (P-142) is the larger of the collector's own count and the filter chain's.

The broker registers four mandatory filters:

| Filter ID | Chain | Order | Action |
|---|---|---|---|
| `secret-vault-args` | request | 115 | Blocks a call whose arguments contain a delivered value: `SECRET_IN_ARGUMENTS`. |
| `secret-delivery-s2` | request | 1000 | Delivers S2 secrets for the call; blocks with the denial reason when a delivery is denied. |
| `secret-release-s2` | response | 0 | Deletes the call's S2 files. |
| `secret-vault-leak` | response | 35 | Withholds a result that contains a delivered value: `SECRET_LEAK`, and suspends S2 delivery of that secret until `smcpctl secrets resume`. |

These filters match the vault's own values. The rule-set filters named `secret-fingerprint` in the SRS (FR-4.16) belong to the inspection pipelines; they run after these (orders 120 and 40), so a leak of a delivered value is withheld, suspended and recorded by the broker first; the built-in filter is a second check on the same values.

## Evidence

Every vault change and every secret use is committed to the evidence journal before it takes effect outside the broker. No event contains a value or ciphertext.

| Class | Origin | Outcome | Detail |
|---|---|---|---|
| `secret` | E-19 | `created`, `rotated`, `retired` (reason code `SECRET_RETIRED`), `removed` | `secret_ref`, `name`, `type`, `version`, `previous_version`, `previous_deliverable_until`, `reason`, `actor` |
| `secret_use` | E-20 | `delivered`, `denied`, `withdrawn`, `detected`, `suspended`, `unsuspended` | `secret`, `secret_ref`, `version`, `slot`, `mode`, `server`, `tool`, `use_policy`, `purpose`, `grant_id` |
| `admin` | E-05 | `activated` (`SECRET_USE_POLICY_ACTIVATED`), `rejected` (`SECRET_USE_POLICY_INVALID`) | `actor`, `digest`, `bindings` or `error` |

Secret-use events carry `correlation_id`, `decision_id`, `server_revision` and `policy_revision` (the Secret Use Policy revision). For S2 the correlation and decision IDs are the call's. For launch-time deliveries the correlation ID is shared by all deliveries of one launch, the decision ID identifies the broker's secret-use decision, and `server_revision` is empty at the first launch because the revision is computed from the tool list after the server starts.

If the journal cannot accept an event, nothing is delivered and the vault change is reported as failed.

## Reason codes

| Code | Meaning | What to do |
|---|---|---|
| `SECRET_NOT_GRANTED` | A `secret_env` entry has no Secret Use Policy. | Add a policy for the slot, or remove the entry. |
| `SECRET_NOT_FOUND` | The bound secret is not in the vault. | `smcpctl secrets set NAME`. |
| `SECRET_EXPIRED` | The secret's expiry has passed. | Rotate it and update `--expires`, or create a new one. |
| `SECRET_VERSION_RETIRED` | A pinned version was retired. | Remove or update `version` in the policy. |
| `SECRET_OUTSIDE_WINDOW` | Outside `not_before`, `not_after`, `hours`, or the S4 waiver expired. | Wait for the window or change the policy. |
| `SECRET_MODE_UNAVAILABLE` | S1 without an Egress Broker. | Set `[egress] enabled = true`, or use S3 or S2. |
| `SECRET_RATE_LIMITED` | S2 `calls_per_minute` reached. | Retry later. |
| `SECRET_PURPOSE_MISMATCH` | S2 `session_purpose` differs from the session's purpose. | Sign in with the right purpose. |
| `SECRET_APPROVAL_REQUIRED` | S2 binding requires approval but the decision carries none. | Make the policy rule approval-obligated. |
| `SECRET_SUSPENDED` | A leak of this secret was detected. | Review, rotate if needed, then `smcpctl secrets resume NAME`. |
| `SECRET_NO_INSTANCE` | No running instance prepared the S2 slot. | Check the server started; reload does not add S2 slots to running instances. |
| `SECRET_DELIVERY_FAILED` | Writing the file or binding the header failed. | Check `runtime_dir` permissions and space. |
| `SECRET_UNAVAILABLE` | The value could not be decrypted. | Check the vault files. |
| `EMERGENCY_STOP` | The Gateway is stopped. | `smcpctl resume`. |
| `SECRET_LEAK` | A result contained a delivered value; it was withheld. | Investigate the server. |
| `SECRET_IN_ARGUMENTS` | The call's arguments contained a delivered value; it was blocked. | Investigate the harness session. |

Control API error codes are listed in [api/secrets.md](api/secrets.md).

## Limits

- The master key is held by this element's key sources, not by the Key & Trust Anchor Manager in `internal/keys`; key backup and rotation of the master key are not implemented.
- On macOS there is no tmpfs: S2 and S3 files are on disk in an owner-only directory and are overwritten before deletion, which a journaling or copy-on-write file system may not honor.
- Plaintext is held briefly in Go strings: the S4 environment map, the decoded control API request and the CLI's request body. Byte buffers the broker controls are overwritten after use. Overwriting cannot be guaranteed for strings.
- The vault is protected by file modes for the Gateway's user. The Secret Broker runs inside `smcpd`, so in the Enforced profile the vault is readable by `smcp-core` only; every other CP-46 identity, `smcp-vault` and `smcp-srv` included, is denied (SR-2.13-3, `TestIntegrationVaultIsolation` on the Enforced CI host). The vault and the broker do not run as separate identities.
- In the Standalone profile nothing stops a server from copying an S2 or S3 file or its environment; containment needs the Enforced profile.
- S1 headers are inserted only on Egress Broker endpoint requests; a server that ignores its endpoint variable and connects through the forward proxy does not get the header.
- Session termination does not withdraw launch-time deliveries: instances are not session-scoped yet.
- Fingerprints are registered when a value is delivered, so a value that was never delivered is not detected. The scan runs at about 9 MB/s on an Apple M4.
