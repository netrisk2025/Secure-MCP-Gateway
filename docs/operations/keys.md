# Certificates and keys

The Key & Trust Anchor Manager (E-22, `internal/keys`) keeps the Gateway's keys as files under the state directory, owned by the Gateway's account with mode 0600 (public certificates and public keys 0644).

| File | Purpose |
|---|---|
| `tls/ca.crt` | Trust bundle: the active server CA first, during a CA rotation also the next CA |
| `tls/ca.key` | Active server CA private key |
| `tls/server.crt`, `tls/server.key` | Listener certificate for the harness and admin listeners |
| `tls/ca-next.crt`, `tls/ca-next.key`, `tls/rotation.json` | Present only during a CA rotation's overlap |
| `tls/retired/ca-<serial>.crt` | CAs replaced by a rotation |
| `keys/evidence.key`, `keys/evidence.pub` | Current evidence-signing key (Ed25519) |
| `keys/evidence-genesis.pub` | Key that signed the first journal segment: the trust root of `smcpctl journal verify` |
| `keys/evidence.key.next` | Present only while an evidence-key rotation is in progress |
| `keys/admin.token` | Local operator token of the control API |
| `keys/installation.id` | Installation ID, asked for by `smcpctl uninstall --purge` |

Deferred from release 1.0 (SRS Appendix N): TPM sealing, macOS Keychain storage and passphrase encryption of key files (FR-7.9), and the client CA of the mTLS Harness Profile (FR-7.15). FR-7.8 lists the key purposes release 1.0 has, each with its rationale; the research pseudonymization keys are kept per dataset by E-32. The vault master key is held in the macOS Keychain or a passphrase-wrapped file (`docs/secrets.md`).

## Lifetimes (CP-53)

| Item | Validity | Renewal |
|---|---|---|
| Server CA | 365 days, path length 0, dNSName name constraints `localhost` and the configured listener host names, no iPAddress constraints (BoringSSL clients such as native Claude Code and OpenCode reject them); the listener certificate names loopback addresses and the listener IP literals | Operator action: `smcpctl keys rotate ca`; health reports `keys_expiring` 30 days ahead |
| Listener certificate | 90 days, never past the CA's expiry | Automatic when 30 days remain: at start and hourly while running |

A listener certificate is issued only for names inside the CA's name constraints (SR-2.8-4). When the configuration names a listener host the CA does not permit, the certificate leaves that name out, `smcpctl keys rotate tls` reports it under `uncovered_names`, and rotating the CA adds it.

## Status

```
smcpctl keys status [--config smcp.toml]
```

Prints `server_ca`, `trust_bundle`, `listener_certificate` (subject, serial, validity, SHA-256, names), `ca_rotation` when one is in progress, `ca_due` and `listener_due` (within 30 days of expiry), `evidence_public_key`, `evidence_trust_root`, `evidence_rotation_pending`, `installation_id` and the key files by purpose.

## Rotation (FR-17.7)

### Listener certificate

```
smcpctl keys rotate tls [--offline]
```

Issues a new listener certificate from the active CA. The listeners re-read the certificate file at most once per second, so new connections get the new certificate without a restart; open connections and sessions continue (sessions are bearer tokens, not TLS state). `--offline` rotates in the state directory while the Gateway is stopped.

### Server CA, with an overlap period

```
smcpctl keys rotate ca [--overlap 168h]     # start: default overlap 7 days
smcpctl keys rotate ca --finish             # end the overlap now
smcpctl keys rotate ca --overlap 0          # replace at once
```

1. Start: a new CA is created and `tls/ca.crt` becomes a bundle of both CAs. The listeners keep presenting the certificate from the outgoing CA, so every client that trusts the outgoing CA keeps connecting. Distribute the new `tls/ca.crt` to every client during the overlap (the client quick starts in `docs/clients/` say where each client reads its CA).
2. Switch: when the overlap ends (checked hourly and at start) or on `--finish`, the new CA becomes active, the listener certificate is reissued from it and the outgoing CA moves to `tls/retired/`. Clients that never imported the new bundle stop connecting at this point.

During the overlap a client that trusts only the new CA does not connect, because the listener still presents the outgoing CA's certificate; give clients the bundle, not the new CA alone. A second rotation is refused (`rotation_in_progress`, HTTP 409) until the first finishes. The overlap is shortened so that it ends before the outgoing CA expires.

### Evidence-signing key

```
smcpctl keys rotate evidence
```

Runs in the Gateway, because the journal writes the transition:

1. The new key is stored as `keys/evidence.key.next`, and `keys/evidence-genesis.pub` is written if missing.
2. The journal appends a `key_rotated` event naming both public keys, closes the open segment with a footer signed by the outgoing key whose `next_key` field names the incoming key (the key-transition record), rewrites the anchor under the incoming key and opens the next segment, signed by the incoming key.
3. The new key replaces `keys/evidence.key` and `keys/evidence.pub`.

If the Gateway stops between steps 2 and 3, the next start finishes the commit; if it stops before step 2, the pending key is discarded. A journal whose last transition names a different key than the one configured refuses to open.

`smcpctl journal verify` starts from `evidence-genesis.pub` and follows each transition record, verifying every segment with the key in force when it was signed (FR-17.8). Altering or removing a transition record fails verification. To verify a copied journal elsewhere: `smcpctl journal verify --dir <journal> --key <evidence-genesis.pub>`.

Every rotation is recorded in the journal as an `admin` event with outcome `key_rotated` and reason `LISTENER_CERT_ROTATED`, `LISTENER_CERT_RENEWED`, `SERVER_CA_ROTATION_STARTED`, `SERVER_CA_ACTIVATED` or `EVIDENCE_KEY_ROTATED`.

## Errors

| Message | Meaning |
|---|---|
| `server CA has expired; rotate it with smcpctl keys rotate ca --overlap 0` | No listener certificate can be issued from an expired CA |
| `name is outside the server CA name constraints` | A certificate was requested for a name the CA does not permit |
| `a server CA rotation is already in its overlap period` | Finish the current rotation first |
| `--offline rotates only tls and ca` | The evidence key is rotated by the running Gateway |
| `the journal's last key-transition record names evidence key ...` | The configured evidence key is not the one the journal handed over to; restore `keys/evidence.key` from a backup |
