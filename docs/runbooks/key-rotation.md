# Runbook: key and certificate rotation

Reference: [../operations/keys.md](../operations/keys.md). Execution records go in `docs/verification/runbooks/` (FR-18.8); the latest is [runbook-key-rotation-2026-10-18.md](../verification/runbooks/runbook-key-rotation-2026-10-18.md). `scripts/ci-integration.sh` rotates all three kinds on every pull request.

## Listener certificate

1. `smcpctl keys rotate tls --config smcp.toml`
2. `smcpctl keys status --config smcp.toml` — `listener_certificate.not_after` is about 90 days ahead.
3. Existing harness sessions continue; no client change is needed.

## Server CA

1. `smcpctl keys rotate ca --overlap 168h --config smcp.toml` — note `switch_at`.
2. Distribute `<state>/tls/ca.crt` (now holding both CAs) to every client before `switch_at` (for example `NODE_EXTRA_CA_CERTS` for Claude Code; see `docs/clients/`).
3. Confirm each client still connects.
4. At `switch_at` the Gateway activates the new CA, or run `smcpctl keys rotate ca --finish --config smcp.toml`.
5. `smcpctl keys status` — `trust_bundle` has one CA and `ca_rotation` is gone. The listeners pick up the listener certificate reissued by the new CA within a second (they check the file at most once per second), so wait a second before checking a client that trusts only the new bundle.

## Evidence-signing key

1. `smcpctl keys rotate evidence --config smcp.toml` — note `public_key`.
2. `smcpctl keys status` — `evidence_public_key` is the new key, `evidence_trust_root` is unchanged.
3. After the next segment closes (or after stopping the Gateway): `smcpctl journal verify --config smcp.toml` — the output counts the evidence-key transitions.
4. Copy `<state>/keys/evidence-genesis.pub` off the machine if it is not there already; it is the trust root for every later verification.
