# Goose

Status: configuration generated and unit-tested; the setup it writes has not been run by the matrix job. The real-agent suite (`docs/agents-conformance.md`) ran Goose 1.55.0 over Streamable HTTP with a pre-issued session token on 2026-10-16 and it passed.

## Connect

```
smcpctl clients credentials --client-id <id> --secret-file <file>
smcpctl clients setup goose --dry-run
smcpctl clients setup goose
```

Adds a stdio extension to `~/.config/goose/config.yaml` (only when the file has no `extensions:` section yet; otherwise setup prints the block):

```yaml
extensions:
  smcp:
    name: smcp
    type: stdio
    cmd: smcp-stdio
    args: []
    enabled: true
    timeout: 300
```

## Lockdown

`smcpctl lockdown apply goose` writes `~/.config/smcp/goose-allowlist.yaml` listing only `smcp-stdio`. Set `GOOSE_ALLOWLIST=~/.config/smcp/goose-allowlist.yaml` in the environment Goose starts from; Goose checks the allowlist when an extension is installed. The mechanism comes from a guide not confirmed as Block's own and is to be confirmed at pinning.

## Verify

`smcpctl doctor --client goose` lists `extensions` and flags any extension whose command is not a Gateway adapter (built-in extensions are listed too).
