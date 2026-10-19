# Hermes Agent

Status: configuration generated and unit-tested; the setup it writes has not been run by the matrix job. The real-agent suite (`docs/agents-conformance.md`) ran Hermes Agent 0.17.0 over Streamable HTTP with a pre-issued session token on 2026-10-16 and it passed.

## Connect

```
smcpctl clients setup hermes --dry-run
smcpctl clients setup hermes
```

Adds to `~/.hermes/config.yaml` (only when the file has no `mcp_servers:` section yet; otherwise setup prints the block to add by hand):

```yaml
mcp_servers:
  smcp:
    url: "https://127.0.0.1:8443/mcp"
    auth: oauth
    ssl_verify: "<state>/tls/ca.crt"
```

Hermes signs in with OAuth and PKCE; register its client ID (or allowlisted metadata document) as a `[[client]]`. With `--stdio` the entry is `command: smcp-stdio` instead. For a static header, `export $(smcp-session --env SMCP_AUTHORIZATION)` and use `headers: {Authorization: "${env:SMCP_AUTHORIZATION}"}`; the token then expires with the session's idle timeout.

## Lockdown

Hermes offers no administrator MCP allowlist and no file-tool deny rule (Appendix K). `smcpctl lockdown apply hermes` writes nothing and says so. Hermes stays `gateway-available`.

## Verify

`smcpctl doctor --client hermes` lists the servers in `mcp_servers`, flags those that are not the Gateway, and reports the settings file as writable by Hermes's own tools.
