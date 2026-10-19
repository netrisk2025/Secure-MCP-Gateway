# OpenCode

Status: configuration generated and unit-tested; the setup it writes has not been run by the matrix job. The real-agent suite (`docs/agents-conformance.md`) ran OpenCode 1.15.13 with a remote server on 2026-10-16 and it failed: like the native Claude Code build, it rejects the iPAddress name constraints of the CP-53 local CA ("unsupported name constraint type"). The default `smcp-stdio` configuration avoids this.

## Connect

```
smcpctl clients credentials --client-id <id> --secret-file <file>
smcpctl clients setup opencode --dry-run
smcpctl clients setup opencode
```

Sets `mcp.smcp` in `~/.config/opencode/opencode.json` to a local server running `smcp-stdio`:

```json
{"mcp": {"smcp": {"type": "local", "command": ["smcp-stdio"], "enabled": true}}}
```

`--helper` writes a remote server (`"type": "remote", "url": "https://127.0.0.1:8443/mcp"`) instead; OpenCode then needs `NODE_EXTRA_CA_CERTS` set to the Gateway CA in its environment (to confirm at pinning). `opencode.json` files with comments are refused; edit those by hand.

## Lockdown

No configuration scope that the user and agent cannot write has been confirmed for OpenCode (Appendix K). `smcpctl lockdown apply opencode` writes nothing and says so.

## Verify

`smcpctl doctor --client opencode` lists `mcp` in the global and project `opencode.json` and flags servers that are not the Gateway.
