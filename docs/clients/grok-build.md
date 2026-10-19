# Grok Build (xAI, local CLI)

Status: not run (matrix `not-run`). Its MCP configuration location, session mechanism, lockdown mechanism and CA trust are to be confirmed at pinning (Appendix K).

## Connect

Configure a stdio MCP server in Grok Build whose command is `smcp-stdio` with no arguments, after writing the credential file:

```
smcpctl clients credentials --client-id <id> --secret-file <file>
smcpctl clients setup grok-build      # prints these instructions; changes no files
```

`smcp-stdio` holds the session and trusts the Gateway CA, so Grok Build needs no CA configuration.

## Lockdown

None known. `smcpctl lockdown apply grok-build` writes nothing and says so.

## Verify

`smcpctl doctor --client grok-build` reports that the configuration location is not known, plus the readable-path findings. Check in Grok Build that the `smcp` server lists the Gateway's tools.
