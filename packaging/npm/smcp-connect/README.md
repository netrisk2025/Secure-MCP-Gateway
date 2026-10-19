# smcp-connect

A stdio MCP server that relays to a Secure MCP Gateway's Remote Access URL. Use it when an agent runs on a computer that is not the Gateway's (a cloud coding sandbox, a vendor VM) and accepts only a command to launch, not a URL.

```
npx smcp-connect --url https://<public name>/mcp
```

Node 18 or later. No dependencies.

On first use it:

1. reads the Gateway's OAuth metadata (the authorization server must be the same origin as the URL);
2. registers itself as a client, which waits until the Gateway operator runs `smcpctl clients approve <client-id>` (it prints the command);
3. prints a sign-in URL and a code on standard error; a Session Approver opens `https://<public name>/oauth/device`, enters the code and approves;
4. stores the tokens in the credential file (mode 0600) and relays standard input and output to the Gateway, refreshing the session at half its lifetime.

```
smcp-connect [login|logout] [--url URL] [--credentials FILE] [--ca FILE] [--client-id ID] [--scope SCOPE] [-v]
```

| Option | Meaning |
|---|---|
| `login` | Sign in and exit |
| `logout` | Remove the stored tokens |
| `--url` | `https://<public name>/mcp` (or `SMCP_URL`) |
| `--credentials` | Credential file (default `$SMCP_CREDENTIALS`, else `$XDG_CONFIG_HOME/smcp/credentials.toml`, else `~/.config/smcp/credentials.toml`) |
| `--ca` | Trust this CA file instead of the system roots |
| `--client-id` | Pre-registered client ID (skips registration); a confidential client's secret comes from `SMCP_CLIENT_SECRET` |
| `--scope` | OAuth scope, for example `smcp:template:remote` |
| `-v` | Log relay failures to standard error |

A credential file readable or writable by other users is refused. The release binary `smcp-connect` behaves the same and uses the same file. Full documentation: `docs/adapters.md` and `docs/remote-access.md` in the Secure MCP Gateway repository.

License: Apache-2.0.
