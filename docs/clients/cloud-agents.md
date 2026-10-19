# Cloud agents: Grok Bot, ChatGPT, Meta Muse

These agents run on the vendor's computer and cannot reach `127.0.0.1`. They connect through the Remote Access Profile (FR-16, `docs/remote-access.md`). Their own browser, terminal and connector tools are outside the Gateway's control, and the tunnel provider can read the traffic (`docs/security-limitations.md`).

Status: the Remote Access Profile, Dynamic Client Registration with operator approval, the device flow and `smcp-connect` are implemented and tested against a local test tunnel, including the MCP conformance fixtures relayed through `smcp-connect` (`internal/conformance.TestConformanceThroughAdapters`). These agents are documented but not live-tested: live cloud-agent runs were descoped from release 1.x by the owner on 2026-10-18, because the project holds no vendor account for them. Every cloud entry in `matrix.json` is `not-run`, with the date it was last reviewed and the reason (FR-15.9).

Vendor allowlist settings (FR-16.10) were checked on 2026-10-18 against the vendors' public documentation; vendor administration consoles were not reachable. Where the public documentation names no setting, the line below says so and lists what was reviewed.

## Common setup

1. Configure `[remote]` (`docs/remote-access.md`): at least `default_principal` (a principal for cloud agents) and `templates` (the templates a remote session may use; keep them narrow), and mark the same templates `remote_allowed` in that principal's Framework Profile in the policy (`smcpctl policy publish`).
2. Enable remote access with a tunnel, as the Gateway's user:

   ```
   smcpctl remote enable --provider tailscale          # https://<machine>.<tailnet>.ts.net
   smcpctl remote check
   ```

   Use `--provider cloudflare` for a Cloudflare quick tunnel (new random `trycloudflare.com` name on every start, no uptime guarantee) or `--provider manual --public-url https://<name>` for a tunnel you run yourself, including a vendor's MCP tunnel.
3. Add `https://<public name>/mcp` as an MCP server or connector in the agent.
4. The agent registers itself; approve it: `smcpctl clients list --status pending`, then `smcpctl clients approve <client-id>`.
5. Sign in as a Session Approver on the page the agent opens (it says the request came through the tunnel).
6. When finished: `smcpctl remote disable` (ends remote sessions and stops the tunnel).

If the agent accepts only a command to run (a cloud coding sandbox), run `npx smcp-connect --url https://<public name>/mcp` there; it registers, waits for your approval, prints a device code to enter at `https://<public name>/oauth/device`, and then relays (`docs/adapters.md`).

## Grok Bot (xAI)

- Connection: remote MCP URL through the tunnel, or `smcp-connect` where the agent accepts only a command.
- Registration: Dynamic Client Registration with operator approval, or a pre-registered client listed in `remote.clients`.
- Vendor allowlist (FR-16.10): no setting confirmed in xAI's public documentation (checked 2026-10-18). xAI's Remote MCP Tools documentation describes a server URL and an `allowed_tools` filter set per request, not an administrator restriction of the agent's MCP servers. A third-party guide describes a team MCP allowlist on a Grok team plugins page ("Disabled by team admin"); no xAI documentation of it was found. Treat it as not offered until confirmed. Sources reviewed: https://docs.x.ai/developers/tools/remote-mcp, https://composio.dev/blog/how-to-add-mcp-servers-to-grok-bot.
- Matrix: `not-run` (reviewed 2026-10-18; live runs descoped from release 1.x).

## ChatGPT agent "dots" and ChatGPT custom connectors (OpenAI)

- Connection: add a custom connector (MCP server URL) `https://<public name>/mcp`. ChatGPT connects from OpenAI's servers through the tunnel; OpenAI's own MCP tunnel, where offered, is used with `--provider manual` (or `vendor`) and its public URL.
- Registration: Dynamic Client Registration with operator approval (the connector registers when added), or a pre-registered client.
- Vendor allowlist (FR-16.10): no setting that limits connectors to one URL confirmed in OpenAI's public documentation (checked 2026-10-18). OpenAI's help article "Plugins in ChatGPT" could not be retrieved (HTTP 403); its search excerpt and third-party administrator guides describe workspace controls that limit who adds a connector rather than which URL: on Business plans only admins and owners create and publish apps for custom MCP servers, on Enterprise and Edu role-based access control grants the permission to create custom MCP connections and apps are off by default, and the workspace directory sets which actions of a published app are allowed. The nearest restriction to the Gateway URL is to publish only the Gateway's app and not grant members the create permission. Connectors were renamed apps in December 2025. Sources reviewed: https://help.openai.com/en/articles/12584461-plugins-in-chatgpt (search excerpt), https://support.fyxer.com/article/admin-setup-guide-how-to-enable-apps-and-mcp-connectors-in-chatgpt, https://developers.pleo.io/docs/current/pleo-mcp/how-tos/enablement/chatgpt.
- Matrix: `not-run` (reviewed 2026-10-18; live runs descoped from release 1.x).

## Meta Muse (Meta)

- Connection: remote MCP URL through the tunnel, or `smcp-connect`.
- Registration: to be confirmed; both Dynamic Client Registration and pre-registered clients are supported by the Gateway.
- Vendor allowlist (FR-16.10): no setting found in Meta's public documentation (checked 2026-10-18). Meta's developer MCP documentation covers Meta's own platform integrations, not Muse; third-party guides place Muse custom connectors under Settings, Connectors, with no administrator restriction described. Treat it as not offered. Sources reviewed: https://developers.facebook.com/documentation/mcp, https://anythingmcp.com/de/guides/clients/muse, https://parallel.ai/articles/best-mcp-servers-for-meta-muse.
- Matrix: `not-run` (reviewed 2026-10-18; live runs descoped from release 1.x).

## Limitations

- Per-address limits use the address the tunnel reports; it is recorded as `server-asserted`.
- A remote session's template must be marked `remote_allowed` in the Framework Profile and listed in `remote.templates` (FR-16.12, `docs/remote-access.md`).
- The tunnel must preserve the public `Host` header; `smcpctl remote check` reports a tunnel that does not.
