# Tool-call approvals

This guide covers the Approval Service (E-07): how a call that needs a person's approval is held, how approvers learn about it and decide, and how the harness sees each outcome. It implements SRS FR-3.14 to FR-3.24, FR-1.50, FR-1.51 and SR-1.18-2. The control API routes are in [api/approvals.md](api/approvals.md); the sequence is in [flows/approval-hold.md](flows/approval-hold.md).

## When a call needs approval

A policy rule with `"approval": true` puts an approval obligation on the tools it grants. Those tools are presented to the harness with `_meta["anthropic/requiresUserInteraction"] = true` and `_meta["local.smcpgw/approvalRequired"] = true` (FR-1.50); Claude Code then also asks the person before each call. The hint is presentation only. The Gateway still decides every call itself.

When such a call arrives the Gateway:

1. Runs the decision and request inspection as for any call.
2. Computes the canonical argument digest: the arguments after request filters, with object keys sorted and insignificant whitespace removed, hashed with SHA-256 (`sha256:<hex>`).
3. Looks for an approval bound to the same session, principal, server, backend tool, public tool name, server revision, tool revision, policy revision and argument digest (SR-1.18-2).
   - An approved, unexpired, unused approval is consumed and the call continues (FR-3.15).
   - A pending one is reused: the call waits on it.
   - Otherwise a new pending approval is created, recorded in the evidence journal and announced to approvers.
4. Holds the call for up to `limits.approval_hold` (CP-45, default 120 s) while sending keep-alives every `approvals.keepalive` (default 10 s).

An approval can be used once. It expires `approvals.lifetime` (CP-17, default and maximum 5 minutes) after it was requested, whether or not it was approved.

## What the harness sees

| Outcome | Harness result | Reason code |
|---|---|---|
| Approved during the hold | The tool result, as the response to the original request (FR-3.20) | none |
| Denied during the hold | Error `-31001`, `data.message` "A person reviewing this call denied it." (FR-3.21) | `APPROVAL_DENIED` |
| Hold bound reached | Error `-31002` with `data.approvalId`, `data.expiresAt`, `data.approvalUrl` and `data.message` "This call needs approval. Open <approvalUrl> to approve it, then run the same request again." (FR-3.22) | `APPROVAL_REQUIRED` |
| Approval expired while held | Error `-31002`; run the request again to ask for a new approval | `APPROVAL_EXPIRED` |
| An identical concurrent call used the approval first | Error `-31002`; run the request again | `APPROVAL_CONSUMED` |
| The approval service failed (for example, the journal could not record the request) | Error `-31002`; the call is refused | `APPROVAL_UNAVAILABLE` |
| Retry of the same request after approval | The tool result, without a hold | none |

For these approval errors the JSON-RPC `error.message` is the short name followed by `data.message`, for example `approval required: This call needs approval. Open <approvalUrl> to approve it, then run the same request again.` Claude Code 2.1.302 shows a failed tool call as `error.message` only, so without this the person would not see the explanation or the approval link. The FR-3.25 run in [verification/FR-3.25.md](verification/FR-3.25.md) records what Claude Code shows for each outcome.

`data.retry` and `data.consoleUrl` repeat `data.message` and `data.approvalUrl` for clients written against the first slice.

### Keep-alives and the response format

The MCP endpoint answers in JSON. A `tools/call` request is answered as `text/event-stream` only once it is held, so that keep-alives can reach the harness while a person decides (FR-3.19):

- When the request carries a progress token (`params._meta.progressToken`), each keep-alive is a `notifications/progress` message on the request's stream.
- Otherwise each keep-alive is an SSE comment line, `: keep-alive Waiting for a person to approve this call (approval <id>). Open <url>`, which clients ignore.

The first keep-alive is sent as soon as the call is held. A call that is not held (no approval obligation, or an approved retry) is still answered as `application/json`.

### Approval status for the harness

`GET /smcp/v1/approvals/{id}` on the harness listener, with the session's bearer token, returns the state of an approval that this session created (FR-3.16). Any other session receives 404; a missing or invalid token receives 401.

```json
{"approvalId": "01a1...", "state": "pending", "expiresAt": "2026-10-16T23:51:04Z", "approvalUrl": "https://127.0.0.1:8444/approvals/01a1..."}
```

States are `pending`, `approved`, `denied`, `expired` and `consumed`.

## Who can decide

| Account | Configured in | Can decide tool-call approvals |
|---|---|---|
| Administrator (operator token or administrator sign-in) | `[admin]`, `keys/admin.token` | Yes |
| Approver | `[[approvals.account]]` | Yes, and nothing else on the control API |
| Session Approver | `[[approver]]` | No. Session Approvers approve harness sign-ins only (SRS Appendix C) |

Approver accounts sign in at `POST /api/v1/approvals/login` (or `smcpctl approvals --user <name>`) and receive a 30-minute bearer token. That token reaches only the `/api/v1/approvals` routes; every other control API route answers 403 `role_refused` and records `ADMIN_ROLE_REFUSED` in the journal. Harness session tokens are never accepted on the control API.

Create an Approver account by hashing a password and adding it to the configuration:

```
smcpctl hash-password --password-file alice.pw
```

```toml
[[approvals.account]]
username = "alice"
password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
```

Restart `smcpd` after changing accounts.

## Commands

All commands take `--config <file>` (default `smcp.toml`). Without `--user` they use the local operator token from the state directory, which acts as the Administrator. With `--user <name>` they sign in as that Approver account and read the password from `--password-file <file>` (mode 0600 or stricter; `-` for standard input) or a prompt.

| Command | What it does |
|---|---|
| `smcpctl approvals` or `smcpctl approvals list [--state pending\|approved\|denied\|expired\|consumed\|all] [--json]` | Lists approvals, newest first (default: pending) |
| `smcpctl approvals show <id> [--json]` | Prints the evidence of one approval: public tool name, server and backend tool, server and tool revisions, manifest source, policy revision, decisive rules, anomaly evidence, session, principal, template, times, decision, argument digest, console URL and the canonical arguments (FR-3.18) |
| `smcpctl approvals approve <id> [--comment text] [--yes]` | Prints the evidence, asks `Approve this call? [y/N]` unless `--yes`, then approves |
| `smcpctl approvals deny <id> [--comment text] [--yes]` | As `approve`, then denies |
| `smcpctl approvals watch [--max-events n]` | Prints the pending approvals, then one line per event (`requested`, `approved`, `denied`, `expired`, `consumed`) until interrupted or until `n` events |

Each decision is recorded with the deciding actor (`operator-token`, `admin:<user>` or `approver:<user>`), the time and the optional comment (FR-3.17). A decision on an approval that is no longer pending fails with `not_pending` and the current state.

## Notifications

Within 2 seconds of creating an approval the service sends (FR-3.23):

- an `approval` event with type `requested` on every open watch stream (`smcpctl approvals watch`, the console's Approvals view);
- an OS desktop notification whose text is only the public tool name, the server alias, the approval ID and the console URL. Argument values are never put in a notification, because notification centers keep and display them outside the Gateway.

| `approvals.notify` | Notifier |
|---|---|
| `auto` (default) | macOS: `terminal-notifier` when installed, otherwise `osascript`; Linux: `notify-send`; other systems: none |
| `off` | No desktop notification |
| `osascript`, `terminal-notifier`, `notify-send` | That program |
| `command` | `approvals.notify_command`, run with two arguments: the title and the body |

A missing or failing notifier never affects the approval: the service writes the diagnostic log warning `desktop notification failed; the approval is unaffected` and continues. Each notification is bounded to 5 seconds.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `limits.approval_hold` | `120s` | CP-45 hold bound, `0s` to `600s`; `0s` disables holding and answers `-31002` at once |
| `approvals.lifetime` | `5m` | CP-17 approval lifetime, at most `5m` |
| `approvals.keepalive` | `10s` | CP-45 keep-alive interval |
| `approvals.notify` | `auto` | Desktop notifier (see above) |
| `approvals.notify_command` | none | Program for `notify = "command"` |
| `approvals.console_url` | the control API URL | Base of approval links: `<console_url>/approvals/<id>` |
| `[[approvals.account]]` `username`, `password_hash` | none | Approver accounts (Argon2id hash) |

`smcpd` refuses to start when `approvals.lifetime` exceeds 5 minutes, `approvals.notify` names an unknown notifier, `notify = "command"` has no `notify_command`, or two accounts share a username.

## Records and evidence

Approval records are kept in `<state>/approvals/<id>.json` (mode 0600), written atomically, and reloaded when `smcpd` starts, so an approval granted after a restart can still be consumed by a retry. Records that are decided, expired or consumed are removed 24 hours after their expiry; the journal keeps the evidence.

Every state change is committed to the evidence journal before it takes effect. Events have class `approval`, origin `E-07` and these outcomes:

| Outcome | Reason code | Detail |
|---|---|---|
| `requested` | `APPROVAL_REQUESTED` | approval ID, public tool name, server, backend tool, argument digest, expiry, hold bound |
| `approved` | `APPROVAL_GRANTED` | as above plus `approver`, `comment`, `decided_at` |
| `denied` | `APPROVAL_DENIED` | as above plus `approver`, `comment`, `decided_at` |
| `expired` | `APPROVAL_EXPIRED` | as above plus `previous_state` |
| `consumed` | `APPROVAL_CONSUMED` | as above plus `consumed_correlation_id`, `approver` |

When the call arrived on the Remote Access listener, the record has `channel = "remote"`, `client_id` and `client_address`, and every approval event of it, including the decision and consumption, carries the same remote-origin fields as the call's own events (FR-16.8).

Argument values are not written to the journal; only their digest is. If the journal cannot record a request or a decision, the request is refused (`APPROVAL_UNAVAILABLE`) or the decision fails (`audit_unavailable`) and nothing changes. Approver sign-ins are recorded as `APPROVER_SIGNIN` and failures as `APPROVER_SIGNIN_FAILED`.

## Limitations

- Anomaly-band approvals (E-31, `require_approval_band`) carry the band, the contributing feature, its z-score, the baseline snapshot and the context on the approval record (`anomaly` in `GET /api/v1/approvals/{id}`), and G-13 shows them (FR-3.18). Session-taint approvals (`TAINT_APPROVAL`) carry no anomaly evidence.
- The console's Approvals view (G-13) is served by the console element; this service provides its data through `/api/v1/approvals` and the watch stream.
- Which roles reach the approval routes follows the Appendix C role matrix (`internal/adminapi/rolematrix.go`).
- The real-harness acceptance run with Claude Code (FR-3.25) is recorded in [verification/FR-3.25.md](verification/FR-3.25.md).
