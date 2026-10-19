# FR-3.25 Real-harness approval acceptance

| Field | Content |
|---|---|
| Requirement or scenario | FR-3.25 |
| Commit | `1391541c07403092c5818faf132c97bfde4f4577` |
| Profile and platform | Standalone; darwin/arm64 (macOS 26.6) |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification task) |
| Method | Demonstration |
| Result | pass |

## Steps

1. Ran `go run ./scripts/agents -approval-acceptance docs/verification/FR-3.25-transcript.md` with `AI_GATEWAY_API_KEY` set, at the commit above (a commit of `main`, checked out with a clean tree). The command builds `smcpd`, `smcpctl` and `smcp-refserver` from the tree, bootstraps a fresh instance on ephemeral ports with `approvals.notify = "off"`, sets `limits.approval_hold = "60s"`, and signs Claude Code in with the OAuth 2.1 code flow as principal `agents-claude-code` on template `conformance`, whose rule `conf-approve` requires approval for `ref_read_file` (`scripts/agents/gateway.go`).
2. Claude Code 2.1.302, the version pinned in `docs/clients/matrix.json` (SRS Appendix K), ran four times over Streamable HTTP with only the Gateway's MCP tools (`--tools ""`), model `anthropic/claude-haiku-5.5` through the Vercel AI Gateway. Each time it was asked to call `ref_read_file` once on its own file in the sandbox. Claude Code asks before every call to a tool marked `anthropic/requiresUserInteraction` (FR-1.50); the driver answered that local prompt with allow through the SDK control protocol (`scripts/agents/streamjson.go`).
3. While each call was held, the driver:
   - case 1: ran `console/e2e/approve-held.mjs`, which signs in to the console as the Administrator in headless Chromium (Playwright 1.64.1), waits for the call to appear in the live pending list of the Approvals view (G-13), opens it, enters a comment and presses "Approve this call";
   - case 2: approved it with `smcpctl approvals approve <id> --yes`;
   - case 3: ran the same browser script and pressed "Deny this call";
   - case 4: did nothing until the hold bound passed.
4. Each case was decided from the journal of the session (approval and call events), and the tool result Claude Code received was read from its stream-json output. After the run `smcpd` was stopped with SIGTERM and `smcpctl journal verify` was run.

## Observations

The full transcript, with prompts, the tool call Claude Code sent, the decision step, the tool result it received, its final reply and the journal events of each case, is [FR-3.25-transcript.md](FR-3.25-transcript.md).

| Case | Outcome in the journal | Text Claude Code received |
|---|---|---|
| 1. Approved from G-13 | approval `requested`, `approved` by `admin:admin`, `consumed`; call `dispatched`, `delivered` (`release`) | the file content `fr325-console-…` |
| 2. Approved with smcpctl | approval `requested`, `approved` by `operator-token`, `consumed`; call `dispatched`, `delivered` (`release`) | the file content `fr325-smcpctl-…` |
| 3. Denied from G-13 | approval `requested`, `denied` by `admin:admin`; call `denied` with `APPROVAL_DENIED`; no `dispatched` event | `approval denied: A person reviewing this call denied it.` (is_error true) |
| 4. Hold bound reached | approval `requested`, still pending; call `denied` with outcome `pending` and `APPROVAL_REQUIRED` 60 s after the request; no `dispatched` event | `approval required: This call needs approval. Open https://127.0.0.1:<port>/approvals/<id> to approve it, then run the same request again.` (is_error true) |

Journal verification after shutdown: `journal OK: 2 segments, 43 events, anchored at segment 2`.

The first run on the same day, before pull request #40, failed case 4: Claude Code received only `approval required`, and in case 3 only `approval denied`. Claude Code shows a failed MCP tool call as the JSON-RPC `error.message` and does not show `error.data`, so the plain-language `data.message` and the `data.approvalUrl` of FR-1.51 never reached the person. Pull request #40 appends `data.message` to `error.message` for approval errors (`harnessVisible` in `internal/edge/pipeline.go`); the run recorded here includes that change, as did a passing run on the pull request branch earlier the same day.

## Deviations

- The Gateway was built from the `main` commit above, not from a release commit; no release of this project has been published yet.
- The hold bound was set to 60 s instead of the CP-45 default of 120 s to keep the run short; CP-45 allows 0 s to 600 s and the behavior at the bound does not depend on its value.
- The model was Claude Haiku 5.5 through the Vercel AI Gateway rather than a default Anthropic login. The model only chooses to call the tool; every outcome above is taken from the journal and from the tool result, not from the model's reply.
