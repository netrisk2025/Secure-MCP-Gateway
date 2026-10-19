// Package conformance holds the MCP protocol conformance suite of FR-12.9
// (tests only). The suite runs a complete Gateway (app.Start, TLS
// listener, journal, policy) over a scripted stdio backend and drives it
// with the message examples of mcp-spec/2026-07-28/schema/examples:
//
//   - every example validates against its schema.json definition;
//   - northbound, the example requests are sent to the Gateway and every
//     response is validated against schema.json (results, errors and
//     stream messages), and unsupported methods are refused with -32601;
//   - southbound, the backend presents the Tool examples and returns the
//     CallToolResult and InputRequiredResult examples, sends the
//     server-initiated request examples and a logging notification during
//     calls, and records what the Gateway sent it, which is validated
//     against the JSON-RPC message definitions.
//
// Every example directory gets a row in the report: what was checked and
// the outcome. Set SMCP_CONFORMANCE_REPORT to a file path to have the
// report written as Markdown (make conformance writes
// build/conformance.md). See docs/icd/x-01-harness-interface.md.
package conformance
