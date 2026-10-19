# Control API: filter test workbench

Routes of the request and response filters (E-09, E-11) on the control API (admin listener, CP-03), used by the filter test workbench of the Policy Studio (G-02, FR-8.27). They are the control API form of `smcpctl filters rules` and `smcpctl filters scan` ([../filters.md](../filters.md)). Implementation: `internal/filterapi` (routes) and `internal/filters/scan.go`.

The listener's rules apply: loopback TLS, `Host` must name the admin listener, a foreign `Origin` or cross-site `Sec-Fetch-Site` is refused with 403 `origin_refused`, POST bodies must be `application/json` of at most 64 KiB. `GET /api/v1/filters` is open to the Administrator, Operator, Policy Author and Auditor; `POST /api/v1/filters/scan` to the Administrator and Policy Author (Appendix C, see [console.md](console.md#roles)).

Errors have the form `{"error": {"code": "<code>", "message": "<text>"}}`.

## GET /api/v1/filters

The built-in filters of each stage in chain order, the mandatory lists in effect and the loaded rule sets.

```json
{
  "request": ["size-limit", "unicode-control", "secret-fingerprint", "path-canonicalize", "url-canonicalize", "injection-detect"],
  "response": ["size-limit", "output-schema", "content-type-gate", "secret-fingerprint", "unicode-control", "pii-detect", "injection-marker", "delimit-untrusted"],
  "mandatory_request": ["size-limit", "unicode-control", "secret-fingerprint", "path-canonicalize", "url-canonicalize", "injection-detect"],
  "mandatory_response": ["size-limit", "output-schema", "content-type-gate", "secret-fingerprint", "unicode-control", "injection-marker"],
  "rule_sets": [
    {"id": "pii", "version": "2026.10.1", "rules": 9, "in_effect": true, "digest": "…", "false_positive_max": 0.02, "false_negative_max": 0.05}
  ]
}
```

## POST /api/v1/filters/scan

Runs the selected filters of one stage, with the rule sets and limits of the Gateway's `[filters]` configuration, on synthetic input. Nothing is sent to a server and no evidence is written; the input is not a call. The response never echoes the input.

Request:

```json
{"stage": "response", "filters": ["pii-detect"], "input": "mail jane@example.com"}
```

| Field | Meaning |
|---|---|
| `stage` | `request` (input is tool arguments: a JSON object, or text that is wrapped as `{"text": …}`) or `response` (input is the text of a tool result) |
| `filters` | Filter IDs of that stage to run; empty or absent runs every built-in filter of the stage |
| `input` | The synthetic input |

Response 200:

```json
{
  "stage": "response",
  "disposition": "redact",
  "filters": [
    {"id": "pii-detect", "version": "1.0.0+pii.2026.10.1", "action": "transform", "durationUs": 41,
     "findings": [{"rule": "pii-email", "class": "pii", "action": "redact", "path": "/content/0/text"}]}
  ],
  "output": "mail [REDACTED:pii-email]",
  "inputBytes": 21,
  "durationUs": 63,
  "findings": [ … every filter's findings … ]
}
```

`disposition` is `release`, `redact` or `tag` for a response that passes, `withhold` for a refused response, `transform` for request arguments a filter changed and `block` for refused arguments; `reasonCode` and `finding` name the refusal. `output` is the transformed text when a filter changed it. Errors: 400 `bad_request` (unknown field, unknown stage, or a filter that is not of the stage), 500 `filters_unavailable` (the rule sets could not be loaded).
