# Control API: egress

Routes of the Egress Broker (E-18) on the control API (admin listener, CP-03). They use the control API's authentication (`Authorization: Bearer <operator token or administrator session token>`), host, origin and `Sec-Fetch-Site` checks; a request without valid authentication gets `401` and an `auth_failure` journal event. All routes are read-only `GET`s.

When `[egress] enabled` is false every route answers:

```
404 Not Found
{"error": {"code": "egress_disabled", "message": "the Egress Broker is not enabled; set [egress] enabled = true"}}
```

The command-line equivalents are `smcpctl egress status`, `grants` and `connections` ([../egress.md](../egress.md)).

## GET /api/v1/egress

Broker limits and attached instances.

```json
{
  "enabled": true,
  "enforced_instances": 0,
  "advisory_instances": 1,
  "require_capability": true,
  "instances": [
    {
      "id": "01a1471f-b8ee-7530-ac2d-96e06687f437",
      "server": "web",
      "enforced": false,
      "proxy": "http://127.0.0.1:52314",
      "endpoints": {"API_URL": "http://127.0.0.1:52315"},
      "attached_at": "2026-10-16T23:50:22.104Z"
    }
  ],
  "limits": {
    "request_bytes": 1048576,
    "response_bytes": 8388608,
    "operation_timeout": "30s",
    "dial_timeout": "10s",
    "requests_per_minute": 60,
    "bytes_per_minute": 67108864
  }
}
```

`enforced` is true when nftables rules confine the instance's network namespace to its listeners; false means the proxy variables are advisory (standalone profile). `require_capability` is true when every operation needs a one-use capability of the current call (`[egress] require_capability`, SR-5.16-1).

## GET /api/v1/egress/grants

Query: `server` (optional) limits the list to one server alias.

```json
{
  "grants": [
    {
      "server": "web",
      "host": "api.example.com",
      "ports": [443],
      "methods": ["GET", "CONNECT-TLS"],
      "class": "api",
      "addresses": ["10.0.0.5"],
      "endpoint_env": "API_URL",
      "request_bytes": 1048576,
      "response_bytes": 8388608,
      "timeout": "30s"
    }
  ]
}
```

`request_bytes`, `response_bytes` and `timeout` are the effective limits: the smaller of the broker limit and the grant's own. `addresses` and `endpoint_env` are omitted when empty.

## GET /api/v1/egress/connections

Recent operation records, newest first, from an in-memory ring of `[egress] recent_records` entries (the journal holds all of them).

Query parameters, all optional:

| Parameter | Meaning |
|---|---|
| `server` | Only this server alias |
| `decision` | `allowed` or `denied` |
| `since` | RFC 3339 time; only records at or after it |
| `limit` | 1 to 10000, default 100 |

```json
{
  "connections": [
    {
      "id": "01a1471f-b8f1-7a3c-9e1d-3c1b2f0e8a55",
      "time": "2026-10-16T23:50:23.412Z",
      "instance": "01a1471f-b8ee-7530-ac2d-96e06687f437",
      "server": "web",
      "mode": "connect",
      "method": "CONNECT-TLS",
      "host": "api.example.com",
      "port": 443,
      "sni": "api.example.com",
      "grant": "api.example.com",
      "resolved": ["93.184.216.34"],
      "address": "93.184.216.34",
      "address_class": "public",
      "capability": "consumed",
      "correlation_id": "01a1471f-b8ef-7d10-9a2b-5c6d7e8f9a01",
      "decision_id": "01a1471f-b8ef-7d11-8b3c-6d7e8f9a0b12",
      "policy_revision": "r-2026-10-16",
      "decision": "allowed",
      "bytes_up": 1834,
      "bytes_down": 6120,
      "duration_ms": 212
    },
    {
      "id": "01a1471f-b8f0-71d2-8f4e-0d5b6a7c8e90",
      "time": "2026-10-16T23:50:23.101Z",
      "instance": "01a1471f-b8ee-7530-ac2d-96e06687f437",
      "server": "web",
      "mode": "http",
      "method": "GET",
      "host": "10.0.0.1",
      "port": 80,
      "path": "/",
      "decision": "denied",
      "reason": "EGRESS_NO_GRANT",
      "detail": "10.0.0.1:80 is not an egress destination of server web",
      "status": 403,
      "bytes_up": 0,
      "bytes_down": 0,
      "duration_ms": 0
    }
  ]
}
```

Fields are described under Evidence in [../egress.md](../egress.md). Errors:

| Status | `error.code` | Cause |
|---|---|---|
| 400 | `bad_limit` | `limit` is not an integer from 1 to 10000 |
| 400 | `bad_since` | `since` is not an RFC 3339 time |
