# Egress through the broker

How a server instance reaches a network destination through the Egress Broker: attachment at launch, then one brokered operation through a TLS-originating endpoint and one HTTPS tunnel through the forward proxy (E-18; FR-5.36 to FR-5.40, FR-6.6, SR-5.17-1; ARCH §18.6). Grants, limits and every reason code are in the [Egress Broker guide](../egress.md).

```mermaid
sequenceDiagram
  autonumber
  participant L as Launcher (Podman or standalone wrapper)
  participant E18 as E-18 Egress Broker
  participant S as Server instance
  participant DNS as Host resolver
  participant X as Destination
  participant E21 as E-21 Journal

  L->>E18: Attach(server alias)
  E18->>E18: open a forward proxy listener and one endpoint listener per endpoint_env grant on 127.0.0.1
  E18->>E21: egress attached
  E18-->>L: HTTP_PROXY, HTTPS_PROXY, empty NO_PROXY, endpoint URLs
  L->>S: start with those variables (they replace configured ones)
  Note over S,E18: Each tools/call: E-10 asks E-18 for one-use capabilities bound to the call and sends them in _meta local.smcpgw/egress_auth
  Note over S,X: Endpoint request, for example GET $API_URL/v1/items
  S->>E18: plain HTTP to the endpoint listener with Smcp-Egress-Auth
  E18->>E18: current grant for host, port and method, then spend the capability (this instance, this grant, unused)
  E18->>E18: request rate per alias, public-fetch profile
  E18->>E18: strip Cookie, Proxy-Authorization, Smcp-Egress-Auth and hop-by-hop headers
  E18->>E21: egress authorized, committed before any byte is forwarded
  E18->>E18: insert the S1 header bound for this destination
  E18->>DNS: resolve the name
  DNS-->>E18: addresses
  E18->>E18: refuse reserved addresses unless the grant lists them, dial the validated IP
  E18->>X: HTTPS, certificate checked against the system trust store
  X-->>E18: response
  E18->>E18: follow up to 3 redirects to granted HTTPS targets, each checked again
  E18-->>S: response without Set-Cookie, bounded by response_bytes and the byte rate
  E18->>E21: egress completed (or failed with the reason)
  Note over S,X: HTTPS tunnel through the forward proxy
  S->>E18: CONNECT host:443 with Smcp-Egress-Auth
  E18->>E18: grant with CONNECT-TLS, capability, request rate
  E18->>DNS: resolve, then validate addresses
  E18->>X: TCP to the validated IP
  E18-->>S: 200 Connection Established
  S->>E18: TLS ClientHello
  E18->>E18: SNI must equal the CONNECT host
  E18->>E21: egress authorized
  S->>X: TLS bytes relayed, not terminated, bounded by size, time and byte rate
  E18->>E21: egress completed
```

## Implementation

`internal/egress` (`proxy.go`, `dial.go`, `inject.go`, `launcher.go`, `nft_linux.go`), built by `egress.FromConfig` in `app.Start` when `[egress] enabled = true`. A refused operation answers with the reason code in `Smcp-Egress-Reason` and records an `egress` event with phase `denied`. Differences from the specification:

- In the enforced profile the rootless Podman launcher attaches a server with `network = "egress"` and installs the nftables table `inet smcp_egress` in the container's network namespace (slirp4netns with host loopback) before the server starts; the instance reaches the broker at `10.0.2.2`. `TestIntegrationEgressBroker` and the linux-integration job check on real Podman that direct connections are refused and a proxied request succeeds. The standalone wrapper attaches unconfined subprocesses.
- In the standalone profile the proxy variables are advisory: a server that ignores them reaches the network directly.
- Grants come from `[[egress.grant]]` in the configuration, not from policy decision obligations; endpoint variable names come from `endpoint_env`, not from signed manifests.
- One-use capabilities (SR-5.16-1) are minted by the broker when the Tool Dispatcher sends a call (`pipeline.EgressIssuer`) and revoked when the call returns; with `[egress] require_capability = false` they are neither minted nor required.
- A registered secret in the URL, a header or the body of a brokered HTTP request is refused with `EGRESS_SECRET_DETECTED` (SR-5.8-2); the bytes of a CONNECT tunnel are not scanned.
