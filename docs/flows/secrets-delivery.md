# Secret delivery

How the Secret Broker hands a vault secret to a server instance without the harness or the model seeing it: launch-time delivery (S1, S3, S4), per-call delivery (S2), and leak detection on every call (FR-6.4 to FR-6.12; ARCH §8). Configuration, the Secret Use Policy file and every reason code are in the [secrets guide](../secrets.md).

```mermaid
sequenceDiagram
  autonumber
  participant E10 as E-10 Server registry
  participant E20 as E-20 Secret Broker
  participant E19 as E-19 Secret Vault
  participant E18 as E-18 Egress Broker
  participant F as E-09 and E-11 filter chains
  participant S as Server instance
  participant E21 as E-21 Journal

  Note over E10,E20: At launch
  E10->>E20: Resolve(server alias, secret_env)
  E20->>E20: tear down an earlier instance of the alias, check every secret_env has a Secret Use Policy
  E20->>E20: for each launch-time binding check emergency stop, time window, S1 needs an Egress Broker
  E20->>E19: open the bound secret and version
  E19-->>E20: plaintext (age-decrypted)
  E20->>E20: refuse a suspended secret, register HMAC leak fingerprints of the value
  alt S3 per instance
    E20->>E20: write a 0600 file in the instance's 0700 directory under runtime_dir
  else S4 environment (waiver required)
    E20->>E20: value for the slot's environment variable
  else S1 header injection
    E20->>E18: BindHeader(grant, destination, header, template, value)
  end
  E20->>E21: secret_use delivered (no value), committed. On failure the delivery is undone
  E20-->>E10: environment variables (S3 paths, S4 values, S2 paths)
  E10->>S: launch with that environment
  Note over F,S: Each permitted tools/call of the server
  F->>F: secret-vault-args (order 115) blocks arguments that contain a delivered value with SECRET_IN_ARGUMENTS
  F->>E20: secret-delivery-s2 (order 1000) for an S2 binding of this tool
  E20->>E20: purpose, approval obligation, window, rate, suspension checks
  E20->>E19: open the secret
  E20->>E20: write the S2 file at the path given at launch
  E20->>E21: secret_use delivered with the call's correlation and decision IDs
  F->>S: dispatch
  S-->>F: result
  F->>E20: secret-release-s2 (response order 0) deletes the call's S2 file
  F->>F: secret-vault-leak (order 35) withholds a result that contains a delivered value
  F->>E21: secret_use detected and suspended, SECRET_LEAK
  Note over E20,S: Teardown, emergency stop and retirement
  E20->>E18: Withdraw(grant) on instance close or emergency stop
  E20->>E20: at instance teardown overwrite and delete S3 files. S4 cannot be withdrawn
  E20->>E21: secret_use withdrawn
```

## Implementation

`internal/secrets` (`Broker.Resolve`, `deliverLaunch`, `filters.go`, `launcher.go`), enabled by a `[secrets]` table through `secrets.Configure` in `cmd/smcpd`. `app.Start` connects the broker to the Egress Broker as its `pipeline.SecretHeaderInjector` when `[egress] enabled = true`, and registers each delivered value with the E-09/E-11 inspector's fingerprint set. Differences from the specification:

- Secret Use Policies are read from their own file, not from the signed policy document, and slots are declared in that file until signed manifests declare them.
- The S2 file is written at request inspection, which runs before an approval hold, so it exists while a held call waits. It is deleted when the call's context ends, whatever the outcome, with a safety timer as a backstop.
- S1 headers are inserted only on Egress Broker endpoint requests, never on forward-proxy tunnels; sandboxed servers with `network = "egress"` reach the endpoints through the broker as unconfined ones do.
- Launch-time deliveries are not withdrawn when a session ends, because instances are not session-scoped.
- Delivered values are scanned in arguments, results and brokered outbound HTTP requests (`EGRESS_SECRET_DETECTED`, SR-5.8-2); CONNECT tunnels are not scanned.
