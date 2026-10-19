# Evidence journal verification

How `smcpctl journal verify` checks the Evidence Journal (FR-7.4, FR-7.5, FR-17.8, SR-6.12-1). The journal is a directory of JSON Lines segments `segment-NNNNNN.jsonl`; each starts with a header line, holds event lines and, once closed, ends with a footer carrying the SHA-256 of the segment body and an Ed25519 signature over that hash.

```mermaid
sequenceDiagram
  autonumber
  participant O as Operator
  participant V as smcpctl journal verify
  participant K as Evidence public key
  participant J as Journal directory

  O->>V: journal verify --config smcp.toml
  V->>K: load evidence public key from the state directory
  V->>J: list segment files in number order
  loop each segment
    V->>V: segment numbers are consecutive
    V->>J: read the segment
    V->>V: header names this segment and prev_sha256 equals the SHA-256 of the previous segment file
    alt last line is a footer
      V->>V: SHA-256 of all lines before the footer equals body_sha256
      V->>V: Ed25519 signature over body_sha256 verifies
      V->>V: footer event count equals the number of event lines
      V->>V: remember the SHA-256 of the whole file for the next header
    else no footer
      alt last segment
        V->>V: report it as open (normal while the Gateway runs)
      else not last
        V-->>O: failure, segment not closed
      end
    end
  end
  opt key-transition record (FR-17.8)
    V->>V: verify the transition with the outgoing key, then use the incoming key
  end
  V-->>O: segments, events, open segment, or the first failure
```

## Implementation

`audit.Verify` in `internal/audit` and `smcpctl journal verify` perform every step above. Verification starts from `keys/evidence-genesis.pub` (or `--key`); a segment footer with `next_key` hands the chain to that key after its signature verifies under the outgoing key, and the segment must also hold the `key_rotated` event naming the same key. The anchor records the public key that signed it and must be signed by the key in force for the segment it names or by that segment's next key. A segment left unclosed by a crash is sealed in place and marked `recovered`; `--strict` treats recovered segments and a truncated tail as failures. See [../operations/keys.md](../operations/keys.md).

Limit: replacing the anchor with an older signed copy together with deleting later segments is not detectable locally; set `[evidence] export_dir` to storage off the machine (FR-7.14).
