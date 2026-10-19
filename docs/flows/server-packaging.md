# Server packaging and admission

How an operator admits a local MCP server without an external curation system (FR-14, SR-3-1 to SR-3.10-1, SR-3.5-1, SR-5.9-2; ARCH §18.1). Packaging is the only step that contacts a package registry.

The flow is drawn in two parts. Step numbers run on from one part to the next.

## 1. Build and sign (steps 1–11)

```mermaid
sequenceDiagram
  autonumber
  participant O as Operator
  participant PK as smcpctl package (F-96)
  participant R as Package registry (X-17)
  participant S as Candidate server (throwaway run)
  participant L as Library directory

  O->>PK: package build with type, name, exact version, digest, classification
  PK->>PK: refuse ranges, dist-tags and missing digests
  PK->>R: fetch artifact
  R-->>PK: tarball, wheel, image or binary
  PK->>PK: verify digest, store under SHA-256
  PK->>S: start once, empty directory, no secrets, no network (Enforced)
  PK->>S: era probe, then tools/list
  S-->>PK: tools
  PK->>PK: write manifest.json (Appendix J) and provenance.json
  O->>PK: package sign with minisign key from file or prompt
  PK->>L: index.json, index.json.minisig, manifest, provenance, artifact
```

## 2. Import and enable (steps 12–19)

```mermaid
sequenceDiagram
  autonumber 12
  participant L as Library directory
  participant E13 as E-13 Trust Verifier
  participant E22 as E-22 Trust anchors
  participant E14 as E-14 Registry
  participant E21 as E-21 Journal
  participant E24 as E-24 Console or CLI
  participant O as Operator

  E13->>L: scan library (interval or on command)
  E13->>E22: anchor for the signer, scope includes the risk class?
  E13->>E13: verify signature, digests, schema, provenance, revocations, metadata rule set
  E13->>E14: register immutable revision as verified-disabled
  E13->>E21: import receipt event
  O->>E24: enable revision (Administrator)
  E24->>E14: verified-disabled to enabled
  E14->>E21: enablement event
  Note over E14: Standalone profile: a high risk class is refused at this step (SR-4-1)
  Note over E14: At each launch E-13 re-verifies the artifact digest (SR-3-2). A changed tool list at run time suspends the revision (SR-3.8-1)
```

## Implementation

Implemented in `internal/packaging` (formats, build, probe, minisign signing and verification, trust anchors) and `internal/library` (verifier, registry, run-time manifest source, control API routes); the operator procedure is the [packaging guide](../packaging-guide.md). Differences from the diagram:

- Only the directory library is scanned; there is no OCI registry library (FR-5.1).
- The probe runs with the host network in the Standalone profile; network removal needs a confining launcher (E-16).
- Enabling is done by `smcpctl package enable`, `POST /api/v1/packages/{id}/{revision}/enable` or **Enable** in the console view G-10 (Servers and library). A revision enabled while `smcpd` runs is launched at the next start.
- Instances are torn down by the backend registry (`Registry.Suspend`); there is no separate E-15 instance manager.
- `smcpctl bootstrap` packages the bundled `smcp-refserver`, signs it with a one-time key enrolled for the `low` class, and writes it as the example's only backend (FR-14.10).
