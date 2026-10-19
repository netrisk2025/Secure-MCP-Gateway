# SRS build sources

`Secure_MCP_Gateway_SRS.md` is generated from these files. Edit the sources here, not the generated SRS, and commit the regenerated SRS together with the sources.

| File | Contents |
|---|---|
| `front.md` | Document control, purpose, scope, profiles, conventions, technology stack (Sections 1–3) |
| `req1.txt` … `req4.txt` | Functional requirements FR-1 … FR-19 |
| `req5.txt` | Security requirements (SR) and SEC dispositions (`@DISP`) |
| `appendix.md` | Appendices A–D (controlled parameters, error and reason codes, roles, graph data model) |
| `appendix2.md` | Appendices J–M (manifest schema summary, client matrix, hostile fixture suite, acceptance scenario mapping), emitted after the generated appendices |
| `gen.py` | Validator and generator; also produces Appendices E–I |

Record format: `@ID | Title`, then `P:` parent, `S:` statement, `A:` allocation (`;`-separated E/F/X/I/D IDs), `V:` `Method | statement`, `SRC:` sources, `R:` rationale, optionally `DEFER:` with the reason the requirement is deferred from release 1.0 (SRS Section 2.7: the record moves to Appendix N and leaves the requirement set and the requirement report), followed by a blank line. `TEXT:` lines and `#` headings between records are copied into the output.

Build (from the project directory):

```
python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md
```

The build fails on any traceability error and prints warnings for coverage gaps against `ArchitectureV2.md` and `MCP_Gateway_Security_SRS.md`. It also fails when:

- `front.md`, `appendix.md` or `appendix2.md` names an FR, SR or CP ID that does not exist;
- `docs/parameters.json` lacks a parameter ID defined in `ArchitectureV2.md` §10.3 or an attribute of FR-10.37;
- `docs/schemas/manifest.schema.json` is not valid JSON;
- `docs/status/elements.json` lacks an element E-01 … E-33 or uses an implementation value other than `implemented`, `partial` or `not-started`.

Controlled parameters are recognized from the `| CP-nn |` rows of `appendix.md`; adding a row makes the ID available to requirements.
