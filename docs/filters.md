# Request and response filters

This document describes the Request Inspection Pipeline (E-09), the Response Inspection Pipeline (E-11), the detection rule sets they load and the tool metadata scan. The code is in `internal/filters`; the chain mechanics are in `internal/pipeline`.

## Where the filters run

Every `tools/call` passes through the stages of FR-4.3. Request filters run after the policy decision and before approval and dispatch. Response filters run after the backend answers and before provenance is added and the result is released.

A filter returns one of three actions (FR-4.4):

| Action | Request side | Response side |
|---|---|---|
| `pass` | The arguments continue unchanged | The result continues unchanged |
| `transform` | The arguments are replaced (canonical path or URL, redaction) | The result is replaced (redaction, removed binary content, delimiting) |
| `block` | The call is refused before dispatch with `-31001` and the filter's reason code | The result is withheld with `-31003` and the filter's reason code |

A filter may also report findings without changing anything. Findings name the filter, the rule set and its version, the rule, and the location as a JSON pointer (for example `/content/0/text` or `/opts/path`). Findings never contain the matched text.

A filter that fails, panics or makes its chain exceed the deadline blocks the request or withholds the result (`FILTER_ERROR`, `FILTER_TIMEOUT`; SR-5.10-1). A policy rule that names an unknown filter ID refuses the call with `FILTER_UNAVAILABLE`.

### Release disposition

Each released result carries `_meta["local.smcpgw/provenance"].disposition` (FR-4.11):

- `release`: no response filter changed the content.
- `redact`: a response filter removed or replaced content. Replaced text carries a `[REDACTED:<rule>]` marker; removed binary content is replaced by a text item `[removed by content-type-gate: <type>, <bytes> bytes, <rule>]`; removed invisible characters leave no marker.
- `withhold`: the result is not released; the harness receives `-31003`.

Tag findings (from `injection-detect` and `injection-marker`) are listed in `provenance.tags`. They never change the disposition (FR-4.17).

## Filters

Filters run in the order shown. A mandatory filter runs on every call. Any other filter runs only when the policy rule that permitted the call names it in its `filters` list, for example:

```json
{"id": "web-read", "server": "web", "tools": ["fetch"], "filters": ["pii-detect", "delimit-untrusted"]}
```

The same ID may name a request and a response filter (`size-limit`, `secret-fingerprint`, `unicode-control`, `pii-detect`); naming it in `filters` selects both.

### Request filters (FR-4.5)

| Order | ID | Default | What it does | Block reason |
|---|---|---|---|---|
| 50 | `size-limit` | mandatory | Bounds argument bytes (default CP-07, 1 MiB), nesting depth (default 32) and, when set, the length of any one string | `ARGUMENTS_TOO_LARGE`, `ARGUMENTS_TOO_DEEP`, `ARGUMENTS_INVALID` |
| 100 | `schema-validate` | always mandatory | Validates the arguments against the tool's input schema | `SCHEMA_INVALID` (`-32602`) |
| 110 | `unicode-control` | mandatory | Applies the `unicode-control` rule set to every argument string | `UNICODE_CONTROL` |
| 120 | `secret-fingerprint` | mandatory | Applies the `secret-formats` rule set and the registered secret fingerprints to every argument string (SR-5.8-1) | `SECRET_IN_ARGUMENTS` |
| 125 | `pii-detect` | by obligation | Applies the `pii` data-class rule set to every argument string with each rule's request action (SR-5.8-1); the built-in rules tag | `DATA_CLASS_IN_ARGUMENTS` (a rule with request action `block`) |
| 130 | `path-canonicalize` | mandatory | Canonicalizes path-typed arguments and checks them against the granted roots (SR-1.8-4) | `PATH_INVALID`, `PATH_OUTSIDE_ROOTS` |
| 140 | `url-canonicalize` | mandatory | Canonicalizes URL-typed arguments and checks scheme, host and address (SR-1.8-5) | `URL_INVALID`, `URL_NOT_ALLOWED`, `URL_PRIVATE_ADDRESS` |
| 150 | `injection-detect` | mandatory | Applies the `prompt-injection` rule set to every argument string; tag only | never blocks |

### Response filters (FR-4.6)

| Order | ID | Default | What it does | Withhold reason |
|---|---|---|---|---|
| 10 | `size-limit` | mandatory | Bounds the expanded result size (text, decoded binary data and structured content; default CP-08, 8 MiB) and the structured-content depth (default 32) | `RESULT_TOO_LARGE` |
| 20 | `output-schema` | mandatory | When the tool declares an output schema, withholds a non-error result whose `structuredContent` is missing or does not validate (SR-5.20-2) | `FILTER_BLOCKED` |
| 30 | `content-type-gate` | mandatory | Removes image, audio and binary embedded-resource content unless its MIME type is allowlisted, its magic bytes match and its size is within the bound (SR-5.18-1); removes content types the Gateway does not inspect | never withholds; redacts |
| 40 | `secret-fingerprint` | mandatory | Redacts known credential formats; withholds a result that contains a registered secret fingerprint | `SECRET_LEAK` |
| 50 | `unicode-control` | mandatory | Removes the characters the `unicode-control` rule set flags | never withholds; redacts |
| 60 | `pii-detect` | by obligation | Redacts e-mail addresses, US social security numbers, payment card numbers, North American phone numbers and IBANs | never withholds; redacts |
| 70 | `injection-marker` | mandatory | Applies the `prompt-injection` rule set; tag only | never withholds |
| 90 | `delimit-untrusted` | by obligation | Encloses text items of untrusted tools in nonce delimiters (FR-4.18) | never withholds |

Response filters inspect every surface that reaches the harness (SR-5.9-1): text content, structured content, embedded resource text and URIs, resource-link URIs, names, titles and descriptions, error results (`isError`) and the backend's `_meta`. Backend progress messages (`notifications/progress`) pass the same chain before relay: a blocked message is dropped, a transformed one is relayed as transformed, and each relayed notification carries `_meta["local.smcpgw/provenance"]` with the filters applied and any tags.

### Path-typed and URL-typed arguments

An argument is path-typed when its schema has `"format"` `path`, `file-path`, `filepath`, `directory` or `dir-path`, when it has `"x-smcp-type": "path"`, or when its property name is one of `path`, `paths`, `file`, `files`, `filename`, `filepath`, `file_path`, `dir`, `directory`, `folder`, `cwd`, `root` or ends in `_path`, `path`, `_paths`, `paths`, `_file`, `_dir`, `_directory`, `_folder` or `dir`. Array items inherit their property's type, and nested objects are walked at any depth.

An argument is URL-typed when its schema has `"format"` `uri`, `url`, `iri`, `uri-reference` or `iri-reference`, when it has `"x-smcp-type": "url"`, or when its name is one of `url`, `urls`, `uri`, `uris`, `href`, `link`, `endpoint`, `webhook`, `callback`, `redirect_uri` or ends in `_url`, `url`, `_urls`, `urls`, `_uri`, `uri`, `_href` or `_endpoint`.

Any other `x-smcp-type` value (for example `"x-smcp-type": "text"`) marks the property as neither. `ignore_names` lists property names never treated as paths or URLs; `argument_names` adds names.

`path-canonicalize`:

- refuses a NUL byte, a percent-encoded separator, dot, NUL or percent (`%2f`, `%5c`, `%2e`, `%00`, `%25`), a backslash traversal (`..\`, `\..`), a leading `~` when roots are configured, and a `file:` URL that names a host;
- joins a relative path to the first granted root, resolves `.`, `..` and symbolic links in the longest existing prefix (a dangling link resolves to its target), and requires the result to lie inside a granted root;
- with roots configured, replaces the argument by its canonical form (`rewrite`, default true);
- without roots, refuses a relative path that climbs out of the working directory and changes nothing else.

`url-canonicalize` lower-cases the scheme, percent-decodes the host, converts it to its IDNA A-label form (including full-width digits and letters), removes a trailing dot and the scheme's default port, reads IPv4 literals in decimal, octal, hexadecimal and shortened form, and unmaps IPv4-mapped IPv6. It refuses user information in the URL, control characters, spaces and backslashes. It then checks:

- the scheme is in `schemes` (default `http` and `https`);
- the destination is not loopback, private (RFC 1918, ULA), link-local (including `169.254.169.254`), CGNAT, multicast, unspecified, documentation, benchmarking or NAT64 space, and the name is not `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa` or `*.localdomain`, unless `allow_private = true`;
- the host is not in `deny_hosts` and, when `hosts` is not empty, is in `hosts`. `example.com` matches that host only; `*.example.com` matches its subdomains and not the apex.

The filter does not resolve names. A public name that resolves to a private address is the Egress Broker's concern (E-18).

## Configuration

Every key is optional.

```toml
[filters]
rules_dir = "rules"                     # replace the built-in rule sets (relative to this file)
rule_versions = { prompt-injection = "2026.10.1" }  # pin a version listed in the index
deadline = "2s"                         # CP-14 bound on one chain run
mandatory_request = ["size-limit", "unicode-control", "secret-fingerprint", "path-canonicalize", "url-canonicalize", "injection-detect"]
mandatory_response = ["size-limit", "output-schema", "content-type-gate", "secret-fingerprint", "unicode-control", "injection-marker"]
metadata_scan = true                    # scan tool metadata at import and presentation

[filters.size]
argument_bytes = 1048576                # default [limits] request_body_bytes
argument_depth = 32
string_bytes = 0                        # 0: no separate bound on one string
result_depth = 32                       # the byte bound is [limits] result_bytes

[filters.paths]
roots = ["/home/me/projects"]           # granted roots for every server
server_roots = { fs = ["/home/me/notes"] }  # per server alias; replaces roots for that server
argument_names = []
ignore_names = []
rewrite = true

[filters.urls]
schemes = ["https", "http"]
hosts = []                              # empty: any public host
deny_hosts = []
allow_private = false
argument_names = []
ignore_names = []
rewrite = true

[filters.content_types]
allow = []                              # for example ["image/png", "image/jpeg"]
max_bytes = 1048576
```

`mandatory_request` and `mandatory_response` replace the default lists; a filter left out still runs when a policy rule names it. `schema-validate` is always mandatory. Startup fails when a list names an unknown filter, when `rule_versions` names an unknown rule set or version, when a granted root does not exist or is not absolute, or when a rule-set file does not match its digest.

Content types with a magic-byte check: `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/bmp`, `application/pdf`, `audio/wav`, `audio/x-wav`, `audio/mpeg`, `audio/ogg`, `audio/flac`, `application/zip`, `application/gzip`. An allowlisted type without a signature is still removed, because its bytes cannot be checked.

## Rule sets (FR-4.16)

The rules of `secret-fingerprint`, `injection-detect`, `injection-marker`, `pii-detect`, `unicode-control` and the metadata scan are data files. The built-in files are in `internal/filters/rules/` and compiled into the binary.

| Rule set | Used by | Rules | Version |
|---|---|---|---|
| `unicode-control` | `unicode-control` (both sides), metadata scan | 8 | 2026.10.1 |
| `secret-formats` | `secret-fingerprint` (both sides) | 17 | 2026.10.1 |
| `prompt-injection` | `injection-detect`, `injection-marker` | 11 | 2026.10.1 |
| `pii` | `pii-detect` | 5 | 2026.10.1 |
| `tool-metadata` | metadata scan | 12 | 2026.10.1 |

`index.json` lists every rule-set file with its ID, version, SHA-256 digest, whether it is the active version, its corpus file and its error-rate targets. Several versions of one rule set may be listed; exactly one is active unless `rule_versions` pins another. A file whose digest does not match the index refuses startup.

A rule-set file has `id`, `version`, `description`, optional `normalize` and `rules`. Each rule has an `id`, a `kind`, a `request_action` and a `response_action` (`block`, `redact` or `tag`) and an optional `score` (default 1). Kinds:

| Kind | Fields | Matches |
|---|---|---|
| `regex` | `pattern`, `case_sensitive` | RE2 regular expression, case-insensitive unless `case_sensitive` |
| `luhn` | `pattern` | Pattern matches whose 13 to 19 digits pass the Luhn check |
| `entropy` | `pattern`, `min_length`, `min_classes`, `min_entropy` | Tokens selected by the pattern with at least the given length, character classes (upper, lower, digit, other) and Shannon entropy in bits per character |
| `codepoints` | `ranges`, `permitted_scripts`, `permit_emoji`, `permit_after`, `permit_at_start` | Runs of the listed code points, except where the context is permitted: both neighbours in a permitted script, both neighbours pictographic, the run directly after a listed code point, or the run at the start of the string |

`normalize: true` rule sets match on text that is NFKC-normalized, lower-cased, stripped of format characters and whitespace-collapsed, so full-width letters and zero-width splits do not evade them. Such rules cannot redact.

When a rule set is loaded, each `regex`, `luhn` and `entropy` pattern is analysed for literals of which every match must contain one (a keyword, a token prefix such as `ghp_` or `AKIA`, a marker such as `<|im_start|>`). A scan runs the pattern only when the text contains one of them; for a case-insensitive literal the lookup is made in the ASCII lower-cased text, and a text with any non-ASCII byte runs the pattern regardless (Unicode case folding maps some non-ASCII letters, such as the Kelvin sign, to ASCII ones). A pattern without such a set (character classes only, as in `high-entropy-token`, `payment-card`, `iban`) always runs; one that is a single character class repeated without an upper bound (`high-entropy-token`) is matched by a loop over the text that finds the same runs as the regexp. `codepoints` rules whose ranges hold no ASCII code point pass over ASCII bytes without decoding them, and normalization handles ASCII bytes without decoding them. On the FR-11 reference result (64 KiB of text) this took a scan of all embedded rule sets from about 39 ms to about 5 ms of CPU on an Apple M4 (`BenchmarkRuleSetScan64K`); `TestPrefilterNeverSkipsAMatch`, `TestClassRunMatchesRegexp` and `TestNormalizeTextASCIIPath` check the shortcuts against the regexps and the reference normalization on the corpus, case and Unicode variants and random texts.

The `unicode-control` set flags bidirectional embeddings, overrides and isolates (U+202A to U+202E, U+2066 to U+2069); zero-width space, joiners and invisible operators outside the scripts that use them (Arabic, Indic, Southeast Asian and others) and outside emoji sequences; U+FEFF except at the start; tag characters except in emoji flag sequences; ideographic variation selectors except after Han; interlinear annotations; deprecated format characters; and Hangul fillers outside Hangul. U+200E and U+200F (left-to-right and right-to-left marks) are not flagged.

The `secret-formats` set blocks (arguments) or redacts (results) AWS access keys and secret assignments, GitHub, GitLab, Slack, Stripe live, Google, Anthropic, OpenAI and npm tokens, Slack webhooks, private key headers, JSON Web Tokens and Azure storage keys. Credential-looking assignments and high-entropy tokens are tags only.

### Registered secret fingerprints

`Inspector.Fingerprints().Register(ref, value)` adds the FR-6.10 fingerprints of a delivered secret: keyed HMAC-SHA-256 of the full value and of every 12-character substring of its raw, Base64 (standard and URL, padded and unpadded), hex (lower and upper) and URL-encoded forms. The plaintext is not kept. The Secret Broker (E-20) registers values when it delivers them; until it exists nothing is registered. A match blocks the request (`SECRET_IN_ARGUMENTS`) or withholds the result (`SECRET_LEAK`).

### Changing a rule set

1. `smcpctl filters export --dir /etc/smcp/rules` writes the built-in files.
2. Copy the rule-set file to a new name, change its `version` and its rules.
3. Add an entry for the new file to `index.json` with `shasum -a 256 <file>` as `sha256`; set `active` on the version to use, or pin it with `rule_versions`.
4. Set `[filters] rules_dir` and restart. `smcpctl filters rules --config smcp.toml` shows every version and the one in effect.
5. Measure the new version against its corpus before using it (below).

## Labelled corpora and measured rates (FR-19.5)

Each rule set has a corpus in `internal/filters/testdata/corpus/<rule set>.jsonl`: one JSON object per line with `label` (`positive` or `negative`), `text` and `note`. Secret-shaped samples are split with the marker U+27E8 U+27E9, which the loader removes, so that repository secret scanners do not flag them.

`go test ./internal/filters -run TestCorpusRates -v` measures every rule-set version in the index and prints one `CORPUS` line per version; the test fails when a rate exceeds the target recorded in the index. In CI, `tools/reqreport` collects these lines into the `corpora` array of `status.json` (rule set, version, sample counts, measured rates, targets, and whether the measuring test passed), which the status job publishes on the `site-data` branch. A sample counts as detected when the rule set produces any finding, including tags. For `tool-metadata` a sample is detected when the metadata scan (with `unicode-control`) blocks a tool whose description is the sample.

Measured on 2026-10-16:

| Rule set | Version | Positives | Negatives | False-positive rate | False-negative rate | Target FP | Target FN |
|---|---|---|---|---|---|---|---|
| `unicode-control` | 2026.10.1 | 22 | 30 | 0.000 | 0.000 | 0.000 | 0.000 |
| `secret-formats` | 2026.10.1 | 25 | 30 | 0.033 | 0.000 | 0.050 | 0.000 |
| `prompt-injection` | 2026.10.1 | 30 | 40 | 0.000 | 0.000 | 0.050 | 0.150 |
| `pii` | 2026.10.1 | 12 | 12 | 0.083 | 0.000 | 0.100 | 0.050 |
| `tool-metadata` | 2026.10.1 | 20 | 25 | 0.000 | 0.000 | 0.000 | 0.100 |

These corpora are small and were written together with the rules, so the rates describe the rules against known samples, not against unseen attacks. The known false positives are a publishable Stripe test key tagged by the entropy heuristic and a git remote (`git@github.com:...`) read as an e-mail address. Prompt-injection detection in particular is easy to evade with paraphrase; this is why its findings are tags only.

## Tool metadata scan (SR-5.9-2, FR-1.52)

The scan covers every presented string of a tool: name, title, description, annotation title and, at any depth of the input and output schemas, every `title`, `description`, `enum`, `const`, `default`, `examples` and `$comment` string. It applies:

- the `unicode-control` rules (any match blocks);
- the `tool-metadata` rules (instruction overrides, concealment, exfiltration, `<IMPORTANT>`-style directive tags, covert actions, requests for credential files, smuggling data in side parameters, redefinition or suppression of other tools);
- schema bounds (rule set `schema-bounds`): a `$ref` that is not a local `#` reference, a `$schema` other than JSON Schema 2020-12 or draft-07, nesting deeper than 32, more than 1,000 subschemas, an enum with more than 1,000 members;
- cross-server shadowing (rule set `cross-server-shadowing`): a description that names another server's public tool name, or a distinctive backend tool name (at least five characters containing `_`, `-` or `.`) of another server that this server does not also provide.

At import, a tool with a blocking finding is left out of the server's tool set: it is never registered, presented or callable, and a `server` event with outcome `metadata_blocked`, reason code `METADATA_BLOCKED`, origin `E-14` and `detail.findings` naming each rule, rule set and version is committed to the journal. The other tools of the server are enabled.

Before presentation in a session catalog, the rule sets in effect are applied again, so a rule-set change after import takes effect in new catalogs. A tool blocked at presentation is omitted from the catalog and calls to it fail as an unknown tool; the first block per server revision, tool and rule-set versions is recorded with origin `E-08`.

`metadata_scan = false` turns off both stages.

## Untrusted-content delimiting (FR-4.18)

When the policy rule names `delimit-untrusted`, each text item of a result from a tool whose source trust is not `trusted` is enclosed as:

```
<<<SMCP-UNTRUSTED-BEGIN nonce=<32 hex digits>>>
...text...
<<<SMCP-UNTRUSTED-END nonce=<32 hex digits>>>
```

The nonce is 128 random bits, fresh for each response and shared by the items of one response. Any line in the text that contains `<<<` followed by `SMCP-UNTRUSTED-BEGIN` or `SMCP-UNTRUSTED-END`, in any case or spacing, is removed before enclosing. A tool is trusted only when its definition carries `_meta["local.smcpgw/source_trust"] = "trusted"`, which a verified manifest source sets from the manifest's `source_trust`; tools from the live list are untrusted. Delimiting is framing for agents that honour it; it is not a control on its own and does not change the disposition.

## Evidence

Each chain run appends one journal event (FR-4.7):

| Field | Value |
|---|---|
| `class` | `filter` |
| `origin` | `E-09` (request) or `E-11` (response) |
| `outcome` | `pass`, `transform` or `block` |
| `reason_code` | The blocking filter's reason code, if any |
| `detail.stage` | `request` or `response` |
| `detail.filters` | One entry per filter that ran: `id`, `version` (code version and rule-set version, for example `1.0.0+prompt-injection.2026.10.1`), `action`, `reason_code`, `duration_us`, `findings` |
| `detail.parameters` | Request: `P-043` (highest injection score), `P-044` (unicode-control findings). Response: `P-140` (findings per filter), `P-141` (redacting filters), `P-142` (secret findings), `P-143` (highest injection score), `P-144` (PII findings) |

The event also carries the call's correlation, session, principal, decision, policy revision, server revision and tool revision. Evidence observers (E-29) receive it from the journal fan-out.

## Commands

| Command | Purpose |
|---|---|
| `smcpctl filters rules [--config <file>]` | List every rule-set version with its rule count, digest, targets and whether it is in effect |
| `smcpctl filters export --dir <dir>` | Write the built-in index and rule sets to a directory; existing files are not overwritten |
| `smcpctl filters scan --stage request\|response\|metadata [--config <file>] [--file <file>]` | Run every filter of a stage, including the optional ones, over the input (stdin by default) and print the disposition, each filter's action, timing and findings, and the redacted output as JSON. For `request`, a JSON object is used as the arguments; other input becomes `{"text": ...}`. For `metadata`, the input is a tool definition in JSON or a description. The input itself is never printed |

## Reason codes

| Reason code | Code | Filter |
|---|---|---|
| `ARGUMENTS_INVALID` | `-31001` | `size-limit`, argument filters |
| `ARGUMENTS_TOO_LARGE` | `-31001` | `size-limit` |
| `ARGUMENTS_TOO_DEEP` | `-31001` | `size-limit` |
| `UNICODE_CONTROL` | `-31001` | `unicode-control` |
| `SECRET_IN_ARGUMENTS` | `-31001` | `secret-fingerprint` |
| `PATH_INVALID` | `-31001` | `path-canonicalize` |
| `PATH_OUTSIDE_ROOTS` | `-31001` | `path-canonicalize` |
| `URL_INVALID` | `-31001` | `url-canonicalize` |
| `URL_NOT_ALLOWED` | `-31001` | `url-canonicalize` |
| `URL_PRIVATE_ADDRESS` | `-31001` | `url-canonicalize` |
| `FILTER_UNAVAILABLE` | `-31001` | chain |
| `FILTER_ERROR` | `-31001`, `-31003` | chain |
| `FILTER_TIMEOUT` | `-31001`, `-31003` | chain |
| `RESULT_TOO_LARGE` | `-31003` | `size-limit` |
| `FILTER_BLOCKED` | `-31003` | `output-schema`, any rule with `response_action = "block"` |
| `SECRET_LEAK` | `-31003` | `secret-fingerprint` |
| `REDACTED` | journal only | transforming filters |
| `METADATA_BLOCKED` | journal only | metadata scan |

`data.findings` in the error is a one-line description naming the rule, rule set, version and location.

## Limitations

- A request filter that transforms arguments causes a second policy decision before launch, and the launch is bound to it (SR-5.12-1); argument predicates (FR-3.6) can therefore decide differently on the transformed arguments.
- Request and response scoring (E-31) run as the last filters of their chains. Every filter run emits a span with monotonic time and thread CPU time, stored by the Observation Collector (FR-10.2, [acceptance.md](acceptance.md#stage-timing-spans-fr-102-fr-1011)).
- Relayed progress notifications pass the response chain one message at a time: a blocked message is dropped, a transformed one is relayed as transformed.
- Path-typed and URL-typed arguments are recognized by schema annotations and names. A server that takes a path under another name needs `argument_names` or `"x-smcp-type": "path"` in its manifest schema.
- Suspended tools are recorded by the inspector (`Inspector.Suspended()`), not yet in a registry record that the console can show (E-14).
- The detection corpora are small and written with the rules; see the measured rates above.
