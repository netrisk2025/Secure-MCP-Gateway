# Skills.md — Requirement Development (INCOSE GtWR + Project Rules)

**Load this skill when** the user asks you to create, derive, refine, decompose, quality-check, or reorganize requirements from one or more source texts.

**Primary references (this directory):**

- `incose_rwg_gtwr_v4_040423_final_drafts.pdf` — INCOSE Guide to Writing Requirements (GtWR) v4
- `Requirements analysis.docx` — orphan / barren (traceability gap) analysis for sets
- `Resource.md` (owner document, not in this repository) — base imperative definitions (SHALL, Should, Will, May)

**Address the user as Boss.**

---

## 0. Binding Outcomes

For every requirement you produce, the finished record **must** include:

| Field | Requirement |
|-------|-------------|
| **ID** | Unique hierarchical ID (see §5) |
| **Statement** | One well-formed requirement sentence (see §2–§3) |
| **Parent ID** | Empty for roots; otherwise the parent’s ID |
| **Verification Method** | Exactly one of: `Inspection`, `Analysis`, `Demonstration`, `Test` |
| **Verification Statement** | One or two sentences describing the procedure that, when performed successfully, shows the requirement statement is satisfied |
| **Source** | Citation or short pointer to the originating text(s) |
| **Rationale** | Brief why this requirement exists (supports C1 Necessary) |

Default deliverable format is **markdown** (see §7). Write to the path the task directs; if none is given, create a clearly named markdown file in the active project workspace.

---

## 1. End-to-End Workflow (do in this order)

```
1. Ingest     → Read all source texts for this task. Extract candidate needs/obligations.
2. Draft ALL  → Write the full candidate set first. Do NOT finalize hierarchy or IDs yet.
3. Quality    → For each candidate: apply §3 tests; revise until it PASSES.
4. Verify     → Assign Verification Method + Verification Statement (§4).
5. Hierarchy  → Order the set and assign/adjust IDs per §5 (MUST on top).
6. Set check  → Apply set characteristics C10–C15 and orphan/barren guidance (§6).
7. Emit       → Write the markdown (or directed format) to the directed location (§7).
```

**Hard rule:** create the complete drafted set before hierarchical ordering and final ID assignment. Draft IDs may be temporary (`T-001` …); replace them in step 5.

---

## 2. How to Formulate a Requirement Statement

### 2.1 Pattern (INCOSE-aligned)

Prefer the structured pattern:

> [When \<condition clause\>,] the \<subject clause\> **SHALL** \<action verb clause\> \<object clause\>[, \<qualifying clause\>].

Rules of thumb:

- Put the obligation on the **system / SOI / software / subsystem** under design — not on the user or operator (“The User shall …” is unacceptable; transform into what the system must do so the need is met).
- Use **active voice**, one main thought per statement.
- Prefer definite articles and defined terms; put glossary terms in a project glossary when needed.
- Include conditions, performance, and interface references when needed for completeness and verifiability.
- Stay **solution-free** at the level you are writing (what/how-well, not premature design) unless the source is already a design constraint.

### 2.2 Imperatives (project definitions)

| Imperative | Meaning | When to use |
|------------|---------|-------------|
| **SHALL** | Binding; implementation is mandatory; correct behavior must be verified | Default for normal requirements |
| **MUST** | Binding security-control *generator* (see §2.3) | Only under the MUST rules below |
| **SHOULD** | Treated as SHALL unless justified omission/deferral is approved | Preferential but not absolute |
| **WILL** | Expected behavior that results from other requirements; no special action | Outcomes / consequential behavior |
| **MAY** | Optional; if employed, treat as SHALL; no justification needed to omit | Truly optional capability |

**Formatting (mandatory):** every imperative appearing in a requirement statement is written in **ALL CAPS** and **bold** in markdown: `**SHALL**`, `**MUST**`, `**WILL**`, `**SHOULD**`, `**MAY**`.

Base definitions also live in the owner's `Resource.md` (not in this repository). Where Resource.md and this skill conflict on **MUST**, **this skill wins**.

### 2.3 Project correction: when to use **MUST** (overrides naive INCOSE “shall-only” habit)

Use **MUST** **only** when **all** of the following are true:

1. The requirement states a **security condition** (confidentiality, integrity, availability, authentication, authorization, privacy/PII/PPI protection, access restriction, cryptographic protection, audit of security-relevant events, etc.).
2. The verification of that condition is **inherently broad or vague at this level** (e.g., “protect,” “guarantee confidentiality,” “restrict unauthorized access,” “verify protect user PPI”) — i.e., it names a security *outcome* that will be satisfied by a **set of security controls**, not a single measurable atomic behavior.
3. The intent is to **generate / parent security controls**: child requirements written with **SHALL** will define the concrete, verifiable controls that realize the MUST.

Examples of appropriate **MUST** parents:

- The System **MUST** protect user PPI.
- The System **MUST** guarantee password confidentiality.
- The Software **MUST** restrict access to files from unauthorized users.

**MUST** requirements sit at the **top of the hierarchy** and, where possible, are **parents of SHALL** control requirements. Do **not** sprinkle MUST through leaf-level measurable controls — those are **SHALL**.

If a security obligation is already atomic and directly verifiable, write it as **SHALL**, not MUST.

### 2.4 Decomposition

When a requirement must be decomposed:

- Parent keeps the broader obligation.
- Children refine functions, conditions, performance, interfaces, or (for MUST parents) the security controls that satisfy it.
- After hierarchy assignment (§5), child IDs extend the parent ID: parent `1` → children `1.1`, `1.2`; child of `1.2` → `1.2.1`; and so on.

---

## 3. Individual Requirement Quality Gate (revise until PASS)

Apply these tests to **each** statement. Fail ⇒ revise and re-test. Do not emit a requirement that fails.

### 3.1 Characteristics (INCOSE C1–C9) — pass/fail tests

| ID | Characteristic | PASS if… | Typical FAIL signals |
|----|----------------|----------|----------------------|
| C1 | Necessary | Removing it leaves a real gap; has rationale and source trace | Gold-plating; intent already covered elsewhere; no source |
| C2 | Appropriate | Detail matches the architectural / organizational level of the subject | Component detail in system set; system goal buried in leaf set |
| C3 | Unambiguous | One shared interpretation for all audiences | Vague adjectives (“secure,” “user-friendly,” “robust,” “adequate”) |
| C4 | Complete | Self-contained enough to implement and verify without guessing | Missing conditions, performance, interface ref, or defined terms |
| C5 | Singular | One thought / one obligation | “and/or” bundles; multiple unrelated verbs |
| C6 | Feasible | Achievable with known constraints (tech, cost, schedule, policy) | Absolutes with no tolerance; known-impossible claims |
| C7 | Verifiable | Can be shown met by Inspection, Analysis, Demonstration, or Test | Subjective acceptance; no observable success criteria |
| C8 | Correct | Accurately reflects source/need/parent intent; no wrong values | Contradicts source; wrong subject; wrong strength |
| C9 | Conforming | Matches this skill’s pattern, imperative rules, and formatting | Missing bold CAPS imperative; wrong MUST/SHALL use; non-pattern sprawl |

### 3.2 High-yield writing rules (INCOSE R-set — enforce these)

Use the full GtWR R1–R42 catalog when stuck; agents **must** enforce at least:

| Rule | Enforce |
|------|---------|
| R1 Structured | Prefer the When/subject/imperative/action/object pattern |
| R2 Active voice | Subject performs the action |
| R3 Appropriate subject-verb | Subject is the entity under design at this level |
| R4 Defined terms | Undefined jargon → define or rephrase |
| R7 No vague terms | Ban unspecified “etc.,” “and so on,” “appropriate,” “as required” |
| R8 No escape clauses | Ban “if possible,” “as a minimum” weasel outs that void verifiability |
| R9 No open-ended lists | Enumerate or reference a controlled list/ICD |
| R16 Careful “not” | Prefer positive requirements; if negation is required, keep it testable |
| R18 Single thought | Split compound sentences into separate requirements |
| R19 No combinators | Avoid “and/or”; split or rewrite |
| R24 No ambiguous pronouns | Replace “it/they/this/that” with the named subject |
| R26 No unverifiable absolutes | Avoid “always/never/all/every” unless truly required and testable |
| R27 Explicit conditions | State triggering conditions in the statement (or clear When-clause) |
| R31 Solution-free (level-appropriate) | Don’t smuggle design unless the source is a design constraint |
| R34 Measurable performance | Quantify when performance is implied |

### 3.3 Revision loop

```
draft → run C1–C9 + R-rules → list FAIL reasons → rewrite → repeat
until all PASS
then proceed to §4
```

Keep a short `Quality Notes` field during drafting if useful; strip or fold into rationale before final emit if the task wants a clean export.

---

## 4. Verification Method and Verification Statement

### 4.1 Methods (choose exactly one)

| Method | Use when verification is primarily… |
|--------|-------------------------------------|
| **Inspection** | Visual / document / static review of artifacts, configuration, code structure, labels, presence of data or settings — without exercising dynamic behavior |
| **Analysis** | Calculation, modeling, proof, review of design evidence, threat/risk analysis, or examination of records — without (or beyond) a live functional exercise |
| **Demonstration** | Showing the required behavior under representative conditions, often qualitative or operational, without full quantitative instrumentation |
| **Test** | Exercising the system with controlled inputs and measured/observed results against quantified or pass/fail criteria |

Select the **least expensive method that still objectively shows compliance**, consistent with INCOSE verifiability guidance. Prefer Inspection or Analysis when they suffice; use Test when measurement or controlled stimulus is required; use Demonstration for observable behavior that is not a metrology exercise.

For **MUST** (security-control parent) requirements, Verification Method is often **Analysis** or **Inspection** of the control set and its evidence; child **SHALL** controls usually take Demonstration or Test.

### 4.2 Verification Statement

Write **one or two sentences** that:

1. Name what will be done (procedure-level, not a full test plan).
2. State what observable result constitutes satisfaction of the **requirement text**.

The procedure, if performed successfully, must be sufficient to claim the requirement is met.

**Good:** “Inspect access-control configuration and authorization logs for a sample of protected files; confirm unauthorized principals receive deny decisions and authorized principals receive allow decisions per the access policy.”

**Bad:** “Verify security.” / “Test the system.”

---

## 5. Hierarchy and ID Assignment (after the full set is drafted)

### 5.1 Ordering rules

1. Place **MUST** requirements at the **top** of the hierarchy (roots or highest security parents).
2. Where possible, make **MUST** items **parents** of the **SHALL** requirements that define the security controls realizing them.
3. Non-security **SHALL** / **SHOULD** / **WILL** / **MAY** trees hang under their functional parents as appropriate.
4. Prefer a clean decomposition tree: each non-root has exactly one primary parent for ID purposes.

### 5.2 ID scheme

- Roots: `1`, `2`, `3`, …
- Children: append `.N` in order — `1.1`, `1.2`, …
- Deeper levels: `1.2.1`, `1.2.2`, `1.2.1.1`, …
- IDs are unique within the emitted set.
- When re-ordering, **renumber** so IDs always reflect the final tree (do not leave gaps that imply missing parents unless Boss directs stable legacy IDs).

### 5.3 Parent linkage

Every requirement records `Parent ID` (empty for roots). Child statements should remain singular and appropriate to their level (C2, C5).

---

## 6. Requirement-Set Checks

After individual PASS and hierarchy assignment, check the **set**:

### 6.1 Set characteristics (INCOSE C10–C15)

| ID | Characteristic | Check |
|----|----------------|-------|
| C10 | Complete (set) | Critical functions, security, interfaces, constraints covered for the scope |
| C11 | Consistent | No contradictions between statements |
| C12 | Feasible (set) | The combination is achievable |
| C13 | Comprehensible | Organized so stakeholders can navigate (hierarchy helps) |
| C14 | Able to be validated | Traceable back to needs/sources for validation intent |
| C15 | Correct (set) | Collectively represents stakeholder/source intent |

### 6.2 Orphan & barren (baron) analysis

Per `Requirements analysis.docx`:

| Gap | Meaning | Action |
|-----|---------|--------|
| **Orphan** | No upstream parent / justifying need | Link to parent/need, reclassify as intentional root, merge, or remove with rationale |
| **Barren** | No downstream children / verification path where one is expected | Decompose, add verification children/artifacts, mark as intentional leaf constraint, or merge/retire |

Do **not** force fake parents onto true roots. Do **not** force decomposition onto intentional leaf constraints or pure performance metrics that should not split further.

Record unresolved orphans/barrens for Boss if they remain after reasonable remediation.

---

## 7. Output Format (default: markdown)

Unless the task specifies otherwise, emit:

```markdown
# Requirements — <title or SOI>

## Metadata
- Generated: <YYYY-MM-DD>
- Sources: <list>
- Skill: `Skills.md` (this repository)

## Requirements

### <ID> — <short name>

| Field | Value |
|-------|-------|
| ID | <ID> |
| Parent ID | <parent or —> |
| Statement | The \<Subject\> **SHALL** … |
| Verification Method | Inspection \| Analysis \| Demonstration \| Test |
| Verification Statement | <one or two sentences> |
| Source | <pointer pointer> |
| Rationale | <brief> |

### <next ID> — …
```

You may also emit a compact table appendix for navigation:

```markdown
## Index

| ID | Parent | Method | Statement (summary) |
|----|--------|--------|---------------------|
| 1 | — | Analysis | … |
| 1.1 | 1 | Test | … |
```

If Boss names another format (CSV, JSON, DOORS-like table, SysML-oriented export), map the same fields.

---

## 8. Navigation Contract (how agents find this skill)

When Boss asks for requirements to be created or refined:

1. Follow the repository `FloorPlan.md`.
2. Use this `Skills.md` for requirement work (only directories relevant to the task).
3. Read this `Skills.md` and apply it to the source text(s) **wherever those texts live**.
4. Place output in the format and directory the task directs (default format: markdown).

Do not skip the quality gate or hierarchy rules to save time.

---

## 9. Quick MUST vs SHALL Decision Tree

```
Is this a security outcome that will be realized by multiple controls,
and is verification still broad at this level?
  YES → write as **MUST** parent; draft SHALL children as controls
  NO  → is it a binding, verifiable obligation?
          YES → **SHALL**
          NO  → SHOULD / WILL / MAY per §2.2
```

---

## 10. Failure Handling

- If source text is too vague to form a verifiable requirement even after analysis: draft the best conforming statement, mark `Needs Boss input`, and list the missing facts (thresholds, subjects, conditions).
- If MUST vs SHALL is unclear: prefer **SHALL** for atomic controls; escalate only genuine security-outcome parents as **MUST**.
- If two sources conflict: keep both candidates, flag inconsistency under set check C11, and ask Boss which governs.
