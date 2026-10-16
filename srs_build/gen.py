#!/usr/bin/env python3
"""Assemble Secure_MCP_Gateway_SRS.md from requirement sources and validate traceability."""
import re, sys, collections, pathlib

HERE = pathlib.Path(__file__).parent
PROJ = pathlib.Path(sys.argv[1])
OUT = pathlib.Path(sys.argv[2])
SEC_FILE = PROJ / "MCP_Gateway_Security_SRS.md"
ARCH_FILE = PROJ / "ArchitectureV2.md"
errors, warnings = [], []

# ---------- security SRS ----------
sec = {}
t = SEC_FILE.read_text()
for m in re.finditer(r'^### ([\d.]+) — (.*?)\n.*?\| Statement \| (.*?) \|', t, re.S | re.M):
    sid, name, stmt = m.group(1), m.group(2).strip(), m.group(3)
    imp = "MUST" if "**MUST**" in stmt else "SHALL"
    sec[sid] = dict(name=name, stmt=stmt, imp=imp)
sec_children = collections.defaultdict(list)
for sid in sec:
    if "." in sid:
        sec_children[sid.rsplit(".", 1)[0]].append(sid)

# ---------- architecture IDs ----------
a = ARCH_FILE.read_text()
arch = {k: set(re.findall(rf'\b{k}-\d\d\b', a)) for k in ["E", "F", "I", "X", "G", "D", "P"]}
enames = dict(re.findall(r'^#### (E-\d\d) (.*?) — T', a, re.M))
fnames = dict(re.findall(r'^\| (F-\d\d) \| ([^|]+?) \|', a, re.M))

# ---------- requirement sources ----------
items = []  # sequence of ("md", text) / ("req", dict) / ("disp", dict)
reqs, disps = collections.OrderedDict(), {}
for fn in sorted(HERE.glob("req*.txt")):
    cur = None
    for raw in fn.read_text().splitlines() + [""]:
        line = raw.rstrip()
        if line.startswith("@DISP "):
            sid, txt = line[6:].split(" | ", 1)
            disps[sid.replace("SEC-", "")] = txt
            continue
        if line.startswith("@"):
            rid, title = line[1:].split(" | ", 1)
            cur = dict(id=rid.strip(), title=title.strip(), file=fn.name)
            continue
        if cur is not None:
            if not line:
                if cur["id"] in reqs:
                    errors.append(f"duplicate id {cur['id']}")
                reqs[cur["id"]] = cur
                items.append(("req", cur))
                cur = None
                continue
            key, _, val = line.partition(": ")
            cur[{"P": "parent", "S": "stmt", "A": "alloc", "V": "ver", "SRC": "src", "R": "rat"}[key]] = val.strip()
            continue
        if line.startswith("TEXT: "):
            items.append(("md", line[6:] + "\n"))
        elif line.startswith("#"):
            items.append(("md", line + "\n"))

# ---------- validation ----------
FIELDS = ["parent", "stmt", "alloc", "ver", "src", "rat"]
for r in reqs.values():
    for f in FIELDS:
        if f not in r:
            errors.append(f"{r['id']}: missing {f}")
    if "stmt" in r and "SHALL" not in r["stmt"]:
        errors.append(f"{r['id']}: no SHALL")
    if "stmt" in r and re.search(r'\bMUST\b', r["stmt"]):
        errors.append(f"{r['id']}: MUST used as imperative")
    meth, _, vst = r.get("ver", "").partition(" | ")
    if meth not in ("Inspection", "Analysis", "Demonstration", "Test") or not vst:
        errors.append(f"{r['id']}: bad verification '{r.get('ver')}'")
    r["method"], r["vstmt"] = meth, vst
    p = r.get("parent", "")
    if r["id"].startswith("FR-"):
        exp = "—" if r["id"].count(".") == 0 else r["id"].rsplit(".", 1)[0]
        if p != exp:
            errors.append(f"{r['id']}: parent {p} expected {exp}")
        if p != "—" and p not in reqs:
            errors.append(f"{r['id']}: parent {p} missing")
    elif r["id"].startswith("SR-"):
        m = re.fullmatch(r'SR-([\d.]+)-(\d+)', r["id"])
        if not m:
            errors.append(f"{r['id']}: bad SR id")
        elif p != f"SEC-{m.group(1)}":
            errors.append(f"{r['id']}: parent {p} mismatch")
        sid = p.replace("SEC-", "")
        if sid not in sec:
            errors.append(f"{r['id']}: parent {p} not in security SRS")
        elif sec[sid]["imp"] != "MUST":
            errors.append(f"{r['id']}: parent {p} is not a MUST")
    else:
        errors.append(f"{r['id']}: unknown id class")
    al = r.get("alloc", "")
    toks = [x.strip() for x in al.split(";")]
    r["alloc_ids"] = toks
    for tok in toks:
        k = tok.split("-")[0]
        if k not in ("E", "F", "I", "X", "D") or tok not in arch[k]:
            errors.append(f"{r['id']}: allocation {tok} not in ArchitectureV2")
    if not any(x.startswith("E-") for x in toks):
        errors.append(f"{r['id']}: no element allocation")
    body = " ".join(r.get(f, "") for f in FIELDS)
    for ref in re.findall(r'\b(?:FR|SR)-[\d.]+(?:-\d+)?\b', body):
        ref = ref.rstrip(".")
        if ref not in reqs and ref != r["id"]:
            errors.append(f"{r['id']}: references unknown {ref}")
    for cp in re.findall(r'\bCP-(\d\d)\b', body):
        if not 1 <= int(cp) <= 43:
            errors.append(f"{r['id']}: unknown CP-{cp}")
    for g in re.findall(r'\bG-\d\d\b', body):
        if g not in arch["G"]:
            errors.append(f"{r['id']}: unknown {g}")
    for pp in re.findall(r'\bP-\d{3}\b', body):
        pass
for sid in disps:
    if sid not in sec:
        errors.append(f"disposition for unknown SEC-{sid}")

# ---------- coverage ----------
sr_by_parent = collections.defaultdict(list)
for r in reqs.values():
    if r["id"].startswith("SR-"):
        sr_by_parent[r["parent"].replace("SEC-", "")].append(r["id"])
cited = collections.defaultdict(list)
for r in reqs.values():
    for sid in re.findall(r'SEC (\d+(?:\.\d+)?)\b', r.get("src", "")):
        cited[sid].append(r["id"])

def sec_status(sid):
    s = sec[sid]
    kids = sec_children.get(sid, [])
    if sr_by_parent.get(sid):
        return "Realized by SR"
    if sid in disps:
        return "Disposition"
    if s["imp"] == "MUST" and kids:
        return "Decomposed in SEC"
    if s["imp"] == "SHALL" and cited.get(sid):
        return "Source of FR"
    if s["imp"] == "SHALL" and kids:
        return "Decomposed in SEC"
    return "GAP"

gaps = [sid for sid in sec if sec_status(sid) == "GAP"]
for sid in gaps:
    warnings.append(f"SEC {sid} has no SR, disposition or citing FR")

alloc_count = collections.Counter()
for r in reqs.values():
    for tok in r["alloc_ids"]:
        alloc_count[tok] += 1
gmention = collections.Counter()
for r in reqs.values():
    for g in set(re.findall(r'\bG-\d\d\b', r["stmt"] + r["title"])):
        gmention[g] += 1
CONTEXT_ONLY = {"X-02"}  # outside the SoI by definition (ARCH §6.1)
arch_gaps = {k: sorted(x for x in arch[k] if alloc_count[x] == 0 and x not in CONTEXT_ONLY) for k in ["E", "F", "I", "X", "D"]}
arch_gaps["G"] = sorted(x for x in arch["G"] if gmention[x] == 0)
for k, v in arch_gaps.items():
    for x in v:
        warnings.append(f"architecture {x} has no allocated requirement")

if errors:
    print("ERRORS:\n" + "\n".join(errors))
    sys.exit(1)

# ---------- render ----------
def bold(s):
    return re.sub(r'\b(SHALL|MUST|SHOULD|MAY|WILL)\b', r'**\1**', s)

def esc(s):
    return s.replace("|", "\\|")

def alloc_fmt(toks):
    groups = collections.OrderedDict((k, []) for k in ["E", "F", "X", "I", "D"])
    for t in toks:
        groups[t.split("-")[0]].append(t)
    out = []
    lab = {"E": "Elements", "F": "Functions", "X": "External interfaces", "I": "Internal interfaces", "D": "Data stores"}
    for k, v in groups.items():
        if v:
            if k == "E":
                v = [f"{x} {enames.get(x, '')}".strip() for x in v]
            out.append(f"{lab[k]}: " + ", ".join(v))
    return "; ".join(out)

def parent_fmt(r):
    p = r["parent"]
    if p == "—":
        return "— (root)"
    if p.startswith("SEC-"):
        s = sec[p[4:]]
        return f"{p} — {s['name']} (MUST, `MCP_Gateway_Security_SRS.md`)"
    return f"{p} — {reqs[p]['title']}"

out = [(HERE / "front.md").read_text().rstrip() + "\n\n"]
for kind, obj in items:
    if kind == "md":
        out.append(obj + "\n")
        continue
    r = obj
    out.append(f"#### {r['id']} — {r['title']}\n\n| Field | Value |\n|---|---|\n")
    out.append(f"| ID | {r['id']} |\n| Parent ID | {esc(parent_fmt(r))} |\n")
    out.append(f"| Statement | {esc(bold(r['stmt']))} |\n| Allocation | {esc(alloc_fmt(r['alloc_ids']))} |\n")
    out.append(f"| Verification Method | {r['method']} |\n| Verification Statement | {esc(r['vstmt'])} |\n")
    out.append(f"| Source | {esc(r['src'])} |\n| Rationale | {esc(r['rat'])} |\n\n")

out.append((HERE / "appendix.md").read_text().rstrip() + "\n\n")

# Appendix E
out.append("## Appendix E — Security-control coverage (SEC → SR)\n\n")
out.append("Every requirement of `MCP_Gateway_Security_SRS.md` is listed. A MUST is covered when it has SR children here, is decomposed into child MUSTs in that document, or carries a recorded disposition. SHALL items of that document are covered as sources of FRs.\n\n")
out.append("| SEC ID | Title | Imperative | Coverage | Children / citing requirements |\n|---|---|---|---|---|\n")
def seckey(s):
    return [int(x) for x in s.split(".")]
for sid in sorted(sec, key=seckey):
    s = sec[sid]
    st = sec_status(sid)
    if st == "Realized by SR":
        det = ", ".join(sr_by_parent[sid])
    elif st == "Disposition":
        det = disps[sid]
    elif st == "Decomposed in SEC":
        det = "SEC " + ", ".join(sec_children[sid])
    elif st == "Source of FR":
        det = ", ".join(sorted(set(cited[sid]), key=lambda x: list(reqs).index(x)))
    else:
        det = "—"
    out.append(f"| {sid} | {esc(s['name'])} | {s['imp']} | {st} | {esc(det)} |\n")
out.append("\n")

# Appendix F
out.append("## Appendix F — Allocation matrix (element → requirements)\n\n")
out.append("Use this matrix to code element by element. A requirement allocated to several elements appears under each.\n\n")
out.append("| Element | Name | Functional (FR) | Security (SR) |\n|---|---|---|---|\n")
for e in sorted(arch["E"]):
    fr = [r["id"] for r in reqs.values() if e in r["alloc_ids"] and r["id"].startswith("FR")]
    sr = [r["id"] for r in reqs.values() if e in r["alloc_ids"] and r["id"].startswith("SR")]
    out.append(f"| {e} | {enames.get(e,'')} | {', '.join(fr) or '—'} | {', '.join(sr) or '—'} |\n")
out.append("\n")

# Appendix G
out.append("## Appendix G — Architecture coverage\n\n")
def cov_table(prefix, label, names=None):
    out.append(f"### {label}\n\n| ID | {'Name | ' if names else ''}Requirements |\n|---|{'---|' if names else ''}---|\n")
    for x in sorted(arch[prefix]):
        rs = [r["id"] for r in reqs.values() if x in r["alloc_ids"]]
        nm = f" {esc(names.get(x,''))} |" if names else ""
        out.append(f"| {x} |{nm} {', '.join(rs) or ('context only — outside SoI' if x in CONTEXT_ONLY else '**none**')} |\n")
    out.append("\n")
cov_table("F", "G.1 Functions", fnames)
cov_table("X", "G.2 External interfaces")
cov_table("I", "G.3 Internal interfaces")
cov_table("D", "G.4 Data stores")
out.append("### G.5 GUI view modules\n\n| ID | Requirements naming the module |\n|---|---|\n")
for g in sorted(arch["G"]):
    rs = [r["id"] for r in reqs.values() if re.search(rf'\b{g}\b', r["stmt"] + r["title"])]
    out.append(f"| {g} | {', '.join(rs) or '**none**'} |\n")
out.append("\n")

# Appendix H
out.append("## Appendix H — Requirement index\n\n| ID | Parent | Method | Elements | Title |\n|---|---|---|---|---|\n")
for r in reqs.values():
    els = ", ".join(x for x in r["alloc_ids"] if x.startswith("E-"))
    out.append(f"| {r['id']} | {r['parent']} | {r['method']} | {els} | {esc(r['title'])} |\n")
out.append("\n")

# Appendix I
fr = [r for r in reqs.values() if r["id"].startswith("FR")]
sr = [r for r in reqs.values() if r["id"].startswith("SR")]
roots = [r for r in fr if r["parent"] == "—"]
barren_roots = [r["id"] for r in roots if not any(x["parent"] == r["id"] for x in fr)]
mcount = collections.Counter(r["method"] for r in reqs.values())
must_ids = [s for s in sec if sec[s]["imp"] == "MUST"]
out.append("## Appendix I — Requirement-set checks\n\n")
out.append("Generated by the SRS build script from the requirement records, `ArchitectureV2.md` and `MCP_Gateway_Security_SRS.md`.\n\n")
out.append("| Check | Result |\n|---|---|\n")
out.append(f"| Requirements | {len(reqs)} total: {len(fr)} FR ({len(roots)} roots), {len(sr)} SR |\n")
out.append(f"| Verification methods | " + ", ".join(f"{k} {v}" for k, v in sorted(mcount.items())) + " |\n")
out.append(f"| Unique IDs; required fields; SHALL present; no MUST imperative | Pass |\n")
out.append(f"| Orphans (non-root without a valid parent) | None |\n")
out.append(f"| Every SR parent is a MUST in the security SRS | Pass |\n")
out.append(f"| Security MUSTs ({len(must_ids)}) covered (SR, SEC decomposition or disposition) | {'Pass' if not [g for g in gaps if sec[g]['imp']=='MUST'] else 'Gaps: ' + ', '.join(g for g in gaps if sec[g]['imp']=='MUST')} |\n")
out.append(f"| SEC requirements with dispositions (realized outside the Gateway or by process) | {', '.join('SEC ' + d for d in sorted(disps, key=seckey))} |\n")
out.append(f"| Security SHALL items without citing FR | {', '.join(g for g in gaps if sec[g]['imp']=='SHALL') or 'None'} |\n")
out.append(f"| Barren functional roots (no children) | {', '.join(barren_roots) or 'None'} |\n")
for k, lab in [("E", "Elements"), ("F", "Functions"), ("X", "External interfaces"), ("I", "Internal interfaces"), ("D", "Data stores"), ("G", "GUI modules")]:
    out.append(f"| {lab} without an allocated requirement | {', '.join(arch_gaps[k]) or 'None'} |\n")
out.append(f"| Allocation IDs resolve in `ArchitectureV2.md` | Pass |\n")
out.append(f"| Cross-references to FR/SR/CP IDs resolve | Pass |\n")
out.append("\n### I.1 Items for owner review\n\n")
out.append("1. **SEC wording versus V2.** Several parent MUSTs name V1 components (Neo4j \"graph service\", \"admission worker\", Hermes). The SR children realize them on V2 elements; the parent text is unchanged in the security SRS.\n")
out.append("2. **Dispositions.** The SEC requirements listed above are realized outside the Gateway (curation system or harness deployment). Confirm that these allocations are acceptable.\n")
out.append("3. **Owner-set values.** CP values marked *New* in Appendix A are engineering proposals and need owner confirmation.\n")
out.append("4. **Usability measure.** FR-8.24 turns \"user friendly\" into a timed task; confirm the threshold.\n")

OUT.write_text("".join(out))
print(f"OK: {len(reqs)} requirements ({len(fr)} FR, {len(sr)} SR) -> {OUT}")
print("WARNINGS:\n" + ("\n".join(warnings) if warnings else "none"))
