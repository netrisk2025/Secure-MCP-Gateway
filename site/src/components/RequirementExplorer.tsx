"use client";

import { useEffect, useMemo, useState } from "react";
import type { Requirement } from "@/lib/parse-reqs";
import { Inline } from "@/lib/inline";

type Props = {
  reqs: Requirement[];
  sections: { id: string; title: string }[];
  elementNames: Record<string, string>;
  secNames: Record<string, string>;
  initialElement?: string;
};

const METHODS = ["Test", "Inspection", "Demonstration", "Analysis"];

export default function RequirementExplorer({ reqs, sections, elementNames, secNames, initialElement }: Props) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<"all" | "FR" | "SR">("all");
  const [root, setRoot] = useState("all");
  const [element, setElement] = useState(initialElement ?? "all");
  const [method, setMethod] = useState("all");
  const [open, setOpen] = useState<string | null>(null);

  // Open a requirement linked by hash, e.g. /requirements/#FR-2.5
  useEffect(() => {
    const id = decodeURIComponent(window.location.hash.replace(/^#/, ""));
    if (id && reqs.some((r) => r.id === id)) {
      setOpen(id);
      setTimeout(() => document.getElementById(id)?.scrollIntoView({ block: "center" }), 50);
    }
  }, [reqs]);

  const elements = useMemo(
    () => Object.keys(elementNames).sort(),
    [elementNames],
  );

  const roots = useMemo(() => {
    if (kind === "SR") {
      return Object.keys(secNames)
        .filter((k) => !k.includes("."))
        .sort((a, b) => Number(a) - Number(b))
        .map((k) => ({ id: k, label: `SEC ${k}  ${secNames[k]}` }));
    }
    if (kind === "FR") return sections.map((s) => ({ id: s.id, label: `${s.id}  ${s.title}` }));
    return [
      ...sections.map((s) => ({ id: s.id, label: `${s.id}  ${s.title}` })),
      ...Object.keys(secNames)
        .filter((k) => !k.includes("."))
        .sort((a, b) => Number(a) - Number(b))
        .map((k) => ({ id: k, label: `SEC ${k}  ${secNames[k]}` })),
    ];
  }, [kind, sections, secNames]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return reqs.filter((r) => {
      if (kind !== "all" && r.kind !== kind) return false;
      if (root !== "all" && r.root !== root) return false;
      if (element !== "all" && !r.alloc.includes(element)) return false;
      if (method !== "all" && r.method !== method) return false;
      if (needle) {
        const hay = `${r.id} ${r.title} ${r.stmt} ${r.rat} ${r.src} ${r.alloc.join(" ")}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [reqs, q, kind, root, element, method]);

  const counts = useMemo(() => {
    let fr = 0;
    let sr = 0;
    for (const r of filtered) r.kind === "FR" ? fr++ : sr++;
    return { fr, sr };
  }, [filtered]);

  return (
    <div className="explorer">
      <div className="explorer-controls">
        <label className="field">
          <span>Search</span>
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="ID, words in the statement, a source, an element"
          />
        </label>
        <label className="field">
          <span>Kind</span>
          <select value={kind} onChange={(e) => { setKind(e.target.value as "all" | "FR" | "SR"); setRoot("all"); }}>
            <option value="all">Functional and security</option>
            <option value="FR">Functional (FR)</option>
            <option value="SR">Security (SR)</option>
          </select>
        </label>
        <label className="field">
          <span>Root</span>
          <select value={root} onChange={(e) => setRoot(e.target.value)}>
            <option value="all">Any root</option>
            {roots.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Element</span>
          <select value={element} onChange={(e) => setElement(e.target.value)}>
            <option value="all">Any element</option>
            {elements.map((e) => (
              <option key={e} value={e}>
                {e}  {elementNames[e]}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Verified by</span>
          <select value={method} onChange={(e) => setMethod(e.target.value)}>
            <option value="all">Any method</option>
            {METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
      </div>

      <p className="explorer-count">
        {filtered.length === reqs.length
          ? `All ${reqs.length} requirements.`
          : `${filtered.length} of ${reqs.length} requirements.`}{" "}
        {counts.fr} functional, {counts.sr} security.
      </p>

      <ol className="req-list">
        {filtered.map((r) => {
          const isOpen = open === r.id;
          return (
            <li key={r.id} id={r.id} className={`req ${r.kind === "SR" ? "req-sr" : "req-fr"} ${isOpen ? "open" : ""}`}>
              <button
                type="button"
                className="req-head"
                aria-expanded={isOpen}
                onClick={() => setOpen(isOpen ? null : r.id)}
              >
                <span className="req-id">{r.id}</span>
                <span className="req-title">{r.title}</span>
                <span className="req-method">{r.method}</span>
              </button>
              <p className="req-stmt">
                <Inline text={r.stmt} />
              </p>
              {isOpen && (
                <dl className="req-detail">
                  <dt>Parent</dt>
                  <dd>
                    {r.kind === "SR" ? (
                      <>
                        Security control {r.parent.replace("SEC-", "")}
                        {secNames[r.parent.replace("SEC-", "")] ? `, ${secNames[r.parent.replace("SEC-", "")]}` : ""}
                      </>
                    ) : (
                      r.parent
                    )}
                  </dd>
                  <dt>Allocated to</dt>
                  <dd>
                    {r.alloc.map((a, i) => (
                      <span key={a}>
                        {i > 0 && ", "}
                        <Inline text={a} />
                        {elementNames[a] ? ` ${elementNames[a]}` : ""}
                      </span>
                    ))}
                  </dd>
                  <dt>Verification</dt>
                  <dd>
                    <strong>{r.method}.</strong> <Inline text={r.vstmt} linkIds={false} />
                  </dd>
                  <dt>Source</dt>
                  <dd>
                    <Inline text={r.src} linkIds={false} />
                  </dd>
                  <dt>Rationale</dt>
                  <dd>
                    <Inline text={r.rat} linkIds={false} />
                  </dd>
                </dl>
              )}
            </li>
          );
        })}
      </ol>
      {filtered.length === 0 && (
        <p className="empty">No requirement matches those filters. Clear one of them to widen the list.</p>
      )}
    </div>
  );
}
