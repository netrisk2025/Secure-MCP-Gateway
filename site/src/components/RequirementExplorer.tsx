"use client";

import { useEffect, useMemo, useState } from "react";
import type { Requirement } from "@/lib/parse-reqs";
import type { ReqStatus } from "@/lib/status";
import { Inline } from "@/lib/inline";
import { ReqBadge } from "@/components/Sheet";

type Props = {
  reqs: Requirement[];
  sections: { id: string; title: string }[];
  elementNames: Record<string, string>;
  secNames: Record<string, string>;
  statusById: Record<string, { s: ReqStatus; t: string[] }>;
};

const METHODS = ["Test", "Inspection", "Demonstration", "Analysis"];
const STATUSES: ReqStatus[] = ["verified", "partial", "failing", "unverified"];

export default function RequirementExplorer({ reqs, sections, elementNames, secNames, statusById }: Props) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<"all" | "FR" | "SR">("all");
  const [root, setRoot] = useState("all");
  const [element, setElement] = useState("all");
  const [method, setMethod] = useState("all");
  const [status, setStatus] = useState<"all" | ReqStatus>("all");
  const [open, setOpen] = useState<string | null>(null);

  // Deep links: /requirements/#FR-2.5 opens one; ?element=E-07&status=failing presets filters.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const el = params.get("element");
    if (el && elementNames[el]) setElement(el);
    const st = params.get("status");
    if (st && (STATUSES as string[]).includes(st)) setStatus(st as ReqStatus);
    const id = decodeURIComponent(window.location.hash.replace(/^#/, ""));
    if (id && reqs.some((r) => r.id === id)) {
      setOpen(id);
      setTimeout(() => document.getElementById(id)?.scrollIntoView({ block: "center" }), 50);
    }
  }, [reqs, elementNames]);

  const elements = useMemo(() => Object.keys(elementNames).filter((k) => k.startsWith("E-")).sort(), [elementNames]);

  const roots = useMemo(() => {
    const sec = Object.keys(secNames)
      .filter((k) => !k.includes("."))
      .sort((a, b) => Number(a) - Number(b))
      .map((k) => ({ id: k, label: `SEC ${k} ${secNames[k]}` }));
    const fr = sections.map((s) => ({ id: s.id, label: `${s.id} ${s.title}` }));
    if (kind === "SR") return sec;
    if (kind === "FR") return fr;
    return [...fr, ...sec];
  }, [kind, sections, secNames]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return reqs.filter((r) => {
      if (kind !== "all" && r.kind !== kind) return false;
      if (root !== "all" && r.root !== root) return false;
      if (element !== "all" && !r.alloc.includes(element)) return false;
      if (method !== "all" && r.method !== method) return false;
      if (status !== "all" && statusById[r.id]?.s !== status) return false;
      if (needle) {
        const hay = `${r.id} ${r.title} ${r.stmt} ${r.rat} ${r.src} ${r.alloc.join(" ")}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [reqs, q, kind, root, element, method, status, statusById]);

  const counts = useMemo(() => {
    const c: Record<ReqStatus, number> = { verified: 0, partial: 0, failing: 0, unverified: 0 };
    for (const r of filtered) c[statusById[r.id]?.s ?? "unverified"]++;
    return c;
  }, [filtered, statusById]);

  const reset = () => {
    setQ("");
    setKind("all");
    setRoot("all");
    setElement("all");
    setMethod("all");
    setStatus("all");
  };
  const filtering = q || kind !== "all" || root !== "all" || element !== "all" || method !== "all" || status !== "all";

  return (
    <div className="explorer">
      <form className="explorer-controls" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="field search">
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
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as "all" | "FR" | "SR");
              setRoot("all");
            }}
          >
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
                {e} {elementNames[e]}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Verification method</span>
          <select value={method} onChange={(e) => setMethod(e.target.value)}>
            <option value="all">Any method</option>
            {METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Status</span>
          <select value={status} onChange={(e) => setStatus(e.target.value as "all" | ReqStatus)}>
            <option value="all">Any status</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </form>

      <p className="explorer-count" aria-live="polite">
        {filtered.length === reqs.length ? `All ${reqs.length} requirements` : `${filtered.length} of ${reqs.length} requirements`}
        : {STATUSES.map((s) => `${counts[s]} ${s}`).join(", ")}.{" "}
        {filtering && (
          <button type="button" className="linkish" onClick={reset}>
            Clear filters
          </button>
        )}
      </p>

      <ol className="req-list">
        {filtered.map((r) => {
          const isOpen = open === r.id;
          const st = statusById[r.id] ?? { s: "unverified" as ReqStatus, t: [] };
          return (
            <li key={r.id} id={r.id} className="req">
              <button
                type="button"
                className="req-head"
                aria-expanded={isOpen}
                aria-controls={`${r.id}-d`}
                onClick={() => setOpen(isOpen ? null : r.id)}
              >
                <span className="req-id">{r.id}</span>
                <span className="req-title">{r.title}</span>
                <ReqBadge status={st.s} />
              </button>
              <p className="req-stmt">
                <Inline text={r.stmt} />
              </p>
              {isOpen && (
                <dl className="facts" id={`${r.id}-d`}>
                  <dt>Status</dt>
                  <dd>
                    <ReqBadge status={st.s} />
                    {st.t.length > 0 && (
                      <>
                        {" "}
                        claimed by{" "}
                        {st.t.map((t, i) => (
                          <span key={t}>
                            {i > 0 && ", "}
                            <code>{t}</code>
                          </span>
                        ))}
                      </>
                    )}
                  </dd>
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
        <p className="empty">No requirement matches these filters. Clear a filter to widen the list.</p>
      )}
    </div>
  );
}
