import React from "react";
import Link from "next/link";

/**
 * Render the light inline markdown used in requirement statements:
 * `code`, **bold**, and architecture IDs (E-xx, F-xx, etc.) as links.
 */
export function Inline({ text, linkIds = true }: { text: string; linkIds?: boolean }) {
  const parts: React.ReactNode[] = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\b(?:E|F|X|I|D|G)-\d\d\b)|(\b(?:FR|SR)-[\d.]+(?:-\d+)?\b)|(\bCP-\d\d\b)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    if (m[1]) parts.push(<code key={k++}>{m[1].slice(1, -1)}</code>);
    else if (m[2]) parts.push(<strong key={k++}>{m[2].slice(2, -2)}</strong>);
    else if (m[3] && linkIds) {
      const id = m[3];
      const href = id.startsWith("E-") ? `/elements/${id}/` : `/interfaces/#${id}`;
      parts.push(
        <Link key={k++} className="idref" href={href}>
          {id}
        </Link>,
      );
    } else if (m[4] && linkIds) {
      const id = m[4].replace(/\.$/, "");
      parts.push(
        <Link key={k++} className="idref" href={`/requirements/#${id}`}>
          {id}
        </Link>,
      );
    } else parts.push(m[0]);
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <>{parts}</>;
}
