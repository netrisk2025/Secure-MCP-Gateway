import { useState } from "react";

export type Theme = "system" | "light" | "dark";
const KEY = "smcp.console.theme";

export function storedTheme(): Theme {
  try {
    const t = localStorage.getItem(KEY);
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

export function applyTheme(t: Theme): void {
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  try {
    localStorage.setItem(KEY, t);
  } catch {
    // Storage blocked: the choice lasts for this page only.
  }
}

export function ThemeSelect() {
  const [t, setT] = useState<Theme>(storedTheme);
  return (
    <label className="theme">
      <span>Theme</span>
      <select
        value={t}
        onChange={(e) => {
          const v = e.target.value as Theme;
          setT(v);
          applyTheme(v);
        }}
      >
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
  );
}
