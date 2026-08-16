export type ThemePref = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export function systemPrefersDark(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function resolveTheme(pref: ThemePref): ResolvedTheme {
  if (pref === "light" || pref === "dark") return pref;
  return systemPrefersDark() ? "dark" : "light";
}

export function applyTheme(pref: ThemePref): ResolvedTheme {
  const theme = resolveTheme(pref);
  if (typeof document === "undefined") return theme;
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.style.colorScheme = theme;
  return theme;
}
