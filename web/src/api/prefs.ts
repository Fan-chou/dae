const storageKey = "kdae-ui-prefs";

export type ConnViewMode = "auto" | "table" | "card";
export type ConnTab = "active" | "closed" | "all";
export type GroupSort = "default" | "latency" | "traffic";

export type ThemePref = "system" | "light" | "dark";

export type UiPrefs = {
  theme: ThemePref;
  connView: ConnViewMode;
  connInterval: number;
  connHiddenCols: string[];
  connExclude: string;
  connExcludeOn: boolean;
  groupSort: GroupSort;
};

export const defaultPrefs: UiPrefs = {
  theme: "system",
  connView: "auto",
  connInterval: 2000,
  connHiddenCols: ["policy"],
  connExclude: "",
  connExcludeOn: false,
  groupSort: "default",
};

export function loadPrefs(): UiPrefs {
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "{}") as Partial<UiPrefs>;
    const interval = saved.connInterval === 1000 || saved.connInterval === 5000 ? saved.connInterval : 2000;
    const connView: ConnViewMode =
      saved.connView === "card" || saved.connView === "table" || saved.connView === "auto" ? saved.connView : "auto";
    return {
      theme: saved.theme === "light" || saved.theme === "dark" ? saved.theme : "system",
      connView,
      connInterval: interval,
      connHiddenCols: Array.isArray(saved.connHiddenCols) ? saved.connHiddenCols.map(String) : defaultPrefs.connHiddenCols.slice(),
      connExclude: typeof saved.connExclude === "string" ? saved.connExclude : "",
      connExcludeOn: !!saved.connExcludeOn,
      groupSort: saved.groupSort === "latency" || saved.groupSort === "traffic" ? saved.groupSort : "default",
    };
  } catch {
    return { ...defaultPrefs, connHiddenCols: defaultPrefs.connHiddenCols.slice() };
  }
}

export function savePrefs(prefs: UiPrefs): void {
  localStorage.setItem(storageKey, JSON.stringify(prefs));
}
